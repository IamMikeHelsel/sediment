// SPDX-License-Identifier: MIT OR Apache-2.0
//! Split volumes (`name.001`, `name.002`, ...) and volume-size switches.
//!
//! This is the adapter seam for the forge-owned `split_volumes` and
//! `size_parse` modules, which were not yet harvested when it was written.
//! It covers only what the CLI needs (size parsing, naming, planning,
//! reading and atomically writing plain byte-split volumes). When the forge
//! modules land, these functions should delegate to them; the CLI only
//! calls the functions below.
//!
//! Format: a split archive is the byte-for-byte concatenation of its
//! volumes in numeric order; names are the full archive name plus `.NNN`
//! (three digits, zero padded, starting at `.001`, growing to more digits
//! past 999). Size suffixes follow the 7-Zip `-v` switch convention:
//! none or `b` = bytes, `k` = KiB, `m` = MiB, `g` = GiB (case-insensitive).
//! These are documented conventions of the 7-Zip command line, not code.
//!
//! Limits: at most [`MAX_VOLUMES`] volumes; readers take an explicit total
//! byte cap and never allocate beyond it.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

/// Largest number of volumes created or read.
pub const MAX_VOLUMES: u32 = 99_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeError {
    /// Size switch is empty, zero, malformed or overflows.
    InvalidSize,
    /// More than [`MAX_VOLUMES`] volumes would be needed.
    TooManyVolumes,
    /// The first volume does not exist.
    NotFound,
    /// A volume exists and overwriting was not requested.
    Exists,
    /// A volume path exists but is not a regular file.
    NotAFile,
    /// The combined size exceeds the caller's limit.
    LimitExceeded,
    Allocation,
    Io,
}

/// Parse a volume size such as `100`, `512b`, `64k`, `10m`, `2g`.
pub fn parse_size(s: &[u8]) -> Result<u64, VolumeError> {
    let (digits, mult): (&[u8], u64) = match s.last().map(u8::to_ascii_lowercase) {
        Some(b'b') => (&s[..s.len() - 1], 1),
        Some(b'k') => (&s[..s.len() - 1], 1 << 10),
        Some(b'm') => (&s[..s.len() - 1], 1 << 20),
        Some(b'g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    if digits.is_empty() || digits.len() > 20 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(VolumeError::InvalidSize);
    }
    let mut v: u64 = 0;
    for &d in digits {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or(VolumeError::InvalidSize)?;
    }
    let v = v.checked_mul(mult).ok_or(VolumeError::InvalidSize)?;
    if v == 0 {
        return Err(VolumeError::InvalidSize);
    }
    Ok(v)
}

/// Extension of volume `index` (1-based): `001`, ..., `999`, `1000`, ...
pub fn volume_suffix(index: u32) -> String {
    format!("{index:03}")
}

/// Path of volume `index` (1-based) of the archive `base`.
pub fn volume_path(base: &Path, index: u32) -> PathBuf {
    let mut s: OsString = base.as_os_str().to_os_string();
    s.push(".");
    s.push(volume_suffix(index));
    PathBuf::from(s)
}

/// If `path` names a first volume (`*.001` with a non-empty stem), the
/// archive base path without the `.001`.
pub fn first_volume_base(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.as_encoded_bytes();
    if name.len() <= 4 || !name.ends_with(b".001") {
        return None;
    }
    let full = path.as_os_str().as_encoded_bytes();
    let stem = &full[..full.len() - 4];
    // `stem` ends on an ASCII byte boundary of a valid OsStr encoding.
    let s = std::str::from_utf8(stem).ok().map(PathBuf::from);
    s.or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Some(PathBuf::from(std::ffi::OsStr::from_bytes(stem)))
        }
        #[cfg(not(unix))]
        {
            None
        }
    })
}

/// Lengths of the volumes needed for `total` bytes. `sizes` are the
/// requested volume sizes in order; the last one repeats. An empty input
/// still produces one (empty) volume.
pub fn plan_volumes(total: u64, sizes: &[u64]) -> Result<Vec<u64>, VolumeError> {
    if sizes.is_empty() || sizes.contains(&0) {
        return Err(VolumeError::InvalidSize);
    }
    let mut out = Vec::new();
    let mut left = total;
    let mut i = 0usize;
    loop {
        if out.len() >= MAX_VOLUMES as usize {
            return Err(VolumeError::TooManyVolumes);
        }
        let cap = sizes[i.min(sizes.len() - 1)];
        let n = left.min(cap);
        out.try_reserve(1).map_err(|_| VolumeError::Allocation)?;
        out.push(n);
        left -= n;
        i = i.saturating_add(1);
        if left == 0 {
            return Ok(out);
        }
    }
}

fn io_err(e: &std::io::Error) -> VolumeError {
    match e.kind() {
        ErrorKind::NotFound => VolumeError::NotFound,
        ErrorKind::OutOfMemory => VolumeError::Allocation,
        _ => VolumeError::Io,
    }
}

/// Read and concatenate `base.001`, `base.002`, ... up to the first missing
/// volume. Returns the bytes and the number of volumes. Fails if the
/// combined size exceeds `max_total`.
pub fn read_volumes(base: &Path, max_total: u64) -> Result<(Vec<u8>, u32), VolumeError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut count = 0u32;
    loop {
        let index = count + 1;
        let p = volume_path(base, index);
        let f = match fs::File::open(&p) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound && count > 0 => break,
            Err(e) => return Err(io_err(&e)),
        };
        let m = f.metadata().map_err(|e| io_err(&e))?;
        if !m.is_file() {
            return Err(VolumeError::NotAFile);
        }
        if count >= MAX_VOLUMES {
            return Err(VolumeError::TooManyVolumes);
        }
        let room = max_total - buf.len() as u64;
        if m.len() > room {
            return Err(VolumeError::LimitExceeded);
        }
        let want = usize::try_from(m.len()).map_err(|_| VolumeError::LimitExceeded)?;
        buf.try_reserve_exact(want).map_err(|_| VolumeError::Allocation)?;
        let before = buf.len();
        f.take(room + 1).read_to_end(&mut buf).map_err(|e| io_err(&e))?;
        if (buf.len() - before) as u64 > room {
            return Err(VolumeError::LimitExceeded);
        }
        count = index;
    }
    Ok((buf, count))
}

fn tmp_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(format!(".sediment-tmp-{}", std::process::id()));
    PathBuf::from(s)
}

fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// Split `data` into volumes of `base` (see [`plan_volumes`]). Every volume
/// is written to a temporary sibling and renamed into place only after all
/// were written, so a failure leaves no partial set. Without `overwrite`,
/// any existing volume (including the one after the last, which a reader
/// would otherwise append) is an error; with it, stale following volumes
/// left by an earlier, longer set are removed. Returns the volume count.
pub fn write_volumes(base: &Path, data: &[u8], sizes: &[u64], overwrite: bool) -> Result<u32, VolumeError> {
    let plan = plan_volumes(data.len() as u64, sizes)?;
    let n = plan.len() as u32;
    for i in 1..=n + 1 {
        let p = volume_path(base, i);
        if let Ok(m) = fs::symlink_metadata(&p) {
            if !overwrite {
                return Err(VolumeError::Exists);
            }
            if !m.is_file() {
                return Err(VolumeError::NotAFile);
            }
        }
    }
    let mut tmps: Vec<PathBuf> = Vec::new();
    let mut pos = 0usize;
    let mut result = Ok(());
    for (i, &len) in plan.iter().enumerate() {
        let tmp = tmp_path(&volume_path(base, i as u32 + 1));
        let end = pos + len as usize;
        let r = (|| -> std::io::Result<()> {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            tmps.push(tmp.clone());
            f.write_all(&data[pos..end])?;
            f.sync_all()
        })();
        if let Err(e) = r {
            result = Err(if e.kind() == ErrorKind::AlreadyExists { VolumeError::Exists } else { io_err(&e) });
            break;
        }
        pos = end;
    }
    if result.is_ok() {
        for (i, tmp) in tmps.iter().enumerate() {
            if let Err(e) = fs::rename(tmp, volume_path(base, i as u32 + 1)) {
                result = Err(io_err(&e));
                break;
            }
        }
    }
    if let Err(e) = result {
        for t in &tmps {
            let _ = fs::remove_file(t);
        }
        return Err(e);
    }
    // Remove a stale tail from an earlier, longer volume set.
    let mut i = n + 1;
    while i <= MAX_VOLUMES {
        let p = volume_path(base, i);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() => {
                fs::remove_file(&p).map_err(|e| io_err(&e))?;
            }
            _ => break,
        }
        i += 1;
    }
    Ok(n)
}

/// Existing volumes of `base` (consecutive from `.001`), for excluding them
/// from the inputs of an archive being written.
pub fn existing_volumes(base: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut i = 1;
    while i <= MAX_VOLUMES {
        let p = volume_path(base, i);
        if !exists(&p) {
            break;
        }
        v.push(p);
        i += 1;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size(b"1"), Ok(1));
        assert_eq!(parse_size(b"10b"), Ok(10));
        assert_eq!(parse_size(b"3K"), Ok(3072));
        assert_eq!(parse_size(b"2m"), Ok(2 << 20));
        assert_eq!(parse_size(b"1g"), Ok(1 << 30));
        for bad in [&b""[..], b"k", b"0", b"0m", b"-1", b"1.5m", b"1t", b"99999999999999999999", b"18446744073709551615k"] {
            assert_eq!(parse_size(bad), Err(VolumeError::InvalidSize), "{bad:?}");
        }
    }

    #[test]
    fn names() {
        assert_eq!(volume_path(Path::new("a/b.7z"), 1), PathBuf::from("a/b.7z.001"));
        assert_eq!(volume_path(Path::new("x"), 1000), PathBuf::from("x.1000"));
        assert_eq!(first_volume_base(Path::new("d/x.tar.gz.001")), Some(PathBuf::from("d/x.tar.gz")));
        assert_eq!(first_volume_base(Path::new("d/.001")), None);
        assert_eq!(first_volume_base(Path::new("x.002")), None);
    }

    #[test]
    fn planning() {
        assert_eq!(plan_volumes(0, &[5]), Ok(vec![0]));
        assert_eq!(plan_volumes(10, &[5]), Ok(vec![5, 5]));
        assert_eq!(plan_volumes(11, &[5]), Ok(vec![5, 5, 1]));
        assert_eq!(plan_volumes(11, &[2, 4]), Ok(vec![2, 4, 4, 1]));
        assert_eq!(plan_volumes(1, &[]), Err(VolumeError::InvalidSize));
        assert_eq!(plan_volumes(u64::MAX, &[1]), Err(VolumeError::TooManyVolumes));
    }
}
