// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory TAR reader: iterates the entries of a complete archive slice.
//!
//! Covers:
//! - POSIX ustar headers (IEEE Std 1003.1, "pax" utility, ustar Interchange
//!   Format), including the 155-byte `prefix` field.
//! - POSIX pax extended headers (same document, "pax Interchange Format"):
//!   typeflag `x` (next entry) and `g` (global), keywords `path`, `linkpath`,
//!   `size`, `mtime` (with fractional seconds), `uid`, `gid`, `uname`, `gname`.
//!   An empty value removes the keyword (falls back to the header field).
//! - GNU tar extensions (GNU tar manual, "Basic Tar Format"): `L` long name,
//!   `K` long link name, the `"ustar  \0"` old-GNU magic (no prefix field),
//!   and base-256 numeric fields (leading byte with the 0x80 bit set, value is
//!   the remaining bits as a two's-complement number).
//! - Pre-POSIX (v7) headers without magic.
//!
//! Entry types: regular file (`0`, NUL, `7`), hard link (`1`), symlink (`2`),
//! character device (`3`), block device (`4`), directory (`5`), FIFO (`6`).
//! Devices and FIFOs carry metadata only. Other typeflags (GNU sparse `S`,
//! multi-volume `M`, volume label `V`, ...) and `GNU.sparse.*` pax keys return
//! [`TarReadError::UnsupportedType`] rather than guessing at data layout.
//!
//! The end of archive is the first all-zero block (two are written by
//! conforming writers; anything after the first is ignored, as POSIX readers
//! do). A missing end marker is accepted when the archive ends exactly on an
//! entry boundary.

use std::ops::Range;

const BLOCK: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarReadError {
    /// Archive ends inside a header, entry data, or after a dangling
    /// extended header.
    Truncated,
    /// Header checksum does not match (neither unsigned nor signed sum).
    BadChecksum,
    /// Structurally invalid header (e.g. empty name).
    InvalidHeader,
    /// Numeric field is not octal / base-256.
    InvalidNumber,
    /// Numeric value does not fit the target type.
    NumericOverflow,
    /// Negative entry size.
    InvalidSize,
    /// Malformed pax extended header record.
    InvalidPax,
    /// Typeflag or extension that this reader does not interpret.
    UnsupportedType,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    File,
    Directory,
    Symlink,
    HardLink,
    CharDevice,
    BlockDevice,
    Fifo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    /// Raw path bytes (after pax/GNU overrides). Trailing `/` is removed from
    /// directory names.
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    /// Data size in bytes. Zero for links, directories, devices and FIFOs.
    pub size: u64,
    pub mode: u32,
    /// Seconds since the epoch (floor for negative fractional pax values).
    pub mtime: i64,
    /// Sub-second part of a pax `mtime`, 0..1_000_000_000.
    pub mtime_nanos: u32,
    pub uid: u64,
    pub gid: u64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub dev_major: u32,
    pub dev_minor: u32,
    /// Link target for symlinks and hard links.
    pub link_target: Option<Vec<u8>>,
    /// Byte range of the entry data within the archive slice.
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarReadLimits {
    /// Maximum number of returned entries.
    pub max_entries: usize,
    /// Maximum length of a resolved path or link target.
    pub max_name_len: usize,
    /// Maximum sum of entry data sizes.
    pub max_total_size: u64,
    /// Maximum size of a single pax / GNU long-name meta entry.
    pub max_meta_size: usize,
}

impl Default for TarReadLimits {
    fn default() -> Self {
        TarReadLimits {
            max_entries: 100_000,
            max_name_len: 4096,
            max_total_size: 1 << 40,
            max_meta_size: 1 << 20,
        }
    }
}

/// Parse a tar numeric field: octal text (leading spaces allowed, terminated
/// by space/NUL or field end; empty means 0) or GNU base-256 (first byte has
/// the 0x80 bit set; the remaining 8n-1 bits are a two's-complement number).
pub fn parse_numeric_field(field: &[u8]) -> Result<i64, TarReadError> {
    let Some(&first) = field.first() else {
        return Ok(0);
    };
    if first & 0x80 != 0 {
        if field.len() > 15 {
            return Err(TarReadError::InvalidNumber);
        }
        let bits = field.len() as u32 * 8 - 1;
        let mut u: i128 = (first & 0x7f) as i128;
        for &b in &field[1..] {
            u = (u << 8) | b as i128;
        }
        let v = if u & (1i128 << (bits - 1)) != 0 { u - (1i128 << bits) } else { u };
        return i64::try_from(v).map_err(|_| TarReadError::NumericOverflow);
    }
    let mut i = 0;
    while i < field.len() && field[i] == b' ' {
        i += 1;
    }
    let mut val: i64 = 0;
    while i < field.len() {
        let b = field[i];
        match b {
            b'0'..=b'7' => {
                val = val
                    .checked_mul(8)
                    .and_then(|v| v.checked_add((b - b'0') as i64))
                    .ok_or(TarReadError::NumericOverflow)?;
            }
            b' ' | 0 => break,
            _ => return Err(TarReadError::InvalidNumber),
        }
        i += 1;
    }
    Ok(val)
}

fn checksum_ok(block: &[u8]) -> Result<bool, TarReadError> {
    let field = &block[148..156];
    if !field.iter().any(u8::is_ascii_digit) {
        return Err(TarReadError::BadChecksum);
    }
    let stored = match parse_numeric_field(field) {
        Ok(v) => v,
        Err(_) => return Err(TarReadError::BadChecksum),
    };
    let mut unsigned: i64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as i64;
        signed += b as i8 as i64;
    }
    Ok(stored == unsigned || stored == signed)
}

/// True if `block` (at least 512 bytes) is a tar header with a valid checksum.
pub fn header_checksum_valid(block: &[u8]) -> bool {
    block.len() >= BLOCK && !block[..BLOCK].iter().all(|&b| b == 0) && matches!(checksum_ok(&block[..BLOCK]), Ok(true))
}

fn cstr(field: &[u8]) -> &[u8] {
    match field.iter().position(|&b| b == 0) {
        Some(p) => &field[..p],
        None => field,
    }
}

fn copy_bytes(src: &[u8], max: usize) -> Result<Vec<u8>, TarReadError> {
    if src.len() > max {
        return Err(TarReadError::LimitExceeded);
    }
    let mut v = Vec::new();
    v.try_reserve_exact(src.len()).map_err(|_| TarReadError::Allocation)?;
    v.extend_from_slice(src);
    Ok(v)
}

fn to_u64(v: i64) -> Result<u64, TarReadError> {
    u64::try_from(v).map_err(|_| TarReadError::InvalidNumber)
}

/// pax keyword values. `Some(empty)` means "explicitly unset".
#[derive(Default, Clone)]
struct PaxValues {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<Vec<u8>>,
    mtime: Option<Vec<u8>>,
    uid: Option<Vec<u8>>,
    gid: Option<Vec<u8>>,
    uname: Option<Vec<u8>>,
    gname: Option<Vec<u8>>,
}

fn pick<'a>(ext: &'a Option<Vec<u8>>, global: &'a Option<Vec<u8>>) -> Option<&'a [u8]> {
    let v = match ext {
        Some(v) => v.as_slice(),
        None => global.as_deref()?,
    };
    if v.is_empty() { None } else { Some(v) }
}

fn parse_pax(data: &[u8], out: &mut PaxValues, max_name_len: usize) -> Result<(), TarReadError> {
    let mut rest = data;
    while !rest.is_empty() {
        // Some writers pad the record area with NULs.
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let sp = rest.iter().position(|&b| b == b' ').ok_or(TarReadError::InvalidPax)?;
        let digits = &rest[..sp];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(TarReadError::InvalidPax);
        }
        let mut len: usize = 0;
        for &d in digits {
            len = len
                .checked_mul(10)
                .and_then(|v| v.checked_add((d - b'0') as usize))
                .ok_or(TarReadError::InvalidPax)?;
        }
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(TarReadError::InvalidPax);
        }
        let kv = &rest[sp + 1..len - 1];
        let eq = kv.iter().position(|&b| b == b'=').ok_or(TarReadError::InvalidPax)?;
        let (key, value) = (&kv[..eq], &kv[eq + 1..]);
        if key.is_empty() {
            return Err(TarReadError::InvalidPax);
        }
        let slot = match key {
            b"path" => &mut out.path,
            b"linkpath" => &mut out.linkpath,
            b"size" => &mut out.size,
            b"mtime" => &mut out.mtime,
            b"uid" => &mut out.uid,
            b"gid" => &mut out.gid,
            b"uname" => &mut out.uname,
            b"gname" => &mut out.gname,
            k if k.starts_with(b"GNU.sparse.") => return Err(TarReadError::UnsupportedType),
            _ => {
                rest = &rest[len..];
                continue;
            }
        };
        *slot = Some(copy_bytes(value, max_name_len)?);
        rest = &rest[len..];
    }
    Ok(())
}

fn parse_decimal_u64(s: &[u8]) -> Result<u64, TarReadError> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return Err(TarReadError::InvalidPax);
    }
    let mut v: u64 = 0;
    for &d in s {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add((d - b'0') as u64))
            .ok_or(TarReadError::NumericOverflow)?;
    }
    Ok(v)
}

/// pax `mtime`: `[-]digits[.digits]` -> (floor seconds, nanos).
fn parse_pax_time(s: &[u8]) -> Result<(i64, u32), TarReadError> {
    let (neg, body) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let (int_part, frac_part) = match body.iter().position(|&b| b == b'.') {
        Some(p) => (&body[..p], &body[p + 1..]),
        None => (body, &body[body.len()..]),
    };
    if !frac_part.iter().all(u8::is_ascii_digit) {
        return Err(TarReadError::InvalidPax);
    }
    let secs = i64::try_from(parse_decimal_u64(int_part)?).map_err(|_| TarReadError::NumericOverflow)?;
    let mut nanos: u32 = 0;
    for i in 0..9 {
        nanos = nanos * 10 + frac_part.get(i).map_or(0, |d| (d - b'0') as u32);
    }
    if !neg {
        return Ok((secs, nanos));
    }
    if nanos == 0 {
        Ok((-secs, 0))
    } else {
        let s = (-secs).checked_sub(1).ok_or(TarReadError::NumericOverflow)?;
        Ok((s, 1_000_000_000 - nanos))
    }
}

/// Read every entry of an in-memory tar archive.
pub fn read_entries(archive: &[u8], limits: TarReadLimits) -> Result<Vec<TarEntry>, TarReadError> {
    let mut entries: Vec<TarEntry> = Vec::new();
    let mut global = PaxValues::default();
    let mut ext: Option<PaxValues> = None;
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut total: u64 = 0;
    let mut pos: usize = 0;

    loop {
        let remaining = archive.len() - pos;
        let pending = ext.is_some() || long_name.is_some() || long_link.is_some();
        if remaining == 0 {
            if pending {
                return Err(TarReadError::Truncated);
            }
            break;
        }
        if remaining < BLOCK {
            if !pending && archive[pos..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(TarReadError::Truncated);
        }
        let block = &archive[pos..pos + BLOCK];
        if block.iter().all(|&b| b == 0) {
            if pending {
                return Err(TarReadError::Truncated);
            }
            break;
        }
        if !checksum_ok(block)? {
            return Err(TarReadError::BadChecksum);
        }

        let magic = &block[257..265];
        let is_posix = &magic[..6] == b"ustar\0";
        let typeflag = block[156];

        let size_raw = parse_numeric_field(&block[124..136])?;
        if size_raw < 0 {
            return Err(TarReadError::InvalidSize);
        }
        let mut size = size_raw as u64;

        let data_start = pos + BLOCK;

        // Meta entries: data is consumed here.
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
            let len = usize::try_from(size).map_err(|_| TarReadError::LimitExceeded)?;
            if len > limits.max_meta_size {
                return Err(TarReadError::LimitExceeded);
            }
            let end = data_start.checked_add(len).ok_or(TarReadError::Truncated)?;
            if end > archive.len() {
                return Err(TarReadError::Truncated);
            }
            let data = &archive[data_start..end];
            match typeflag {
                b'x' => {
                    let mut v = PaxValues::default();
                    parse_pax(data, &mut v, limits.max_name_len)?;
                    ext = Some(v);
                }
                b'g' => parse_pax(data, &mut global, limits.max_name_len)?,
                b'L' => long_name = Some(copy_bytes(cstr(data), limits.max_name_len)?),
                _ => long_link = Some(copy_bytes(cstr(data), limits.max_name_len)?),
            }
            pos = advance(end, archive.len());
            continue;
        }

        let kind = match typeflag {
            b'0' | 0 | b'7' => TarEntryKind::File,
            b'1' => TarEntryKind::HardLink,
            b'2' => TarEntryKind::Symlink,
            b'3' => TarEntryKind::CharDevice,
            b'4' => TarEntryKind::BlockDevice,
            b'5' => TarEntryKind::Directory,
            b'6' => TarEntryKind::Fifo,
            _ => return Err(TarReadError::UnsupportedType),
        };
        // Pre-POSIX archives mark directories with a trailing slash on a
        // regular-file typeflag.
        let name_field = cstr(&block[0..100]);
        let kind = if kind == TarEntryKind::File && typeflag != b'0' && !is_posix && name_field.ends_with(b"/") {
            TarEntryKind::Directory
        } else {
            kind
        };

        let e = ext.take().unwrap_or_default();

        // Path.
        let mut path: Vec<u8> = if let Some(p) = pick(&e.path, &global.path) {
            copy_bytes(p, limits.max_name_len)?
        } else if let Some(n) = long_name.take() {
            n
        } else {
            let prefix = if is_posix { cstr(&block[345..500]) } else { &[][..] };
            let mut v = Vec::new();
            let n = prefix.len() + 1 + name_field.len();
            v.try_reserve_exact(n).map_err(|_| TarReadError::Allocation)?;
            if !prefix.is_empty() {
                v.extend_from_slice(prefix);
                v.push(b'/');
            }
            v.extend_from_slice(name_field);
            v
        };
        long_name = None;
        if kind == TarEntryKind::Directory {
            while path.len() > 1 && path.ends_with(b"/") {
                path.pop();
            }
        }
        if path.is_empty() {
            return Err(TarReadError::InvalidHeader);
        }
        if path.len() > limits.max_name_len {
            return Err(TarReadError::LimitExceeded);
        }

        // Link target.
        let link_target = if matches!(kind, TarEntryKind::Symlink | TarEntryKind::HardLink) {
            let t = if let Some(l) = pick(&e.linkpath, &global.linkpath) {
                copy_bytes(l, limits.max_name_len)?
            } else if let Some(l) = long_link.take() {
                l
            } else {
                copy_bytes(cstr(&block[157..257]), limits.max_name_len)?
            };
            Some(t)
        } else {
            None
        };
        long_link = None;

        if let Some(s) = pick(&e.size, &global.size) {
            size = parse_decimal_u64(s)?;
        }
        let mode_raw = parse_numeric_field(&block[100..108])?;
        let mode = u32::try_from(mode_raw).map_err(|_| TarReadError::InvalidNumber)?;
        let mut uid = to_u64(parse_numeric_field(&block[108..116])?)?;
        let mut gid = to_u64(parse_numeric_field(&block[116..124])?)?;
        let mut mtime = parse_numeric_field(&block[136..148])?;
        let mut mtime_nanos = 0;
        if let Some(s) = pick(&e.uid, &global.uid) {
            uid = parse_decimal_u64(s)?;
        }
        if let Some(s) = pick(&e.gid, &global.gid) {
            gid = parse_decimal_u64(s)?;
        }
        if let Some(s) = pick(&e.mtime, &global.mtime) {
            (mtime, mtime_nanos) = parse_pax_time(s)?;
        }
        let has_magic = is_posix || magic == b"ustar  \0";
        let uname = match pick(&e.uname, &global.uname) {
            Some(s) => copy_bytes(s, limits.max_name_len)?,
            None if has_magic => copy_bytes(cstr(&block[265..297]), 32)?,
            None => Vec::new(),
        };
        let gname = match pick(&e.gname, &global.gname) {
            Some(s) => copy_bytes(s, limits.max_name_len)?,
            None if has_magic => copy_bytes(cstr(&block[297..329]), 32)?,
            None => Vec::new(),
        };
        let (dev_major, dev_minor) = if has_magic && matches!(kind, TarEntryKind::CharDevice | TarEntryKind::BlockDevice) {
            let ma = parse_numeric_field(&block[329..337])?;
            let mi = parse_numeric_field(&block[337..345])?;
            (
                u32::try_from(ma).map_err(|_| TarReadError::InvalidNumber)?,
                u32::try_from(mi).map_err(|_| TarReadError::InvalidNumber)?,
            )
        } else {
            (0, 0)
        };

        // Only regular files carry data; hard links, symlinks, devices,
        // directories and FIFOs have no data area per POSIX.
        if kind != TarEntryKind::File {
            size = 0;
        }

        if entries.len() >= limits.max_entries {
            return Err(TarReadError::LimitExceeded);
        }
        total = total.checked_add(size).ok_or(TarReadError::LimitExceeded)?;
        if total > limits.max_total_size {
            return Err(TarReadError::LimitExceeded);
        }
        let len = usize::try_from(size).map_err(|_| TarReadError::Truncated)?;
        let data_end = data_start.checked_add(len).ok_or(TarReadError::Truncated)?;
        if data_end > archive.len() {
            return Err(TarReadError::Truncated);
        }

        if entries.len() == entries.capacity() {
            entries.try_reserve(1).map_err(|_| TarReadError::Allocation)?;
        }
        entries.push(TarEntry {
            path,
            kind,
            size,
            mode,
            mtime,
            mtime_nanos,
            uid,
            gid,
            uname,
            gname,
            dev_major,
            dev_minor,
            link_target,
            data_range: data_start..data_end,
        });
        pos = advance(data_end, archive.len());
    }
    Ok(entries)
}

/// Round `end` up to the next block boundary, clamped to the archive length
/// (a final entry whose padding was cut off still ends the archive cleanly).
fn advance(end: usize, len: usize) -> usize {
    let padded = end.div_ceil(BLOCK).saturating_mul(BLOCK);
    padded.min(len)
}
