// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unix `ar` archives (System V/GNU and 4.4BSD variants) and Debian binary
//! packages (`.deb`), as [`ArchiveReader`]s.
//!
//! Spec sources: ar(5) (FreeBSD / 4.4BSD), the GNU binutils documentation
//! of the System V/GNU long-name table (`//`) and symbol tables (`/`,
//! `/SYM64/`), and deb(5) / deb-split(5) from dpkg for the package layout:
//! an ar archive whose first member is `debian-binary` (text `2.x\n`),
//! followed by `control.tar[.gz|.xz|.zst]` and
//! `data.tar[|.gz|.bz2|.xz|.lzma|.zst]`.
//!
//! ar layout: magic `!<arch>\n`, then members with a 60-byte header (name
//! 16, mtime 12 decimal, uid 6, gid 6, mode 8 octal, size 10 decimal, fmag
//! `` `\n ``), data padded to an even length. Long names: GNU `/<offset>`
//! into the `//` table (entries end in `/\n`), BSD `#1/<len>` with the name
//! prefixed to the data.
//!
//! [`DebReader`] lists the package's files (the inner data tarball) and
//! places the control tarball's members under `DEBIAN/` (the layout of
//! `dpkg-deb --raw-extract`). Zstandard-compressed members are reported as
//! `Unsupported` (no zstd decoder in the crate yet).
//!
//! Adapter seam: [`parse_ar`] follows the forge ticket `ar_read` (same
//! walk, error order and naming rules); once that module is harvested this
//! parser can delegate to it.

use std::borrow::Cow;

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::{TarReader, decompress};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::cpio_archive::{copy_vec, is_root_name};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::lzma_decode::decode_lzma_alone;

pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;
/// Largest LZMA dictionary accepted for `.lzma` data members.
const MAX_DICTIONARY: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArError {
    BadMagic,
    Truncated,
    BadHeader,
    BadNumber,
    BadName,
    TooManyEntries,
    Allocation,
}

impl From<ArError> for ReaderError {
    fn from(e: ArError) -> Self {
        match e {
            ArError::Truncated => ReaderError::Truncated,
            ArError::TooManyEntries => ReaderError::LimitExceeded,
            ArError::Allocation => ReaderError::Allocation,
            ArError::BadMagic | ArError::BadHeader | ArError::BadNumber | ArError::BadName => ReaderError::Invalid,
        }
    }
}

/// One ar member (symbol and long-name tables are not returned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArMember {
    pub name: Vec<u8>,
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    /// Absolute offset of the member data in the input.
    pub data_offset: usize,
    pub data_len: usize,
}

fn trim_spaces(f: &[u8]) -> &[u8] {
    let end = f.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
    &f[..end]
}

fn number(f: &[u8], radix: u32, empty_ok: bool) -> Result<u64, ArError> {
    let t = trim_spaces(f);
    if t.is_empty() {
        return if empty_ok { Ok(0) } else { Err(ArError::BadNumber) };
    }
    let mut v = 0u64;
    for &c in t {
        let d = (c as char).to_digit(radix).ok_or(ArError::BadNumber)?;
        v = v.checked_mul(u64::from(radix)).and_then(|v| v.checked_add(u64::from(d))).ok_or(ArError::BadNumber)?;
    }
    Ok(v)
}

fn all_digits(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

fn to_u32(v: u64) -> Result<u32, ArError> {
    u32::try_from(v).map_err(|_| ArError::BadNumber)
}

/// Parse a complete ar archive held in memory.
pub fn parse_ar(input: &[u8], max_entries: usize) -> Result<Vec<ArMember>, ArError> {
    if input.len() < 8 || &input[..8] != AR_MAGIC {
        return Err(ArError::BadMagic);
    }
    let mut out = Vec::new();
    let mut table: Option<&[u8]> = None;
    let mut p = 8usize;
    while p < input.len() {
        let h = input.get(p..p + HEADER_LEN).ok_or(ArError::Truncated)?;
        if h[58..60] != [0x60, 0x0A] {
            return Err(ArError::BadHeader);
        }
        let mtime = number(&h[16..28], 10, true)?;
        let uid = to_u32(number(&h[28..34], 10, true)?)?;
        let gid = to_u32(number(&h[34..40], 10, true)?)?;
        let mode = to_u32(number(&h[40..48], 8, true)?)?;
        let size = usize::try_from(number(&h[48..58], 10, false)?).map_err(|_| ArError::Truncated)?;
        let mut data_offset = p + HEADER_LEN;
        let data_end = data_offset.checked_add(size).ok_or(ArError::Truncated)?;
        let data = input.get(data_offset..data_end).ok_or(ArError::Truncated)?;
        let mut data_len = size;
        // Next header: data padded to even; a missing final pad byte is fine.
        p = data_end + (size & 1);
        let t = trim_spaces(&h[..16]);
        let name: Vec<u8> = if t == b"/" || t == b"/SYM64/" {
            continue;
        } else if t == b"//" {
            table = Some(data);
            continue;
        } else if t.len() > 1 && t[0] == b'/' && all_digits(&t[1..]) {
            let tab = table.ok_or(ArError::BadName)?;
            let off = usize::try_from(number(&t[1..], 10, false).map_err(|_| ArError::BadName)?)
                .map_err(|_| ArError::BadName)?;
            let rest = tab.get(off..).filter(|r| !r.is_empty()).ok_or(ArError::BadName)?;
            let nl = rest.iter().position(|&b| b == b'\n').ok_or(ArError::BadName)?;
            let n = &rest[..nl];
            n.strip_suffix(b"/").unwrap_or(n).to_vec()
        } else if t.len() > 3 && t.starts_with(b"#1/") && all_digits(&t[3..]) {
            let n = usize::try_from(number(&t[3..], 10, false).map_err(|_| ArError::BadName)?)
                .map_err(|_| ArError::BadName)?;
            if n > size {
                return Err(ArError::BadName);
            }
            let raw = &data[..n];
            let end = raw.iter().rposition(|&b| b != 0).map_or(0, |q| q + 1);
            data_offset += n;
            data_len -= n;
            raw[..end].to_vec()
        } else if t.starts_with(b"/") || t.starts_with(b"#1/") {
            return Err(ArError::BadName);
        } else {
            t.strip_suffix(b"/").unwrap_or(t).to_vec()
        };
        if name.is_empty() {
            return Err(ArError::BadName);
        }
        if out.len() >= max_entries {
            return Err(ArError::TooManyEntries);
        }
        out.try_reserve(1).map_err(|_| ArError::Allocation)?;
        out.push(ArMember { name, mtime, uid, gid, mode, data_offset, data_len });
    }
    Ok(out)
}

/// True when `input` is an ar archive whose first member is
/// `debian-binary`.
pub fn is_deb(input: &[u8]) -> bool {
    input.starts_with(AR_MAGIC) && input.get(8..8 + 16).is_some_and(|n| trim_spaces(n) == b"debian-binary" || trim_spaces(n) == b"debian-binary/")
}

/// Plain ar archive: every member is a regular file.
pub struct ArReader<'a> {
    bytes: &'a [u8],
    entries: Vec<PlannedEntry>,
    ranges: Vec<std::ops::Range<usize>>,
    max_entry_size: u64,
}

impl<'a> ArReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let members = parse_ar(bytes, limits.max_entries)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(members.len()).map_err(|_| ReaderError::Allocation)?;
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(members.len()).map_err(|_| ReaderError::Allocation)?;
        let mut total: u64 = 0;
        for m in members {
            total = total.checked_add(m.data_len as u64).ok_or(ReaderError::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded);
            }
            let mode = Some(m.mode & 0o7777);
            let mtime = i64::try_from(m.mtime).ok();
            entries.push(PlannedEntry { path: m.name, kind: EntryKind::File, size: m.data_len as u64, mode, mtime });
            ranges.push(m.data_offset..m.data_offset + m.data_len);
        }
        Ok(ArReader { bytes, entries, ranges, max_entry_size: limits.max_entry_size })
    }
}

impl ArchiveReader for ArReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Ar
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let r = self.ranges.get(index).ok_or(ReaderError::OutOfRange)?;
        if r.len() as u64 > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        copy_vec(self.bytes.get(r.clone()).ok_or(ReaderError::Invalid)?)
    }
}

/// Decompress a tarball member of a package by its leading bytes (gzip,
/// bzip2, xz; plain tar as is). `.lzma` is recognised by the member name.
/// Zstandard and anything unknown are `Unsupported`.
pub(crate) fn unpack_tarball<'a>(name: &[u8], data: &'a [u8], max_output: usize) -> Result<Cow<'a, [u8]>, ReaderError> {
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Err(ReaderError::Unsupported);
    }
    match detect_format(data) {
        Detected::Gzip => Ok(Cow::Owned(decompress(ArchiveFormat::Gzip, data, max_output)?)),
        Detected::Bzip2 => Ok(Cow::Owned(decompress(ArchiveFormat::Bzip2, data, max_output)?)),
        Detected::Xz => Ok(Cow::Owned(decompress(ArchiveFormat::Xz, data, max_output)?)),
        Detected::Tar | Detected::TarHeuristic => Ok(Cow::Borrowed(data)),
        _ if name.ends_with(b".lzma") => {
            use crate::lzma_decode::LzmaError;
            decode_lzma_alone(data, MAX_DICTIONARY, max_output).map(Cow::Owned).map_err(|e| match e {
                LzmaError::LimitExceeded => ReaderError::LimitExceeded,
                LzmaError::UnexpectedEof => ReaderError::Truncated,
                _ => ReaderError::Invalid,
            })
        }
        // An empty data.tar (a package with no files) is a valid tar.
        _ if data.is_empty() || data.iter().all(|&b| b == 0) => Ok(Cow::Borrowed(data)),
        _ => Err(ReaderError::Unsupported),
    }
}

fn strip_dot_slash(mut p: &[u8]) -> &[u8] {
    while let Some(r) = p.strip_prefix(b"./") {
        p = r;
    }
    while let Some(r) = p.strip_prefix(b"/") {
        p = r;
    }
    p
}

const CONTROL_PREFIX: &[u8] = b"DEBIAN/";

/// Debian binary package: the data tarball's members, then the control
/// tarball's members under `DEBIAN/`.
pub struct DebReader {
    control: TarReader<'static>,
    data: TarReader<'static>,
    /// (true = control, index in that tar) per listed entry.
    map: Vec<(bool, usize)>,
    entries: Vec<PlannedEntry>,
    version: Vec<u8>,
}

impl DebReader {
    pub fn new(bytes: &[u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        // A package has a handful of members; bound the walk tightly.
        let members = parse_ar(bytes, 64)?;
        let first = members.first().ok_or(ReaderError::Invalid)?;
        if first.name != b"debian-binary" {
            return Err(ReaderError::Invalid);
        }
        let ver = &bytes[first.data_offset..first.data_offset + first.data_len];
        if !ver.starts_with(b"2.") || ver.len() > 64 {
            return Err(ReaderError::Unsupported);
        }
        let version = ver.strip_suffix(b"\n").unwrap_or(ver).to_vec();
        let find = |prefix: &[u8]| {
            members.iter().skip(1).find(|m| m.name == prefix || (m.name.starts_with(prefix) && m.name.get(prefix.len()) == Some(&b'.')))
        };
        let control_m = find(b"control.tar").ok_or(ReaderError::Invalid)?;
        let data_m = find(b"data.tar").ok_or(ReaderError::Invalid)?;
        let max_out = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
        let open = |m: &ArMember, max: usize| -> Result<TarReader<'static>, ReaderError> {
            let raw = &bytes[m.data_offset..m.data_offset + m.data_len];
            let tar = unpack_tarball(&m.name, raw, max)?;
            if tar.iter().all(|&b| b == 0) {
                return TarReader::new(Cow::Owned(Vec::new()), limits).or_else(|_| empty_tar(limits));
            }
            TarReader::new(Cow::Owned(tar.into_owned()), limits)
        };
        let control = open(control_m, max_out)?;
        let data = open(data_m, max_out)?;
        let n = control.entries().len().checked_add(data.entries().len()).ok_or(ReaderError::LimitExceeded)?;
        if n > limits.max_entries {
            return Err(ReaderError::LimitExceeded);
        }
        let mut total: u64 = 0;
        let mut map = Vec::new();
        map.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        for (is_control, tar) in [(false, &data), (true, &control)] {
            for (i, e) in tar.entries().iter().enumerate() {
                if matches!(e.kind, EntryKind::Dir) && is_root_name(&e.path) {
                    continue;
                }
                let mut e = e.clone();
                if matches!(e.kind, EntryKind::File) {
                    total = total.checked_add(e.size).ok_or(ReaderError::LimitExceeded)?;
                }
                if is_control {
                    e.path = prefixed(&e.path)?;
                    if let EntryKind::Hardlink { target } = &mut e.kind {
                        *target = prefixed(target)?;
                    }
                }
                entries.push(e);
                map.push((is_control, i));
            }
        }
        if total > limits.max_total_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(DebReader { control, data, map, entries, version })
    }

    /// Contents of `debian-binary` without the newline (e.g. `2.0`).
    pub fn format_version(&self) -> &[u8] {
        &self.version
    }
}

fn empty_tar(limits: ReaderLimits) -> Result<TarReader<'static>, ReaderError> {
    TarReader::new(Cow::Owned(vec![0u8; 1024]), limits)
}

fn prefixed(path: &[u8]) -> Result<Vec<u8>, ReaderError> {
    let rest = strip_dot_slash(path);
    let mut v = Vec::new();
    v.try_reserve_exact(CONTROL_PREFIX.len() + rest.len()).map_err(|_| ReaderError::Allocation)?;
    v.extend_from_slice(CONTROL_PREFIX);
    v.extend_from_slice(rest);
    Ok(v)
}

impl ArchiveReader for DebReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Deb
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let &(is_control, i) = self.map.get(index).ok_or(ReaderError::OutOfRange)?;
        if is_control { self.control.read(i) } else { self.data.read(i) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(name: &str, size: usize) -> Vec<u8> {
        let s = format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n", 0, 0, 0, 644);
        assert_eq!(s.len(), 60);
        s.into_bytes()
    }

    #[test]
    fn short_and_padding() {
        let mut a = AR_MAGIC.to_vec();
        a.extend(hdr("a.o/", 3));
        a.extend(b"abc\n");
        a.extend(hdr("b", 2));
        a.extend(b"xy");
        let m = parse_ar(&a, 10).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].name, b"a.o");
        assert_eq!(&a[m[1].data_offset..m[1].data_offset + 2], b"xy");
        // Missing final pad byte is accepted.
        assert_eq!(parse_ar(&a[..a.len()], 10).unwrap().len(), 2);
        for n in 0..a.len() {
            let _ = parse_ar(&a[..n], 10);
        }
        assert_eq!(parse_ar(&a, 1), Err(ArError::TooManyEntries));
        assert_eq!(parse_ar(b"!<thin>\n", 1), Err(ArError::BadMagic));
    }
}
