// SPDX-License-Identifier: MIT OR Apache-2.0
//! cpio archive reading: "new ASCII" (newc, magic `070701`), "new CRC"
//! (`070702`), "old portable ASCII" (odc, `070707`) and "old binary"
//! (16-bit words in either byte order), plus an [`ArchiveReader`] over the
//! parsed members (also used for the cpio payload of RPM packages).
//!
//! Spec sources: cpio(5) as documented by libarchive and the GNU cpio
//! manual ("Archive formats"), and POSIX.1-1988 / SUSv2 `cpio` (odc).
//! Header layouts:
//! - newc/crc: 110 bytes = magic(6) + 13 x 8 hex digits (ino, mode, uid,
//!   gid, nlink, mtime, filesize, devmajor, devminor, rdevmajor, rdevminor,
//!   namesize, check). The name follows; header+name is padded to a multiple
//!   of 4, and so is the data. For `070702`, `check` is the 32-bit sum of all
//!   data bytes.
//! - odc: 76 bytes of octal fields: magic(6) dev(6) ino(6) mode(6) uid(6)
//!   gid(6) nlink(6) rdev(6) mtime(11) namesize(6) filesize(11); no padding.
//! - binary: 13 u16 words (magic 070707, dev, ino, mode, uid, gid, nlink,
//!   rdev, mtime hi/lo, namesize, filesize hi/lo) in the writer's byte order;
//!   name and data are each padded to an even length.
//!
//! `namesize` includes the terminating NUL. The member named `TRAILER!!!`
//! ends the archive; anything after it (block padding) is ignored.
//!
//! Hard links: newc stores the data once, with the last link of a group
//! (same device and inode, `nlink > 1`), and earlier links carry size 0.
//! [`CpioReader`] presents the first link of such a group as the regular
//! file (with the shared data) and the others as hard links to it. Old
//! formats store the data with every link, so those stay separate files.
//!
//! The RPM "stripped" cpio variant (`07070X`, RPM >= 4.12 for files over
//! 4 GiB) is reported as `Unsupported`.
//!
//! Adapter seam: the forge ticket `cpio_read` defines a list-only subset of
//! this parser (no inode/device fields). This module needs inode/device for
//! hard links, so it carries its own parser; once `cpio_read` is harvested
//! it can be checked against [`parse_cpio`] (same walk, same error order).

use std::borrow::Cow;

use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioFormat {
    Binary,
    Odc,
    Newc,
    NewcCrc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioError {
    Truncated,
    BadMagic,
    BadNumber,
    BadName,
    ChecksumMismatch,
    TooManyEntries,
    LimitExceeded,
    Allocation,
    Unsupported,
}

impl From<CpioError> for ReaderError {
    fn from(e: CpioError) -> Self {
        match e {
            CpioError::Truncated => ReaderError::Truncated,
            CpioError::ChecksumMismatch => ReaderError::CrcMismatch,
            CpioError::TooManyEntries | CpioError::LimitExceeded => ReaderError::LimitExceeded,
            CpioError::Allocation => ReaderError::Allocation,
            CpioError::Unsupported => ReaderError::Unsupported,
            CpioError::BadMagic | CpioError::BadNumber | CpioError::BadName => ReaderError::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpioLimits {
    /// Members returned (the trailer is not counted).
    pub max_entries: usize,
    /// Longest member name in bytes (without the NUL).
    pub max_name_len: usize,
}

impl Default for CpioLimits {
    fn default() -> Self {
        CpioLimits { max_entries: 100_000, max_name_len: 16 * 1024 }
    }
}

/// One cpio member as stored. Device numbers are `major << 32 | minor` for
/// newc/crc and the raw 16/18-bit value for the old formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpioMember {
    pub format: CpioFormat,
    /// Name without the terminating NUL.
    pub name: Vec<u8>,
    pub ino: u64,
    pub dev: u64,
    pub rdev: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    /// Offset of the header in the input.
    pub header_offset: usize,
    /// Absolute offset of the file data in the input.
    pub data_offset: usize,
    pub data_len: usize,
}

const TRAILER: &[u8] = b"TRAILER!!!";
const NEWC_LEN: usize = 110;
const ODC_LEN: usize = 76;
const BIN_LEN: usize = 26;

fn hex_field(f: &[u8]) -> Result<u64, CpioError> {
    let mut v = 0u64;
    for &c in f {
        let d = (c as char).to_digit(16).ok_or(CpioError::BadNumber)?;
        v = (v << 4) | u64::from(d);
    }
    Ok(v)
}

fn oct_field(f: &[u8]) -> Result<u64, CpioError> {
    let mut v = 0u64;
    for &c in f {
        if !(b'0'..=b'7').contains(&c) {
            return Err(CpioError::BadNumber);
        }
        // 11 octal digits fit in 33 bits: no overflow.
        v = (v << 3) | u64::from(c - b'0');
    }
    Ok(v)
}

fn u32_of(v: u64) -> Result<u32, CpioError> {
    u32::try_from(v).map_err(|_| CpioError::BadNumber)
}

fn align(v: usize, a: usize) -> Option<usize> {
    v.checked_add(a - 1).map(|x| x / a * a)
}

/// Detect the member format at offset `p`.
fn detect_at(input: &[u8], p: usize) -> Result<(CpioFormat, bool), CpioError> {
    let rest = input.get(p..).unwrap_or(&[]);
    if rest.len() >= 6 {
        match &rest[..6] {
            b"070701" => return Ok((CpioFormat::Newc, false)),
            b"070702" => return Ok((CpioFormat::NewcCrc, false)),
            b"070707" => return Ok((CpioFormat::Odc, false)),
            b"07070X" | b"07070x" => return Err(CpioError::Unsupported),
            _ => {}
        }
    }
    if rest.len() >= 2 {
        match (rest[0], rest[1]) {
            (0xC7, 0x71) => return Ok((CpioFormat::Binary, false)),
            (0x71, 0xC7) => return Ok((CpioFormat::Binary, true)),
            _ => {}
        }
    }
    if rest.len() < 6 { Err(CpioError::Truncated) } else { Err(CpioError::BadMagic) }
}

/// True when `input` starts with a cpio header (any supported variant). For
/// the 2-byte binary magic the whole first header and name are checked.
pub fn looks_like_cpio(input: &[u8]) -> bool {
    if input.len() >= 6 && matches!(&input[..6], b"070701" | b"070702" | b"070707") {
        return true;
    }
    match detect_at(input, 0) {
        Ok((CpioFormat::Binary, _)) => parse_member(input, 0, &CpioLimits::default()).is_ok(),
        _ => false,
    }
}

struct Header {
    format: CpioFormat,
    ino: u64,
    dev: u64,
    rdev: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    nlink: u64,
    mtime: u64,
    filesize: u64,
    namesize: u64,
    check: u64,
    header_len: usize,
    /// Alignment of name end and data end.
    pad: usize,
}

fn parse_header(input: &[u8], p: usize) -> Result<Header, CpioError> {
    let (format, big) = detect_at(input, p)?;
    match format {
        CpioFormat::Newc | CpioFormat::NewcCrc => {
            let h = input.get(p..p.checked_add(NEWC_LEN).ok_or(CpioError::Truncated)?).ok_or(CpioError::Truncated)?;
            let f = |i: usize| hex_field(&h[6 + i * 8..6 + i * 8 + 8]);
            Ok(Header {
                format,
                ino: f(0)?,
                mode: f(1)?,
                uid: f(2)?,
                gid: f(3)?,
                nlink: f(4)?,
                mtime: f(5)?,
                filesize: f(6)?,
                dev: (f(7)? << 32) | f(8)?,
                rdev: (f(9)? << 32) | f(10)?,
                namesize: f(11)?,
                check: f(12)?,
                header_len: NEWC_LEN,
                pad: 4,
            })
        }
        CpioFormat::Odc => {
            let h = input.get(p..p.checked_add(ODC_LEN).ok_or(CpioError::Truncated)?).ok_or(CpioError::Truncated)?;
            Ok(Header {
                format,
                dev: oct_field(&h[6..12])?,
                ino: oct_field(&h[12..18])?,
                mode: oct_field(&h[18..24])?,
                uid: oct_field(&h[24..30])?,
                gid: oct_field(&h[30..36])?,
                nlink: oct_field(&h[36..42])?,
                rdev: oct_field(&h[42..48])?,
                mtime: oct_field(&h[48..59])?,
                namesize: oct_field(&h[59..65])?,
                filesize: oct_field(&h[65..76])?,
                check: 0,
                header_len: ODC_LEN,
                pad: 1,
            })
        }
        CpioFormat::Binary => {
            let h = input.get(p..p.checked_add(BIN_LEN).ok_or(CpioError::Truncated)?).ok_or(CpioError::Truncated)?;
            let w = |i: usize| {
                let b = [h[i * 2], h[i * 2 + 1]];
                u64::from(if big { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
            };
            Ok(Header {
                format,
                dev: w(1),
                ino: w(2),
                mode: w(3),
                uid: w(4),
                gid: w(5),
                nlink: w(6),
                rdev: w(7),
                mtime: (w(8) << 16) | w(9),
                namesize: w(10),
                filesize: (w(11) << 16) | w(12),
                check: 0,
                header_len: BIN_LEN,
                pad: 2,
            })
        }
    }
}

/// Parse the member at `p`. Returns the member (or `None` for the trailer)
/// and the offset of the next header.
fn parse_member(input: &[u8], p: usize, limits: &CpioLimits) -> Result<(Option<CpioMember>, usize), CpioError> {
    let h = parse_header(input, p)?;
    if h.namesize == 0 {
        return Err(CpioError::BadName);
    }
    let namesize = usize::try_from(h.namesize).map_err(|_| CpioError::LimitExceeded)?;
    let name_start = p + h.header_len;
    let name_end = name_start.checked_add(namesize).ok_or(CpioError::Truncated)?;
    let name = input.get(name_start..name_end).ok_or(CpioError::Truncated)?;
    let (last, body) = name.split_last().ok_or(CpioError::BadName)?;
    if *last != 0 || body.contains(&0) {
        return Err(CpioError::BadName);
    }
    if body == TRAILER {
        return Ok((None, name_end));
    }
    if body.len() > limits.max_name_len {
        return Err(CpioError::LimitExceeded);
    }
    let data_offset = align(name_end, h.pad).ok_or(CpioError::Truncated)?;
    let data_len = usize::try_from(h.filesize).map_err(|_| CpioError::Truncated)?;
    let data_end = data_offset.checked_add(data_len).ok_or(CpioError::Truncated)?;
    let data = input.get(data_offset..data_end).ok_or(CpioError::Truncated)?;
    if h.format == CpioFormat::NewcCrc {
        let sum = data.iter().fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
        if u64::from(sum) != h.check {
            return Err(CpioError::ChecksumMismatch);
        }
    }
    let mut owned = Vec::new();
    owned.try_reserve_exact(body.len()).map_err(|_| CpioError::Allocation)?;
    owned.extend_from_slice(body);
    let next = align(data_end, h.pad).ok_or(CpioError::Truncated)?;
    let m = CpioMember {
        format: h.format,
        name: owned,
        ino: h.ino,
        dev: h.dev,
        rdev: h.rdev,
        mode: u32_of(h.mode)?,
        uid: u32_of(h.uid)?,
        gid: u32_of(h.gid)?,
        nlink: u32_of(h.nlink)?,
        mtime: h.mtime,
        header_offset: p,
        data_offset,
        data_len,
    };
    Ok((Some(m), next))
}

/// Walk a complete cpio archive. Each header's format is detected on its
/// own (mixed archives are accepted). Stops at `TRAILER!!!`; running out of
/// input before it is `Truncated`.
pub fn parse_cpio(input: &[u8], limits: &CpioLimits) -> Result<Vec<CpioMember>, CpioError> {
    let mut out = Vec::new();
    let mut p = 0usize;
    loop {
        let (m, next) = parse_member(input, p, limits)?;
        let Some(m) = m else { return Ok(out) };
        if out.len() >= limits.max_entries {
            return Err(CpioError::TooManyEntries);
        }
        out.try_reserve(1).map_err(|_| CpioError::Allocation)?;
        out.push(m);
        // Every header is at least 26 bytes, so `next > p`.
        p = next;
    }
}

// ---------------------------------------------------------------------------
// ArchiveReader
// ---------------------------------------------------------------------------

pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFREG: u32 = 0o100000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFLNK: u32 = 0o120000;
/// Longest symlink target accepted.
pub(crate) const MAX_LINK_TARGET: usize = 4096;

/// True for names that denote the archive root (`.`, `./`, `/`, empty):
/// such directory entries carry nothing to extract and are dropped.
pub(crate) fn is_root_name(name: &[u8]) -> bool {
    name.split(|&b| b == b'/').all(|c| c.is_empty() || c == b".")
}

pub(crate) fn copy_vec(data: &[u8]) -> Result<Vec<u8>, ReaderError> {
    let mut v = Vec::new();
    v.try_reserve_exact(data.len()).map_err(|_| ReaderError::Allocation)?;
    v.extend_from_slice(data);
    Ok(v)
}

/// cpio archive (borrowed, or owned after decompression) as an
/// [`ArchiveReader`]. Device, FIFO and socket members are omitted and
/// counted by [`CpioReader::skipped_special`]; root directory entries
/// (`.`) are dropped.
pub struct CpioReader<'a> {
    data: Cow<'a, [u8]>,
    format: ArchiveFormat,
    entries: Vec<PlannedEntry>,
    ranges: Vec<std::ops::Range<usize>>,
    max_entry_size: u64,
    skipped_special: usize,
}

impl<'a> CpioReader<'a> {
    pub fn new(data: Cow<'a, [u8]>, limits: ReaderLimits) -> Result<Self, ReaderError> {
        Self::with_format(data, limits, ArchiveFormat::Cpio)
    }

    /// As [`CpioReader::new`], reporting `format` from
    /// [`ArchiveReader::format`] (RPM payloads).
    pub fn with_format(data: Cow<'a, [u8]>, limits: ReaderLimits, format: ArchiveFormat) -> Result<Self, ReaderError> {
        let cl = CpioLimits { max_entries: limits.max_entries, ..CpioLimits::default() };
        let members = parse_cpio(&data, &cl)?;
        let n = members.len();
        // Hard-link groups: for each member, the index of the member whose
        // data the group shares (newc keeps it with the last link).
        let mut group_first: Vec<Option<usize>> = Vec::new();
        group_first.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut bearer: Vec<usize> = Vec::new();
        bearer.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        {
            use std::collections::HashMap;
            let mut first: HashMap<(u64, u64), usize> = HashMap::new();
            let mut last_data: HashMap<(u64, u64), usize> = HashMap::new();
            let mut has_empty: HashMap<(u64, u64), bool> = HashMap::new();
            for (i, m) in members.iter().enumerate() {
                let linked = m.nlink > 1 && is_regular(m.mode);
                if linked {
                    let k = (m.dev, m.ino);
                    first.entry(k).or_insert(i);
                    if m.data_len > 0 {
                        last_data.insert(k, i);
                    } else {
                        has_empty.insert(k, true);
                    }
                }
            }
            for (i, m) in members.iter().enumerate() {
                let k = (m.dev, m.ino);
                // Only groups where some link has no data share data.
                let shared = m.nlink > 1 && is_regular(m.mode) && has_empty.get(&k).copied().unwrap_or(false);
                if shared {
                    let f = first[&k];
                    group_first.push(if f == i { None } else { Some(f) });
                    bearer.push(last_data.get(&k).copied().unwrap_or(f));
                } else {
                    group_first.push(None);
                    bearer.push(i);
                }
            }
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut skipped_special = 0usize;
        let mut total: u64 = 0;
        for (i, m) in members.iter().enumerate() {
            let fmt = m.mode & S_IFMT;
            let mtime = i64::try_from(m.mtime).ok();
            let mode = Some(m.mode & 0o7777);
            let b = &members[bearer[i]];
            let range = b.data_offset..b.data_offset + b.data_len;
            let (kind, size, range) = match fmt {
                S_IFDIR => {
                    if is_root_name(&m.name) {
                        continue;
                    }
                    (EntryKind::Dir, 0, 0..0)
                }
                S_IFLNK => {
                    if m.data_len > MAX_LINK_TARGET {
                        return Err(ReaderError::LimitExceeded);
                    }
                    let t = copy_vec(&data[m.data_offset..m.data_offset + m.data_len])?;
                    (EntryKind::Symlink { target: t }, 0, 0..0)
                }
                _ if is_regular(m.mode) => match group_first[i] {
                    Some(f) => {
                        let target = copy_vec(&members[f].name)?;
                        (EntryKind::Hardlink { target }, b.data_len as u64, 0..0)
                    }
                    None => {
                        total = total.checked_add(b.data_len as u64).ok_or(ReaderError::LimitExceeded)?;
                        (EntryKind::File, b.data_len as u64, range)
                    }
                },
                _ => {
                    skipped_special += 1;
                    continue;
                }
            };
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded);
            }
            entries.push(PlannedEntry { path: copy_vec(&m.name)?, kind, size, mode, mtime });
            ranges.push(range);
        }
        Ok(CpioReader { data, format, entries, ranges, max_entry_size: limits.max_entry_size, skipped_special })
    }

    /// Number of device/FIFO/socket members that were left out.
    pub fn skipped_special(&self) -> usize {
        self.skipped_special
    }
}

/// Regular file, including type 0 (very old archives that leave the type
/// bits clear).
fn is_regular(mode: u32) -> bool {
    let f = mode & S_IFMT;
    f == S_IFREG || f == 0
}

impl ArchiveReader for CpioReader<'_> {
    fn format(&self) -> ArchiveFormat {
        self.format
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let r = self.ranges.get(index).ok_or(ReaderError::OutOfRange)?;
        if r.len() as u64 > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        copy_vec(self.data.get(r.clone()).ok_or(ReaderError::Invalid)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newc(name: &[u8], mode: u32, data: &[u8], crc: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(if crc { b"070702" } else { b"070701" });
        let sum = data.iter().fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
        let fields = [1, mode, 0, 0, 1, 0, data.len() as u32, 0, 0, 0, 0, name.len() as u32 + 1, if crc { sum } else { 0 }];
        for f in fields {
            v.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        v.extend_from_slice(name);
        v.push(0);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn minimal_newc() {
        let mut a = newc(b"x", 0o100644, b"hello", true);
        a.extend(newc(TRAILER, 0, b"", false));
        let m = parse_cpio(&a, &CpioLimits::default()).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(&a[m[0].data_offset..m[0].data_offset + m[0].data_len], b"hello");
        a[m[0].data_offset] ^= 1;
        assert_eq!(parse_cpio(&a, &CpioLimits::default()), Err(CpioError::ChecksumMismatch));
    }

    #[test]
    fn truncation_never_panics() {
        let mut a = newc(b"dir/x", 0o100644, b"hello world", false);
        let t = a.len();
        a.extend(newc(TRAILER, 0, b"", false));
        // The trailer's padding is not needed.
        let end = t + NEWC_LEN + TRAILER.len() + 1;
        for n in 0..a.len() {
            assert_eq!(parse_cpio(&a[..n], &CpioLimits::default()).is_err(), n < end, "{n}");
        }
        assert!(is_root_name(b"./"));
        assert!(is_root_name(b"."));
        assert!(!is_root_name(b"./a"));
    }
}
