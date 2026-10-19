// SPDX-License-Identifier: MIT OR Apache-2.0
//! Format-neutral archive reading interface used by the CLI and the
//! extractor. Each container format (zip now; tar/gz/xz/bz2/7z at
//! integration) provides an [`ArchiveReader`] and an arm in
//! [`open_archive`].
//!
//! ZIP metadata (DOS time, external attributes, the 0x5455 extended
//! timestamp extra field) is taken from the central directory as described
//! in the PKWARE APPNOTE 6.3.x, sections 4.3.12, 4.4.2, 4.4.6, 4.4.15 and
//! 4.5 (extra field registry); the Unix mode lives in the high 16 bits of
//! the external attributes when "version made by" names host 3 (Unix).

use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::zip::{ZipError, parse_eocd};
use crate::zip_decode::entry_data;
use crate::zip_dos_time::decode_dos;
use crate::zip_index::{ZipEntry, ZipLimits, parse_entries};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderError {
    Truncated,
    Invalid,
    Unsupported,
    LimitExceeded,
    CrcMismatch,
    Allocation,
    OutOfRange,
}

impl From<ZipError> for ReaderError {
    fn from(e: ZipError) -> Self {
        match e {
            ZipError::Truncated => ReaderError::Truncated,
            ZipError::Invalid => ReaderError::Invalid,
            ZipError::Unsupported => ReaderError::Unsupported,
            ZipError::LimitExceeded => ReaderError::LimitExceeded,
            ZipError::CrcMismatch => ReaderError::CrcMismatch,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    Gzip,
    Xz,
    Bzip2,
    SevenZ,
    /// cpio (newc/crc/odc/binary).
    Cpio,
    /// Unix ar archive.
    Ar,
    /// Debian binary package (ar of control/data tarballs).
    Deb,
    /// RPM package (cpio payload).
    Rpm,
    /// xar archive.
    Xar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderLimits {
    pub max_entries: usize,
    /// Total uncompressed bytes across entries.
    pub max_total_size: u64,
    /// Largest single entry that `read` will materialize.
    pub max_entry_size: u64,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        ReaderLimits { max_entries: 100_000, max_total_size: 4 << 30, max_entry_size: 1 << 30 }
    }
}

/// Random-access view of an archive's members.
pub trait ArchiveReader {
    fn format(&self) -> ArchiveFormat;
    /// All members, in archive order. Indices are stable for `read`.
    fn entries(&self) -> &[PlannedEntry];
    /// Full contents of member `index` (empty for dirs and links),
    /// integrity-checked where the format allows it.
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError>;
    /// Stored CRC-32 of the member, when the format records one.
    fn crc32(&self, _index: usize) -> Option<u32> {
        None
    }
}

/// Identify a container by magic bytes.
pub fn detect_format(bytes: &[u8]) -> Option<ArchiveFormat> {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(ArchiveFormat::Zip)
    } else if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        Some(ArchiveFormat::SevenZ)
    } else if bytes.starts_with(b"\xfd7zXZ\x00") {
        Some(ArchiveFormat::Xz)
    } else if bytes.starts_with(b"\x1f\x8b") {
        Some(ArchiveFormat::Gzip)
    } else if bytes.starts_with(b"BZh") {
        Some(ArchiveFormat::Bzip2)
    } else if bytes.get(257..262) == Some(b"ustar") {
        Some(ArchiveFormat::Tar)
    } else {
        None
    }
}

/// Open `bytes` with the reader for its detected format.
/// Formats without a reader yet return `Unsupported`.
pub fn open_archive<'a>(
    bytes: &'a [u8],
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    match detect_format(bytes) {
        Some(ArchiveFormat::Zip) => Ok(Box::new(ZipReader::new(bytes, limits)?)),
        _ => Err(ReaderError::Unsupported),
    }
}

/// In-memory reader: useful for tests and for formats decoded up front.
#[derive(Debug, Clone, Default)]
pub struct MemReader {
    pub entries: Vec<PlannedEntry>,
    pub data: Vec<Vec<u8>>,
}

impl MemReader {
    pub fn push(&mut self, entry: PlannedEntry, data: Vec<u8>) {
        self.entries.push(entry);
        self.data.push(data);
    }
}

impl ArchiveReader for MemReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        self.data.get(index).cloned().ok_or(ReaderError::OutOfRange)
    }
}

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
const MAX_LINK_TARGET: usize = 4096;

pub struct ZipReader<'a> {
    bytes: &'a [u8],
    zip: Vec<ZipEntry<'a>>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

struct CentralMeta {
    made_by_host: u8,
    external: u32,
    dos_time: u16,
    dos_date: u16,
    ut_mtime: Option<i64>,
}

fn le16(b: &[u8], at: usize) -> Result<u16, ReaderError> {
    let s = b.get(at..at + 2).ok_or(ReaderError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Result<u32, ReaderError> {
    let s = b.get(at..at + 4).ok_or(ReaderError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Walk the (already validated) central directory for metadata that
/// `zip_index` does not expose.
fn central_meta(bytes: &[u8], count: usize) -> Result<Vec<CentralMeta>, ReaderError> {
    let info = parse_eocd(bytes)?;
    let end = info.offset.checked_add(info.size).ok_or(ReaderError::Truncated)?;
    let dir = bytes.get(info.offset..end).ok_or(ReaderError::Truncated)?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| ReaderError::Allocation)?;
    let mut at = 0usize;
    for _ in 0..count {
        if le32(dir, at)? != 0x0201_4b50 {
            return Err(ReaderError::Invalid);
        }
        let made_by = le16(dir, at + 4)?;
        let dos_time = le16(dir, at + 12)?;
        let dos_date = le16(dir, at + 14)?;
        let name_len = le16(dir, at + 28)? as usize;
        let extra_len = le16(dir, at + 30)? as usize;
        let comment_len = le16(dir, at + 32)? as usize;
        let external = le32(dir, at + 38)?;
        let extra_start = at + 46 + name_len;
        let extra = dir.get(extra_start..extra_start + extra_len).ok_or(ReaderError::Truncated)?;
        let mut ut_mtime = None;
        let mut p = 0usize;
        while p + 4 <= extra.len() {
            let id = le16(extra, p)?;
            let len = le16(extra, p + 2)? as usize;
            let body = match extra.get(p + 4..p + 4 + len) {
                Some(b) => b,
                None => break,
            };
            if id == 0x5455 && body.len() >= 5 && body[0] & 1 != 0 {
                ut_mtime = Some(i64::from(i32::from_le_bytes([body[1], body[2], body[3], body[4]])));
            }
            p += 4 + len;
        }
        out.push(CentralMeta { made_by_host: (made_by >> 8) as u8, external, dos_time, dos_date, ut_mtime });
        at = extra_start + extra_len + comment_len;
    }
    Ok(out)
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn dos_to_unix(date: u16, time: u16) -> Option<i64> {
    let t = decode_dos(date, time).ok()?;
    let days = days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day));
    Some(days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second))
}

impl<'a> ZipReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let max_total = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
        let zip = parse_entries(bytes, ZipLimits { max_entries: limits.max_entries, max_total_size: max_total })?;
        let meta = central_meta(bytes, zip.len())?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(zip.len()).map_err(|_| ReaderError::Allocation)?;
        let mut reader = ZipReader { bytes, zip, entries: Vec::new(), max_entry_size: limits.max_entry_size };
        for (i, z) in reader.zip.iter().enumerate() {
            let m = &meta[i];
            let unix_mode = if m.made_by_host == 3 { Some(m.external >> 16) } else { None };
            let dos_dir = m.external & 0x10 != 0;
            let fmt = unix_mode.map(|v| v & S_IFMT);
            let kind = if fmt == Some(S_IFLNK) {
                if z.size > MAX_LINK_TARGET {
                    return Err(ReaderError::LimitExceeded);
                }
                let target = entry_data(bytes, z, MAX_LINK_TARGET, 64)?.into_owned();
                EntryKind::Symlink { target }
            } else if z.name.ends_with(b"/") || fmt == Some(S_IFDIR) || (dos_dir && z.size == 0) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let mode = unix_mode.filter(|&v| v != 0).map(|v| v & 0o7777);
            let mtime = m.ut_mtime.or_else(|| dos_to_unix(m.dos_date, m.dos_time));
            let size = if matches!(kind, EntryKind::File) { z.size as u64 } else { 0 };
            entries.push(PlannedEntry { path: z.name.to_vec(), kind, size, mode, mtime });
        }
        reader.entries = entries;
        Ok(reader)
    }
}

impl ArchiveReader for ZipReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Zip
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let z = self.zip.get(index).ok_or(ReaderError::OutOfRange)?;
        if z.size as u64 > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        // One DEFLATE block emits at least one byte unless empty; bound the
        // block count by output size plus slack.
        let max_blocks = z.size.saturating_add(16);
        let data = entry_data(self.bytes, z, z.size, max_blocks)?;
        if data.len() != z.size {
            return Err(ReaderError::Invalid);
        }
        let mut v = Vec::new();
        v.try_reserve_exact(data.len()).map_err(|_| ReaderError::Allocation)?;
        v.extend_from_slice(&data);
        Ok(v)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        self.zip.get(index).map(|z| z.crc32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(dos_to_unix((1 << 5) | 1, 0), Some(315_532_800));
        assert_eq!(dos_to_unix((20 << 9) | (1 << 5) | 1, 0), Some(946_684_800));
    }
}
