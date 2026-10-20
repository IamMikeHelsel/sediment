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
use crate::bzip2_decode::decode_bzip2;
use crate::crc32::crc32;
use crate::deflate64::inflate64_raw_prefix;
use crate::inflate::inflate_raw_prefix;
use crate::lzma_decode::{decode_lzma_raw, decode_props_byte};
use crate::lzma_properties::LzmaProperties;
use crate::xz_decode::decode_xz;
use crate::zip::ZipError;
use crate::zip_dos_time::decode_dos;
use crate::zip_reader2::{Reader2Error, Reader2Limits, ZipArchive2};

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
    /// LHA/LZH (see `legacy_open`).
    Lzh,
    /// ARJ (see `legacy_open`).
    Arj,
    /// Unix `compress` single stream (see `legacy_open`).
    CompressZ,
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
    /// Zstandard single stream (`.zst`); see `archive_open_ext`.
    Zstd,
    /// Windows Imaging (`.wim`); see `archive_open_ext`.
    Wim,
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

/// ZIP compression methods decoded by [`ZipReader`] (APPNOTE 4.4.5).
mod zip_method {
    pub const STORED: u16 = 0;
    pub const DEFLATE: u16 = 8;
    pub const DEFLATE64: u16 = 9;
    pub const BZIP2: u16 = 12;
    pub const LZMA: u16 = 14;
    pub const XZ: u16 = 95;
    pub const ZSTD: u16 = 93;
    pub const PPMD: u16 = 98;
}

/// Largest PPMd var.I model accepted inside a ZIP entry (the format maximum).
const MAX_ZIP_PPMD_MEMORY: u64 = 256 << 20;

/// Largest LZMA/xz dictionary accepted inside a ZIP entry.
const MAX_ZIP_DICTIONARY: u64 = 1 << 32;

/// ZIP archive reader built on [`ZipArchive2`]: classic and ZIP64
/// directories, data descriptors, Info-ZIP Unicode Path names, and the
/// methods Stored, Deflate, Deflate64, BZip2 (12), LZMA (14, APPNOTE
/// 5.8.8 framing: 2-byte version, 2-byte property size, properties),
/// Zstandard (93), XZ (95) and PPMd var.I rev1 (98). Encrypted entries are listed; reading them returns
/// `Unsupported`.
pub struct ZipReader<'a> {
    zip: ZipArchive2<'a>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

impl From<Reader2Error> for ReaderError {
    fn from(e: Reader2Error) -> Self {
        match e {
            Reader2Error::Truncated => ReaderError::Truncated,
            Reader2Error::Invalid => ReaderError::Invalid,
            Reader2Error::Unsupported | Reader2Error::Encrypted => ReaderError::Unsupported,
            Reader2Error::LimitExceeded => ReaderError::LimitExceeded,
            Reader2Error::Allocation => ReaderError::Allocation,
            Reader2Error::CrcMismatch => ReaderError::CrcMismatch,
        }
    }
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

/// Decode a ZIP entry payload with method `method` into exactly `size`
/// bytes. For LZMA the end marker (general purpose flag bit 1) is optional
/// because the size is known. Zstandard (93) payloads are one or more
/// zstd frames; PPMd (98) payloads carry the APPNOTE 5.10 2-byte parameter
/// word followed by the PPMd var.I rev1 range-coded stream.
pub(crate) fn decode_zip_payload(method: u16, raw: &[u8], size: usize) -> Result<Vec<u8>, ReaderError> {
    // One DEFLATE block emits at least one byte unless empty, and costs at
    // least 3 bits of input.
    let max_blocks = size.saturating_add(16).min(raw.len().saturating_mul(8) / 3 + 16);
    let out = match method {
        zip_method::STORED => {
            if raw.len() != size {
                return Err(ReaderError::Invalid);
            }
            let mut v = Vec::new();
            v.try_reserve_exact(size).map_err(|_| ReaderError::Allocation)?;
            v.extend_from_slice(raw);
            v
        }
        zip_method::DEFLATE => inflate_raw_prefix(raw, size, max_blocks).map_err(|_| ReaderError::Invalid)?.0,
        zip_method::DEFLATE64 => inflate64_raw_prefix(raw, size, max_blocks).map_err(|_| ReaderError::Invalid)?.0,
        zip_method::BZIP2 => decode_bzip2(raw, size).map_err(|_| ReaderError::Invalid)?,
        zip_method::LZMA => {
            let hdr = raw.get(..4).ok_or(ReaderError::Truncated)?;
            let props_len = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
            if props_len != 5 {
                return Err(ReaderError::Invalid);
            }
            let p = raw.get(4..9).ok_or(ReaderError::Truncated)?;
            let (lc, lp, pb) = decode_props_byte(p[0]).map_err(|_| ReaderError::Invalid)?;
            let dictionary_size = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
            let props = LzmaProperties { lc, lp, pb, dictionary_size };
            decode_lzma_raw(&raw[9..], props, Some(size as u64), MAX_ZIP_DICTIONARY, size)
                .map_err(|_| ReaderError::Invalid)?
                .0
        }
        zip_method::XZ => decode_xz(raw, MAX_ZIP_DICTIONARY, size).map_err(|_| ReaderError::Invalid)?,
        zip_method::ZSTD => crate::zstd_decode::decode_zstd(raw, size).map_err(|e| match e {
            crate::zstd_decode::ZstdError::Unsupported => ReaderError::Unsupported,
            crate::zstd_decode::ZstdError::Allocation => ReaderError::Allocation,
            crate::zstd_decode::ZstdError::Truncated => ReaderError::Truncated,
            _ => ReaderError::Invalid,
        })?,
        zip_method::PPMD => crate::ppmd8::decode_zip(raw, size, MAX_ZIP_PPMD_MEMORY).map_err(|e| match e {
            crate::ppmd8::Ppmd8Error::UnsupportedProperties => ReaderError::Unsupported,
            crate::ppmd8::Ppmd8Error::Allocation => ReaderError::Allocation,
            crate::ppmd8::Ppmd8Error::UnexpectedEof => ReaderError::Truncated,
            _ => ReaderError::Invalid,
        })?,
        _ => return Err(ReaderError::Unsupported),
    };
    if out.len() != size {
        return Err(ReaderError::Invalid);
    }
    Ok(out)
}

impl<'a> ZipReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let l2 = Reader2Limits {
            max_entries: limits.max_entries,
            // Oversized single entries are listed; `read` refuses them.
            max_entry_size: limits.max_total_size,
            max_total_size: limits.max_total_size,
            max_deflate_blocks: 1 << 20,
        };
        let zip = ZipArchive2::open(bytes, l2)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(zip.len()).map_err(|_| ReaderError::Allocation)?;
        let mut reader = ZipReader { zip, entries: Vec::new(), max_entry_size: limits.max_entry_size };
        for (i, z) in reader.zip.entries().iter().enumerate() {
            let unix_mode = z.unix_mode();
            let dos_dir = z.external_attributes & 0x10 != 0;
            let fmt = unix_mode.map(|v| v & S_IFMT);
            let name = z.name();
            let kind = if fmt == Some(S_IFLNK) {
                if z.uncompressed_size > MAX_LINK_TARGET as u64 {
                    return Err(ReaderError::LimitExceeded);
                }
                let target = reader.decode(i, MAX_LINK_TARGET)?;
                EntryKind::Symlink { target }
            } else if name.ends_with(b"/") || fmt == Some(S_IFDIR) || (dos_dir && z.uncompressed_size == 0) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let mode = unix_mode.filter(|&v| v != 0).map(|v| v & 0o7777);
            let ut_mtime = z.extended_timestamp.as_ref().and_then(|t| t.mtime).map(i64::from);
            let mtime = ut_mtime.or_else(|| dos_to_unix(z.dos_date, z.dos_time));
            let size = if matches!(kind, EntryKind::File) { z.uncompressed_size } else { 0 };
            entries.push(PlannedEntry { path: name.to_vec(), kind, size, mode, mtime });
        }
        reader.entries = entries;
        Ok(reader)
    }

    /// True when some entry uses a pre-Deflate PKZIP method (Shrink,
    /// Reduce 1-4, Implode: APPNOTE methods 1-6) that this reader does not
    /// decode; `archive_open` then routes the archive to `legacy_open`.
    pub fn has_legacy_method(&self) -> bool {
        self.zip.entries().iter().any(|z| (1..=6).contains(&z.method))
    }

    /// Decode entry `index` (capped at `max_output`) and verify its CRC-32.
    fn decode(&self, index: usize, max_output: usize) -> Result<Vec<u8>, ReaderError> {
        let z = self.zip.entries().get(index).ok_or(ReaderError::OutOfRange)?;
        if z.is_encrypted() {
            return Err(ReaderError::Unsupported);
        }
        let size = usize::try_from(z.uncompressed_size).map_err(|_| ReaderError::LimitExceeded)?;
        if size > max_output {
            return Err(ReaderError::LimitExceeded);
        }
        let raw = self.zip.raw_data(index)?;
        let data = decode_zip_payload(z.method, raw, size)?;
        if crc32(&data) != z.crc32 {
            return Err(ReaderError::CrcMismatch);
        }
        Ok(data)
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
        let max = usize::try_from(self.max_entry_size).unwrap_or(usize::MAX);
        self.decode(index, max)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        self.zip.entries().get(index).map(|z| z.crc32)
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
