// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`ArchiveReader`] adapters for the legacy read-only formats: LHA/LZH
//! ([`crate::lzh_read`]), ARJ ([`crate::arj_read`]), Unix `compress` `.Z`
//! files (decoder supplied by the forge-owned `lzw_z` module through the
//! [`Z_DECODER`] seam), and a ZIP reader built on [`crate::zip_reader2`]
//! that also decodes the legacy methods Shrink (1) and Implode (6)
//! ([`crate::zip_legacy`]) plus Deflate64 (9).
//!
//! [`open_legacy`] is called by `archive_open::open_named` for inputs whose
//! magic bytes match none of the primary formats; [`open_zip_fallback`] is
//! used when the strict ZIP reader reports `Unsupported`.
//!
//! Limits: entry counts and the sum of declared sizes are checked against
//! [`ReaderLimits`] at open time; each `read` is capped at
//! `max_entry_size` and integrity-checked (CRC-16 for LZH, CRC-32 for ARJ
//! and ZIP).

use std::borrow::Cow;

use crate::archive_open::{StreamReader, TarReader, stream_member_name};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::arj_read::{ArjEntry, ArjError, ArjLimits, TYPE_CHAPTER, TYPE_LABEL, parse_arj, read_arj_entry};
use crate::crc32::crc32;
use crate::deflate64::inflate64_raw;
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::lzh_read::{LzhEntry, LzhError, LzhLimits, dos_stamp_to_unix, looks_like_lzh, parse_lzh, read_lzh_entry};
use crate::zip_legacy::{METHOD_IMPLODE, METHOD_SHRINK, ZipLegacyError, explode, unshrink};
use crate::zip_reader2::{Compression, Entry2, Reader2Limits, ZipArchive2};

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
const MAX_LINK_TARGET: usize = 4096;

impl From<LzhError> for ReaderError {
    fn from(e: LzhError) -> Self {
        match e {
            LzhError::Truncated => ReaderError::Truncated,
            LzhError::Unsupported => ReaderError::Unsupported,
            LzhError::LimitExceeded => ReaderError::LimitExceeded,
            LzhError::Allocation => ReaderError::Allocation,
            LzhError::CrcMismatch | LzhError::BadChecksum => ReaderError::CrcMismatch,
            LzhError::BadHeader | LzhError::InvalidData => ReaderError::Invalid,
        }
    }
}

impl From<ArjError> for ReaderError {
    fn from(e: ArjError) -> Self {
        match e {
            ArjError::Truncated => ReaderError::Truncated,
            ArjError::Unsupported => ReaderError::Unsupported,
            ArjError::LimitExceeded => ReaderError::LimitExceeded,
            ArjError::Allocation => ReaderError::Allocation,
            ArjError::CrcMismatch | ArjError::BadChecksum => ReaderError::CrcMismatch,
            ArjError::BadHeader | ArjError::InvalidData => ReaderError::Invalid,
        }
    }
}

impl From<ZipLegacyError> for ReaderError {
    fn from(e: ZipLegacyError) -> Self {
        match e {
            ZipLegacyError::Truncated => ReaderError::Truncated,
            ZipLegacyError::InvalidData => ReaderError::Invalid,
            ZipLegacyError::LimitExceeded => ReaderError::LimitExceeded,
            ZipLegacyError::Allocation => ReaderError::Allocation,
        }
    }
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn ends_with_ci(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn base_name(name: &[u8]) -> &[u8] {
    name.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(name)
}

/// Enforce entry-count and total-size limits on a listing.
fn check_totals(sizes: impl Iterator<Item = u64>, count: usize, limits: &ReaderLimits) -> Result<(), ReaderError> {
    if count > limits.max_entries {
        return Err(ReaderError::LimitExceeded);
    }
    let mut total: u64 = 0;
    for s in sizes {
        total = total.checked_add(s).ok_or(ReaderError::LimitExceeded)?;
        if total > limits.max_total_size {
            return Err(ReaderError::LimitExceeded);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LZH
// ---------------------------------------------------------------------------

/// LHA/LZH archive as an [`ArchiveReader`].
pub struct LzhReader<'a> {
    lzh: Vec<LzhEntry<'a>>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

impl<'a> LzhReader<'a> {
    /// `max_scan` > 0 allows a self-extractor stub before the first header.
    pub fn new(bytes: &'a [u8], limits: ReaderLimits, max_scan: usize) -> Result<Self, ReaderError> {
        let lzh = parse_lzh(bytes, LzhLimits { max_entries: limits.max_entries, max_name: 4096, max_scan })?;
        check_totals(lzh.iter().map(|e| e.original_size), lzh.len(), &limits)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(lzh.len()).map_err(|_| ReaderError::Allocation)?;
        for e in &lzh {
            let mode = e.unix_mode.map(u32::from);
            let (path, kind) = if e.is_dir() {
                // LHa stores Unix symlinks as `-lhd-` members named `link|target`.
                match e.path.iter().position(|&c| c == b'|') {
                    Some(p) => (e.path[..p].to_vec(), EntryKind::Symlink { target: e.path[p + 1..].to_vec() }),
                    None => (e.path.clone(), EntryKind::Dir),
                }
            } else {
                (e.path.clone(), EntryKind::File)
            };
            let size = if kind == EntryKind::File { e.original_size } else { 0 };
            let mode = mode.map(|m| m & 0o7777).filter(|&m| m != 0);
            entries.push(PlannedEntry { path, kind, size, mode, mtime: e.mtime });
        }
        Ok(LzhReader { lzh, entries, max_entry_size: limits.max_entry_size })
    }

    /// The underlying listing (method ids, header levels, CRCs).
    pub fn raw_entries(&self) -> &[LzhEntry<'a>] {
        &self.lzh
    }
}

impl ArchiveReader for LzhReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Lzh
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let e = self.lzh.get(index).ok_or(ReaderError::OutOfRange)?;
        if self.entries[index].kind != EntryKind::File {
            return Ok(Vec::new());
        }
        if e.original_size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(read_lzh_entry(e, to_usize(self.max_entry_size))?)
    }
}

// ---------------------------------------------------------------------------
// ARJ
// ---------------------------------------------------------------------------

/// ARJ archive as an [`ArchiveReader`]. Volume labels and chapter markers
/// are not listed.
pub struct ArjReader<'a> {
    arj: Vec<ArjEntry<'a>>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

impl<'a> ArjReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits, max_scan: usize) -> Result<Self, ReaderError> {
        let arj_limits = ArjLimits { max_entries: limits.max_entries, max_scan, ..ArjLimits::default() };
        let (_main, mut arj) = parse_arj(bytes, arj_limits)?;
        arj.retain(|e| e.file_type != TYPE_LABEL && e.file_type != TYPE_CHAPTER);
        check_totals(arj.iter().map(|e| e.original_size), arj.len(), &limits)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(arj.len()).map_err(|_| ReaderError::Allocation)?;
        for e in &arj {
            let mut path = e.path.clone();
            while path.last() == Some(&b'/') {
                path.pop();
            }
            let kind = if e.is_dir() { EntryKind::Dir } else { EntryKind::File };
            let size = if e.is_dir() { 0 } else { e.original_size };
            let mode = e.unix_mode().filter(|&m| m != 0);
            entries.push(PlannedEntry { path, kind, size, mode, mtime: e.mtime });
        }
        Ok(ArjReader { arj, entries, max_entry_size: limits.max_entry_size })
    }

    pub fn raw_entries(&self) -> &[ArjEntry<'a>] {
        &self.arj
    }
}

impl ArchiveReader for ArjReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Arj
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let e = self.arj.get(index).ok_or(ReaderError::OutOfRange)?;
        if e.original_size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(read_arj_entry(e, to_usize(self.max_entry_size))?)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        self.arj.get(index).filter(|e| !e.is_dir()).map(|e| e.crc32)
    }
}

// ---------------------------------------------------------------------------
// ZIP with legacy methods
// ---------------------------------------------------------------------------

/// ZIP reader over [`ZipArchive2`] that decodes Stored, Deflate, Deflate64,
/// Shrink and Implode. Encrypted members are listed; reading them is
/// `Unsupported`.
pub struct ZipLegacyReader<'a> {
    zip: ZipArchive2<'a>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

fn decode_zip_entry(zip: &ZipArchive2<'_>, index: usize, max_output: usize) -> Result<Vec<u8>, ReaderError> {
    let e: &Entry2<'_> = zip.entries().get(index).ok_or(ReaderError::OutOfRange)?;
    if e.is_encrypted() {
        return Err(ReaderError::Unsupported);
    }
    let size = usize::try_from(e.uncompressed_size).map_err(|_| ReaderError::LimitExceeded)?;
    if size > max_output {
        return Err(ReaderError::LimitExceeded);
    }
    let raw = zip.raw_data(index)?;
    let out = match e.compression {
        Compression::Stored | Compression::Deflate => return Ok(zip.read(index, max_output)?.into_owned()),
        Compression::Deflate64 => {
            let blocks = raw.len().saturating_mul(8) / 3 + 16;
            let out = inflate64_raw(raw, size, blocks).map_err(|_| ReaderError::Invalid)?;
            if out.len() != size {
                return Err(ReaderError::Invalid);
            }
            out
        }
        Compression::Other(METHOD_SHRINK) => unshrink(raw, size, max_output)?,
        Compression::Other(METHOD_IMPLODE) => explode(raw, e.flags, size, max_output)?,
        Compression::Other(_) => return Err(ReaderError::Unsupported),
    };
    if crc32(&out) != e.crc32 {
        return Err(ReaderError::CrcMismatch);
    }
    Ok(out)
}

impl<'a> ZipLegacyReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let zl = Reader2Limits {
            max_entries: limits.max_entries,
            // Per-entry size is enforced in `read`, like the strict reader.
            max_entry_size: u64::MAX,
            max_total_size: limits.max_total_size,
            ..Reader2Limits::default()
        };
        let zip = ZipArchive2::open(bytes, zl)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(zip.len()).map_err(|_| ReaderError::Allocation)?;
        for (i, e) in zip.entries().iter().enumerate() {
            let unix = e.unix_mode();
            let fmt = unix.map(|m| m & S_IFMT);
            let kind = if fmt == Some(S_IFLNK) {
                if e.uncompressed_size > MAX_LINK_TARGET as u64 {
                    return Err(ReaderError::LimitExceeded);
                }
                EntryKind::Symlink { target: decode_zip_entry(&zip, i, MAX_LINK_TARGET)? }
            } else if e.is_dir() || fmt == Some(S_IFDIR) || (e.external_attributes & 0x10 != 0 && e.uncompressed_size == 0) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let mut path = e.name().to_vec();
            while path.last() == Some(&b'/') {
                path.pop();
            }
            let mtime = e
                .extended_timestamp
                .and_then(|t| t.mtime)
                .map(i64::from)
                .or_else(|| dos_stamp_to_unix((u32::from(e.dos_date) << 16) | u32::from(e.dos_time)));
            let size = if kind == EntryKind::File { e.uncompressed_size } else { 0 };
            let mode = unix.map(|m| m & 0o7777).filter(|&m| m != 0);
            entries.push(PlannedEntry { path, kind, size, mode, mtime });
        }
        Ok(ZipLegacyReader { zip, entries, max_entry_size: limits.max_entry_size })
    }
}

impl ArchiveReader for ZipLegacyReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Zip
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        match self.entries.get(index).map(|e| &e.kind) {
            None => Err(ReaderError::OutOfRange),
            Some(EntryKind::File) => decode_zip_entry(&self.zip, index, to_usize(self.max_entry_size)),
            Some(_) => Ok(Vec::new()),
        }
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        match self.entries.get(index).map(|e| &e.kind) {
            Some(EntryKind::File) => self.zip.entries().get(index).map(|e| e.crc32),
            _ => None,
        }
    }
}

/// Open a ZIP archive that the strict reader rejected (legacy methods,
/// data descriptors, ZIP64, prefixed archives).
pub fn open_zip_fallback<'a>(bytes: &'a [u8], limits: ReaderLimits) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    Ok(Box::new(ZipLegacyReader::new(bytes, limits)?))
}

// ---------------------------------------------------------------------------
// Unix compress (.Z) seam
// ---------------------------------------------------------------------------

/// A `.Z` stream decoder: `(input, max_output) -> data`.
pub type ZDecoder = fn(&[u8], usize) -> Result<Vec<u8>, ReaderError>;

/// The `.Z` decoder used by [`open_legacy`]. The LZW decoder is owned by
/// the forge `lzw_z` module (`decompress_z(input, max_output)`), wired here.
pub const Z_DECODER: Option<ZDecoder> = Some(|b, m| crate::lzw_z::decompress_z(b, m).map_err(z_error));

/// Map the forge `lzw_z` errors onto [`ReaderError`].
fn z_error(e: crate::lzw_z::LzwError) -> ReaderError {
    use crate::lzw_z::LzwError;
    match e {
        LzwError::Truncated => ReaderError::Truncated,
        LzwError::LimitExceeded => ReaderError::LimitExceeded,
        LzwError::BadMagic | LzwError::BadHeader | LzwError::InvalidCode => ReaderError::Invalid,
    }
}

/// `compress` magic.
pub fn is_compress_z(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x1F && bytes[1] == 0x9D
}

/// Member name for a `.Z` file and whether it is a compressed tar:
/// `x.tar.Z`/`x.taz`/`x.tZ` -> `x.tar` (tar), `notes.txt.Z` -> `notes.txt`.
pub fn z_member_name(archive_name: &[u8]) -> (Vec<u8>, bool) {
    let base = base_name(archive_name);
    for s in [&b".taz"[..], b".tz"] {
        if ends_with_ci(base, s) {
            let mut v = base[..base.len() - s.len()].to_vec();
            v.extend_from_slice(b".tar");
            return (v, true);
        }
    }
    let member = stream_member_name(archive_name);
    let is_tar = ends_with_ci(&member, b".tar");
    (member, is_tar)
}

/// Open a `.Z` file with an explicit decoder (the seam [`Z_DECODER`] fills).
pub fn open_z_with<'a>(
    bytes: &[u8],
    archive_name: &[u8],
    limits: ReaderLimits,
    decode: ZDecoder,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    if !is_compress_z(bytes) {
        return Err(ReaderError::Invalid);
    }
    let (member, is_tar) = z_member_name(archive_name);
    let data = decode(bytes, to_usize(limits.max_total_size))?;
    if is_tar {
        return Ok(Box::new(TarReader::new(Cow::Owned(data), limits)?));
    }
    if data.len() as u64 > limits.max_entry_size {
        return Err(ReaderError::LimitExceeded);
    }
    Ok(Box::new(StreamReader::new(ArchiveFormat::CompressZ, member, data, None, None)))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Which legacy container `bytes` holds, by magic bytes at offset 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFormat {
    CompressZ,
    Arj,
    Lzh,
}

pub fn detect_legacy(bytes: &[u8]) -> Option<LegacyFormat> {
    if is_compress_z(bytes) {
        Some(LegacyFormat::CompressZ)
    } else if crate::arj_read::looks_like_arj(bytes) {
        Some(LegacyFormat::Arj)
    } else if looks_like_lzh(bytes) {
        Some(LegacyFormat::Lzh)
    } else {
        None
    }
}

/// How far to look for an embedded archive in a self-extractor.
const SFX_SCAN: usize = 1 << 20;

/// Open a legacy archive. Detection is by magic bytes; for names ending in
/// `.lzh`/`.lha`, `.arj` or `.exe` an archive after an executable stub is
/// also searched for (first 1 MiB). Anything else is `Unsupported`.
pub fn open_legacy<'a>(
    bytes: &'a [u8],
    archive_name: &[u8],
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    match detect_legacy(bytes) {
        Some(LegacyFormat::CompressZ) => match Z_DECODER {
            Some(d) => open_z_with(bytes, archive_name, limits, d),
            None => Err(ReaderError::Unsupported),
        },
        Some(LegacyFormat::Arj) => Ok(Box::new(ArjReader::new(bytes, limits, 0)?)),
        Some(LegacyFormat::Lzh) => Ok(Box::new(LzhReader::new(bytes, limits, 0)?)),
        None => {
            let base = base_name(archive_name);
            let sfx = ends_with_ci(base, b".exe");
            if (ends_with_ci(base, b".arj") || sfx)
                && let Ok(r) = ArjReader::new(bytes, limits, SFX_SCAN)
            {
                return Ok(Box::new(r));
            }
            if (ends_with_ci(base, b".lzh") || ends_with_ci(base, b".lha") || sfx)
                && let Ok(r) = LzhReader::new(bytes, limits, SFX_SCAN)
            {
                return Ok(Box::new(r));
            }
            Err(ReaderError::Unsupported)
        }
    }
}
