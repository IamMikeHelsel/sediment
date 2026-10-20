// SPDX-License-Identifier: MIT OR Apache-2.0
//! Microsoft Cabinet (.cab) reader: listing and extraction, in memory.
//!
//! Spec source: [MS-CAB] Cabinet File Format (CFHEADER, CFFOLDER, CFFILE,
//! CFDATA, the reserve fields, multi-cabinet flags and the CFDATA checksum
//! algorithm). Compression types: 0 none, 1 MSZIP ([MS-MCI], see
//! [`crate::mszip`]), 3 LZX (see [`crate::lzx`]); 2 Quantum is recognised and
//! reported as [`CabError::UnsupportedCompression`].
//!
//! Notes:
//! - The CFDATA checksum covers the data bytes first, then cbData, cbUncomp
//!   and abReserve (a zero checksum means "not computed"). Verification is on
//!   by default ([`CabLimits::verify_checksums`]).
//! - A folder's LZX data is the concatenation of its CFDATA payloads, decoded
//!   as one continuous stream of 32 KiB frames.
//! - Files continued from/to another cabinet (iFolder 0xFFFD..0xFFFF) are
//!   listed but extracting them returns [`CabError::Spanned`]; so does a
//!   folder whose last CFDATA continues in the next cabinet (cbUncomp = 0).
//! - Names without the UTF-8 attribute (0x80) are decoded byte-for-byte as
//!   ISO-8859-1 (the original OEM code page is unknown); `\` becomes `/`.
//!
//! All sizes are bounded by [`CabLimits`]; malformed input returns an error.

use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::lzx::{LzxError, lzx_decompress};
use crate::mszip::{MszipDecoder, MszipError};
use crate::zip_dos_time::decode_dos;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CabError {
    /// Archive ends inside a structure.
    Truncated,
    /// Missing `MSCF` signature or reserved fields not zero.
    InvalidSignature,
    /// Inconsistent header (version, offsets, counts).
    InvalidHeader,
    /// CFFOLDER entry or its CFDATA chain is malformed.
    InvalidFolder,
    /// CFFILE entry is malformed (bad folder index, unterminated name,
    /// range outside its folder).
    InvalidFile,
    /// CFDATA checksum mismatch.
    ChecksumMismatch,
    /// Quantum or an unknown compression type.
    UnsupportedCompression,
    /// Data lives (partly) in another cabinet of a multi-cabinet set.
    Spanned,
    /// Compressed data is corrupt or does not match the declared sizes.
    DataError,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Index out of range.
    OutOfRange,
}

impl From<LzxError> for CabError {
    fn from(e: LzxError) -> Self {
        match e {
            LzxError::LimitExceeded => CabError::LimitExceeded,
            LzxError::Allocation => CabError::Allocation,
            LzxError::InvalidWindow => CabError::UnsupportedCompression,
            _ => CabError::DataError,
        }
    }
}

impl From<MszipError> for CabError {
    fn from(e: MszipError) -> Self {
        match e {
            MszipError::LimitExceeded => CabError::LimitExceeded,
            MszipError::Allocation => CabError::Allocation,
            _ => CabError::DataError,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CabLimits {
    pub max_files: usize,
    pub max_folders: usize,
    /// Longest file name in bytes (MS-CAB caps names at 256 bytes).
    pub max_name_len: usize,
    /// Largest decompressed folder (bounds memory per extraction).
    pub max_folder_size: u64,
    pub verify_checksums: bool,
    /// Total bytes [`CabArchive::extract_all`] may return across all files
    /// (same default as `ReaderLimits::max_total_size`).
    pub max_total_size: u64,
}

impl Default for CabLimits {
    fn default() -> Self {
        CabLimits {
            max_files: 65535,
            max_folders: 65535,
            max_name_len: 1024,
            max_folder_size: 1 << 31,
            verify_checksums: true,
            max_total_size: 4 << 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CabCompression {
    None,
    MsZip,
    /// Quantum: recognised, not decoded.
    Quantum { level: u8, window_bits: u8 },
    Lzx { window_bits: u8 },
    Unknown(u16),
}

impl CabCompression {
    pub fn from_type(t: u16) -> Self {
        match t & 0x000F {
            0 => CabCompression::None,
            1 => CabCompression::MsZip,
            2 => CabCompression::Quantum { level: ((t >> 4) & 0xF) as u8, window_bits: ((t >> 8) & 0x1F) as u8 },
            3 => CabCompression::Lzx { window_bits: ((t >> 8) & 0x1F) as u8 },
            _ => CabCompression::Unknown(t),
        }
    }
}

/// Where a file's data lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CabFolderRef {
    Index(u16),
    /// 0xFFFD: continued from the previous cabinet.
    ContinuedFromPrev,
    /// 0xFFFE: continued in the next cabinet.
    ContinuedToNext,
    /// 0xFFFF: continued from the previous and into the next cabinet.
    ContinuedPrevAndNext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabHeader {
    pub cabinet_size: u32,
    pub version_major: u8,
    pub version_minor: u8,
    pub flags: u16,
    pub set_id: u16,
    pub cabinet_index: u16,
    /// abReserve of CFHEADER (e.g. signature data).
    pub reserve: Vec<u8>,
    /// (cabinet name, disk name) of the previous cabinet, when flagged.
    pub prev: Option<(Vec<u8>, Vec<u8>)>,
    /// (cabinet name, disk name) of the next cabinet, when flagged.
    pub next: Option<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabFolder {
    pub type_compress: u16,
    pub compression: CabCompression,
    /// Absolute offset of the first CFDATA block.
    pub data_offset: u32,
    pub num_blocks: u16,
    /// Sum of cbUncomp over the CFDATA chain, when the chain is readable.
    pub uncompressed_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabFile {
    /// Name bytes as stored.
    pub raw_name: Vec<u8>,
    /// Name decoded to UTF-8 with `/` separators.
    pub path: String,
    pub size: u32,
    pub folder_offset: u32,
    pub folder: CabFolderRef,
    pub date: u16,
    pub time: u16,
    pub attributes: u16,
    /// DOS date/time as Unix seconds (local time taken as UTC), if valid.
    pub mtime: Option<i64>,
}

pub const ATTR_READONLY: u16 = 0x01;
pub const ATTR_HIDDEN: u16 = 0x02;
pub const ATTR_SYSTEM: u16 = 0x04;
pub const ATTR_ARCHIVE: u16 = 0x20;
pub const ATTR_EXEC: u16 = 0x40;
pub const ATTR_NAME_IS_UTF: u16 = 0x80;

const FLAG_PREV: u16 = 0x0001;
const FLAG_NEXT: u16 = 0x0002;
const FLAG_RESERVE: u16 = 0x0004;

/// Parsed cabinet over a borrowed byte slice.
#[derive(Debug, Clone)]
pub struct CabArchive<'a> {
    bytes: &'a [u8],
    limits: CabLimits,
    data_reserve: usize,
    pub header: CabHeader,
    pub folders: Vec<CabFolder>,
    pub files: Vec<CabFile>,
}

fn le16(b: &[u8], at: usize) -> Result<u16, CabError> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(CabError::Truncated)
}

fn le32(b: &[u8], at: usize) -> Result<u32, CabError> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(CabError::Truncated)
}

/// Read a NUL-terminated string starting at `at`; returns (bytes, next offset).
fn cstr(b: &[u8], at: usize, max: usize) -> Result<(Vec<u8>, usize), CabError> {
    let rest = b.get(at..).ok_or(CabError::Truncated)?;
    let window = &rest[..rest.len().min(max.saturating_add(1))];
    match window.iter().position(|&c| c == 0) {
        Some(n) => Ok((window[..n].to_vec(), at + n + 1)),
        None if window.len() < rest.len() || rest.len() > max => Err(CabError::LimitExceeded),
        None => Err(CabError::Truncated),
    }
}

/// MS-CAB CFDATA checksum (CSUMCompute): XOR of little-endian 32-bit words;
/// a 1..3 byte tail is folded in most-significant byte first.
pub fn cab_checksum(data: &[u8], seed: u32) -> u32 {
    let mut cs = seed;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        cs ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let mut ul = 0u32;
    for &b in chunks.remainder() {
        ul = (ul << 8) | u32::from(b);
    }
    cs ^ ul
}

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

fn decode_name(raw: &[u8], utf8: bool) -> String {
    let s: String = if utf8 {
        String::from_utf8_lossy(raw).into_owned()
    } else {
        raw.iter().map(|&b| char::from(b)).collect()
    };
    s.replace('\\', "/")
}

/// One CFDATA block header + payload location.
struct DataBlock {
    checksum: u32,
    /// cbData, cbUncomp and abReserve (covered by the checksum).
    header_tail: std::ops::Range<usize>,
    data: std::ops::Range<usize>,
    uncompressed: u16,
}

impl<'a> CabArchive<'a> {
    pub fn parse(bytes: &'a [u8], limits: CabLimits) -> Result<Self, CabError> {
        if bytes.len() < 36 {
            return Err(if bytes.starts_with(b"MSCF") || b"MSCF".starts_with(bytes) {
                CabError::Truncated
            } else {
                CabError::InvalidSignature
            });
        }
        if &bytes[0..4] != b"MSCF" {
            return Err(CabError::InvalidSignature);
        }
        let cabinet_size = le32(bytes, 8)?;
        let coff_files = le32(bytes, 16)? as usize;
        let version_minor = bytes[24];
        let version_major = bytes[25];
        let c_folders = le16(bytes, 26)? as usize;
        let c_files = le16(bytes, 28)? as usize;
        let flags = le16(bytes, 30)?;
        let set_id = le16(bytes, 32)?;
        let cabinet_index = le16(bytes, 34)?;
        if version_major != 1 {
            return Err(CabError::InvalidHeader);
        }
        if c_folders > limits.max_folders || c_files > limits.max_files {
            return Err(CabError::LimitExceeded);
        }
        let mut at = 36usize;
        let (mut cb_folder_res, mut cb_data_res) = (0usize, 0usize);
        let mut reserve = Vec::new();
        if flags & FLAG_RESERVE != 0 {
            let cb_header = le16(bytes, at)? as usize;
            cb_folder_res = *bytes.get(at + 2).ok_or(CabError::Truncated)? as usize;
            cb_data_res = *bytes.get(at + 3).ok_or(CabError::Truncated)? as usize;
            at += 4;
            reserve = bytes.get(at..at + cb_header).ok_or(CabError::Truncated)?.to_vec();
            at += cb_header;
        }
        let mut prev = None;
        let mut next = None;
        for (flag, slot) in [(FLAG_PREV, &mut prev), (FLAG_NEXT, &mut next)] {
            if flags & flag != 0 {
                let (cab, a) = cstr(bytes, at, 255)?;
                let (disk, a) = cstr(bytes, a, 255)?;
                at = a;
                *slot = Some((cab, disk));
            }
        }
        let mut folders = Vec::new();
        folders.try_reserve(c_folders).map_err(|_| CabError::Allocation)?;
        for _ in 0..c_folders {
            let data_offset = le32(bytes, at)?;
            let num_blocks = le16(bytes, at + 4)?;
            let type_compress = le16(bytes, at + 6)?;
            at = at.checked_add(8 + cb_folder_res).ok_or(CabError::Truncated)?;
            if at > bytes.len() {
                return Err(CabError::Truncated);
            }
            folders.push(CabFolder {
                type_compress,
                compression: CabCompression::from_type(type_compress),
                data_offset,
                num_blocks,
                uncompressed_size: None,
            });
        }
        if coff_files < at {
            return Err(CabError::InvalidHeader);
        }
        let mut files = Vec::new();
        files.try_reserve(c_files).map_err(|_| CabError::Allocation)?;
        let mut at = coff_files;
        for _ in 0..c_files {
            let size = le32(bytes, at)?;
            let folder_offset = le32(bytes, at + 4)?;
            let ifolder = le16(bytes, at + 8)?;
            let date = le16(bytes, at + 10)?;
            let time = le16(bytes, at + 12)?;
            let attributes = le16(bytes, at + 14)?;
            let (raw_name, a) = cstr(bytes, at + 16, limits.max_name_len)?;
            at = a;
            if raw_name.is_empty() {
                return Err(CabError::InvalidFile);
            }
            let folder = match ifolder {
                0xFFFD => CabFolderRef::ContinuedFromPrev,
                0xFFFE => CabFolderRef::ContinuedToNext,
                0xFFFF => CabFolderRef::ContinuedPrevAndNext,
                i if (i as usize) < c_folders => CabFolderRef::Index(i),
                _ => return Err(CabError::InvalidFile),
            };
            let path = decode_name(&raw_name, attributes & ATTR_NAME_IS_UTF != 0);
            files.push(CabFile {
                raw_name,
                path,
                size,
                folder_offset,
                folder,
                date,
                time,
                attributes,
                mtime: dos_to_unix(date, time),
            });
        }
        let mut cab = CabArchive {
            bytes,
            limits,
            data_reserve: cb_data_res,
            header: CabHeader {
                cabinet_size,
                version_major,
                version_minor,
                flags,
                set_id,
                cabinet_index,
                reserve,
                prev,
                next,
            },
            folders,
            files,
        };
        // Folder sizes from the CFDATA headers. Every CFDATA header is at
        // least 8 bytes, so honest cabinets never need more than len / 8
        // header reads in total; stop there to bound work on hostile input.
        let mut budget = bytes.len() / 8 + 1;
        for i in 0..cab.folders.len() {
            let n = cab.folders[i].num_blocks as usize;
            if n > budget {
                break;
            }
            budget -= n;
            let size = cab.data_blocks(i).ok().map(|blocks| blocks.iter().map(|b| u64::from(b.uncompressed)).sum());
            cab.folders[i].uncompressed_size = size;
        }
        Ok(cab)
    }

    fn data_blocks(&self, folder: usize) -> Result<Vec<DataBlock>, CabError> {
        let f = self.folders.get(folder).ok_or(CabError::OutOfRange)?;
        let mut at = f.data_offset as usize;
        let mut out = Vec::new();
        out.try_reserve(f.num_blocks as usize).map_err(|_| CabError::Allocation)?;
        for _ in 0..f.num_blocks {
            let checksum = le32(self.bytes, at)?;
            let cb_data = le16(self.bytes, at + 4)? as usize;
            let cb_uncomp = le16(self.bytes, at + 6)?;
            let tail_end = at + 8 + self.data_reserve;
            let data_end = tail_end + cb_data;
            if data_end > self.bytes.len() {
                return Err(CabError::Truncated);
            }
            out.push(DataBlock {
                checksum,
                header_tail: at + 4..tail_end,
                data: tail_end..data_end,
                uncompressed: cb_uncomp,
            });
            at = data_end;
        }
        Ok(out)
    }

    /// Decompress a whole folder.
    pub fn folder_data(&self, folder: usize) -> Result<Vec<u8>, CabError> {
        let f = self.folders.get(folder).ok_or(CabError::OutOfRange)?;
        let blocks = self.data_blocks(folder)?;
        let mut total: u64 = 0;
        for (k, b) in blocks.iter().enumerate() {
            if b.uncompressed == 0 {
                // the block continues in the next cabinet (only legal last)
                return Err(if k + 1 == blocks.len() && self.header.next.is_some() {
                    CabError::Spanned
                } else {
                    CabError::InvalidFolder
                });
            }
            if b.uncompressed as usize > 32768 {
                return Err(CabError::InvalidFolder);
            }
            total += u64::from(b.uncompressed);
            if self.limits.verify_checksums && b.checksum != 0 {
                let cs = cab_checksum(&self.bytes[b.header_tail.clone()], cab_checksum(&self.bytes[b.data.clone()], 0));
                if cs != b.checksum {
                    return Err(CabError::ChecksumMismatch);
                }
            }
        }
        if total > self.limits.max_folder_size {
            return Err(CabError::LimitExceeded);
        }
        let total = usize::try_from(total).map_err(|_| CabError::LimitExceeded)?;
        let mut out: Vec<u8> = Vec::new();
        match f.compression {
            CabCompression::None => {
                out.try_reserve(total).map_err(|_| CabError::Allocation)?;
                for b in &blocks {
                    if b.data.len() != b.uncompressed as usize {
                        return Err(CabError::DataError);
                    }
                    out.extend_from_slice(&self.bytes[b.data.clone()]);
                }
            }
            CabCompression::MsZip => {
                out.try_reserve(total).map_err(|_| CabError::Allocation)?;
                let mut dec = MszipDecoder::new();
                for b in &blocks {
                    let part = dec.decode_block(&self.bytes[b.data.clone()], b.uncompressed as usize)?;
                    out.extend_from_slice(&part);
                }
            }
            CabCompression::Lzx { window_bits } => {
                let clen: usize = blocks.iter().map(|b| b.data.len()).sum();
                let mut input: Vec<u8> = Vec::new();
                input.try_reserve(clen).map_err(|_| CabError::Allocation)?;
                for b in &blocks {
                    input.extend_from_slice(&self.bytes[b.data.clone()]);
                }
                out = lzx_decompress(&input, window_bits, total, 0)?;
            }
            CabCompression::Quantum { .. } | CabCompression::Unknown(_) => {
                return Err(CabError::UnsupportedCompression);
            }
        }
        Ok(out)
    }

    fn file_range(&self, index: usize, folder_len: usize) -> Result<std::ops::Range<usize>, CabError> {
        let f = &self.files[index];
        let start = f.folder_offset as usize;
        let end = start.checked_add(f.size as usize).ok_or(CabError::InvalidFile)?;
        if end > folder_len {
            return Err(CabError::InvalidFile);
        }
        Ok(start..end)
    }

    fn folder_index(&self, index: usize) -> Result<usize, CabError> {
        let f = self.files.get(index).ok_or(CabError::OutOfRange)?;
        match f.folder {
            CabFolderRef::Index(i) => Ok(i as usize),
            _ => Err(CabError::Spanned),
        }
    }

    /// Extract one file (decompresses its whole folder).
    pub fn extract(&self, index: usize) -> Result<Vec<u8>, CabError> {
        let folder = self.folder_index(index)?;
        if self.files[index].size == 0 {
            return Ok(Vec::new());
        }
        let data = self.folder_data(folder)?;
        let r = self.file_range(index, data.len())?;
        Ok(data[r].to_vec())
    }

    /// Folders whose CFDATA chain overlaps the chain of a folder at a lower
    /// (offset, index): honest cabinets never share data between folders, so
    /// these are only used to multiply output. Each non-overlapping chain is
    /// walked once, bounding the work by the archive size.
    fn overlapping_folders(&self) -> Vec<bool> {
        let mut order: Vec<usize> = (0..self.folders.len()).filter(|&i| self.folders[i].num_blocks > 0).collect();
        order.sort_by_key(|&i| (self.folders[i].data_offset, i));
        let mut bad = vec![false; self.folders.len()];
        let mut end = 0usize;
        for i in order {
            let start = self.folders[i].data_offset as usize;
            if start < end {
                bad[i] = true;
                continue;
            }
            // an unreadable chain runs off the end of the archive
            end = match self.data_blocks(i) {
                Ok(blocks) => blocks.last().map_or(start, |b| b.data.end),
                Err(_) => self.bytes.len(),
            };
        }
        bad
    }

    /// Extract every file, decompressing each folder once. The result has one
    /// entry per file, in archive order. Files past
    /// [`CabLimits::max_total_size`] bytes of output return
    /// [`CabError::LimitExceeded`]; files in a folder whose CFDATA overlaps
    /// another folder's return [`CabError::InvalidFolder`]. A decompressed
    /// folder is dropped after its last file.
    pub fn extract_all(&self) -> Vec<Result<Vec<u8>, CabError>> {
        let overlapping = self.overlapping_folders();
        let mut last_use = vec![usize::MAX; self.folders.len()];
        for i in 0..self.files.len() {
            if let Ok(f) = self.folder_index(i) {
                last_use[f] = i;
            }
        }
        let mut cache: Vec<Option<Result<Vec<u8>, CabError>>> = vec![None; self.folders.len()];
        let mut remaining = self.limits.max_total_size;
        let mut out = Vec::with_capacity(self.files.len());
        for i in 0..self.files.len() {
            let r = (|| {
                let folder = self.folder_index(i)?;
                let size = u64::from(self.files[i].size);
                if size == 0 {
                    return Ok(Vec::new());
                }
                if overlapping[folder] {
                    return Err(CabError::InvalidFolder);
                }
                if size > remaining {
                    return Err(CabError::LimitExceeded);
                }
                if cache[folder].is_none() {
                    cache[folder] = Some(self.folder_data(folder));
                }
                match cache[folder].as_ref() {
                    Some(Ok(d)) => {
                        let r = self.file_range(i, d.len())?;
                        remaining -= size;
                        Ok(d[r].to_vec())
                    }
                    Some(Err(e)) => Err(*e),
                    None => Err(CabError::DataError),
                }
            })();
            if let Ok(f) = self.folder_index(i)
                && last_use[f] == i
            {
                cache[f] = None;
            }
            out.push(r);
        }
        out
    }

    /// Format-neutral entries for the extractor / CLI: one regular file per
    /// CFFILE; read-only files get mode 0o444, executables 0o755, others 0o644.
    pub fn planned_entries(&self) -> Vec<PlannedEntry> {
        self.files
            .iter()
            .map(|f| PlannedEntry {
                path: f.path.as_bytes().to_vec(),
                kind: EntryKind::File,
                size: u64::from(f.size),
                mode: Some(if f.attributes & ATTR_EXEC != 0 {
                    0o755
                } else if f.attributes & ATTR_READONLY != 0 {
                    0o444
                } else {
                    0o644
                }),
                mtime: f.mtime,
            })
            .collect()
    }
}
