// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARJ archive reader (read-only): main header, local file headers,
//! extended headers, methods 0 (stored), 1..3 (static Huffman, see
//! [`crate::lzh_decode::decode_arj_huffman`]) and 4 (fastest).
//!
//! Spec source: Robert Jung's ARJ technical information (TECHNOTE.DOC):
//! every header is `60 EA`, a 16-bit basic-header size (0 = end of
//! archive, at most 2600), the basic header, its CRC-32, then extended
//! headers (`u16 size`, data, CRC-32) terminated by a zero size. The basic
//! header's fixed part (`first_hdr_size` bytes, >= 30) holds version, host
//! OS, flags, method, file type, DOS timestamp, compressed/original sizes,
//! the file CRC-32 and the access mode; the NUL-terminated name and comment
//! follow. File type 2 is the main (archive) header.
//!
//! Garbled (password-protected) members and members split across volumes
//! are listed but `read_arj_entry` reports `Unsupported` for them.
//! Self-extracting archives: the first valid main header within
//! `ArjLimits::max_scan` bytes is used.

use crate::crc32::crc32;
use crate::lzh_decode::{LzhDecodeError, decode_arj_fastest, decode_arj_huffman};
use crate::lzh_read::dos_stamp_to_unix;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArjError {
    Truncated,
    BadHeader,
    /// Basic or extended header CRC-32 mismatch.
    BadChecksum,
    /// Unknown method, garbled (encrypted) or multi-volume member.
    Unsupported,
    LimitExceeded,
    Allocation,
    /// Decoded data does not match the stored CRC-32.
    CrcMismatch,
    InvalidData,
}

impl From<LzhDecodeError> for ArjError {
    fn from(e: LzhDecodeError) -> Self {
        match e {
            LzhDecodeError::Truncated => ArjError::Truncated,
            LzhDecodeError::InvalidData => ArjError::InvalidData,
            LzhDecodeError::LimitExceeded => ArjError::LimitExceeded,
            LzhDecodeError::Allocation => ArjError::Allocation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArjLimits {
    pub max_entries: usize,
    /// How far to search for the main header (SFX stubs).
    pub max_scan: usize,
    /// Maximum extended headers per member.
    pub max_ext_headers: usize,
}

impl Default for ArjLimits {
    fn default() -> Self {
        ArjLimits { max_entries: 100_000, max_scan: 1 << 20, max_ext_headers: 64 }
    }
}

pub const FLAG_GARBLED: u8 = 0x01;
pub const FLAG_VOLUME: u8 = 0x04;
pub const FLAG_EXTFILE: u8 = 0x08;
pub const FLAG_PATHSYM: u8 = 0x10;

pub const TYPE_BINARY: u8 = 0;
pub const TYPE_TEXT: u8 = 1;
pub const TYPE_MAIN: u8 = 2;
pub const TYPE_DIR: u8 = 3;
pub const TYPE_LABEL: u8 = 4;
pub const TYPE_CHAPTER: u8 = 5;

pub const HOST_UNIX: u8 = 2;
const MAX_BASIC: usize = 2600;
const FIXED_MIN: usize = 30;

/// Main (archive) header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjMain {
    pub offset: usize,
    pub host_os: u8,
    pub flags: u8,
    pub name: Vec<u8>,
    pub comment: Vec<u8>,
}

/// One member, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjEntry<'a> {
    /// Path with `/` separators.
    pub path: Vec<u8>,
    pub comment: Vec<u8>,
    pub method: u8,
    pub file_type: u8,
    pub flags: u8,
    pub host_os: u8,
    pub data: &'a [u8],
    pub original_size: u64,
    pub crc32: u32,
    pub mtime: Option<i64>,
    /// Raw access mode (Unix mode when `host_os == HOST_UNIX`, else DOS attributes).
    pub access_mode: u16,
    pub header_offset: usize,
}

impl ArjEntry<'_> {
    pub fn is_dir(&self) -> bool {
        self.file_type == TYPE_DIR
    }
    pub fn unix_mode(&self) -> Option<u32> {
        (self.host_os == HOST_UNIX).then_some(u32::from(self.access_mode) & 0o7777)
    }
}

fn le16(b: &[u8], at: usize) -> Result<u16, ArjError> {
    let s = b.get(at..at + 2).ok_or(ArjError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Result<u32, ArjError> {
    let s = b.get(at..at + 4).ok_or(ArjError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct Header<'a> {
    basic: &'a [u8],
    /// Position after the basic header, its CRC and the extended headers.
    next: usize,
}

/// Read one header at `at`. `Ok(None)` is the end-of-archive marker.
fn read_header<'a>(b: &'a [u8], at: usize, limits: &ArjLimits) -> Result<Option<Header<'a>>, ArjError> {
    if b.get(at..at + 2).ok_or(ArjError::Truncated)? != [0x60, 0xEA] {
        return Err(ArjError::BadHeader);
    }
    let size = usize::from(le16(b, at + 2)?);
    if size == 0 {
        return Ok(None);
    }
    if !(FIXED_MIN..=MAX_BASIC).contains(&size) {
        return Err(ArjError::BadHeader);
    }
    let start = at + 4;
    let basic = b.get(start..start + size).ok_or(ArjError::Truncated)?;
    if le32(b, start + size)? != crc32(basic) {
        return Err(ArjError::BadChecksum);
    }
    let mut p = start + size + 4;
    let mut n = 0usize;
    loop {
        let ext = usize::from(le16(b, p)?);
        p += 2;
        if ext == 0 {
            break;
        }
        n += 1;
        if n > limits.max_ext_headers {
            return Err(ArjError::LimitExceeded);
        }
        let data = b.get(p..p + ext).ok_or(ArjError::Truncated)?;
        if le32(b, p + ext)? != crc32(data) {
            return Err(ArjError::BadChecksum);
        }
        p += ext + 4;
    }
    Ok(Some(Header { basic, next: p }))
}

/// Name and comment (NUL-terminated strings after the fixed part).
fn strings(basic: &[u8]) -> Result<(&[u8], &[u8]), ArjError> {
    let first = usize::from(basic[0]);
    if first < FIXED_MIN || first > basic.len() {
        return Err(ArjError::BadHeader);
    }
    let rest = &basic[first..];
    let nul = rest.iter().position(|&c| c == 0).ok_or(ArjError::BadHeader)?;
    let name = &rest[..nul];
    let rest = &rest[nul + 1..];
    let comment = match rest.iter().position(|&c| c == 0) {
        Some(n) => &rest[..n],
        None => rest,
    };
    Ok((name, comment))
}

fn locate_main(b: &[u8], limits: &ArjLimits) -> Result<(ArjMain, usize), ArjError> {
    let end = b.len().saturating_sub(1).min(limits.max_scan.saturating_add(1));
    let mut first_err = None;
    for at in 0..end {
        if b[at] != 0x60 || b[at + 1] != 0xEA {
            continue;
        }
        match read_header(b, at, limits) {
            Ok(Some(h)) if h.basic[6] == TYPE_MAIN => {
                let (name, comment) = strings(h.basic)?;
                let main = ArjMain {
                    offset: at,
                    host_os: h.basic[3],
                    flags: h.basic[4],
                    name: name.to_vec(),
                    comment: comment.to_vec(),
                };
                return Ok((main, h.next));
            }
            Ok(_) => first_err.get_or_insert(ArjError::BadHeader),
            Err(e) => first_err.get_or_insert(e),
        };
    }
    Err(first_err.unwrap_or(ArjError::BadHeader))
}

/// True if `b` starts with an ARJ main header (signature, sane size, CRC).
pub fn looks_like_arj(b: &[u8]) -> bool {
    matches!(read_header(b, 0, &ArjLimits::default()), Ok(Some(h)) if h.basic[6] == TYPE_MAIN)
}

/// Parse an ARJ archive: the main header and every member header.
pub fn parse_arj<'a>(bytes: &'a [u8], limits: ArjLimits) -> Result<(ArjMain, Vec<ArjEntry<'a>>), ArjError> {
    let (main, mut at) = locate_main(bytes, &limits)?;
    let mut entries = Vec::new();
    while let Some(h) = read_header(bytes, at, &limits)? {
        if entries.len() >= limits.max_entries {
            return Err(ArjError::LimitExceeded);
        }
        let b = h.basic;
        let file_type = b[6];
        if file_type == TYPE_MAIN {
            return Err(ArjError::BadHeader);
        }
        let compressed = le32(b, 12)? as usize;
        let data_start = h.next;
        let data_end = data_start.checked_add(compressed).ok_or(ArjError::Truncated)?;
        let data = bytes.get(data_start..data_end).ok_or(ArjError::Truncated)?;
        let (name, comment) = strings(b)?;
        let path: Vec<u8> = name.iter().map(|&c| if c == b'\\' { b'/' } else { c }).collect();
        let entry = ArjEntry {
            path,
            comment: comment.to_vec(),
            method: b[5],
            file_type,
            flags: b[4],
            host_os: b[3],
            data,
            original_size: u64::from(le32(b, 16)?),
            crc32: le32(b, 20)?,
            mtime: dos_stamp_to_unix(le32(b, 8)?),
            access_mode: le16(b, 26)?,
            header_offset: at,
        };
        entries.try_reserve(1).map_err(|_| ArjError::Allocation)?;
        entries.push(entry);
        at = data_end;
    }
    Ok((main, entries))
}

/// Decode a member, refusing output larger than `max_output`, and verify
/// its CRC-32. Directories, labels and chapters decode to an empty Vec.
pub fn read_arj_entry(entry: &ArjEntry<'_>, max_output: usize) -> Result<Vec<u8>, ArjError> {
    if matches!(entry.file_type, TYPE_DIR | TYPE_LABEL | TYPE_CHAPTER) {
        return Ok(Vec::new());
    }
    if entry.flags & (FLAG_GARBLED | FLAG_VOLUME | FLAG_EXTFILE) != 0 {
        return Err(ArjError::Unsupported);
    }
    let size = usize::try_from(entry.original_size).map_err(|_| ArjError::LimitExceeded)?;
    if size > max_output {
        return Err(ArjError::LimitExceeded);
    }
    let out = match entry.method {
        0 => {
            if entry.data.len() != size {
                return Err(ArjError::InvalidData);
            }
            let mut v = Vec::new();
            v.try_reserve_exact(size).map_err(|_| ArjError::Allocation)?;
            v.extend_from_slice(entry.data);
            v
        }
        1..=3 => decode_arj_huffman(entry.data, size, max_output)?,
        4 => decode_arj_fastest(entry.data, size, max_output)?,
        _ => return Err(ArjError::Unsupported),
    };
    if crc32(&out) != entry.crc32 {
        return Err(ArjError::CrcMismatch);
    }
    Ok(out)
}
