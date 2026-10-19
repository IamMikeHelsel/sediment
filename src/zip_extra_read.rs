// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZIP "extra field" parsing for the common third-party and PKWARE records.
//!
//! Spec sources (public documentation only):
//! - PKWARE APPNOTE.TXT 6.3.x, section 4.5 (extensible data fields), 4.5.5
//!   (0x000a NTFS), and 4.6 (third-party mappings list).
//! - Info-ZIP `extrafld.txt`: 0x5455 extended timestamp, 0x7875 Info-ZIP
//!   Unix "ux" (uid/gid), 0x7075 Info-ZIP Unicode Path.
//! - WinZip "AES Encryption Information" document: 0x9901 AE-x record.
//!
//! All parsers take the payload of one record (without the 4-byte id/length
//! header) or a whole extra block, borrow from the input, and return `Err`
//! for malformed data instead of panicking.

use crate::crc32::crc32;

/// Header id of the PKWARE ZIP64 extended information record.
pub const ZIP64_EXTRA_ID: u16 = 0x0001;
/// Header id of the PKWARE NTFS record.
pub const NTFS_EXTRA_ID: u16 = 0x000a;
/// Header id of the Info-ZIP extended timestamp record ("UT").
pub const EXTENDED_TIMESTAMP_ID: u16 = 0x5455;
/// Header id of the Info-ZIP Unicode Path record ("up").
pub const UNICODE_PATH_ID: u16 = 0x7075;
/// Header id of the Info-ZIP Unicode Comment record ("uc").
pub const UNICODE_COMMENT_ID: u16 = 0x6375;
/// Header id of the Info-ZIP new Unix uid/gid record ("ux").
pub const UNIX_OWNER_ID: u16 = 0x7875;
/// Header id of the WinZip AES encryption record.
pub const AES_EXTRA_ID: u16 = 0x9901;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraError {
    /// A record header or payload runs past the end of the block.
    Truncated,
    /// A record is structurally wrong (bad length, bad version, bad value).
    Invalid,
    /// A well-formed record uses a variant this parser does not handle.
    Unsupported,
    /// More records than the caller's limit.
    LimitExceeded,
}

/// One raw extra-field record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraField<'a> {
    pub id: u16,
    pub data: &'a [u8],
}

/// Iterator over the records of an extra block. Yields `Err` once (and then
/// stops) if the block is malformed.
#[derive(Debug, Clone)]
pub struct ExtraFields<'a> {
    rest: &'a [u8],
    failed: bool,
}

/// Iterate the records of an extra block without allocating.
pub fn extra_fields(block: &[u8]) -> ExtraFields<'_> {
    ExtraFields { rest: block, failed: false }
}

impl<'a> Iterator for ExtraFields<'a> {
    type Item = Result<ExtraField<'a>, ExtraError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 4 {
            self.failed = true;
            return Some(Err(ExtraError::Truncated));
        }
        let id = u16::from_le_bytes([self.rest[0], self.rest[1]]);
        let len = u16::from_le_bytes([self.rest[2], self.rest[3]]) as usize;
        let body = &self.rest[4..];
        if body.len() < len {
            self.failed = true;
            return Some(Err(ExtraError::Truncated));
        }
        let (data, rest) = body.split_at(len);
        self.rest = rest;
        Some(Ok(ExtraField { id, data }))
    }
}

/// Parse a whole extra block into records, refusing more than `max_fields`.
pub fn parse_extra_fields(block: &[u8], max_fields: usize) -> Result<Vec<ExtraField<'_>>, ExtraError> {
    let mut out = Vec::new();
    for field in extra_fields(block) {
        let field = field?;
        if out.len() >= max_fields {
            return Err(ExtraError::LimitExceeded);
        }
        out.try_reserve(1).map_err(|_| ExtraError::LimitExceeded)?;
        out.push(field);
    }
    Ok(out)
}

/// Validate an extra block and return the payload of the first record with
/// `id`, if any. Duplicate records of the same id are rejected as `Invalid`
/// because their interpretation is ambiguous.
pub fn find_extra(block: &[u8], id: u16) -> Result<Option<&[u8]>, ExtraError> {
    let mut found = None;
    for field in extra_fields(block) {
        let field = field?;
        if field.id == id {
            if found.is_some() {
                return Err(ExtraError::Invalid);
            }
            found = Some(field.data);
        }
    }
    Ok(found)
}

fn le_u16(b: &[u8], at: usize) -> Result<u16, ExtraError> {
    let s = b.get(at..at.checked_add(2).ok_or(ExtraError::Truncated)?).ok_or(ExtraError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], at: usize) -> Result<u32, ExtraError> {
    let s = b.get(at..at.checked_add(4).ok_or(ExtraError::Truncated)?).ok_or(ExtraError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le_u64(b: &[u8], at: usize) -> Result<u64, ExtraError> {
    let s = b.get(at..at.checked_add(8).ok_or(ExtraError::Truncated)?).ok_or(ExtraError::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------- 0x7075

/// Info-ZIP Unicode Path record (0x7075 "up").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicodePath<'a> {
    pub version: u8,
    /// CRC-32 of the header file name this record was created for.
    pub name_crc32: u32,
    /// UTF-8 file name.
    pub name: &'a [u8],
}

/// Parse a 0x7075 payload. Version must be 1 and the name valid UTF-8.
pub fn parse_unicode_path(data: &[u8]) -> Result<UnicodePath<'_>, ExtraError> {
    if data.len() < 5 {
        return Err(ExtraError::Truncated);
    }
    let version = data[0];
    if version != 1 {
        return Err(ExtraError::Unsupported);
    }
    let name_crc32 = le_u32(data, 1)?;
    let name = &data[5..];
    if std::str::from_utf8(name).is_err() {
        return Err(ExtraError::Invalid);
    }
    Ok(UnicodePath { version, name_crc32, name })
}

impl<'a> UnicodePath<'a> {
    /// True if the record was written for `header_name` (per Info-ZIP, a
    /// stale record whose CRC does not match must be ignored).
    pub fn matches(&self, header_name: &[u8]) -> bool {
        crc32(header_name) == self.name_crc32
    }
}

/// Look up a usable Unicode Path for `header_name` in an extra block.
/// Returns `Ok(None)` if absent or stale; `Err` if the block or record is
/// malformed.
pub fn unicode_path_for<'a>(block: &'a [u8], header_name: &[u8]) -> Result<Option<&'a [u8]>, ExtraError> {
    match find_extra(block, UNICODE_PATH_ID)? {
        None => Ok(None),
        Some(data) => {
            let up = parse_unicode_path(data)?;
            if up.matches(header_name) { Ok(Some(up.name)) } else { Ok(None) }
        }
    }
}

// ---------------------------------------------------------------- 0x5455

/// Info-ZIP extended timestamp record (0x5455 "UT"). Times are Unix seconds
/// (signed 32-bit). The central-directory copy carries only the modification
/// time even when `flags` advertises more, so absent values are `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedTimestamp {
    pub flags: u8,
    pub mtime: Option<i32>,
    pub atime: Option<i32>,
    pub ctime: Option<i32>,
}

/// Parse a 0x5455 payload (local or central form).
pub fn parse_extended_timestamp(data: &[u8]) -> Result<ExtendedTimestamp, ExtraError> {
    let flags = *data.first().ok_or(ExtraError::Truncated)?;
    let rest = &data[1..];
    if rest.len() % 4 != 0 || rest.len() > 12 {
        return Err(ExtraError::Invalid);
    }
    let mut values = [None; 3];
    let mut pos = 0usize;
    for (bit, slot) in values.iter_mut().enumerate() {
        if flags & (1 << bit) != 0 && pos < rest.len() {
            *slot = Some(le_u32(rest, pos)? as i32);
            pos += 4;
        }
    }
    if pos != rest.len() {
        // More values than the flags allow.
        return Err(ExtraError::Invalid);
    }
    Ok(ExtendedTimestamp { flags, mtime: values[0], atime: values[1], ctime: values[2] })
}

// ---------------------------------------------------------------- 0x7875

/// Info-ZIP Unix uid/gid record (0x7875 "ux", version 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixOwner {
    pub uid: u64,
    pub gid: u64,
}

fn read_var_uint(data: &[u8], pos: &mut usize) -> Result<u64, ExtraError> {
    let size = *data.get(*pos).ok_or(ExtraError::Truncated)? as usize;
    *pos += 1;
    let end = pos.checked_add(size).ok_or(ExtraError::Truncated)?;
    let bytes = data.get(*pos..end).ok_or(ExtraError::Truncated)?;
    *pos = end;
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 8 {
            if b != 0 {
                return Err(ExtraError::Unsupported);
            }
            continue;
        }
        value |= (b as u64) << (8 * i);
    }
    Ok(value)
}

/// Parse a 0x7875 payload.
pub fn parse_unix_owner(data: &[u8]) -> Result<UnixOwner, ExtraError> {
    let version = *data.first().ok_or(ExtraError::Truncated)?;
    if version != 1 {
        return Err(ExtraError::Unsupported);
    }
    let mut pos = 1usize;
    let uid = read_var_uint(data, &mut pos)?;
    let gid = read_var_uint(data, &mut pos)?;
    if pos != data.len() {
        return Err(ExtraError::Invalid);
    }
    Ok(UnixOwner { uid, gid })
}

// ---------------------------------------------------------------- 0x000a

/// NTFS times (Windows FILETIME: 100 ns ticks since 1601-01-01 UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsTimes {
    pub mtime: u64,
    pub atime: u64,
    pub ctime: u64,
}

/// Parse a 0x000a payload. Returns `Ok(None)` if the record has no
/// attribute tag 1 (the only tag defined by APPNOTE).
pub fn parse_ntfs(data: &[u8]) -> Result<Option<NtfsTimes>, ExtraError> {
    if data.len() < 4 {
        return Err(ExtraError::Truncated);
    }
    let mut pos = 4usize; // reserved
    let mut times = None;
    while pos < data.len() {
        let tag = le_u16(data, pos)?;
        let size = le_u16(data, pos + 2)? as usize;
        let start = pos + 4;
        let end = start.checked_add(size).ok_or(ExtraError::Truncated)?;
        let body = data.get(start..end).ok_or(ExtraError::Truncated)?;
        if tag == 1 {
            if size != 24 {
                return Err(ExtraError::Invalid);
            }
            if times.is_some() {
                return Err(ExtraError::Invalid);
            }
            times = Some(NtfsTimes { mtime: le_u64(body, 0)?, atime: le_u64(body, 8)?, ctime: le_u64(body, 16)? });
        }
        pos = end;
    }
    Ok(times)
}

/// FILETIME ticks between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Convert a FILETIME to (Unix seconds, nanoseconds). Exact for all inputs.
pub fn filetime_to_unix(filetime: u64) -> (i64, u32) {
    let ticks = filetime as i128 - FILETIME_UNIX_EPOCH as i128;
    let secs = ticks.div_euclid(10_000_000);
    let rem = ticks.rem_euclid(10_000_000);
    (secs as i64, (rem as u32) * 100)
}

// ---------------------------------------------------------------- 0x9901

/// WinZip AES encryption record (0x9901).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesInfo {
    /// 1 = AE-1 (CRC stored), 2 = AE-2 (CRC zeroed).
    pub vendor_version: u16,
    /// 1, 2, 3 = 128, 192, 256-bit keys.
    pub strength: u8,
    /// Compression method applied before encryption.
    pub actual_method: u16,
}

impl AesInfo {
    pub fn key_bits(&self) -> u16 {
        match self.strength {
            1 => 128,
            2 => 192,
            _ => 256,
        }
    }
}

/// Parse a 0x9901 payload.
pub fn parse_aes(data: &[u8]) -> Result<AesInfo, ExtraError> {
    if data.len() < 7 {
        return Err(ExtraError::Truncated);
    }
    if data.len() != 7 {
        return Err(ExtraError::Invalid);
    }
    let vendor_version = le_u16(data, 0)?;
    if &data[2..4] != b"AE" {
        return Err(ExtraError::Invalid);
    }
    if vendor_version != 1 && vendor_version != 2 {
        return Err(ExtraError::Unsupported);
    }
    let strength = data[4];
    if !(1..=3).contains(&strength) {
        return Err(ExtraError::Invalid);
    }
    let actual_method = le_u16(data, 5)?;
    Ok(AesInfo { vendor_version, strength, actual_method })
}
