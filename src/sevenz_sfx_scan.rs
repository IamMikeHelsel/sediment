// SPDX-License-Identifier: MIT OR Apache-2.0
//! Locate a 7z archive inside a larger byte slice (self-extracting stub + archive).

use crate::crc32::crc32;

/// 7-Zip signature header bytes.
pub const SEVENZ_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Errors from next-header validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfxError {
    /// Truncated: the next-header range extends past the end of the data.
    Truncated,
    /// The next-header CRC does not match.
    BadNextHeaderCrc,
}

/// Parsed start-header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZStart {
    /// Byte offset of the signature within the input slice.
    pub offset: usize,
    /// NextHeaderOffset field (relative to `offset + 32`).
    pub next_header_offset: u64,
    /// NextHeaderSize field.
    pub next_header_size: u64,
    /// NextHeaderCRC field.
    pub next_header_crc: u32,
}

/// Parse a SignatureHeader at the given position.
///
/// Returns `Some` iff:
/// * `pos + 32 <= data.len()` (checked add),
/// * `data[pos..pos+6] == SEVENZ_SIGNATURE`,
/// * CRC-32 of bytes `[pos+12..pos+32]` equals the LE u32 at `pos+8`.
pub fn start_header_at(data: &[u8], pos: usize) -> Option<SevenZStart> {
    let end = (pos as u64).checked_add(32)? as usize;
    if end > data.len() {
        return None;
    }
    if data[pos..pos + 6] != SEVENZ_SIGNATURE {
        return None;
    }
    let stored_crc = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
    let computed = crc32(&data[pos + 12..pos + 32]);
    if computed != stored_crc {
        return None;
    }
    let next_header_offset = u64::from_le_bytes(data[pos + 12..pos + 20].try_into().unwrap());
    let next_header_size = u64::from_le_bytes(data[pos + 20..pos + 28].try_into().unwrap());
    let next_header_crc = u32::from_le_bytes(data[pos + 28..pos + 32].try_into().unwrap());
    Some(SevenZStart {
        offset: pos,
        next_header_offset,
        next_header_size,
        next_header_crc,
    })
}

/// Scan `data` from byte 0 up to `max_offset` (inclusive) for the first valid
/// SignatureHeader.  Returns `None` if none is found.
///
/// Handles `max_offset == usize::MAX` correctly by also requiring `pos + 32 <= data.len()`.
pub fn find_7z_start(data: &[u8], max_offset: usize) -> Option<SevenZStart> {
    if data.len() < 32 {
        return None;
    }
    let limit = data.len() - 32;
    let max_pos = if max_offset < limit { max_offset } else { limit };
    for pos in 0..=max_pos {
        // Cheap first-byte check before CRC
        if data[pos] == SEVENZ_SIGNATURE[0] {
            if let Some(s) = start_header_at(data, pos) {
                return Some(s);
            }
        }
    }
    None
}

/// Validate the next-header range and CRC.
///
/// * `begin = start.offset + 32 + next_header_offset` (checked u64 add)
/// * `end = begin + next_header_size` (checked u64 add)
/// * Overflow or `end > data.len()` → `Truncated`
/// * CRC mismatch → `BadNextHeaderCrc`
/// * Empty archive (size 0, CRC 0) passes.
pub fn check_next_header(data: &[u8], start: &SevenZStart) -> Result<(), SfxError> {
    let begin_u64 = (start.offset as u64).checked_add(32).ok_or(SfxError::Truncated)?;
    let begin_u64 = begin_u64.checked_add(start.next_header_offset).ok_or(SfxError::Truncated)?;
    let begin = begin_u64 as usize;
    let end_u64 = begin_u64.checked_add(start.next_header_size).ok_or(SfxError::Truncated)?;
    let end = end_u64 as usize;
    if end > data.len() {
        return Err(SfxError::Truncated);
    }
    if start.next_header_size > 0 {
        let computed = crc32(&data[begin..end]);
        if computed != start.next_header_crc {
            return Err(SfxError::BadNextHeaderCrc);
        }
    }
    Ok(())
}
