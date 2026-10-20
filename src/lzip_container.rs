// SPDX-License-Identifier: MIT OR Apache-512
//! lzip (`.lz`) container format: member header/trailer + multi-member decode.
//!
//! Spec: [lzip manual, section "File format"](https://www.nongnu.org/lzip/lzip.html)

use crate::crc32::crc32;
use crate::lzma_decode::{decode_lzma_raw, LzmaError};
use crate::lzma_properties::LzmaProperties;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzipError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    BadDictSize,
    Corrupt,
    CrcMismatch,
    SizeMismatch,
    TrailingData,
    LimitExceeded,
}

// ── Member metadata ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzipMember {
    pub dict_size: u32,
    pub crc32: u32,
    pub data_size: u64,
    pub member_size: u64,
}

// ── Constants ─────────────────────────────────────────────────────────────────

const MAGIC: &[u8; 4] = b"LZIP";
const HEADER_SIZE: usize = 6; // magic(4) + version(1) + dict_size(1)
const TRAILER_SIZE: usize = 20; // crc32(4) + data_size(8) + member_size(8)
const VERSION: u8 = 1;
const MAX_DICT: u64 = 512 * 1024 * 1024; // 512 MiB

// ── decode_dict_size ──────────────────────────────────────────────────────────

/// Decode the coded dictionary-size byte per the lzip spec.
///
/// `e = ds & 0x1F`, `frac = ds >> 5`.
/// `base = 1 << e`, `size = base - (base / 16) * frac`.
/// Valid only when `12 <= e <= 29` and `4096 <= size <= 512 MiB`.
pub fn decode_dict_size(ds: u8) -> Result<u32, LzipError> {
    let e = (ds & 0x1F) as u32;
    let frac = (ds >> 5) as u32;
    if e < 12 || e > 29 {
        return Err(LzipError::BadDictSize);
    }
    let base = 1u32 << e;
    let size = base - (base / 16) * frac;
    if size < 4096 || size > 512 * 1024 * 1024 {
        return Err(LzipError::BadDictSize);
    }
    Ok(size)
}

// ── decode_member ─────────────────────────────────────────────────────────────

/// Decode a single lzip member from the start of `input`.
///
/// Returns `(decompressed_data, member_info)` on success.
pub fn decode_member(
    input: &[u8],
    max_dictionary: u64,
    max_output: usize,
) -> Result<(Vec<u8>, LzipMember), LzipError> {
    // 1. Header validation
    if input.len() < HEADER_SIZE {
        return Err(LzipError::Truncated);
    }
    if &input[0..4] != MAGIC {
        return Err(LzipError::BadMagic);
    }
    if input[4] != VERSION {
        return Err(LzipError::UnsupportedVersion);
    }
    let dict_size = decode_dict_size(input[5])?;
    if dict_size as u64 > max_dictionary {
        return Err(LzipError::LimitExceeded);
    }

    // 2. LZMA decode
    let props = LzmaProperties {
        lc: 3,
        lp: 0,
        pb: 2,
        dictionary_size: dict_size,
    };
    let (data, used) = match decode_lzma_raw(&input[HEADER_SIZE..], props, None, max_dictionary, max_output) {
        Ok(result) => result,
        Err(LzmaError::UnexpectedEof) => return Err(LzipError::Truncated),
        Err(LzmaError::LimitExceeded | LzmaError::Allocation) => return Err(LzipError::LimitExceeded),
        Err(_) => return Err(LzipError::Corrupt),
    };

    // 3. Trailer check
    let trailer_start = HEADER_SIZE + used;
    if input.len() < trailer_start + TRAILER_SIZE {
        return Err(LzipError::Truncated);
    }

    // 4. Parse and validate trailer
    let stored_crc = u32::from_le_bytes([
        input[trailer_start],
        input[trailer_start + 1],
        input[trailer_start + 2],
        input[trailer_start + 3],
    ]);
    let stored_data_size = u64::from_le_bytes([
        input[trailer_start + 4],
        input[trailer_start + 5],
        input[trailer_start + 6],
        input[trailer_start + 7],
        input[trailer_start + 8],
        input[trailer_start + 9],
        input[trailer_start + 10],
        input[trailer_start + 11],
    ]);
    let stored_member_size = u64::from_le_bytes([
        input[trailer_start + 12],
        input[trailer_start + 13],
        input[trailer_start + 14],
        input[trailer_start + 15],
        input[trailer_start + 16],
        input[trailer_start + 17],
        input[trailer_start + 18],
        input[trailer_start + 19],
    ]);

    let computed_crc = crc32(&data);
    if stored_crc != computed_crc {
        return Err(LzipError::CrcMismatch);
    }
    let data_len = data.len() as u64;
    if stored_data_size != data_len {
        return Err(LzipError::SizeMismatch);
    }
    let computed_member_size = HEADER_SIZE as u64 + used as u64 + TRAILER_SIZE as u64;
    if stored_member_size != computed_member_size {
        return Err(LzipError::SizeMismatch);
    }

    let member = LzipMember {
        dict_size,
        crc32: stored_crc,
        data_size: stored_data_size,
        member_size: stored_member_size,
    };

    Ok((data, member))
}

// ── decode_lzip (multi-member) ────────────────────────────────────────────────

/// Decode a multi-member lzip file.
///
/// Concatenates all members' decompressed data.
pub fn decode_lzip(input: &[u8], max_dictionary: u64, max_output: usize) -> Result<Vec<u8>, LzipError> {
    if input.is_empty() {
        return Err(LzipError::Truncated);
    }

    let mut out = Vec::new();
    let mut offset = 0;

    loop {
        if offset >= input.len() {
            break;
        }

        // Check if we have at least 4 bytes to check for magic
        if input.len() - offset < 4 {
            // Could be a non-empty prefix of "LZIP" -> Truncated
            // or trailing garbage -> TrailingData
            // Per spec: "a non-empty prefix of LZIP shorter than 4 bytes -> Truncated"
            return Err(LzipError::Truncated);
        }

        // Check if this looks like a new member
        if &input[offset..offset + 4] == MAGIC {
            // Try to decode this member
            let remaining = max_output.saturating_sub(out.len());
            let (data, member) = decode_member(&input[offset..], max_dictionary, remaining)?;
            out.extend_from_slice(&data);
            offset += member.member_size as usize;
        } else {
            // Not LZIP prefix -> trailing data
            return Err(LzipError::TrailingData);
        }
    }

    Ok(out)
}
