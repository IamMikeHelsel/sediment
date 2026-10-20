// SPDX-License-Identifier: MIT OR Apache-2.0
//! UEFI firmware-file section header parsing and section decoding.
//!
//! Handles EFI_COMMON_SECTION_HEADER / HEADER2, EFI_COMPRESSION_SECTION,
//! and EFI_GUID_DEFINED_SECTION (LZMA via EDK2 LzmaCustomDecompress GUID).

use crate::lzma_decode::{decode_lzma_alone, LzmaError};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionError {
    Truncated,
    BadSize,
    BadDataOffset,
    NotEncapsulation,
    Unsupported,
    LengthMismatch,
    Corrupt,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    pub section_type: u8,
    pub size: u32,
    pub header_len: usize,
}

/// EE4E5898-3914-4259-9D6E-DC7BD79403CF in on-disk (EFI_GUID, mixed-endian) byte order.
pub const LZMA_CUSTOM_DECOMPRESS_GUID: [u8; 16] =
    [0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF];

pub const MAX_LZMA_DICTIONARY: u64 = 1 << 26;

// ---------------------------------------------------------------------------
// parse_section_header
// ---------------------------------------------------------------------------

/// Parse one EFI_COMMON_SECTION_HEADER (or HEADER2) from `data`.
pub fn parse_section_header(data: &[u8]) -> Result<SectionHeader, SectionError> {
    if data.len() < 4 {
        return Err(SectionError::Truncated);
    }
    let size24 = u32::from_le_bytes([data[0], data[1], data[2], 0]);
    let section_type = data[3];

    let (size, header_len) = if size24 == 0x00FFFFFF {
        if data.len() < 8 {
            return Err(SectionError::Truncated);
        }
        let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        (size, 8)
    } else {
        (size24, 4)
    };

    if size < header_len as u32 {
        return Err(SectionError::BadSize);
    }

    Ok(SectionHeader { section_type, size, header_len })
}

// ---------------------------------------------------------------------------
// decode_section
// ---------------------------------------------------------------------------

/// Decode a single UEFI section.  Supports EFI_COMPRESSION_SECTION (uncompressed)
/// and EFI_GUID_DEFINED_SECTION with the LZMA custom decompress GUID.
pub fn decode_section(data: &[u8], max_output: usize) -> Result<Vec<u8>, SectionError> {
    let h = parse_section_header(data)?;

    // Truncated: the section claims more bytes than we have.
    if h.size > data.len() as u32 {
        return Err(SectionError::Truncated);
    }

    let sec = &data[..h.size as usize];

    match h.section_type {
        0x02 => {
            // EFI_SECTION_GUID_DEFINED
            if h.size < (h.header_len as u32 + 20) {
                return Err(SectionError::BadSize);
            }
            let guid_off = h.header_len;
            let guid = &sec[guid_off..guid_off + 16];
            if guid != LZMA_CUSTOM_DECOMPRESS_GUID {
                return Err(SectionError::Unsupported);
            }
            let data_offset = u16::from_le_bytes([sec[guid_off + 16], sec[guid_off + 17]]) as usize;
            // DataOffset counts from section start.
            if data_offset < h.header_len + 20 || data_offset > h.size as usize {
                return Err(SectionError::BadDataOffset);
            }
            let payload = &sec[data_offset..];
            match decode_lzma_alone(payload, MAX_LZMA_DICTIONARY, max_output) {
                Ok(out) => Ok(out),
                Err(LzmaError::LimitExceeded | LzmaError::Allocation) => Err(SectionError::LimitExceeded),
                Err(_) => Err(SectionError::Corrupt),
            }
        }
        0x01 => {
            // EFI_SECTION_COMPRESSION
            if h.size < (h.header_len as u32 + 5) {
                return Err(SectionError::BadSize);
            }
            let off = h.header_len;
            let uncompressed_len = u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]]) as usize;
            let compression_type = sec[off + 4];

            if compression_type != 0 {
                return Err(SectionError::Unsupported);
            }

            let payload = &sec[off + 5..];
            if uncompressed_len > max_output {
                return Err(SectionError::LimitExceeded);
            }
            if payload.len() != uncompressed_len {
                return Err(SectionError::LengthMismatch);
            }
            Ok(payload.to_vec())
        }
        _ => Err(SectionError::NotEncapsulation),
    }
}
