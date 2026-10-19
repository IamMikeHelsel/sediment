// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::crc32::crc32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    UnexpectedEof,
    InvalidSignature,
    UnsupportedVersion,
    ChecksumMismatch,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartHeader<'a> {
    pub next_header_offset: u64,
    pub next_header_size: u64,
    pub next_header_crc: u32,
    pub next_header: &'a [u8],
}

pub fn parse_start_header<'a>(bytes: &'a [u8], max_archive_bytes: usize) -> Result<StartHeader<'a>, StartError> {
    if bytes.len() > max_archive_bytes {
        return Err(StartError::LimitExceeded);
    }
    if bytes.len() < 32 {
        return Err(StartError::UnexpectedEof);
    }

    const SIG: [u8; 6] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
    if bytes[0..6] != SIG {
        return Err(StartError::InvalidSignature);
    }

    if bytes[6] != 0 || bytes[7] != 4 {
        return Err(StartError::UnsupportedVersion);
    }

    let stored_crc = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let computed_crc = crc32(&bytes[12..32]);
    if stored_crc != computed_crc {
        return Err(StartError::ChecksumMismatch);
    }

    let next_header_offset = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let next_header_size = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    let next_header_crc = u32::from_le_bytes(bytes[28..32].try_into().unwrap());

    let abs_start = 32u64.checked_add(next_header_offset).ok_or(StartError::LimitExceeded)?;
    let end = abs_start.checked_add(next_header_size).ok_or(StartError::LimitExceeded)?;

    let end_usize = usize::try_from(end).map_err(|_| StartError::LimitExceeded)?;
    if end_usize > max_archive_bytes {
        return Err(StartError::LimitExceeded);
    }

    let bytes_len = bytes.len();
    if abs_start as usize > bytes_len || end_usize > bytes_len {
        return Err(StartError::UnexpectedEof);
    }

    let start_idx = abs_start as usize;
    let next_header = &bytes[start_idx..end_usize];

    Ok(StartHeader {
        next_header_offset,
        next_header_size,
        next_header_crc,
        next_header,
    })
}