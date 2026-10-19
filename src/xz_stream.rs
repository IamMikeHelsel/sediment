// SPDX-License-Identifier: MIT OR Apache-2.0

use core::result::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    None,
    Crc32,
    Crc64,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFlags {
    pub check: CheckId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFooter {
    pub flags: StreamFlags,
    pub index_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XzStreamError {
    UnexpectedEof,
    TrailingData,
    InvalidMagic,
    ChecksumMismatch,
    Unsupported,
    LimitExceeded,
    FlagsMismatch,
}

pub fn parse_header(bytes: &[u8]) -> Result<StreamFlags, XzStreamError> {
    parse_endpoint(bytes, true)
}

pub fn parse_footer(bytes: &[u8], max_index_bytes: u64) -> Result<StreamFooter, XzStreamError> {
    if bytes.len() < 12 {
        return Err(XzStreamError::UnexpectedEof);
    }
    if bytes.len() > 12 {
        return Err(XzStreamError::TrailingData);
    }
    
    // Magic check
    if bytes[10..12] != [0x59, 0x5a] {
        return Err(XzStreamError::InvalidMagic);
    }
    
    // CRC check
    let crc_data = &bytes[4..10];
    let stored_crc = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let calc_crc = crate::crc32::crc32(crc_data);
    if stored_crc != calc_crc {
        return Err(XzStreamError::ChecksumMismatch);
    }
    
    // Backward Size
    let bs_bytes = [bytes[4], bytes[5], bytes[6], bytes[7], 0, 0, 0, 0];
    let bs_val = u64::from_le_bytes(bs_bytes);
    let index_bytes = bs_val.checked_add(1).and_then(|v| v.checked_mul(4)).ok_or(XzStreamError::LimitExceeded)?;
    
    // Flags check
    let flags_bytes = [bytes[8], bytes[9]];
    let flags = parse_flags_bytes(&flags_bytes)?;
    
    // Limit check
    if index_bytes > max_index_bytes {
        return Err(XzStreamError::LimitExceeded);
    }
    
    Ok(StreamFooter {
        flags,
        index_bytes,
    })
}

pub fn validate_pair(header: &[u8], footer: &[u8], max_index_bytes: u64) -> Result<StreamFooter, XzStreamError> {
    let hdr_flags = parse_header(header)?;
    let footer_res = parse_footer(footer, max_index_bytes)?;
    if hdr_flags.check != footer_res.flags.check {
        return Err(XzStreamError::FlagsMismatch);
    }
    Ok(footer_res)
}

fn parse_flags_bytes(bytes: &[u8; 2]) -> Result<StreamFlags, XzStreamError> {
    if bytes[0] != 0 {
        return Err(XzStreamError::Unsupported);
    }
    if bytes[1] & 0xF0 != 0 {
        return Err(XzStreamError::Unsupported);
    }
    let check_id = bytes[1];
    let check = match check_id {
        0 => CheckId::None,
        1 => CheckId::Crc32,
        4 => CheckId::Crc64,
        10 => CheckId::Sha256,
        _ => return Err(XzStreamError::Unsupported),
    };
    Ok(StreamFlags { check })
}

fn parse_endpoint(bytes: &[u8], is_header: bool) -> Result<StreamFlags, XzStreamError> {
    if bytes.len() < 12 {
        return Err(XzStreamError::UnexpectedEof);
    }
    if bytes.len() > 12 {
        return Err(XzStreamError::TrailingData);
    }

    // Magic
    if is_header {
        if bytes[0..6] != [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0] {
            return Err(XzStreamError::InvalidMagic);
        }
    } else {
        if bytes[10..12] != [0x59, 0x5a] {
            return Err(XzStreamError::InvalidMagic);
        }
    }

    // CRC
    let crc_data = if is_header {
        &bytes[6..8]
    } else {
        &bytes[4..10]
    };
    let stored_crc = if is_header {
        u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let calc_crc = crate::crc32::crc32(crc_data);
    if stored_crc != calc_crc {
        return Err(XzStreamError::ChecksumMismatch);
    }

    // Flags
    let flags_bytes = if is_header {
        [bytes[6], bytes[7]]
    } else {
        [bytes[8], bytes[9]]
    };
    parse_flags_bytes(&flags_bytes)
}