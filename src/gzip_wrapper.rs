// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::crc32;
use crate::inflate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipError {
    UnexpectedEof,
    InvalidHeader,
    UnsupportedMethod,
    InvalidData,
    ChecksumMismatch,
    SizeMismatch,
    LimitExceeded,
    Allocation,
    TrailingData,
}

pub fn decode_gzip(input: &[u8], max_output: usize, max_blocks: usize) -> Result<Vec<u8>, GzipError> {
    if input.len() < 10 {
        return Err(GzipError::UnexpectedEof);
    }

    // Magic
    if input[0] != 0x1f || input[1] != 0x8b {
        return Err(GzipError::InvalidHeader);
    }

    // CM
    if input[2] != 8 {
        return Err(GzipError::UnsupportedMethod);
    }

    // FLG reserved bits
    if input[3] & 0xe0 != 0 {
        return Err(GzipError::InvalidHeader);
    }

    let mut pos: usize = 10;
    let len = input.len();

    if len < 18 {
        return Err(GzipError::UnexpectedEof);
    }

    let trailer_start = len - 8;

    let fextra = input[3] & 0x04 != 0;
    let fname = input[3] & 0x08 != 0;
    let fcomment = input[3] & 0x10 != 0;
    let fhcrc = input[3] & 0x02 != 0;

    // FEXTRA
    if fextra {
        let next_pos = pos.checked_add(2).ok_or(GzipError::LimitExceeded)?;
        if next_pos > 65536 {
            return Err(GzipError::LimitExceeded);
        }
        if next_pos > trailer_start {
            return Err(GzipError::UnexpectedEof);
        }
        let xlen = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
        let after_xlen = next_pos.checked_add(xlen).ok_or(GzipError::LimitExceeded)?;
        if after_xlen > 65536 {
            return Err(GzipError::LimitExceeded);
        }
        if after_xlen > trailer_start {
            return Err(GzipError::UnexpectedEof);
        }
        pos = after_xlen;
    }

    // FNAME
    if fname {
        loop {
            let next_pos = pos.checked_add(1).ok_or(GzipError::LimitExceeded)?;
            if next_pos > 65536 {
                return Err(GzipError::LimitExceeded);
            }
            if next_pos > trailer_start {
                return Err(GzipError::UnexpectedEof);
            }
            if input[pos] == 0 {
                pos = next_pos;
                break;
            }
            pos = next_pos;
        }
    }

    // FCOMMENT
    if fcomment {
        loop {
            let next_pos = pos.checked_add(1).ok_or(GzipError::LimitExceeded)?;
            if next_pos > 65536 {
                return Err(GzipError::LimitExceeded);
            }
            if next_pos > trailer_start {
                return Err(GzipError::UnexpectedEof);
            }
            if input[pos] == 0 {
                pos = next_pos;
                break;
            }
            pos = next_pos;
        }
    }

    // FHCRC
    let mut header_crc = 0u32;
    if fhcrc {
        let next_pos = pos.checked_add(2).ok_or(GzipError::LimitExceeded)?;
        if next_pos > 65536 {
            return Err(GzipError::LimitExceeded);
        }
        if next_pos > trailer_start {
            return Err(GzipError::UnexpectedEof);
        }
        let crc_bytes = [input[pos], input[pos + 1]];
        pos = next_pos;
        header_crc = u16::from_le_bytes(crc_bytes) as u32;
    }

    // Compute header CRC if FHCRC was set
    if fhcrc {
        let computed = crc32::crc32(&input[..pos - 2]);
        if (computed & 0xffff) != header_crc {
            return Err(GzipError::ChecksumMismatch);
        }
    }

    // Inflate
    let body = &input[pos..trailer_start];
    let output = inflate::inflate_raw(body, max_output, max_blocks).map_err(|e| match e {
        inflate::InflateError::UnexpectedEof => GzipError::UnexpectedEof,
        inflate::InflateError::InvalidData => GzipError::InvalidData,
        inflate::InflateError::UnsupportedBlock => GzipError::InvalidData,
        inflate::InflateError::LimitExceeded => GzipError::LimitExceeded,
        inflate::InflateError::Allocation => GzipError::Allocation,
        inflate::InflateError::TrailingData => GzipError::TrailingData,
    })?;

    // Check trailer
    let crc_expected = u32::from_le_bytes([input[trailer_start], input[trailer_start + 1], input[trailer_start + 2], input[trailer_start + 3]]);
    let isize_expected = u32::from_le_bytes([input[trailer_start + 4], input[trailer_start + 5], input[trailer_start + 6], input[trailer_start + 7]]);

    let crc_actual = crc32::crc32(&output);
    if crc_actual != crc_expected {
        return Err(GzipError::ChecksumMismatch);
    }

    let isize_actual = output.len() as u32;
    if isize_actual != isize_expected {
        return Err(GzipError::SizeMismatch);
    }

    Ok(output)
}