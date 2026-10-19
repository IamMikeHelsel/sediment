// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::inflate::{inflate_raw, InflateError};
use crate::adler32::adler32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZlibError {
    UnexpectedEof,
    InvalidHeader,
    UnsupportedDictionary,
    InvalidData,
    ChecksumMismatch,
    LimitExceeded,
    Allocation,
    TrailingData,
}

pub fn decode_zlib(input: &[u8], max_output: usize, max_blocks: usize) -> Result<Vec<u8>, ZlibError> {
    if input.len() < 2 {
        return Err(ZlibError::UnexpectedEof);
    }

    let cmf = input[0];
    let flg = input[1];

    let cm = cmf & 0x0F;
    let cinfo = (cmf >> 4) & 0x0F;

    if cm != 8 {
        return Err(ZlibError::InvalidHeader);
    }
    if cinfo > 7 {
        return Err(ZlibError::InvalidHeader);
    }

    if (u16::from_be_bytes([cmf, flg]) % 31) != 0 {
        return Err(ZlibError::InvalidHeader);
    }

    if flg & 0x20 != 0 {
        return Err(ZlibError::UnsupportedDictionary);
    }

    if input.len() < 6 {
        return Err(ZlibError::UnexpectedEof);
    }

    let len = input.len();
    let adler_trailer = ((input[len - 4] as u32) << 24)
        | ((input[len - 3] as u32) << 16)
        | ((input[len - 2] as u32) << 8)
        | (input[len - 1] as u32);

    let raw_input = &input[2..len - 4];

    let output = match inflate_raw(raw_input, max_output, max_blocks) {
        Ok(data) => data,
        Err(InflateError::UnexpectedEof) => return Err(ZlibError::UnexpectedEof),
        Err(InflateError::LimitExceeded) => return Err(ZlibError::LimitExceeded),
        Err(InflateError::Allocation) => return Err(ZlibError::Allocation),
        Err(InflateError::TrailingData) => return Err(ZlibError::TrailingData),
        Err(InflateError::InvalidData) => return Err(ZlibError::InvalidData),
        Err(InflateError::UnsupportedBlock) => return Err(ZlibError::InvalidData),
    };

    let computed_adler = adler32(&output);
    if computed_adler != adler_trailer {
        return Err(ZlibError::ChecksumMismatch);
    }

    Ok(output)
}