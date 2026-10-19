// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::adler32::adler32;
use crate::deflate_encode::encode_stored;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZlibEncodeError {
    LimitExceeded,
    Allocation,
}

pub fn encode_zlib(input: &[u8], max_output: usize, max_blocks: usize) -> Result<Vec<u8>, ZlibEncodeError> {
    // Header is 2 bytes: 78 01
    // Trailer is 4 bytes: Adler32 checksum
    // Total overhead: 6 bytes
    let overhead = 6;

    // Check if max_output is sufficient for overhead
    let raw_cap = max_output.checked_sub(overhead).ok_or(ZlibEncodeError::LimitExceeded)?;

    // Encode the raw DEFLATE data
    // This function handles chunking (max 65535 bytes per chunk) and BFINAL
    let raw_data = encode_stored(input, raw_cap, max_blocks)
        .map_err(|e| match e {
            crate::deflate_encode::EncodeError::LimitExceeded => ZlibEncodeError::LimitExceeded,
            crate::deflate_encode::EncodeError::Allocation => ZlibEncodeError::Allocation,
        })?;

    // Calculate total size: header + raw_data + trailer
    let total_size = overhead
        .checked_add(raw_data.len())
        .ok_or(ZlibEncodeError::LimitExceeded)?;

    // Check against max_output limit
    if total_size > max_output {
        return Err(ZlibEncodeError::LimitExceeded);
    }

    // Allocate the final buffer
    let mut output = Vec::new();
    output.try_reserve_exact(total_size)
        .map_err(|_| ZlibEncodeError::Allocation)?;

    // Append fixed header: 78 01
    output.push(0x78);
    output.push(0x01);

    // Append raw DEFLATE data
    output.extend_from_slice(&raw_data);

    // Compute Adler32 checksum of the original input
    let checksum = adler32(input);

    // Append checksum as 4 big-endian bytes
    output.push((checksum >> 24) as u8);
    output.push((checksum >> 16) as u8);
    output.push((checksum >> 8) as u8);
    output.push(checksum as u8);

    Ok(output)
}