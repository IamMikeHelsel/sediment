// SPDX-License-Identifier: MIT OR Apache-2.0

use std::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    LimitExceeded,
    Allocation,
}

pub fn encode_stored(
    input: &[u8],
    max_output: usize,
    max_blocks: usize,
) -> Result<Vec<u8>, EncodeError> {
    if max_blocks == 0 {
        return Err(EncodeError::LimitExceeded);
    }

    let input_len = input.len();

    // Calculate number of blocks
    // Required blockcount = max(1, ceil(input.len() / 65535))
    let block_count = if input_len == 0 {
        1
    } else {
        let chunks = input_len.div_ceil(65535);
        if chunks > max_blocks {
            return Err(EncodeError::LimitExceeded);
        }
        chunks
    };

    // Calculate required output size
    // Each block adds 5 bytes overhead (1 header + 2 LEN + 2 NLEN)
    // Total = input_len + 5 * block_count
    let required_bytes = block_count.checked_mul(5).and_then(|o| o.checked_add(input_len)).ok_or(EncodeError::LimitExceeded)?;

    if required_bytes > max_output {
        return Err(EncodeError::LimitExceeded);
    }

    // Reserve memory
    let mut output = Vec::new();
    if output.try_reserve_exact(required_bytes).is_err() {
        return Err(EncodeError::Allocation);
    }

    if input_len == 0 {
        // Empty input emits exactly one empty final block: [1, 0, 0, 255, 255]
        output.extend_from_slice(&[1u8, 0, 0, 255, 255]);
        return Ok(output);
    }

    // Process chunks
    let mut offset = 0;
    let mut block_idx = 0;

    while offset < input_len {
        let is_last = (offset + 65535 >= input_len) || (block_idx == block_count - 1);
        let chunk_size = if is_last {
            input_len - offset
        } else {
            65535
        };

        // BFINAL: 1 if last block, 0 otherwise
        // BTYPE: 00 (stored)
        // Header byte: (BFINAL << 7) | (BTYPE << 5) | 0
        let bfinal = if is_last { 1u8 } else { 0 };
        let header = bfinal | (0 << 5);

        // LEN: chunk_size as u16 (little-endian)
        // NLEN: bitwise NOT LEN as u16 (little-endian)
        let len_val = chunk_size as u16;
        let nlen_val = (!len_val) as u16;

        // Write header
        output.push(header);

        // Write LEN (little-endian)
        output.extend_from_slice(&len_val.to_le_bytes());

        // Write NLEN (little-endian)
        output.extend_from_slice(&nlen_val.to_le_bytes());

        // Write chunk data
        output.extend_from_slice(&input[offset..offset + chunk_size]);

        offset += chunk_size;
        block_idx += 1;
    }

    Ok(output)
}