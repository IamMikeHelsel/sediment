// SPDX-License-Identifier: MIT OR Apache-2.0

use std::result::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipEncodeError {
    LimitExceeded,
    Allocation,
}

// Assuming these are available in the crate scope as per instructions
// In a real file, these would be imports or module paths.
// Since we are implementing ONLY src/gzip_encode.rs, we assume
// the crate structure allows access to these modules or they are
// re-exported. For the purpose of this single-file implementation
// that compiles in the context of the project, we use the paths
// specified in the prompt.

// Helper to convert EncodeError to GzipEncodeError
fn map_encode_error(e: crate::deflate_encode::EncodeError) -> GzipEncodeError {
    match e {
        crate::deflate_encode::EncodeError::LimitExceeded => GzipEncodeError::LimitExceeded,
        crate::deflate_encode::EncodeError::Allocation => GzipEncodeError::Allocation,
    }
}

pub fn encode_gzip(input: &[u8], max_output: usize, max_blocks: usize) -> Result<Vec<u8>, GzipEncodeError> {
    // 1. Calculate required raw capacity
    // Header is 18 bytes. Trailer is 8 bytes (4 CRC + 4 ISIZE). Total overhead = 26 bytes.
    // However, the prompt says: "raw_cap=max_output.checked_sub(18)"
    // And "Entire wrapper length is raw.len()+18". This implies the 18 includes the trailer? 
    // Let's re-read carefully: "Fixed header hexadecimal 1f 8b 08 00 00 00 00 00 00 ff" (8 bytes)
    // "Append CRC32 ... as 4 bytes ... input.len() ... as 4 bytes" (8 bytes)
    // Total fixed overhead = 8 (header) + 8 (trailer) = 16 bytes? 
    // But the prompt explicitly says: "raw_cap=max_output.checked_sub(18)". 
    // And "Entire wrapper length is raw.len()+18". 
    // This suggests the "18" accounts for Header(8) + Trailer(8) + maybe 2 bytes for something else? 
    // Or perhaps the prompt considers the header 10 bytes? No, 1f 8b 08 00 00 00 00 00 00 ff is 10 bytes? 
    // 1f 8b (2) 08 (1) 00 (1) 00 00 00 00 (4) 00 (1) ff (1) = 10 bytes. 
    // Trailer: CRC32 (4) + ISIZE (4) = 8 bytes. 
    // Total = 18 bytes. Okay, so Header is 10 bytes, Trailer is 8 bytes. 
    // The prompt says "Fixed header hexadecimal 1f 8b 08 00 00 00 00 00 00 ff". 
    // Let's count: 1f, 8b, 08, 00, 00, 00, 00, 00, 00, ff. That is 10 bytes. 
    // So overhead is 10 + 8 = 18 bytes. 
    
    let raw_cap = match max_output.checked_sub(18) {
        Some(cap) => cap,
        None => return Err(GzipEncodeError::LimitExceeded),
    };

    // 2. Encode DEFLATE STORED blocks
    let raw_data = crate::deflate_encode::encode_stored(input, raw_cap, max_blocks)
        .map_err(map_encode_error)?;

    // 3. Check total size before allocation
    let total_size = match raw_data.len().checked_add(18) {
        Some(size) => size,
        None => return Err(GzipEncodeError::LimitExceeded),
    };

    if total_size > max_output {
        return Err(GzipEncodeError::LimitExceeded);
    }

    // 4. Allocate output buffer
    let mut output = Vec::new();
    if let Err(_) = output.try_reserve(total_size) {
        return Err(GzipEncodeError::Allocation);
    }

    // 5. Build Header
    // 1f 8b 08 00 00 00 00 00 00 ff
    let header = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
    output.extend_from_slice(&header);

    // 6. Append Raw Data
    output.extend_from_slice(&raw_data);

    // 7. Compute CRC32 of original input
    let crc = crate::crc32::crc32(input);
    let crc_bytes = crc.to_le_bytes();
    output.extend_from_slice(&crc_bytes);

    // 8. Compute ISIZE (input length mod 2^32)
    let isize_val = input.len() as u32; // input.len() is usize, cast to u32 is safe for mod 2^32
    let isize_bytes = isize_val.to_le_bytes();
    output.extend_from_slice(&isize_bytes);

    // 9. Verify size
    debug_assert_eq!(output.len(), total_size);

    Ok(output)
}