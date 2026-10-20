//! Android sparse image (simg) header parse + expand to raw.
//!
//! Spec: AOSP `system/core/libsparse/sparse_format.h`, with the strictness
//! 7-Zip 26.04 applies (probed). All integers little-endian.

/// Android sparse image magic number.
pub const SPARSE_MAGIC: u32 = 0xED26_FF3A;

/// Chunk type: RAW (data follows).
pub const CHUNK_RAW: u16 = 0xCAC1;
/// Chunk type: FILL (4-byte fill value follows).
pub const CHUNK_FILL: u16 = 0xCAC2;
/// Chunk type: DONT_CARE (no data, output zeroes).
pub const CHUNK_DONT_CARE: u16 = 0xCAC3;
/// Chunk type: CRC32 (4-byte CRC follows, output is zeros).
pub const CHUNK_CRC32: u16 = 0xCAC4;

/// Error type for sparse image operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseError {
    Truncated,
    BadMagic,
    Unsupported,
    BadHeader,
    BadChunk,
    BadLength,
    LimitExceeded,
}

/// Parsed sparse image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseHeader {
    pub major: u16,
    pub minor: u16,
    pub blk_sz: u32,
    pub total_blks: u32,
    pub total_chunks: u32,
    pub image_checksum: u32,
}

// ── helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parse the sparse image file header.
///
/// Steps (in order):
/// 1. `data.len() < 4` → Truncated; magic != SPARSE_MAGIC → BadMagic;
///    `data.len() < 28` → Truncated.
/// 2. `major != 1` → Unsupported.
/// 3. `file_hdr_sz != 28` or `chunk_hdr_sz != 12` → BadHeader.
/// 4. `blk_sz < 4` or not a power of two → BadHeader.
pub fn parse_header(data: &[u8]) -> Result<SparseHeader, SparseError> {
    if data.len() < 4 {
        return Err(SparseError::Truncated);
    }
    let magic = rd_u32(data, 0);
    if magic != SPARSE_MAGIC {
        return Err(SparseError::BadMagic);
    }
    if data.len() < 28 {
        return Err(SparseError::Truncated);
    }

    let major = rd_u16(data, 4);
    if major != 1 {
        return Err(SparseError::Unsupported);
    }

    let file_hdr_sz = rd_u16(data, 8);
    let chunk_hdr_sz = rd_u16(data, 10);
    if file_hdr_sz != 28 || chunk_hdr_sz != 12 {
        return Err(SparseError::BadHeader);
    }

    let blk_sz = rd_u32(data, 12);
    if blk_sz < 4 || !blk_sz.is_power_of_two() {
        return Err(SparseError::BadHeader);
    }

    let total_blks = rd_u32(data, 16);
    let total_chunks = rd_u32(data, 20);
    let image_checksum = rd_u32(data, 24);

    Ok(SparseHeader {
        major,
        minor: rd_u16(data, 6),
        blk_sz,
        total_blks,
        total_chunks,
        image_checksum,
    })
}

/// Expand a sparse image to its raw form.
///
/// Returns the raw bytes, or an error.  `max_output` caps the output size.
pub fn expand(data: &[u8], max_output: usize) -> Result<Vec<u8>, SparseError> {
    let h = parse_header(data)?;

    // Compute output size, check against max_output before allocating.
    let output_size = (h.total_blks as u64) * (h.blk_sz as u64);
    let output_size_usize = output_size as usize;
    if output_size as usize != output_size_usize || output_size_usize > max_output {
        return Err(SparseError::LimitExceeded);
    }

    // Allocate with try_reserve so we can catch allocation failure as LimitExceeded.
    let mut out = Vec::new();
    if output_size_usize > 0 {
        out.try_reserve(output_size_usize).map_err(|_| SparseError::LimitExceeded)?;
        out.resize(output_size_usize, 0);
    }

    // Process chunks starting at offset 28.
    let mut pos = 28usize;
    let total_chunks = h.total_chunks as usize;
    let blk_sz = h.blk_sz as usize;
    let mut blocks_emitted: u32 = 0;

    for _ in 0..total_chunks {
        // Need 12 bytes for chunk header.
        if pos + 12 > data.len() {
            return Err(SparseError::Truncated);
        }

        let chunk_type = rd_u16(data, pos);
        let _reserved = rd_u16(data, pos + 2);
        let chunk_sz = rd_u32(data, pos + 4);   // output blocks
        let total_sz = rd_u32(data, pos + 8);   // bytes of this chunk incl header

        // Validate total_sz based on chunk type.
        match chunk_type {
            CHUNK_RAW => {
                let expected = 12u64 + (chunk_sz as u64) * (blk_sz as u64);
                if total_sz as u64 != expected {
                    return Err(SparseError::BadChunk);
                }
            }
            CHUNK_FILL => {
                if total_sz != 16 {
                    return Err(SparseError::BadChunk);
                }
            }
            CHUNK_DONT_CARE => {
                if total_sz != 12 {
                    return Err(SparseError::BadChunk);
                }
            }
            CHUNK_CRC32 => {
                if chunk_sz != 0 || total_sz != 16 {
                    return Err(SparseError::BadChunk);
                }
            }
            _ => {
                return Err(SparseError::BadChunk);
            }
        }

        // Check blocks emitted + chunk_sz <= total_blks.
        if blocks_emitted + chunk_sz > h.total_blks {
            return Err(SparseError::BadLength);
        }

        // Payload bytes = total_sz - 12.
        let payload_len = (total_sz as usize) - 12;
        if pos + 12 + payload_len > data.len() {
            return Err(SparseError::Truncated);
        }

        let payload_start = pos + 12;
        let blocks_to_emit = chunk_sz as usize;

        match chunk_type {
            CHUNK_RAW => {
                let dst_start = (blocks_emitted as usize) * blk_sz;
                let dst_end = dst_start + (blocks_to_emit * blk_sz);
                out[dst_start..dst_end]
                    .copy_from_slice(&data[payload_start..payload_start + payload_len]);
            }
            CHUNK_FILL => {
                // 4-byte fill value repeated.
                let fill_val = &data[payload_start..payload_start + 4];
                let dst_start = (blocks_emitted as usize) * blk_sz;
                let dst_end = dst_start + (blocks_to_emit * blk_sz);
                let count = (blocks_to_emit * blk_sz) / 4;
                for i in 0..count {
                    let off = dst_start + i * 4;
                    out[off..off + 4].copy_from_slice(fill_val);
                }
            }
            CHUNK_DONT_CARE => {
                // Already zeroed from resize.
            }
            CHUNK_CRC32 => {
                // Emit nothing (CRC value is not verified).
            }
            _ => unreachable!(),
        }

        blocks_emitted += chunk_sz;
        pos += total_sz as usize;
    }

    // After all chunks, blocks emitted must equal total_blks.
    if blocks_emitted != h.total_blks {
        return Err(SparseError::BadLength);
    }

    Ok(out)
}
