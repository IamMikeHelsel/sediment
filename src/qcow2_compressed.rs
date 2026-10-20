//! qcow2 compressed cluster descriptor parse + raw-deflate cluster decode (standalone leaf).
//!
//! Spec: QEMU `docs/interop/qcow2.txt` ("Compressed Clusters Descriptor");
//! RFC 1951 for the payload (raw deflate, compression_type 0 = zlib).

use crate::inflate::{inflate_raw_prefix, InflateError};

/// Errors returned by compressed-cluster operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qcow2CompError {
    BadClusterBits,
    NotCompressed,
    BadEntry,
    OutOfRange,
    Corrupt,
    SizeMismatch,
}

/// Decoded cluster descriptor from an L2 table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedCluster {
    /// Byte offset in the image where the compressed data starts.
    pub host_offset: u64,
    /// Additional 512-byte sectors after the one containing host_offset.
    pub extra_sectors: u64,
    /// Total compressed length in bytes.
    pub compressed_len: u64,
}

/// Parse a compressed-cluster L2 entry.
///
/// Checks (in order):
/// 1. `cluster_bits` outside `9..=21` → `BadClusterBits`
/// 2. Bit 62 clear → `NotCompressed`
/// 3. Bit 63 (COPIED) set → `BadEntry`
/// 4. Extract `host_offset` and `extra_sectors` from bit fields
/// 5. Compute `compressed_len`
pub fn parse_compressed_entry(
    l2_entry: u64,
    cluster_bits: u32,
) -> Result<CompressedCluster, Qcow2CompError> {
    // 1. cluster_bits validation
    if !(9..=21).contains(&cluster_bits) {
        return Err(Qcow2CompError::BadClusterBits);
    }

    // 2. Bit 62 must be set (compressed flag)
    if l2_entry & (1u64 << 62) == 0 {
        return Err(Qcow2CompError::NotCompressed);
    }

    // 3. Bit 63 (COPIED) must be 0 for compressed clusters
    if l2_entry & (1u64 << 63) != 0 {
        return Err(Qcow2CompError::BadEntry);
    }

    // 4. Compute x and extract fields
    //    x = 62 - (cluster_bits - 8) = 70 - cluster_bits
    let x = 62u32 - (cluster_bits - 8);

    // host_offset = bits 0..x  =>  l2_entry & ((1 << x) - 1)
    let host_offset = l2_entry & ((1u64 << x) - 1);

    // extra_sectors = bits x..62  =>  (l2_entry >> x) & ((1 << (62 - x)) - 1)
    let extra_sectors = (l2_entry >> x) & ((1u64 << (62 - x)) - 1);

    // 5. compressed_len = (extra_sectors + 1) * 512 - (host_offset % 512)
    let compressed_len = (extra_sectors + 1) * 512 - (host_offset % 512);

    Ok(CompressedCluster {
        host_offset,
        extra_sectors,
        compressed_len,
    })
}

/// Read and decompress one compressed cluster from the image.
///
/// 1. Parse the entry (errors pass through).
/// 2. Validate host_offset is within image bounds, clamp range end.
/// 3. Inflate the raw deflate stream.
/// 4. Verify output is exactly cluster_size bytes.
pub fn read_compressed_cluster(
    image: &[u8],
    l2_entry: u64,
    cluster_bits: u32,
) -> Result<Vec<u8>, Qcow2CompError> {
    // 1. Parse the entry
    let desc = parse_compressed_entry(l2_entry, cluster_bits)?;

    // 2. host_offset must be within image
    let host_off = desc.host_offset as usize;
    if host_off >= image.len() {
        return Err(Qcow2CompError::OutOfRange);
    }

    let compressed_end = host_off + desc.compressed_len as usize;
    // Clamp the end to image.len() (last cluster may not be sector-padded)
    let clamped_end = compressed_end.min(image.len());
    let range = &image[host_off..clamped_end];

    // 3. Inflate
    let cluster_size = 1usize << cluster_bits;
    let (output, _consumed) = inflate_raw_prefix(range, cluster_size, 1 << 16)
        .map_err(|e| match e {
            InflateError::LimitExceeded => Qcow2CompError::SizeMismatch,
            _ => Qcow2CompError::Corrupt,
        })?;

    // 4. Output must be exactly cluster_size bytes
    if output.len() != cluster_size {
        return Err(Qcow2CompError::SizeMismatch);
    }

    Ok(output)
}
