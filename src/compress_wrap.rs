// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-stream compression wrappers for tar archives (`.tar.gz` etc.).
//!
//! Spec source: RFC 1952 (gzip member format) over RFC 1951 DEFLATE.
//! Level 0 uses the existing stored-block `gzip_encode::encode_gzip`; levels
//! 1..=9 frame the compressing `deflate_compress` encoder in the same gzip
//! header (MTIME 0, OS 255) so output is deterministic. xz and bzip2 return
//! `Unsupported` until their encoders land.

use crate::crc32::crc32;
use crate::deflate_compress::{CompressError, deflate_bound, deflate_compress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapError {
    /// Format has no encoder yet (xz, bzip2).
    Unsupported,
    InvalidLevel,
    LimitExceeded,
    Allocation,
}

/// Compress `input` with `kind` at `level` (0..=9), producing at most `max_output` bytes.
pub fn compress(kind: Compression, input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, WrapError> {
    if level > 9 {
        return Err(WrapError::InvalidLevel);
    }
    match kind {
        Compression::None => {
            if input.len() > max_output {
                return Err(WrapError::LimitExceeded);
            }
            let mut v = Vec::new();
            v.try_reserve_exact(input.len()).map_err(|_| WrapError::Allocation)?;
            v.extend_from_slice(input);
            Ok(v)
        }
        Compression::Gzip => gzip_compress(input, level, max_output),
        Compression::Xz => xz_compress(input, level, max_output),
        Compression::Bzip2 => bzip2_compress(input, level, max_output),
    }
}

/// Upper bound on `compress` output for `n` input bytes (gzip and none).
pub fn compress_bound(n: usize) -> Option<usize> {
    deflate_bound(n)?.checked_add(18)
}

/// gzip member: 10-byte header, DEFLATE data, CRC32 and ISIZE trailer.
pub fn gzip_compress(input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, WrapError> {
    if level > 9 {
        return Err(WrapError::InvalidLevel);
    }
    if level == 0 {
        let blocks = input.len() / 65535 + 1;
        return crate::gzip_encode::encode_gzip(input, max_output, blocks).map_err(|e| match e {
            crate::gzip_encode::GzipEncodeError::LimitExceeded => WrapError::LimitExceeded,
            crate::gzip_encode::GzipEncodeError::Allocation => WrapError::Allocation,
        });
    }
    let raw_cap = max_output.checked_sub(18).ok_or(WrapError::LimitExceeded)?;
    let raw = deflate_compress(input, level, raw_cap).map_err(|e| match e {
        CompressError::LimitExceeded => WrapError::LimitExceeded,
        CompressError::Allocation => WrapError::Allocation,
        CompressError::InvalidLevel => WrapError::InvalidLevel,
    })?;
    let xfl = match level {
        9 => 2,
        1 => 4,
        _ => 0,
    };
    let mut out = Vec::new();
    out.try_reserve_exact(raw.len() + 18).map_err(|_| WrapError::Allocation)?;
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, xfl, 0xff]);
    out.extend_from_slice(&raw);
    out.extend_from_slice(&crc32(input).to_le_bytes());
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    Ok(out)
}

/// Stub: xz encoding is not implemented yet.
pub fn xz_compress(_input: &[u8], _level: u8, _max_output: usize) -> Result<Vec<u8>, WrapError> {
    Err(WrapError::Unsupported)
}

/// Stub: bzip2 encoding is not implemented yet.
pub fn bzip2_compress(_input: &[u8], _level: u8, _max_output: usize) -> Result<Vec<u8>, WrapError> {
    Err(WrapError::Unsupported)
}
