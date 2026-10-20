// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-stream compression wrappers used for `.tar.gz`/`.tar.xz`/`.tar.bz2`
//! archives and for single-file `.gz`/`.xz`/`.bz2` output.
//!
//! Spec sources: RFC 1952 (gzip member format) over RFC 1951 DEFLATE; "The
//! .xz File Format" (Tukaani) via `xz_encode`; the documented bzip2 stream
//! format via `bzip2_encode`.
//!
//! All output is deterministic (no timestamps, no file names).
//!
//! `-mx` level mapping (`level` is 0..=9 everywhere):
//!
//! | level | gzip                          | xz (LZMA2, CRC64)        | bzip2 block size |
//! |-------|-------------------------------|--------------------------|------------------|
//! | 0     | stored DEFLATE blocks         | xz preset 0 (256 KiB)    | 100 000 (`-1`)   |
//! | 1..=9 | `deflate_compress` level N    | xz preset N              | see [`bzip2_block_level`] |
//!
//! The bzip2 mapping follows 7-Zip's documented BZip2 `-mx` table: levels
//! 0..=2 use 100 kB blocks, 3..=4 use 500 kB, 5..=9 use 900 kB. xz presets
//! follow the xz tool's dictionary sizes (`LzmaEncoderOptions::preset`).

use crate::crc32::crc32;
use crate::bzip2_encode::{Bzip2EncodeError, encode_bzip2};
use crate::deflate_compress::{CompressError, deflate_bound, deflate_compress};
use crate::lzma_encode::MAX_INPUT;
use crate::xz_encode::{XzEncodeError, XzOptions, encode_xz, encode_xz_mt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapError {
    /// Format has no encoder. No longer returned (kept for API stability).
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

/// [`compress`] using up to `threads` workers (see [`crate::mt_pool`]).
///
/// * xz: inputs larger than one block are written as a multi-block `.xz`
///   (blocks of `3 * dictionary`, at least 1 MiB, as `xz -T` does), the
///   blocks' LZMA2 data encoded in parallel.
/// * bzip2: inputs larger than one bzip2 block are written as a sequence of
///   complete bzip2 streams of one block each (the multi-stream layout
///   `bzip2 -d`, Python's `bz2` and `pbzip2` read), compressed in parallel.
/// * gzip / none: unchanged.
///
/// With `threads <= 1` the output is identical to [`compress`]. Otherwise it
/// depends only on the input and level, not on the exact thread count.
pub fn compress_mt(kind: Compression, input: &[u8], level: u8, max_output: usize, threads: usize) -> Result<Vec<u8>, WrapError> {
    if level > 9 {
        return Err(WrapError::InvalidLevel);
    }
    if threads <= 1 {
        return compress(kind, input, level, max_output);
    }
    match kind {
        Compression::Xz => {
            if input.len() > MAX_INPUT {
                return Err(WrapError::LimitExceeded);
            }
            let mut opts = XzOptions::preset(level as u32).map_err(|_| WrapError::InvalidLevel)?;
            let block = (opts.lzma.dictionary_size as usize).saturating_mul(3).max(1 << 20);
            if input.len() <= block {
                return xz_compress(input, level, max_output);
            }
            opts.block_size = Some(block);
            let out = encode_xz_mt(input, &opts, threads).map_err(|e| match e {
                XzEncodeError::InvalidOptions => WrapError::InvalidLevel,
                XzEncodeError::InputTooLarge => WrapError::LimitExceeded,
                XzEncodeError::Allocation => WrapError::Allocation,
            })?;
            if out.len() > max_output {
                return Err(WrapError::LimitExceeded);
            }
            Ok(out)
        }
        Compression::Bzip2 => {
            let digit = bzip2_block_level(level)?;
            let chunk = digit as usize * 100_000;
            if input.len() <= chunk {
                return bzip2_compress(input, level, max_output);
            }
            let pieces: Vec<&[u8]> = input.chunks(chunk).collect();
            let parts = crate::mt_pool::map_ordered(&pieces, threads, WrapError::Allocation, |p| {
                let cap = compress_bound_for(Compression::Bzip2, p.len()).ok_or(WrapError::LimitExceeded)?.min(max_output);
                bzip2_compress(p, level, cap)
            })?;
            let total = parts.iter().try_fold(0usize, |a, p| a.checked_add(p.len())).ok_or(WrapError::LimitExceeded)?;
            if total > max_output {
                return Err(WrapError::LimitExceeded);
            }
            let mut out = Vec::new();
            out.try_reserve_exact(total).map_err(|_| WrapError::Allocation)?;
            for p in &parts {
                out.extend_from_slice(p);
            }
            Ok(out)
        }
        Compression::None | Compression::Gzip => compress(kind, input, level, max_output),
    }
}

/// Upper bound on `compress` output for `n` input bytes (gzip and none).
/// For xz and bzip2 use [`compress_bound_for`].
pub fn compress_bound(n: usize) -> Option<usize> {
    deflate_bound(n)?.checked_add(18)
}

/// Upper bound on `compress(kind, ..)` output for `n` input bytes at any level.
pub fn compress_bound_for(kind: Compression, n: usize) -> Option<usize> {
    match kind {
        Compression::None => Some(n),
        Compression::Gzip => compress_bound(n),
        // LZMA2 falls back to uncompressed chunks (3 header bytes per 64 KiB)
        // and every block (at most 1 GiB) adds header, padding, check and an
        // index record; stream header, index and footer are fixed size.
        Compression::Xz => n.checked_add(3 * (n / 65_536 + 1))?.checked_add(64 * (n / (1 << 30) + 1))?.checked_add(64),
        // Incompressible data after RLE1/BWT/MTF is Huffman coded at a little
        // over 8 bits per byte plus per-block tables and selectors.
        Compression::Bzip2 => n.checked_add(n / 8)?.checked_add(1024),
    }
}

/// bzip2 block-size digit (1..=9, block = digit x 100 000 bytes) for `-mx` level 0..=9.
pub fn bzip2_block_level(level: u8) -> Result<u8, WrapError> {
    match level {
        0..=2 => Ok(1),
        3..=4 => Ok(5),
        5..=9 => Ok(9),
        _ => Err(WrapError::InvalidLevel),
    }
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

/// Single-stream `.xz` (one LZMA2 filter, CRC64 check) at xz preset `level`.
///
/// The encoder works on the whole input; `max_output` is checked on the
/// result (inputs larger than [`MAX_INPUT`] are rejected up front).
pub fn xz_compress(input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, WrapError> {
    if level > 9 {
        return Err(WrapError::InvalidLevel);
    }
    if input.len() > MAX_INPUT {
        return Err(WrapError::LimitExceeded);
    }
    let opts = XzOptions::preset(level as u32).map_err(|_| WrapError::InvalidLevel)?;
    let out = encode_xz(input, &opts).map_err(|e| match e {
        XzEncodeError::InvalidOptions => WrapError::InvalidLevel,
        XzEncodeError::InputTooLarge => WrapError::LimitExceeded,
        XzEncodeError::Allocation => WrapError::Allocation,
    })?;
    if out.len() > max_output {
        return Err(WrapError::LimitExceeded);
    }
    Ok(out)
}

/// Single-stream `.bz2` with the block size chosen by [`bzip2_block_level`].
pub fn bzip2_compress(input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, WrapError> {
    let digit = bzip2_block_level(level)?;
    encode_bzip2(input, digit, max_output).map_err(|e| match e {
        Bzip2EncodeError::InvalidLevel => WrapError::InvalidLevel,
        Bzip2EncodeError::LimitExceeded => WrapError::LimitExceeded,
        Bzip2EncodeError::Allocation => WrapError::Allocation,
    })
}
