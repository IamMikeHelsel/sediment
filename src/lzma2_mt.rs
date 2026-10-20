// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block-parallel LZMA2 encoding.
//!
//! The input is cut into independent blocks; each block is encoded on its own
//! worker with [`crate::lzma2_encode::encode_lzma2`] (which always starts with
//! a dictionary reset + new properties chunk, control `0xE0` or `0x01`), and
//! the blocks' chunk sequences are concatenated with a single `0x00` end
//! marker. Because every block begins with a dictionary reset, a standard
//! LZMA2 decoder reads the result as one stream; the declared dictionary is
//! the largest any block needs. This is the same "block mode" multithreading
//! the public LZMA2 description allows (chunks may reset the dictionary at
//! any point), at a small cost in ratio per block boundary.
//!
//! Output depends only on the input, the options and the block size; the
//! block size depends on the thread count only through [`lzma2_block_size`],
//! so the output is deterministic for a given `-mmt` value. With one thread
//! the output is byte-identical to `encode_lzma2`.
//!
//! Spec sources: the LZMA2 chunk/control-byte layout from the public xz file
//! format specification (filter 0x21) and LZMA SDK documentation, as already
//! used by `lzma2_encode`. No 7-Zip source was consulted.

use crate::lzma_encode::LzmaEncoderOptions;
use crate::lzma2_encode::{Lzma2EncodeError, encode_lzma2};
use crate::mt_pool::map_ordered;

/// Smallest block cut by the parallel encoder (1 MiB).
pub const MIN_BLOCK: usize = 1 << 20;
/// Largest block cut by the parallel encoder (256 MiB).
pub const MAX_BLOCK: usize = 1 << 28;

/// Block size for `len` bytes on `threads` workers with dictionary `dict`:
/// `4 * dict` clamped to `MIN_BLOCK..=MAX_BLOCK`, shrunk so that every worker
/// gets at least one block (never below `MIN_BLOCK`), rounded up to 64 KiB.
/// One thread (or a small input) gives `len` (a single block).
pub fn lzma2_block_size(dict: u32, len: usize, threads: usize) -> usize {
    if threads <= 1 || len <= MIN_BLOCK {
        return len.max(1);
    }
    let base = (dict as usize).saturating_mul(4).clamp(MIN_BLOCK, MAX_BLOCK);
    let per_thread = len.div_ceil(threads).max(MIN_BLOCK);
    let b = base.min(per_thread);
    b.div_ceil(1 << 16).saturating_mul(1 << 16).max(1)
}

/// Encode `input` as one raw LZMA2 stream using up to `threads` workers.
/// Returns the stream and the dictionary property byte to declare.
pub fn encode_lzma2_mt(
    input: &[u8],
    opts: &LzmaEncoderOptions,
    threads: usize,
) -> Result<(Vec<u8>, u8), Lzma2EncodeError> {
    let block = lzma2_block_size(opts.dictionary_size, input.len(), threads);
    encode_lzma2_blocks(input, opts, block, threads)
}

/// Encode `input` in independent blocks of `block` bytes on up to `threads`
/// workers. `block == 0` is invalid.
pub fn encode_lzma2_blocks(
    input: &[u8],
    opts: &LzmaEncoderOptions,
    block: usize,
    threads: usize,
) -> Result<(Vec<u8>, u8), Lzma2EncodeError> {
    if block == 0 {
        return Err(Lzma2EncodeError::InvalidOptions);
    }
    if input.len() <= block {
        return encode_lzma2(input, opts);
    }
    let pieces: Vec<&[u8]> = input.chunks(block).collect();
    let parts = map_ordered(&pieces, threads, Lzma2EncodeError::Allocation, |p| encode_lzma2(p, opts))?;
    join_lzma2_parts(&parts)
}

/// Join complete LZMA2 streams (each from `encode_lzma2`, so each starts with
/// a dictionary reset and ends with `0x00`) into one stream, returning it and
/// the largest dictionary byte. No parts gives an empty stream.
pub fn join_lzma2_parts(parts: &[(Vec<u8>, u8)]) -> Result<(Vec<u8>, u8), Lzma2EncodeError> {
    let total = parts.iter().try_fold(1usize, |acc, (p, _)| acc.checked_add(p.len())).ok_or(Lzma2EncodeError::Allocation)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| Lzma2EncodeError::Allocation)?;
    let mut dict_byte = 0u8;
    for (p, d) in parts {
        // Each part ends with the 0x00 end marker; drop it between parts.
        let body = p.strip_suffix(&[0x00]).ok_or(Lzma2EncodeError::InvalidOptions)?;
        out.extend_from_slice(body);
        dict_byte = dict_byte.max(*d);
    }
    out.push(0x00);
    Ok((out, dict_byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzma2_decode::decode_lzma2;
    use crate::lzma_encode::LzmaEncoderOptions;

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if (i / 4096) % 3 == 0 { (x & 0xFF) as u8 } else { b"sediment block mode "[i % 20] }
            })
            .collect()
    }

    #[test]
    fn block_size_rules() {
        assert_eq!(lzma2_block_size(8 << 20, 100, 4), 100);
        assert_eq!(lzma2_block_size(8 << 20, 64 << 20, 1), 64 << 20);
        assert_eq!(lzma2_block_size(8 << 20, 64 << 20, 4), 16 << 20);
        assert_eq!(lzma2_block_size(8 << 20, 64 << 20, 16), 4 << 20);
        assert_eq!(lzma2_block_size(4096, 64 << 20, 2), 1 << 20);
        assert_eq!(lzma2_block_size(8 << 20, 3 << 20, 64), 1 << 20);
    }

    #[test]
    fn blocks_roundtrip_and_deterministic() {
        let data = sample(300_000);
        let opts = LzmaEncoderOptions::preset(1).unwrap();
        let (single, _) = encode_lzma2(&data, &opts).unwrap();
        assert_eq!(encode_lzma2_blocks(&data, &opts, data.len(), 4).unwrap().0, single);
        let (a, da) = encode_lzma2_blocks(&data, &opts, 65_536, 4).unwrap();
        let (b, db) = encode_lzma2_blocks(&data, &opts, 65_536, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(da, db);
        let (dec, used) = decode_lzma2(&a, 1 << 20, 1 << 20, data.len()).unwrap();
        assert_eq!((dec, used), (data.clone(), a.len()));
        assert_eq!(encode_lzma2_blocks(&data, &opts, 0, 4), Err(Lzma2EncodeError::InvalidOptions));
        let (e, _) = encode_lzma2_blocks(&[], &opts, 1, 4).unwrap();
        assert_eq!(decode_lzma2(&e, 4096, 4096, 0).unwrap().0, Vec::<u8>::new());
    }
}
