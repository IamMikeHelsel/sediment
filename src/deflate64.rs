// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deflate64 ("Enhanced Deflate", PKWARE ZIP compression method 9) decoder.
//!
//! Spec sources:
//! - RFC 1951 (DEFLATE) for the block structure, the fixed Huffman code,
//!   the dynamic-header encoding and the canonical Huffman construction.
//! - PKWARE APPNOTE.TXT section 4.4.5 (method 9, "Enhanced Deflating") and
//!   the publicly documented Deflate64 deltas from RFC 1951:
//!   * the sliding window is 65536 bytes, so distances reach 65536;
//!   * distance codes 30 and 31 become valid: base 32769 and 49153, each with
//!     14 extra bits;
//!   * length code 285 no longer means "258": it has base 3 and 16 extra bits
//!     (lengths 3..=65538);
//!   * a dynamic header may therefore declare up to 32 distance codes.
//!
//! Everything else (stored blocks, fixed code lengths, code-length alphabet,
//! end-of-block symbol) is unchanged from RFC 1951.
//!
//! The decoder reuses [`BitReader`], [`HuffmanDecoder`] and
//! [`read_stored_block`]. It never panics on malformed input, bounds every
//! allocation by the caller's `max_output`, and bounds the work per call by
//! `max_blocks`.

use crate::bit_reader::BitReader;
use crate::deflate_stored::{StoredError, read_stored_block};
use crate::huffman_decode::{DecodeError, HuffmanDecoder};

/// Size of the Deflate64 history window (maximum match distance).
pub const WINDOW_SIZE: usize = 65536;
/// Longest match length a Deflate64 stream can encode (code 285 + 0xFFFF).
pub const MAX_MATCH: usize = 65538;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deflate64Error {
    /// The input ended before the final block was complete.
    UnexpectedEof,
    /// A block header used the reserved block type 3.
    InvalidBlockType,
    /// A stored block's LEN/NLEN pair did not match.
    InvalidStoredLength,
    /// A dynamic header described an invalid Huffman code.
    InvalidTree,
    /// A literal/length or distance code was invalid (e.g. symbol 286/287,
    /// a distance symbol with no code, or a bit pattern with no symbol).
    InvalidCode,
    /// A match referred to data before the start of the output.
    InvalidDistance,
    /// `max_output` or `max_blocks` would be exceeded.
    LimitExceeded,
    /// Memory for the output could not be reserved.
    Allocation,
    /// Non-zero bytes remain after the final block (strict mode only).
    TrailingData,
}

impl std::fmt::Display for Deflate64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Deflate64Error::UnexpectedEof => "deflate64: unexpected end of input",
            Deflate64Error::InvalidBlockType => "deflate64: invalid block type",
            Deflate64Error::InvalidStoredLength => "deflate64: stored block LEN/NLEN mismatch",
            Deflate64Error::InvalidTree => "deflate64: invalid Huffman tree",
            Deflate64Error::InvalidCode => "deflate64: invalid Huffman code",
            Deflate64Error::InvalidDistance => "deflate64: match distance out of range",
            Deflate64Error::LimitExceeded => "deflate64: limit exceeded",
            Deflate64Error::Allocation => "deflate64: allocation failed",
            Deflate64Error::TrailingData => "deflate64: trailing data after final block",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Deflate64Error {}

/// Length symbol 257..=285 -> (base, extra bits), Deflate64 variant.
const LENGTH_BASES: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3,
];
const LENGTH_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
];

/// Distance symbol 0..=31 -> (base, extra bits), Deflate64 variant.
const DIST_BASES: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
const DIST_BITS: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// Returns `(base, extra_bits)` for a Deflate64 length symbol (257..=285).
pub fn length_spec64(symbol: u16) -> Option<(u16, u8)> {
    if !(257..=285).contains(&symbol) {
        return None;
    }
    let i = usize::from(symbol - 257);
    Some((LENGTH_BASES[i], LENGTH_BITS[i]))
}

/// Returns `(base, extra_bits)` for a Deflate64 distance symbol (0..=31).
pub fn distance_spec64(symbol: u16) -> Option<(u32, u8)> {
    let i = usize::from(symbol);
    if i >= 32 {
        return None;
    }
    Some((DIST_BASES[i], DIST_BITS[i]))
}

/// Decodes a complete raw Deflate64 stream. The final block must end the
/// input; only zero padding bits up to the next byte boundary are allowed.
///
/// `max_output` caps the decoded size and `max_blocks` caps the number of
/// blocks processed.
pub fn inflate64_raw(
    input: &[u8],
    max_output: usize,
    max_blocks: usize,
) -> Result<Vec<u8>, Deflate64Error> {
    let (out, consumed) = inflate64_raw_prefix(input, max_output, max_blocks)?;
    if consumed != input.len() {
        return Err(Deflate64Error::TrailingData);
    }
    Ok(out)
}

/// Decodes a raw Deflate64 stream at the start of `input` and returns the
/// output together with the number of input bytes consumed (the final block
/// rounded up to a whole byte). Bytes after that are not examined.
pub fn inflate64_raw_prefix(
    input: &[u8],
    max_output: usize,
    max_blocks: usize,
) -> Result<(Vec<u8>, usize), Deflate64Error> {
    let mut reader = BitReader::new(input).map_err(|_| Deflate64Error::LimitExceeded)?;
    let mut output: Vec<u8> = Vec::new();
    let mut blocks: usize = 0;

    loop {
        if blocks >= max_blocks {
            return Err(Deflate64Error::LimitExceeded);
        }
        blocks += 1;

        let bfinal = read_bits(&mut reader, 1)?;
        let btype = read_bits(&mut reader, 2)?;
        match btype {
            0 => read_stored_block(&mut reader, &mut output, max_output).map_err(|e| match e {
                StoredError::UnexpectedEof => Deflate64Error::UnexpectedEof,
                StoredError::InvalidLength => Deflate64Error::InvalidStoredLength,
                StoredError::LimitExceeded => Deflate64Error::LimitExceeded,
                StoredError::Allocation => Deflate64Error::Allocation,
            })?,
            1 => {
                let (lit, dist) = fixed_trees()?;
                decode_huffman_block(&mut reader, &lit, Some(&dist), &mut output, max_output)?;
            }
            2 => {
                let (lit, dist) = read_dynamic_trees64(&mut reader)?;
                decode_huffman_block(&mut reader, &lit, dist.as_ref(), &mut output, max_output)?;
            }
            _ => return Err(Deflate64Error::InvalidBlockType),
        }

        if bfinal != 0 {
            break;
        }
    }

    reader.align_byte();
    let consumed = reader.position() / 8;
    Ok((output, consumed))
}

fn read_bits(reader: &mut BitReader<'_>, width: u8) -> Result<u32, Deflate64Error> {
    reader.read_bits(width).map_err(|_| Deflate64Error::UnexpectedEof)
}

fn map_tree_err(e: DecodeError) -> Deflate64Error {
    match e {
        DecodeError::Allocation => Deflate64Error::Allocation,
        _ => Deflate64Error::InvalidTree,
    }
}

fn map_symbol_err(e: DecodeError) -> Deflate64Error {
    match e {
        DecodeError::UnexpectedEof => Deflate64Error::UnexpectedEof,
        DecodeError::Allocation => Deflate64Error::Allocation,
        _ => Deflate64Error::InvalidCode,
    }
}

fn fixed_trees() -> Result<(HuffmanDecoder, HuffmanDecoder), Deflate64Error> {
    let mut lit = [8u8; 288];
    lit[144..256].fill(9);
    lit[256..280].fill(7);
    let dist = [5u8; 32];
    let lit = HuffmanDecoder::new(&lit, 15).map_err(map_tree_err)?;
    let dist = HuffmanDecoder::new(&dist, 15).map_err(map_tree_err)?;
    Ok((lit, dist))
}

/// Order in which code-length code lengths are transmitted (RFC 1951 3.2.7).
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Reads a dynamic block header (RFC 1951 3.2.7) allowing up to 32 distance
/// codes. Returns the literal/length decoder and, unless every distance code
/// length is zero, the distance decoder.
fn read_dynamic_trees64(
    reader: &mut BitReader<'_>,
) -> Result<(HuffmanDecoder, Option<HuffmanDecoder>), Deflate64Error> {
    let hlit = read_bits(reader, 5)? as usize + 257;
    let hdist = read_bits(reader, 5)? as usize + 1;
    let hclen = read_bits(reader, 4)? as usize + 4;
    // Literal/length symbols 286 and 287 never occur in valid data.
    if hlit > 286 {
        return Err(Deflate64Error::InvalidTree);
    }

    let mut cl_lengths = [0u8; 19];
    for &i in CL_ORDER.iter().take(hclen) {
        cl_lengths[i] = read_bits(reader, 3)? as u8;
    }
    check_complete(&cl_lengths, 7, false)?;
    let cl_tree = HuffmanDecoder::new(&cl_lengths, 7).map_err(map_tree_err)?;

    let total = hlit + hdist;
    let mut lengths = [0u8; 286 + 32];
    let mut i = 0usize;
    while i < total {
        let sym = cl_tree.decode(reader).map_err(|e| match e {
            DecodeError::UnexpectedEof => Deflate64Error::UnexpectedEof,
            DecodeError::Allocation => Deflate64Error::Allocation,
            _ => Deflate64Error::InvalidTree,
        })?;
        let (value, repeat) = match sym {
            0..=15 => (sym as u8, 1usize),
            16 => {
                if i == 0 {
                    return Err(Deflate64Error::InvalidTree);
                }
                (lengths[i - 1], read_bits(reader, 2)? as usize + 3)
            }
            17 => (0, read_bits(reader, 3)? as usize + 3),
            18 => (0, read_bits(reader, 7)? as usize + 11),
            _ => return Err(Deflate64Error::InvalidTree),
        };
        let end = i + repeat;
        if end > total {
            return Err(Deflate64Error::InvalidTree);
        }
        lengths[i..end].fill(value);
        i = end;
    }

    let lit_lengths = &lengths[..hlit];
    let dist_lengths = &lengths[hlit..total];
    if lit_lengths[256] == 0 {
        return Err(Deflate64Error::InvalidTree);
    }
    check_complete(lit_lengths, 15, true)?;
    let lit = HuffmanDecoder::new(lit_lengths, 15).map_err(map_tree_err)?;
    let dist = if dist_lengths.iter().all(|&l| l == 0) {
        None
    } else {
        check_complete(dist_lengths, 15, true)?;
        Some(HuffmanDecoder::new(dist_lengths, 15).map_err(map_tree_err)?)
    };
    Ok((lit, dist))
}

/// Requires a complete prefix code. When `allow_single` is set, a code made
/// of exactly one symbol of length 1 is also accepted (RFC 1951 3.2.7: "one
/// distance code of one bit").
fn check_complete(lengths: &[u8], max_bits: u8, allow_single: bool) -> Result<(), Deflate64Error> {
    let mut sum: u32 = 0;
    let mut used = 0usize;
    let mut single_len = 0u8;
    for &len in lengths {
        if len == 0 {
            continue;
        }
        if len > max_bits {
            return Err(Deflate64Error::InvalidTree);
        }
        used += 1;
        single_len = len;
        sum += 1u32 << (max_bits - len);
    }
    if sum == 1u32 << max_bits {
        return Ok(());
    }
    if allow_single && used == 1 && single_len == 1 {
        return Ok(());
    }
    Err(Deflate64Error::InvalidTree)
}

fn decode_huffman_block(
    reader: &mut BitReader<'_>,
    lit: &HuffmanDecoder,
    dist: Option<&HuffmanDecoder>,
    output: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), Deflate64Error> {
    loop {
        let sym = lit.decode(reader).map_err(map_symbol_err)?;
        if sym < 256 {
            if output.len() >= max_output {
                return Err(Deflate64Error::LimitExceeded);
            }
            output.try_reserve(1).map_err(|_| Deflate64Error::Allocation)?;
            output.push(sym as u8);
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let (base, extra) = length_spec64(sym).ok_or(Deflate64Error::InvalidCode)?;
        let length = usize::from(base) + read_bits(reader, extra)? as usize;

        let dist_tree = dist.ok_or(Deflate64Error::InvalidCode)?;
        let dsym = dist_tree.decode(reader).map_err(map_symbol_err)?;
        let (dbase, dextra) = distance_spec64(dsym).ok_or(Deflate64Error::InvalidCode)?;
        let distance = dbase as usize + read_bits(reader, dextra)? as usize;

        copy_match(output, distance, length, max_output)?;
    }
}

fn copy_match(
    output: &mut Vec<u8>,
    distance: usize,
    length: usize,
    max_output: usize,
) -> Result<(), Deflate64Error> {
    if distance == 0 || distance > WINDOW_SIZE || distance > output.len() {
        return Err(Deflate64Error::InvalidDistance);
    }
    let new_len = output.len().checked_add(length).ok_or(Deflate64Error::LimitExceeded)?;
    if new_len > max_output {
        return Err(Deflate64Error::LimitExceeded);
    }
    output.try_reserve(length).map_err(|_| Deflate64Error::Allocation)?;
    let mut src = output.len() - distance;
    let mut remaining = length;
    while remaining > 0 {
        // Copy in runs no longer than what already exists, so overlapping
        // matches (distance < length) replicate the period correctly.
        let n = remaining.min(output.len() - src);
        output.extend_from_within(src..src + n);
        src += n;
        remaining -= n;
    }
    Ok(())
}
