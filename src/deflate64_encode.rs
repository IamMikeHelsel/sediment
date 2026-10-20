// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deflate64 ("Enhanced Deflate", ZIP method 9) encoder.
//!
//! Spec sources: RFC 1951 for the block structure (stored / fixed / dynamic
//! Huffman blocks, code-length alphabet, canonical codes) and PKWARE
//! APPNOTE.TXT section 4.4.5 plus the publicly documented Deflate64 deltas
//! that `deflate64` (the decoder) already implements:
//!
//! * the sliding window is 64 KiB, so distances go up to 65536;
//! * distance codes 30 and 31 are valid (base 32769 / 49153, 14 extra bits);
//! * length code 285 has base 3 and 16 extra bits (lengths 3..=65538), so a
//!   length of exactly 258 must use code 284 with extra value 31.
//!
//! The symbol tables come from [`crate::deflate64::length_spec64`] and
//! [`crate::deflate64::distance_spec64`] so the encoder and decoder share one
//! source of truth. Bit output, Huffman length construction (length-limited
//! by frequency halving) and the code-length run-length coding are shared
//! with [`crate::deflate_compress`]. Each block picks the cheapest of stored,
//! fixed and dynamic encodings; fixed blocks are only used when distance
//! codes 30/31 are absent (some readers reject them in fixed blocks).
//! Output is deterministic.

use crate::deflate64::{distance_spec64, length_spec64};
use crate::deflate_compress::{
    BitSink, CL_ORDER, CompressError, codes_for, ensure_two, fixed_lit_lengths, huffman_lengths, put_code, rle_lengths,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deflate64EncodeError {
    /// Level outside 0..=9.
    InvalidLevel,
    /// Output would exceed `max_output`.
    LimitExceeded,
    Allocation,
}

const WINDOW: usize = 65536;
const MIN_MATCH: usize = 3;
/// Longest match a Deflate64 stream can express (code 285, extra 0xFFFF).
pub const MAX_MATCH64: usize = 65538;
const HASH_BITS: u32 = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const BLOCK_TOKENS: usize = 32768;
const NO_POS: u32 = u32::MAX;
const LIT_SYMS: usize = 286;
const DIST_SYMS: usize = 32;

fn map(e: CompressError) -> Deflate64EncodeError {
    match e {
        CompressError::InvalidLevel => Deflate64EncodeError::InvalidLevel,
        CompressError::LimitExceeded => Deflate64EncodeError::LimitExceeded,
        CompressError::Allocation => Deflate64EncodeError::Allocation,
    }
}

/// Worst-case output size of [`deflate64_compress`] for `n` input bytes.
pub fn deflate64_bound(n: usize) -> Option<usize> {
    crate::deflate_compress::deflate_bound(n)
}

#[derive(Clone, Copy)]
enum Token {
    Literal(u8),
    Match { len: u32, dist: u32 },
}

struct Params {
    max_chain: usize,
    nice: usize,
    lazy: bool,
}

fn params(level: u8) -> Params {
    let (max_chain, nice, lazy) = match level {
        1 => (4, 32, false),
        2 => (8, 64, false),
        3 => (16, 64, false),
        4 => (16, 128, true),
        5 => (32, 258, true),
        6 => (128, 1024, true),
        7 => (256, 4096, true),
        8 => (1024, 16384, true),
        _ => (4096, MAX_MATCH64, true),
    };
    Params { max_chain, nice, lazy }
}

/// (symbol, extra bits, base) for a match length 3..=65538.
fn length_symbol(len: u32) -> (u16, u8, u32) {
    if len > 258 {
        return (285, 16, 3);
    }
    if len == 258 {
        return (284, 5, 227);
    }
    let mut sym = 284u16;
    loop {
        // length_spec64 is total for 257..=284.
        let (base, extra) = length_spec64(sym).unwrap_or((3, 0));
        if u32::from(base) <= len || sym == 257 {
            return (sym, extra, u32::from(base));
        }
        sym -= 1;
    }
}

/// (symbol, extra bits, base) for a distance 1..=65536.
fn dist_symbol(dist: u32) -> (usize, u8, u32) {
    let mut s = 31u16;
    loop {
        let (base, extra) = distance_spec64(s).unwrap_or((1, 0));
        if base <= dist || s == 0 {
            return (s as usize, extra, base);
        }
        s -= 1;
    }
}

/// Compress `input` into a raw Deflate64 stream at `level` (0 = stored only, 1..=9).
pub fn deflate64_compress(input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, Deflate64EncodeError> {
    if level > 9 {
        return Err(Deflate64EncodeError::InvalidLevel);
    }
    if level == 0 {
        // Stored blocks are identical in Deflate and Deflate64.
        let blocks = input.len() / 65535 + 1;
        return crate::deflate_encode::encode_stored(input, max_output, blocks).map_err(|e| match e {
            crate::deflate_encode::EncodeError::LimitExceeded => Deflate64EncodeError::LimitExceeded,
            crate::deflate_encode::EncodeError::Allocation => Deflate64EncodeError::Allocation,
        });
    }
    if input.len() >= NO_POS as usize {
        return Err(Deflate64EncodeError::LimitExceeded);
    }
    let p = params(level);
    let mut head: Vec<u32> = Vec::new();
    head.try_reserve_exact(HASH_SIZE).map_err(|_| Deflate64EncodeError::Allocation)?;
    head.resize(HASH_SIZE, NO_POS);
    let mut prev: Vec<u32> = Vec::new();
    prev.try_reserve_exact(WINDOW).map_err(|_| Deflate64EncodeError::Allocation)?;
    prev.resize(WINDOW, NO_POS);
    let mut tokens: Vec<Token> = Vec::new();
    tokens.try_reserve_exact(BLOCK_TOKENS).map_err(|_| Deflate64EncodeError::Allocation)?;
    let mut sink = BitSink {
        out: Vec::new(),
        acc: 0,
        nbits: 0,
        max_output,
    };
    sink.out
        .try_reserve(input.len().min(max_output).min(1 << 20) + 64)
        .map_err(|_| Deflate64EncodeError::Allocation)?;

    let n = input.len();
    if n == 0 {
        write_block(&mut sink, &tokens, input, true).map_err(map)?;
        sink.align().map_err(map)?;
        return Ok(sink.out);
    }
    let insert = |head: &mut Vec<u32>, prev: &mut Vec<u32>, i: usize| {
        if i + MIN_MATCH <= n {
            let h = hash3(&input[i..i + 3]);
            prev[i % WINDOW] = head[h];
            head[h] = i as u32;
        }
    };
    let mut pos = 0usize;
    let mut block_start = 0usize;
    let mut inserted = 0usize;
    while pos < n {
        while inserted < pos {
            insert(&mut head, &mut prev, inserted);
            inserted += 1;
        }
        let (mut len, mut dist) = find_match(input, pos, &head, &prev, &p);
        if len >= MIN_MATCH && p.lazy && len < p.nice && pos + 1 < n {
            insert(&mut head, &mut prev, pos);
            inserted = pos + 1;
            let (l2, d2) = find_match(input, pos + 1, &head, &prev, &p);
            if l2 > len {
                tokens.push(Token::Literal(input[pos]));
                pos += 1;
                len = l2;
                dist = d2;
            }
        }
        if len >= MIN_MATCH {
            tokens.push(Token::Match {
                len: len as u32,
                dist: dist as u32,
            });
            pos += len;
        } else {
            tokens.push(Token::Literal(input[pos]));
            pos += 1;
        }
        if tokens.len() >= BLOCK_TOKENS - 1 {
            write_block(&mut sink, &tokens, &input[block_start..pos], pos >= n).map_err(map)?;
            tokens.clear();
            block_start = pos;
        }
    }
    if !tokens.is_empty() {
        write_block(&mut sink, &tokens, &input[block_start..pos], true).map_err(map)?;
    }
    sink.align().map_err(map)?;
    Ok(sink.out)
}

fn hash3(b: &[u8]) -> usize {
    let v = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

fn find_match(input: &[u8], pos: usize, head: &[u32], prev: &[u32], p: &Params) -> (usize, usize) {
    let n = input.len();
    if pos + MIN_MATCH > n {
        return (0, 0);
    }
    let max_len = (n - pos).min(MAX_MATCH64);
    let mut cand = head[hash3(&input[pos..pos + 3])];
    let mut best_len = 0usize;
    let mut best_dist = 0usize;
    let mut chain = p.max_chain;
    while cand != NO_POS && chain > 0 {
        let c = cand as usize;
        if c >= pos {
            break;
        }
        let dist = pos - c;
        if dist > WINDOW {
            break;
        }
        let probe = best_len.min(max_len - 1);
        if input[c + probe] == input[pos + probe] {
            let limit = max_len.min(p.nice.max(best_len + 1));
            let mut l = 0;
            while l < limit && input[c + l] == input[pos + l] {
                l += 1;
            }
            if l > best_len {
                best_len = l;
                best_dist = dist;
                if l >= p.nice || l == max_len {
                    break;
                }
            }
        }
        let next = prev[c % WINDOW];
        if next == NO_POS || next as usize >= c {
            break;
        }
        cand = next;
        chain -= 1;
    }
    if best_len >= MIN_MATCH { (best_len, best_dist) } else { (0, 0) }
}

fn write_block(sink: &mut BitSink, tokens: &[Token], raw: &[u8], last: bool) -> Result<(), CompressError> {
    let mut lit_freq = [0u32; LIT_SYMS];
    let mut dist_freq = [0u32; DIST_SYMS];
    let mut extra_bits: u64 = 0;
    for tok in tokens {
        match *tok {
            Token::Literal(b) => lit_freq[b as usize] += 1,
            Token::Match { len, dist } => {
                let (s, e, _) = length_symbol(len);
                lit_freq[s as usize] += 1;
                let (ds, de, _) = dist_symbol(dist);
                dist_freq[ds] += 1;
                extra_bits += e as u64 + de as u64;
            }
        }
    }
    lit_freq[256] += 1;

    let fixed_lit = fixed_lit_lengths();
    let fixed_ok = dist_freq[30] == 0 && dist_freq[31] == 0;
    let mut fixed_bits: u64 = 3 + extra_bits;
    for (s, &f) in lit_freq.iter().enumerate() {
        fixed_bits += f as u64 * fixed_lit[s] as u64;
    }
    fixed_bits += dist_freq.iter().map(|&f| f as u64 * 5).sum::<u64>();
    if !fixed_ok {
        fixed_bits = u64::MAX;
    }

    let mut lf = lit_freq;
    ensure_two(&mut lf);
    let mut df = dist_freq;
    ensure_two(&mut df);
    let lit_len = huffman_lengths(&lf, 15)?;
    let dist_len = huffman_lengths(&df, 15)?;
    let hlit = (257..=LIT_SYMS).rev().find(|&k| lit_len[k - 1] != 0).unwrap_or(257).max(257);
    let hdist = (1..=DIST_SYMS).rev().find(|&k| dist_len[k - 1] != 0).unwrap_or(1).max(1);
    let mut all = [0u8; LIT_SYMS + DIST_SYMS];
    all[..hlit].copy_from_slice(&lit_len[..hlit]);
    all[hlit..hlit + hdist].copy_from_slice(&dist_len[..hdist]);
    let rle = rle_lengths(&all[..hlit + hdist]);
    let mut cl_freq = [0u32; 19];
    for &(sym, _) in &rle {
        cl_freq[sym as usize] += 1;
    }
    ensure_two(&mut cl_freq);
    let cl_len = huffman_lengths(&cl_freq, 7)?;
    let hclen = (4..=19).rev().find(|&k| cl_len[CL_ORDER[k - 1]] != 0).unwrap_or(4).max(4);
    let mut dyn_bits: u64 = 3 + 14 + 3 * hclen as u64 + extra_bits;
    for &(sym, _) in &rle {
        dyn_bits += cl_len[sym as usize] as u64
            + match sym {
                16 => 2,
                17 => 3,
                18 => 7,
                _ => 0,
            };
    }
    for (s, &f) in lit_freq.iter().enumerate() {
        dyn_bits += f as u64 * lit_len[s] as u64;
    }
    for (s, &f) in dist_freq.iter().enumerate() {
        dyn_bits += f as u64 * dist_len[s] as u64;
    }

    let chunks = raw.len().div_ceil(65535).max(1) as u64;
    let stored_bits = chunks * (3 + 7 + 32) + raw.len() as u64 * 8;
    if stored_bits <= fixed_bits && stored_bits <= dyn_bits {
        let mut off = 0;
        loop {
            let take = (raw.len() - off).min(65535);
            let fin = last && off + take == raw.len();
            sink.put(fin as u32, 1)?;
            sink.put(0, 2)?;
            sink.align()?;
            let l = take as u16;
            sink.put_bytes(&l.to_le_bytes())?;
            sink.put_bytes(&(!l).to_le_bytes())?;
            sink.put_bytes(&raw[off..off + take])?;
            off += take;
            if off >= raw.len() {
                break;
            }
        }
        return Ok(());
    }

    let fixed_dist = [5u8; DIST_SYMS];
    let (ll, dl): (&[u8], &[u8]);
    sink.put(last as u32, 1)?;
    if fixed_bits <= dyn_bits {
        sink.put(1, 2)?;
        ll = &fixed_lit[..];
        dl = &fixed_dist[..];
    } else {
        sink.put(2, 2)?;
        sink.put((hlit - 257) as u32, 5)?;
        sink.put((hdist - 1) as u32, 5)?;
        sink.put((hclen - 4) as u32, 4)?;
        for &idx in CL_ORDER.iter().take(hclen) {
            sink.put(cl_len[idx] as u32, 3)?;
        }
        let cl_codes = codes_for(&cl_len, 7)?;
        for &(sym, extra) in &rle {
            put_code(sink, cl_codes[sym as usize], cl_len[sym as usize])?;
            match sym {
                16 => sink.put(extra as u32, 2)?,
                17 => sink.put(extra as u32, 3)?,
                18 => sink.put(extra as u32, 7)?,
                _ => {}
            }
        }
        ll = &lit_len[..];
        dl = &dist_len[..];
    }
    let lcodes = codes_for(ll, 15)?;
    let dcodes = codes_for(dl, 15)?;
    for tok in tokens {
        match *tok {
            Token::Literal(b) => put_code(sink, lcodes[b as usize], ll[b as usize])?,
            Token::Match { len, dist } => {
                let (s, e, base) = length_symbol(len);
                put_code(sink, lcodes[s as usize], ll[s as usize])?;
                sink.put(len - base, e as u32)?;
                let (ds, de, dbase) = dist_symbol(dist);
                put_code(sink, dcodes[ds], dl[ds])?;
                sink.put(dist - dbase, de as u32)?;
            }
        }
    }
    put_code(sink, lcodes[256], ll[256])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_tables() {
        assert_eq!(length_symbol(3), (257, 0, 3));
        assert_eq!(length_symbol(257), (284, 5, 227));
        assert_eq!(length_symbol(258), (284, 5, 227));
        assert_eq!(length_symbol(259), (285, 16, 3));
        assert_eq!(length_symbol(65538), (285, 16, 3));
        assert_eq!(dist_symbol(1), (0, 0, 1));
        assert_eq!(dist_symbol(32768), (29, 13, 24577));
        assert_eq!(dist_symbol(32769), (30, 14, 32769));
        assert_eq!(dist_symbol(65536), (31, 14, 49153));
    }
}
