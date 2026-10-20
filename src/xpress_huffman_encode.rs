// SPDX-License-Identifier: MIT OR Apache-2.0
//! XPRESS Huffman ("LZ77+Huffman") compression of one block, as used for
//! WIM chunks. The inverse of [`crate::xpress_huffman`].
//!
//! Spec source: [MS-XCA] "Xpress Compression Algorithm", sections 2.1-2.2
//! (LZ77+Huffman): a 256-byte table of 512 four-bit code lengths (low
//! nibble = even symbol), then a bitstream of 16-bit little-endian words
//! written most-significant bit first. Symbols 0-255 are literals; symbol
//! `256 + (offset_bits << 4) + length_nibble` is a match of length
//! `nibble + 3` (nibble 15: extension bytes follow) at offset
//! `(1 << offset_bits) + extra_bits`. Extension bytes are placed in the
//! byte stream between words, at the position the decoder reaches after
//! the words it has already prefetched (it holds two words ahead).
//! Codes are canonical (shorter first, ties by symbol), at most 15 bits.
//!
//! One call encodes one block of at most [`MAX_BLOCK`] bytes (a WIM chunk
//! is 32 KiB). An end-of-data symbol 256 is appended, as Microsoft's
//! encoder does; decoders stop at the known output size anyway.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpressEncodeError {
    /// Input larger than one block ([`MAX_BLOCK`]).
    TooLarge,
    /// Memory allocation failed.
    Allocation,
}

/// Largest input accepted by [`compress`] (one XPRESS Huffman block).
pub const MAX_BLOCK: usize = 65536;

use std::cmp::Reverse;
use std::collections::BinaryHeap;

const NUM_SYMBOLS: usize = 512;
const MAX_CODE_LEN: u8 = 15;
const MIN_MATCH: usize = 3;
const MAX_OFFSET: usize = 65535;
const HASH_BITS: u32 = 15;
const MAX_CHAIN: usize = 32;
const NIL: u32 = u32::MAX;

#[derive(Clone, Copy)]
enum Token {
    Literal(u8),
    Match { len: u32, offset: u32 },
}

fn hash3(b: &[u8], i: usize) -> usize {
    let v = u32::from(b[i]) | u32::from(b[i + 1]) << 8 | u32::from(b[i + 2]) << 16;
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

fn match_len(b: &[u8], a: usize, c: usize, max: usize) -> usize {
    let mut n = 0;
    while n < max && b[a + n] == b[c + n] {
        n += 1;
    }
    n
}

/// Greedy LZ77 parse with hash chains and one-step lazy matching.
fn parse(input: &[u8]) -> Result<Vec<Token>, XpressEncodeError> {
    let n = input.len();
    let mut tokens = Vec::new();
    tokens.try_reserve(n / 2 + 1).map_err(|_| XpressEncodeError::Allocation)?;
    let mut head = Vec::new();
    head.try_reserve_exact(1 << HASH_BITS).map_err(|_| XpressEncodeError::Allocation)?;
    head.resize(1 << HASH_BITS, NIL);
    let mut prev = Vec::new();
    prev.try_reserve_exact(n).map_err(|_| XpressEncodeError::Allocation)?;
    prev.resize(n, NIL);
    let insert = |i: usize, head: &mut Vec<u32>, prev: &mut Vec<u32>| {
        if i + MIN_MATCH <= n {
            let h = hash3(input, i);
            prev[i] = head[h];
            head[h] = i as u32;
        }
    };
    let find = |i: usize, head: &Vec<u32>, prev: &Vec<u32>| -> (usize, usize) {
        if i + MIN_MATCH > n {
            return (0, 0);
        }
        let max = n - i;
        let (mut best_len, mut best_off) = (0usize, 0usize);
        let mut cand = head[hash3(input, i)];
        let mut steps = 0;
        while cand != NIL && steps < MAX_CHAIN {
            let c = cand as usize;
            let off = i - c;
            if off > MAX_OFFSET {
                break;
            }
            if input[c + best_len.min(max - 1)] == input[i + best_len.min(max - 1)] {
                let l = match_len(input, c, i, max);
                if l > best_len {
                    best_len = l;
                    best_off = off;
                    if l == max {
                        break;
                    }
                }
            }
            cand = prev[c];
            steps += 1;
        }
        (best_len, best_off)
    };
    let mut i = 0;
    while i < n {
        let (len, off) = find(i, &head, &prev);
        if len < MIN_MATCH {
            insert(i, &mut head, &mut prev);
            tokens.push(Token::Literal(input[i]));
            i += 1;
            continue;
        }
        insert(i, &mut head, &mut prev);
        // Lazy step: a longer match one byte later wins.
        let (len2, _) = find(i + 1, &head, &prev);
        if len2 > len + 1 {
            tokens.push(Token::Literal(input[i]));
            i += 1;
            continue;
        }
        tokens.push(Token::Match { len: len as u32, offset: off as u32 });
        for j in i + 1..i + len {
            insert(j, &mut head, &mut prev);
        }
        i += len;
    }
    Ok(tokens)
}

fn offset_bits(offset: u32) -> u32 {
    31 - offset.leading_zeros()
}

fn match_symbol(len: u32, offset: u32) -> usize {
    let nibble = (len - MIN_MATCH as u32).min(15);
    256 + ((offset_bits(offset) << 4) | nibble) as usize
}

/// Huffman code lengths (at most `MAX_CODE_LEN`) for the given frequencies.
/// Zero-frequency symbols get length 0; with a single used symbol it gets
/// length 1 (the caller always uses at least two).
fn code_lengths(freq: &[u32; NUM_SYMBOLS]) -> [u8; NUM_SYMBOLS] {
    let mut f = *freq;
    loop {
        let lens = huffman_lengths(&f);
        if lens.iter().all(|&l| l <= MAX_CODE_LEN) {
            return lens;
        }
        for v in f.iter_mut().filter(|v| **v > 0) {
            *v = (*v >> 1) | 1;
        }
    }
}

fn huffman_lengths(f: &[u32; NUM_SYMBOLS]) -> [u8; NUM_SYMBOLS] {
    // Nodes: leaves 0..NUM_SYMBOLS, internal nodes after. parent[] links.
    let mut lens = [0u8; NUM_SYMBOLS];
    let mut weight: Vec<u64> = f.iter().map(|&v| u64::from(v)).collect();
    let mut parent: Vec<usize> = vec![usize::MAX; NUM_SYMBOLS];
    let live: Vec<usize> = (0..NUM_SYMBOLS).filter(|&s| f[s] > 0).collect();
    if live.len() == 1 {
        lens[live[0]] = 1;
        return lens;
    }
    let leaves = live.clone();
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = live.iter().map(|&s| Reverse((weight[s], s))).collect();
    while heap.len() > 1 {
        let (Some(Reverse((wa, a))), Some(Reverse((wb, b)))) = (heap.pop(), heap.pop()) else { break };
        let node = weight.len();
        weight.push(wa + wb);
        parent.push(usize::MAX);
        parent[a] = node;
        parent[b] = node;
        heap.push(Reverse((wa + wb, node)));
    }
    for s in leaves {
        let mut d = 0u32;
        let mut x = s;
        while parent[x] != usize::MAX {
            x = parent[x];
            d += 1;
        }
        lens[s] = d.min(255) as u8;
    }
    lens
}

/// Canonical codes: shorter codes first, ties by symbol value.
fn canonical(lens: &[u8; NUM_SYMBOLS]) -> [u16; NUM_SYMBOLS] {
    let mut count = [0u32; 16];
    for &l in lens.iter() {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0u32;
    for len in 1..=15 {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    let mut codes = [0u16; NUM_SYMBOLS];
    for (s, &l) in lens.iter().enumerate() {
        if l > 0 {
            codes[s] = next[usize::from(l)] as u16;
            next[usize::from(l)] += 1;
        }
    }
    codes
}

/// Bit writer with the two-word lookahead layout of [MS-XCA]: the word
/// being filled and the next word have reserved slots; extension bytes go
/// after them. A new slot is reserved only when a bit is written past a
/// full word, mirroring the decoder's refill rule.
struct BitOut {
    out: Vec<u8>,
    slot0: usize,
    slot1: usize,
    acc: u32,
    nbits: u32,
}

impl BitOut {
    fn new(mut out: Vec<u8>) -> Self {
        let slot0 = out.len();
        out.extend_from_slice(&[0, 0, 0, 0]);
        BitOut { out, slot0, slot1: slot0 + 2, acc: 0, nbits: 0 }
    }
    fn flush_word(&mut self) {
        let w = (self.acc as u16).to_le_bytes();
        self.out[self.slot0..self.slot0 + 2].copy_from_slice(&w);
        self.slot0 = self.slot1;
        self.slot1 = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        self.acc = 0;
        self.nbits = 0;
    }
    fn bits(&mut self, value: u32, count: u32) {
        let mut k = count;
        while k > 0 {
            if self.nbits == 16 {
                self.flush_word();
            }
            let t = k.min(16 - self.nbits);
            let part = (value >> (k - t)) & ((1u32 << t) - 1);
            self.acc = (self.acc << t) | part;
            self.nbits += t;
            k -= t;
        }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }
    fn finish(mut self) -> Vec<u8> {
        let w = ((self.acc << (16 - self.nbits)) as u16).to_le_bytes();
        self.out[self.slot0..self.slot0 + 2].copy_from_slice(&w);
        self.out
    }
}

/// Compress one block (`input.len() <= MAX_BLOCK`) to an XPRESS Huffman
/// stream. Empty input yields an empty stream.
pub fn compress(input: &[u8]) -> Result<Vec<u8>, XpressEncodeError> {
    if input.len() > MAX_BLOCK {
        return Err(XpressEncodeError::TooLarge);
    }
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = parse(input)?;
    let mut freq = [0u32; NUM_SYMBOLS];
    for t in &tokens {
        match *t {
            Token::Literal(b) => freq[usize::from(b)] += 1,
            Token::Match { len, offset } => freq[match_symbol(len, offset)] += 1,
        }
    }
    freq[256] += 1; // end-of-data symbol
    let lens = code_lengths(&freq);
    let codes = canonical(&lens);
    let mut out = Vec::new();
    // Table + roughly the input size; grows if needed.
    out.try_reserve(256 + input.len() + input.len() / 8 + 16).map_err(|_| XpressEncodeError::Allocation)?;
    for i in 0..256 {
        out.push(lens[2 * i] | lens[2 * i + 1] << 4);
    }
    let mut w = BitOut::new(out);
    for t in &tokens {
        match *t {
            Token::Literal(b) => {
                let s = usize::from(b);
                w.bits(u32::from(codes[s]), u32::from(lens[s]));
            }
            Token::Match { len, offset } => {
                let s = match_symbol(len, offset);
                w.bits(u32::from(codes[s]), u32::from(lens[s]));
                let l = len - MIN_MATCH as u32;
                if l >= 15 {
                    if l - 15 < 255 {
                        w.bytes(&[(l - 15) as u8]);
                    } else if l <= 0xFFFF {
                        w.bytes(&[255]);
                        w.bytes(&(l as u16).to_le_bytes());
                    } else {
                        w.bytes(&[255, 0, 0]);
                        w.bytes(&l.to_le_bytes());
                    }
                }
                let ob = offset_bits(offset);
                if ob > 0 {
                    w.bits(offset - (1 << ob), ob);
                }
            }
        }
    }
    w.bits(u32::from(codes[256]), u32::from(lens[256]));
    Ok(w.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xpress_huffman::decompress;

    fn rt(data: &[u8]) -> usize {
        let c = compress(data).unwrap();
        assert_eq!(decompress(&c, data.len(), data.len()).unwrap(), data);
        c.len()
    }

    #[test]
    fn roundtrips() {
        rt(b"a");
        rt(b"abba");
        rt(b"hello sediment\n");
        let rep: Vec<u8> = b"hello sediment\n".repeat(50);
        assert!(rt(&rep) < 400);
        let bin: Vec<u8> = (0..=255u8).cycle().take(10240).collect();
        rt(&bin);
        rt(&[0u8; 65536]);
        let mut x = 12345u32;
        let noise: Vec<u8> = (0..32768)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        rt(&noise);
        // Mixed: long runs force length-extension bytes of every size.
        let mut mixed = noise[..1000].to_vec();
        mixed.extend(std::iter::repeat_n(7u8, 300));
        mixed.extend_from_slice(&noise[..2000]);
        mixed.extend(std::iter::repeat_n(9u8, 20000));
        rt(&mixed);
    }

    #[test]
    fn limits() {
        assert_eq!(compress(&vec![0u8; MAX_BLOCK + 1]), Err(XpressEncodeError::TooLarge));
        assert_eq!(compress(&[]), Ok(Vec::new()));
    }
}
