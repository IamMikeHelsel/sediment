// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compressing raw DEFLATE encoder (LZ77 + fixed/dynamic Huffman).
//!
//! Spec source: RFC 1951 (DEFLATE Compressed Data Format Specification 1.3).
//! The existing `deflate_encode::encode_stored` only emits stored blocks; this
//! module adds real compression. For every block the encoder computes the exact
//! bit cost of stored, fixed-Huffman and dynamic-Huffman encodings and emits the
//! cheapest one, so output never grows by more than stored-block overhead.
//!
//! Matching uses a 3-byte hash chain over a 32 KiB window with per-level chain
//! limits and lazy matching for levels >= 4. Output is fully deterministic.
//! Huffman code lengths are limited to 15 (7 for the code-length alphabet) by
//! repeatedly halving frequencies, which keeps every code complete.

use crate::deflate_tables::{distance_spec, length_spec};
use crate::huffman::canonical_codes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressError {
    /// Level outside 0..=9.
    InvalidLevel,
    /// Output would exceed `max_output`.
    LimitExceeded,
    Allocation,
}

const WINDOW: usize = 32768;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const BLOCK_TOKENS: usize = 32768;
const NO_POS: u32 = u32::MAX;

/// Worst-case output size for `deflate_compress` of `n` input bytes at any level.
pub fn deflate_bound(n: usize) -> Option<usize> {
    // Each block falls back to stored chunks of <= 65535 bytes (5 bytes overhead
    // each, plus up to one byte of alignment). Blocks cover >= 1 input byte each
    // at the stored fallback granularity; bound generously.
    let chunks = n / 16384 + 2;
    n.checked_add(chunks.checked_mul(8)?)?.checked_add(16)
}

#[derive(Clone, Copy)]
enum Token {
    Literal(u8),
    Match { len: u16, dist: u16 },
}

struct Params {
    max_chain: usize,
    nice: usize,
    lazy: bool,
}

fn params(level: u8) -> Params {
    let (max_chain, nice, lazy) = match level {
        1 => (4, 16, false),
        2 => (8, 32, false),
        3 => (16, 32, false),
        4 => (16, 64, true),
        5 => (32, 128, true),
        6 => (128, 128, true),
        7 => (256, 258, true),
        8 => (1024, 258, true),
        _ => (4096, 258, true),
    };
    Params { max_chain, nice, lazy }
}

struct BitSink {
    out: Vec<u8>,
    acc: u64,
    nbits: u32,
    max_output: usize,
}

impl BitSink {
    fn put(&mut self, value: u32, width: u32) -> Result<(), CompressError> {
        if width == 0 {
            return Ok(());
        }
        self.acc |= (value as u64 & ((1u64 << width) - 1)) << self.nbits;
        self.nbits += width;
        while self.nbits >= 8 {
            self.push_byte(self.acc as u8)?;
            self.acc >>= 8;
            self.nbits -= 8;
        }
        Ok(())
    }

    fn push_byte(&mut self, b: u8) -> Result<(), CompressError> {
        if self.out.len() >= self.max_output {
            return Err(CompressError::LimitExceeded);
        }
        if self.out.len() == self.out.capacity() {
            self.out.try_reserve(4096).map_err(|_| CompressError::Allocation)?;
        }
        self.out.push(b);
        Ok(())
    }

    fn align(&mut self) -> Result<(), CompressError> {
        if self.nbits > 0 {
            self.push_byte(self.acc as u8)?;
            self.acc = 0;
            self.nbits = 0;
        }
        Ok(())
    }

    fn put_bytes(&mut self, bytes: &[u8]) -> Result<(), CompressError> {
        debug_assert_eq!(self.nbits, 0);
        let end = self.out.len().checked_add(bytes.len()).ok_or(CompressError::LimitExceeded)?;
        if end > self.max_output {
            return Err(CompressError::LimitExceeded);
        }
        self.out.try_reserve(bytes.len()).map_err(|_| CompressError::Allocation)?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }
}

/// Lookup tables mapping lengths/distances to DEFLATE symbols, built from
/// `deflate_tables` so the encoder and decoder share one source of truth.
struct Tables {
    /// For length 3..=258: (symbol, extra bits, base).
    len_sym: [(u16, u8, u16); 259],
    dist: [(u16, u8); 30],
}

fn build_tables() -> Tables {
    let mut len_sym = [(0u16, 0u8, 0u16); 259];
    for sym in 257u16..=285 {
        if let Ok((base, extra)) = length_spec(sym) {
            let count = 1usize << extra;
            for i in 0..count {
                let l = base as usize + i;
                // Symbol 284 with extra 31 would encode 258; 285 is canonical.
                if (3..=258).contains(&l) && (l != 258 || sym == 285) {
                    len_sym[l] = (sym, extra, base);
                }
            }
        }
    }
    let mut dist = [(0u16, 0u8); 30];
    for (sym, slot) in dist.iter_mut().enumerate() {
        if let Ok(spec) = distance_spec(sym as u16) {
            *slot = spec;
        }
    }
    Tables { len_sym, dist }
}

fn dist_symbol(t: &Tables, d: u16) -> (usize, u8, u16) {
    let mut s = 29;
    while t.dist[s].0 > d {
        s -= 1;
    }
    (s, t.dist[s].1, t.dist[s].0)
}

/// Compress `input` into a raw DEFLATE stream at `level` (0 = stored only, 1..=9).
pub fn deflate_compress(input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, CompressError> {
    if level > 9 {
        return Err(CompressError::InvalidLevel);
    }
    if level == 0 {
        let blocks = input.len() / 65535 + 1;
        return crate::deflate_encode::encode_stored(input, max_output, blocks).map_err(|e| match e {
            crate::deflate_encode::EncodeError::LimitExceeded => CompressError::LimitExceeded,
            crate::deflate_encode::EncodeError::Allocation => CompressError::Allocation,
        });
    }
    let p = params(level);
    let tables = build_tables();

    let mut head: Vec<u32> = Vec::new();
    head.try_reserve_exact(HASH_SIZE).map_err(|_| CompressError::Allocation)?;
    head.resize(HASH_SIZE, NO_POS);
    let mut prev: Vec<u32> = Vec::new();
    prev.try_reserve_exact(WINDOW).map_err(|_| CompressError::Allocation)?;
    prev.resize(WINDOW, NO_POS);
    let mut tokens: Vec<Token> = Vec::new();
    tokens.try_reserve_exact(BLOCK_TOKENS).map_err(|_| CompressError::Allocation)?;

    let mut sink = BitSink {
        out: Vec::new(),
        acc: 0,
        nbits: 0,
        max_output,
    };
    sink.out
        .try_reserve(input.len().min(max_output).min(1 << 20) + 64)
        .map_err(|_| CompressError::Allocation)?;

    let n = input.len();
    let mut pos = 0usize;
    let mut block_start = 0usize;
    let mut inserted = 0usize; // positions < inserted are in the hash chains

    let insert = |head: &mut Vec<u32>, prev: &mut Vec<u32>, i: usize| {
        if i + MIN_MATCH <= n {
            let h = hash3(&input[i..i + 3]);
            prev[i % WINDOW] = head[h];
            head[h] = i as u32;
        }
    };

    if n == 0 {
        write_block(&mut sink, &tables, &tokens, input, true)?;
        sink.align()?;
        return Ok(sink.out);
    }

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
                len: len as u16,
                dist: dist as u16,
            });
            pos += len;
        } else {
            tokens.push(Token::Literal(input[pos]));
            pos += 1;
        }
        if tokens.len() >= BLOCK_TOKENS - 1 {
            write_block(&mut sink, &tables, &tokens, &input[block_start..pos], pos >= n)?;
            tokens.clear();
            block_start = pos;
        }
    }
    if !tokens.is_empty() || block_start < n {
        write_block(&mut sink, &tables, &tokens, &input[block_start..pos], true)?;
    }
    sink.align()?;
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
    let max_len = (n - pos).min(MAX_MATCH);
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
        if input[c + best_len.min(max_len - 1)] == input[pos + best_len.min(max_len - 1)] {
            let mut l = 0;
            while l < max_len && input[c + l] == input[pos + l] {
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
        // Chain entries must strictly decrease; anything else is a stale slot.
        if next == NO_POS || next as usize >= c {
            break;
        }
        cand = next;
        chain -= 1;
    }
    if best_len >= MIN_MATCH { (best_len, best_dist) } else { (0, 0) }
}

const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn fixed_lit_lengths() -> [u8; 288] {
    let mut l = [8u8; 288];
    l[144..256].fill(9);
    l[256..280].fill(7);
    l
}

fn write_block(
    sink: &mut BitSink,
    t: &Tables,
    tokens: &[Token],
    raw: &[u8],
    last: bool,
) -> Result<(), CompressError> {
    // Symbol frequencies.
    let mut lit_freq = [0u32; 286];
    let mut dist_freq = [0u32; 30];
    let mut extra_bits: u64 = 0;
    for tok in tokens {
        match *tok {
            Token::Literal(b) => lit_freq[b as usize] += 1,
            Token::Match { len, dist } => {
                let (s, e, _) = t.len_sym[len as usize];
                lit_freq[s as usize] += 1;
                let (ds, de, _) = dist_symbol(t, dist);
                dist_freq[ds] += 1;
                extra_bits += e as u64 + de as u64;
            }
        }
    }
    lit_freq[256] += 1;

    // Fixed cost.
    let fixed_lit = fixed_lit_lengths();
    let mut fixed_bits: u64 = 3 + extra_bits;
    for (s, &f) in lit_freq.iter().enumerate() {
        fixed_bits += f as u64 * fixed_lit[s] as u64;
    }
    fixed_bits += dist_freq.iter().map(|&f| f as u64 * 5).sum::<u64>();

    // Dynamic code construction. Ensure >= 2 used symbols per tree so every
    // tree is complete and unambiguous for all decoders.
    let mut lf = lit_freq;
    ensure_two(&mut lf);
    let mut df = dist_freq;
    ensure_two(&mut df);
    let lit_len = huffman_lengths(&lf, 15)?;
    let dist_len = huffman_lengths(&df, 15)?;
    let hlit = (257..=286).rev().find(|&k| lit_len[k - 1] != 0).unwrap_or(257).max(257);
    let hdist = (1..=30).rev().find(|&k| dist_len[k - 1] != 0).unwrap_or(1).max(1);
    let mut all = [0u8; 316];
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

    // Stored cost: worst case alignment of 7 bits per chunk plus 5 bytes each.
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

    let (ll, dl): (&[u8], &[u8]);
    let fixed_dist = [5u8; 30];
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
                let (s, e, base) = t.len_sym[len as usize];
                put_code(sink, lcodes[s as usize], ll[s as usize])?;
                sink.put((len - base) as u32, e as u32)?;
                let (ds, de, dbase) = dist_symbol(t, dist);
                put_code(sink, dcodes[ds], dl[ds])?;
                sink.put((dist - dbase) as u32, de as u32)?;
            }
        }
    }
    put_code(sink, lcodes[256], ll[256])?;
    Ok(())
}

fn ensure_two(freq: &mut [u32]) {
    let used = freq.iter().filter(|&&f| f > 0).count();
    if used >= 2 {
        return;
    }
    let mut need = 2 - used;
    for f in freq.iter_mut() {
        if need == 0 {
            break;
        }
        if *f == 0 {
            *f = 1;
            need -= 1;
        }
    }
}

fn codes_for(lengths: &[u8], max_bits: u8) -> Result<Vec<u16>, CompressError> {
    let codes = canonical_codes(lengths, max_bits).map_err(|e| match e {
        crate::huffman::HuffmanError::Allocation => CompressError::Allocation,
        // Lengths are produced internally and are always valid.
        _ => CompressError::LimitExceeded,
    })?;
    Ok(codes.into_iter().map(|c| c.unwrap_or(0)).collect())
}

fn put_code(sink: &mut BitSink, code: u16, len: u8) -> Result<(), CompressError> {
    // Huffman codes are packed MSB-first; reverse into the LSB-first stream.
    let mut rev = 0u32;
    for i in 0..len {
        rev |= ((code as u32 >> i) & 1) << (len - 1 - i);
    }
    sink.put(rev, len as u32)
}

/// Build length-limited Huffman code lengths. Symbols with zero frequency get
/// length 0. Requires at least two nonzero frequencies.
fn huffman_lengths(freq: &[u32], max_bits: u8) -> Result<Vec<u8>, CompressError> {
    let mut f: Vec<u32> = freq.to_vec();
    loop {
        let lens = huffman_unlimited(&f)?;
        if lens.iter().all(|&l| l <= max_bits) {
            return Ok(lens);
        }
        for x in f.iter_mut() {
            if *x > 0 {
                *x = (*x >> 1).max(1);
            }
        }
    }
}

fn huffman_unlimited(freq: &[u32]) -> Result<Vec<u8>, CompressError> {
    // Node arena: leaves first, then internal nodes. Deterministic tie-break by
    // node index.
    let n = freq.len();
    let mut weight: Vec<u64> = Vec::new();
    let mut parent: Vec<usize> = Vec::new();
    weight.try_reserve(2 * n).map_err(|_| CompressError::Allocation)?;
    parent.try_reserve(2 * n).map_err(|_| CompressError::Allocation)?;
    let mut active: Vec<usize> = Vec::new();
    active.try_reserve(n).map_err(|_| CompressError::Allocation)?;
    for (i, &w) in freq.iter().enumerate() {
        weight.push(w as u64);
        parent.push(usize::MAX);
        if w > 0 {
            active.push(i);
        }
    }
    let mut lens = vec![0u8; n];
    if active.len() == 1 {
        lens[active[0]] = 1;
        return Ok(lens);
    }
    while active.len() > 1 {
        // Pick the two smallest (weight, index).
        let mut a = 0;
        let mut b = 1;
        if (weight[active[b]], active[b]) < (weight[active[a]], active[a]) {
            std::mem::swap(&mut a, &mut b);
        }
        for k in 2..active.len() {
            let key = (weight[active[k]], active[k]);
            if key < (weight[active[a]], active[a]) {
                b = a;
                a = k;
            } else if key < (weight[active[b]], active[b]) {
                b = k;
            }
        }
        let (na, nb) = (active[a], active[b]);
        let id = weight.len();
        weight.push(weight[na] + weight[nb]);
        parent.push(usize::MAX);
        parent[na] = id;
        parent[nb] = id;
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        active.swap_remove(hi);
        active[lo] = id;
    }
    for (i, l) in lens.iter_mut().enumerate() {
        if freq[i] == 0 {
            continue;
        }
        let mut d = 0u32;
        let mut x = i;
        while parent[x] != usize::MAX {
            x = parent[x];
            d += 1;
        }
        *l = d.min(255) as u8;
    }
    Ok(lens)
}

/// Run-length encode code lengths with symbols 16/17/18. Returns (symbol, extra).
fn rle_lengths(lens: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let v = lens[i];
        let mut run = 1;
        while i + run < lens.len() && lens[i + run] == v {
            run += 1;
        }
        let mut left = run;
        if v == 0 {
            while left >= 11 {
                let r = left.min(138);
                out.push((18, (r - 11) as u8));
                left -= r;
            }
            if left >= 3 {
                out.push((17, (left - 3) as u8));
                left = 0;
            }
            for _ in 0..left {
                out.push((0, 0));
            }
        } else {
            out.push((v, 0));
            left -= 1;
            while left >= 3 {
                let r = left.min(6);
                out.push((16, (r - 3) as u8));
                left -= r;
            }
            for _ in 0..left {
                out.push((v, 0));
            }
        }
        i += run;
    }
    out
}
