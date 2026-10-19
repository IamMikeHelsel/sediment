// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA encoding: range encoder, hash-chain and binary-tree match finders,
//! a fast (greedy/lazy) parser and a price-based optimal parser, plus the
//! `.lzma` ("LZMA-alone") container.
//!
//! Spec sources: the public-domain `lzma-specification.txt` from the LZMA SDK
//! (Igor Pavlov), which defines the range coder, the adaptive probability
//! model, the state machine and the symbol layout (literal / match / rep /
//! short-rep, length and distance coding). The encoder here is the mirror image
//! of that decoder description; the match finders (hash chains and a binary
//! search tree over the input) and the optimal parser (a forward shortest-path
//! search over symbol prices) are textbook LZ77 techniques written for this
//! crate. The `.lzma` header layout (properties byte, 32-bit dictionary size,
//! 64-bit unpacked size or all-ones for "unknown, end marker present") also
//! comes from that document.
//!
//! The whole input is the sliding window (slices in, `Vec` out), so the match
//! finder tables are sized by `min(dictionary_size, input.len())`. Every
//! table is allocated with `try_reserve` and reported as
//! [`LzmaEncodeError::Allocation`] on failure.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzmaEncodeError {
    /// lc/lp/pb, dictionary size, nice length or depth out of range.
    InvalidOptions,
    /// Input longer than [`MAX_INPUT`].
    InputTooLarge,
    /// A table or output buffer could not be allocated.
    Allocation,
}

/// Match finder used by the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFinder {
    /// Hash chains (fast, used by levels 0-3).
    HashChain,
    /// Binary search trees (slower, finds longer matches; levels 4-9).
    BinaryTree,
}

/// Parsing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Greedy parsing: take the longest match at each position.
    Greedy,
    /// Greedy with one step of lazy evaluation.
    Lazy,
    /// Price-based optimal parsing over a window of positions.
    Optimal,
}

/// Encoder options. Use [`LzmaEncoderOptions::preset`] for xz-like levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaEncoderOptions {
    pub dictionary_size: u32,
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
    pub match_finder: MatchFinder,
    pub mode: ParseMode,
    /// Matches at least this long are taken immediately (2..=273).
    pub nice_len: u32,
    /// Maximum match-finder candidates examined per position (1..=4096).
    pub depth: u32,
}

/// Smallest accepted dictionary size.
pub const MIN_DICTIONARY: u32 = 4096;
/// Largest accepted dictionary size (1.5 GiB).
pub const MAX_DICTIONARY: u32 = 3 << 29;
/// Largest input accepted by one encoder run. Positions are stored as `u32`.
pub const MAX_INPUT: usize = (u32::MAX - 1024) as usize;
/// Shortest and longest match lengths LZMA can express.
pub const MATCH_LEN_MIN: usize = 2;
pub const MATCH_LEN_MAX: usize = 273;

const MAX_DEPTH: u32 = 4096;

impl LzmaEncoderOptions {
    /// Options for compression level 0..=9. Dictionary sizes follow the xz
    /// presets (256 KiB, 1, 2, 4, 4, 8, 8, 16, 32, 64 MiB); levels 0-3 use hash
    /// chains with greedy/lazy parsing, 4-9 binary trees with optimal parsing.
    pub fn preset(level: u32) -> Result<Self, LzmaEncodeError> {
        use MatchFinder::*;
        use ParseMode::*;
        const MIB: u32 = 1 << 20;
        let (dict, mf, mode, nice, depth) = match level {
            0 => (256 << 10, HashChain, Greedy, 32, 4),
            1 => (MIB, HashChain, Greedy, 32, 8),
            2 => (2 * MIB, HashChain, Lazy, 48, 16),
            3 => (4 * MIB, HashChain, Lazy, 64, 32),
            4 => (4 * MIB, BinaryTree, Optimal, 32, 24),
            5 => (8 * MIB, BinaryTree, Optimal, 48, 32),
            6 => (8 * MIB, BinaryTree, Optimal, 64, 48),
            7 => (16 * MIB, BinaryTree, Optimal, 64, 48),
            8 => (32 * MIB, BinaryTree, Optimal, 128, 80),
            9 => (64 * MIB, BinaryTree, Optimal, 273, 160),
            _ => return Err(LzmaEncodeError::InvalidOptions),
        };
        Ok(Self { dictionary_size: dict, lc: 3, lp: 0, pb: 2, match_finder: mf, mode, nice_len: nice, depth })
    }

    /// Check ranges: lc <= 8, lp <= 4, pb <= 4, dictionary within
    /// [`MIN_DICTIONARY`]..=[`MAX_DICTIONARY`], nice length 2..=273,
    /// depth 1..=4096.
    pub fn validate(&self) -> Result<(), LzmaEncodeError> {
        let ok = self.lc <= 8
            && self.lp <= 4
            && self.pb <= 4
            && (MIN_DICTIONARY..=MAX_DICTIONARY).contains(&self.dictionary_size)
            && (MATCH_LEN_MIN as u32..=MATCH_LEN_MAX as u32).contains(&self.nice_len)
            && (1..=MAX_DEPTH).contains(&self.depth);
        if ok { Ok(()) } else { Err(LzmaEncodeError::InvalidOptions) }
    }
}

/// Encode `(lc, lp, pb)` as the LZMA properties byte.
pub fn props_byte(lc: u8, lp: u8, pb: u8) -> u8 {
    (pb * 5 + lp) * 9 + lc
}

/// Round `size` up to the nearest `2^n` or `3 * 2^(n-1)` (n >= 12), the set
/// representable by the LZMA2 dictionary property byte.
pub fn round_dictionary_size(size: u32) -> u32 {
    let mut byte = 0u32;
    loop {
        let d = (2u64 | (byte & 1) as u64) << (byte / 2 + 11);
        if d >= size as u64 || byte >= 39 {
            return d.min(u32::MAX as u64) as u32;
        }
        byte += 1;
    }
}

/// The dictionary size the encoder actually declares for an input of
/// `input_len` bytes: the configured size, shrunk to the input length (never
/// below 4 KiB) and rounded up with [`round_dictionary_size`]. Distances never
/// exceed this value.
pub fn effective_dictionary_size(dictionary_size: u32, input_len: usize) -> u32 {
    let len = u32::try_from(input_len).unwrap_or(u32::MAX).max(MIN_DICTIONARY);
    round_dictionary_size(dictionary_size.min(len).max(MIN_DICTIONARY))
}

/// Encode `input` as a raw LZMA stream (no header). With `end_marker` the
/// stream is terminated by the end-of-payload marker; otherwise the decoder
/// must know the unpacked size. The dictionary size the decoder needs is
/// [`effective_dictionary_size`]`(opts.dictionary_size, input.len())`.
pub fn encode_lzma_raw(input: &[u8], opts: &LzmaEncoderOptions, end_marker: bool) -> Result<Vec<u8>, LzmaEncodeError> {
    let mut enc = Encoder::new(input, opts, opts.lc, opts.lp)?;
    let mut rc = RangeEncoder::new();
    enc.encode_until(&mut rc, usize::MAX, usize::MAX)?;
    if end_marker {
        enc.encode_end_marker(&mut rc);
    }
    rc.finish()
}

/// Encode a complete `.lzma` file. With `end_marker == false` the header
/// stores the exact unpacked size and no end marker is written; with `true`
/// the size field is all ones and the stream ends with an end marker.
pub fn encode_lzma_alone(input: &[u8], opts: &LzmaEncoderOptions, end_marker: bool) -> Result<Vec<u8>, LzmaEncodeError> {
    opts.validate()?;
    let dict = effective_dictionary_size(opts.dictionary_size, input.len());
    let body = encode_lzma_raw(input, opts, end_marker)?;
    let mut out = Vec::new();
    out.try_reserve_exact(body.len() + 13).map_err(|_| LzmaEncodeError::Allocation)?;
    out.push(props_byte(opts.lc, opts.lp, opts.pb));
    out.extend_from_slice(&dict.to_le_bytes());
    let size = if end_marker { u64::MAX } else { input.len() as u64 };
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Range encoder
// ---------------------------------------------------------------------------

const PROB_INIT: u16 = 1024;
const NUM_STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const LEN_SYMBOLS: usize = 272;

pub(crate) struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
    failed: bool,
}

impl RangeEncoder {
    pub(crate) fn new() -> Self {
        Self { low: 0, range: u32::MAX, cache: 0, cache_size: 1, out: Vec::new(), failed: false }
    }

    /// Upper bound on the flushed size if encoding stopped now.
    pub(crate) fn pending_len(&self) -> usize {
        self.out.len().saturating_add(self.cache_size as usize).saturating_add(5)
    }

    fn push(&mut self, b: u8) {
        if self.out.len() == self.out.capacity() {
            let add = self.out.len().clamp(4096, 1 << 24);
            if self.out.try_reserve(add).is_err() {
                self.failed = true;
                return;
            }
        }
        self.out.push(b);
    }

    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || self.low >= 1 << 32 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    #[inline]
    fn bit(&mut self, prob: &mut u16, bit: u32) {
        let p = *prob as u32;
        let bound = (self.range >> 11) * p;
        if bit == 0 {
            self.range = bound;
            *prob = (p + ((2048 - p) >> 5)) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *prob = (p - (p >> 5)) as u16;
        }
        while self.range < (1 << 24) {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn direct_bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.range >>= 1;
            if (value >> i) & 1 != 0 {
                self.low += self.range as u64;
            }
            while self.range < (1 << 24) {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32, sym: u32) {
        let mut m = 1usize;
        for i in (0..bits).rev() {
            let b = (sym >> i) & 1;
            self.bit(&mut probs[m], b);
            m = (m << 1) | b as usize;
        }
    }

    fn reverse_tree(&mut self, probs: &mut [u16], bits: u32, mut sym: u32) {
        let mut m = 1usize;
        for _ in 0..bits {
            let b = sym & 1;
            sym >>= 1;
            self.bit(&mut probs[m], b);
            m = (m << 1) | b as usize;
        }
    }

    /// Flush the coder and return the encoded bytes.
    pub(crate) fn finish(mut self) -> Result<Vec<u8>, LzmaEncodeError> {
        for _ in 0..5 {
            self.shift_low();
        }
        if self.failed {
            return Err(LzmaEncodeError::Allocation);
        }
        Ok(self.out)
    }
}

// ---------------------------------------------------------------------------
// Prices (in 1/16 bit units)
// ---------------------------------------------------------------------------

const INF: u32 = u32::MAX / 4;

fn price_table() -> &'static [u32; 128] {
    static TABLE: OnceLock<[u32; 128]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 128];
        for (i, v) in t.iter_mut().enumerate() {
            let p = (i as f64 * 16.0 + 8.0) / 2048.0;
            *v = (-p.log2() * 16.0).round() as u32;
        }
        t
    })
}

#[inline]
fn price(t: &[u32; 128], prob: u16, bit: u32) -> u32 {
    let p = if bit == 0 { prob as u32 } else { 2048 - prob as u32 };
    t[(p >> 4) as usize]
}

fn tree_price(t: &[u32; 128], probs: &[u16], bits: u32, sym: u32) -> u32 {
    let mut m = 1usize;
    let mut sum = 0;
    for i in (0..bits).rev() {
        let b = (sym >> i) & 1;
        sum += price(t, probs[m], b);
        m = (m << 1) | b as usize;
    }
    sum
}

fn reverse_tree_price(t: &[u32; 128], probs: &[u16], bits: u32, mut sym: u32) -> u32 {
    let mut m = 1usize;
    let mut sum = 0;
    for _ in 0..bits {
        let b = sym & 1;
        sym >>= 1;
        sum += price(t, probs[m], b);
        m = (m << 1) | b as usize;
    }
    sum
}

// ---------------------------------------------------------------------------
// Probability model
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LenModel {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES_MAX],
    mid: [[u16; 8]; POS_STATES_MAX],
    high: [u16; 256],
}

impl LenModel {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; 8]; POS_STATES_MAX],
            mid: [[PROB_INIT; 8]; POS_STATES_MAX],
            high: [PROB_INIT; 256],
        }
    }

    /// `sym` is `len - 2`.
    fn encode(&mut self, rc: &mut RangeEncoder, sym: u32, ps: usize) {
        if sym < 8 {
            rc.bit(&mut self.choice, 0);
            rc.tree(&mut self.low[ps], 3, sym);
        } else if sym < 16 {
            rc.bit(&mut self.choice, 1);
            rc.bit(&mut self.choice2, 0);
            rc.tree(&mut self.mid[ps], 3, sym - 8);
        } else {
            rc.bit(&mut self.choice, 1);
            rc.bit(&mut self.choice2, 1);
            rc.tree(&mut self.high, 8, sym - 16);
        }
    }

    fn prices(&self, t: &[u32; 128], ps: usize, out: &mut [u32]) {
        let c0 = price(t, self.choice, 0);
        let c1 = price(t, self.choice, 1);
        let c10 = c1 + price(t, self.choice2, 0);
        let c11 = c1 + price(t, self.choice2, 1);
        for (s, v) in out.iter_mut().enumerate().take(LEN_SYMBOLS) {
            let s = s as u32;
            *v = if s < 8 {
                c0 + tree_price(t, &self.low[ps], 3, s)
            } else if s < 16 {
                c10 + tree_price(t, &self.mid[ps], 3, s - 8)
            } else {
                c11 + tree_price(t, &self.high, 8, s - 16)
            };
        }
    }
}

const LIT_NEXT: [u8; NUM_STATES] = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5];

#[inline]
fn match_next(st: u8) -> u8 {
    if st < 7 { 7 } else { 10 }
}
#[inline]
fn rep_next(st: u8) -> u8 {
    if st < 7 { 8 } else { 11 }
}
#[inline]
fn shortrep_next(st: u8) -> u8 {
    if st < 7 { 9 } else { 11 }
}

/// Position slot of a zero-based distance.
#[inline]
fn dist_slot(d0: u32) -> u32 {
    if d0 < 4 {
        d0
    } else {
        let n = 31 - d0.leading_zeros();
        (n << 1) | ((d0 >> (n - 1)) & 1)
    }
}

struct Model {
    lc: u32,
    lp: u32,
    pb: u32,
    literal: Vec<u16>,
    is_match: [u16; NUM_STATES * POS_STATES_MAX],
    is_rep: [u16; NUM_STATES],
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [u16; NUM_STATES * POS_STATES_MAX],
    pos_slot: [[u16; 64]; 4],
    pos_special: [u16; 115],
    align: [u16; 16],
    len: LenModel,
    rep_len: LenModel,
    state: u8,
    reps: [u32; 4],
}

impl Model {
    fn new(lc: u8, lp: u8, pb: u8) -> Result<Self, LzmaEncodeError> {
        let n = 0x300usize << (lc as u32 + lp as u32);
        let mut literal = Vec::new();
        literal.try_reserve_exact(n).map_err(|_| LzmaEncodeError::Allocation)?;
        literal.resize(n, PROB_INIT);
        Ok(Self {
            lc: lc as u32,
            lp: lp as u32,
            pb: pb as u32,
            literal,
            is_match: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
            is_rep: [PROB_INIT; NUM_STATES],
            is_rep_g0: [PROB_INIT; NUM_STATES],
            is_rep_g1: [PROB_INIT; NUM_STATES],
            is_rep_g2: [PROB_INIT; NUM_STATES],
            is_rep0_long: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
            pos_slot: [[PROB_INIT; 64]; 4],
            pos_special: [PROB_INIT; 115],
            align: [PROB_INIT; 16],
            len: LenModel::new(),
            rep_len: LenModel::new(),
            state: 0,
            reps: [0; 4],
        })
    }

    fn reset(&mut self) {
        self.literal.iter_mut().for_each(|p| *p = PROB_INIT);
        self.is_match = [PROB_INIT; NUM_STATES * POS_STATES_MAX];
        self.is_rep = [PROB_INIT; NUM_STATES];
        self.is_rep_g0 = [PROB_INIT; NUM_STATES];
        self.is_rep_g1 = [PROB_INIT; NUM_STATES];
        self.is_rep_g2 = [PROB_INIT; NUM_STATES];
        self.is_rep0_long = [PROB_INIT; NUM_STATES * POS_STATES_MAX];
        self.pos_slot = [[PROB_INIT; 64]; 4];
        self.pos_special = [PROB_INIT; 115];
        self.align = [PROB_INIT; 16];
        self.len = LenModel::new();
        self.rep_len = LenModel::new();
        self.state = 0;
        self.reps = [0; 4];
    }

    #[inline]
    fn lit_base(&self, data: &[u8], pos: usize) -> usize {
        let prev = if pos > 0 { data[pos - 1] as usize } else { 0 };
        let lp_mask = (1usize << self.lp) - 1;
        let lit_state = ((pos & lp_mask) << self.lc) + (prev >> (8 - self.lc));
        0x300 * lit_state
    }

    fn encode_distance(&mut self, rc: &mut RangeEncoder, d0: u32, len_sym: u32) {
        let ls = len_sym.min(3) as usize;
        let slot = dist_slot(d0);
        rc.tree(&mut self.pos_slot[ls], 6, slot);
        if slot >= 4 {
            let direct = (slot >> 1) - 1;
            let base = (2 | (slot & 1)) << direct;
            let rem = d0 - base;
            if slot < 14 {
                rc.reverse_tree(&mut self.pos_special[(base - slot) as usize..], direct, rem);
            } else {
                rc.direct_bits(rem >> 4, direct - 4);
                rc.reverse_tree(&mut self.align, 4, rem & 15);
            }
        }
    }

    fn literal_price(&self, t: &[u32; 128], data: &[u8], pos: usize, st: u8, rep0: u32) -> u32 {
        let base = self.lit_base(data, pos);
        let probs = &self.literal[base..base + 0x300];
        let byte = data[pos] as u32;
        if st < 7 {
            return tree_price(t, probs, 8, byte);
        }
        let mb = data[pos - rep0 as usize - 1] as u32;
        let mut m = 1usize;
        let mut sum = 0;
        let mut matched = true;
        for i in (0..8).rev() {
            let b = (byte >> i) & 1;
            if matched {
                let mbit = (mb >> i) & 1;
                sum += price(t, probs[(((1 + mbit) as usize) << 8) + m], b);
                matched = mbit == b;
            } else {
                sum += price(t, probs[m], b);
            }
            m = (m << 1) | b as usize;
        }
        sum
    }
}

// ---------------------------------------------------------------------------
// Match finder
// ---------------------------------------------------------------------------

const EMPTY: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Match {
    len: u32,
    /// Actual distance (>= 1).
    dist: u32,
}

fn alloc_u32(n: usize, fill: u32) -> Result<Vec<u32>, LzmaEncodeError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| LzmaEncodeError::Allocation)?;
    v.resize(n, fill);
    Ok(v)
}

#[inline]
fn common_len(data: &[u8], a: usize, b: usize, limit: usize) -> usize {
    data[a..a + limit].iter().zip(&data[b..b + limit]).take_while(|(x, y)| x == y).count()
}

struct Finder {
    bt: bool,
    nice: usize,
    depth: u32,
    dict: usize,
    head2: Vec<u32>,
    head3: Vec<u32>,
    head4: Vec<u32>,
    h4_shift: u32,
    links: Vec<u32>,
    cyc: usize,
    pos: usize,
}

const H3_BITS: u32 = 16;

impl Finder {
    fn new(len: usize, dict: usize, kind: MatchFinder, nice: usize, depth: u32) -> Result<Self, LzmaEncodeError> {
        let span = dict.min(len).max(1);
        let bits = (usize::BITS - span.leading_zeros()).clamp(10, 22);
        let cyc = span + 1;
        let bt = kind == MatchFinder::BinaryTree;
        let links = alloc_u32(if bt { cyc.checked_mul(2).ok_or(LzmaEncodeError::Allocation)? } else { cyc }, EMPTY)?;
        Ok(Self {
            bt,
            nice,
            depth,
            dict,
            head2: alloc_u32(1 << 16, EMPTY)?,
            head3: alloc_u32(1 << H3_BITS, EMPTY)?,
            head4: alloc_u32(1 << bits, EMPTY)?,
            h4_shift: 32 - bits,
            links,
            cyc,
            pos: 0,
        })
    }

    #[inline]
    fn hashes(&self, data: &[u8], pos: usize, avail: usize) -> (usize, usize, usize) {
        let b0 = data[pos] as u32;
        let b1 = data[pos + 1] as u32;
        let h2 = (b0 | (b1 << 8)) as usize;
        let h3 = if avail >= 3 {
            let v = b0 | (b1 << 8) | ((data[pos + 2] as u32) << 16);
            (v.wrapping_mul(0x9E37_79B1) >> (32 - H3_BITS)) as usize
        } else {
            0
        };
        let h4 = if avail >= 4 {
            let v = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            (v.wrapping_mul(0x9E37_79B1) >> self.h4_shift) as usize
        } else {
            0
        };
        (h2, h3, h4)
    }

    #[inline]
    fn within(&self, pos: usize, cand: u32) -> bool {
        cand != EMPTY && pos - cand as usize <= self.dict
    }

    /// Find matches at the current position (strictly increasing lengths,
    /// the longest extended up to 273), insert it, and advance by one.
    fn find(&mut self, data: &[u8], out: &mut Vec<Match>) {
        out.clear();
        let pos = self.pos;
        self.pos += 1;
        let avail = data.len() - pos;
        if avail < 2 {
            return;
        }
        let max_len = avail.min(MATCH_LEN_MAX);
        let nice = self.nice.min(max_len);
        let (h2, h3, h4) = self.hashes(data, pos, avail);
        let mut best = 1usize;

        let c2 = self.head2[h2];
        self.head2[h2] = pos as u32;
        if self.within(pos, c2) {
            let l = common_len(data, c2 as usize, pos, max_len);
            if l > best {
                best = l;
                out.push(Match { len: l as u32, dist: (pos - c2 as usize) as u32 });
            }
        }
        if avail >= 3 {
            let c3 = self.head3[h3];
            self.head3[h3] = pos as u32;
            if c3 != c2 && self.within(pos, c3) && best < max_len {
                let l = common_len(data, c3 as usize, pos, max_len);
                if l > best {
                    best = l;
                    out.push(Match { len: l as u32, dist: (pos - c3 as usize) as u32 });
                }
            }
        }
        if avail >= 4 {
            let c4 = self.head4[h4];
            self.head4[h4] = pos as u32;
            if self.bt {
                self.bt_step(data, pos, c4, self.nice.min(avail), Some(out), &mut best);
            } else {
                self.links[pos % self.cyc] = c4;
                let mut cand = c4;
                let mut d = self.depth;
                while best < nice && d > 0 && self.within(pos, cand) {
                    d -= 1;
                    let c = cand as usize;
                    if data[c + best] == data[pos + best] {
                        let l = common_len(data, c, pos, max_len);
                        if l > best {
                            best = l;
                            out.push(Match { len: l as u32, dist: (pos - c) as u32 });
                        }
                    }
                    cand = self.links[c % self.cyc];
                }
            }
        }
        // Extend a match cut at the nice length (binary tree keys stop there).
        if let Some(last) = out.last_mut() {
            let l = last.len as usize;
            if l < max_len && l >= nice {
                let src = pos - last.dist as usize;
                last.len = (l + common_len(data, src + l, pos + l, max_len - l)) as u32;
            }
        }
    }

    /// Insert the next `n` positions without reporting matches.
    fn skip(&mut self, data: &[u8], n: usize) {
        for _ in 0..n {
            let pos = self.pos;
            self.pos += 1;
            let avail = data.len() - pos;
            if avail < 2 {
                continue;
            }
            let (h2, h3, h4) = self.hashes(data, pos, avail);
            self.head2[h2] = pos as u32;
            if avail >= 3 {
                self.head3[h3] = pos as u32;
            }
            if avail >= 4 {
                let c4 = self.head4[h4];
                self.head4[h4] = pos as u32;
                if self.bt {
                    let mut best = usize::MAX;
                    self.bt_step(data, pos, c4, self.nice.min(avail), None, &mut best);
                } else {
                    self.links[pos % self.cyc] = c4;
                }
            }
        }
    }

    /// Binary-tree search and insertion of `pos`, with key length `limit`.
    /// The tree rooted at the newest position orders suffixes
    /// lexicographically (left = smaller).
    fn bt_step(&mut self, data: &[u8], pos: usize, mut cand: u32, limit: usize, mut out: Option<&mut Vec<Match>>, best: &mut usize) {
        let slot = pos % self.cyc;
        let mut left = 2 * slot;
        let mut right = 2 * slot + 1;
        let mut len_l = 0usize;
        let mut len_r = 0usize;
        let mut d = self.depth;
        loop {
            if d == 0 || !self.within(pos, cand) {
                self.links[left] = EMPTY;
                self.links[right] = EMPTY;
                return;
            }
            d -= 1;
            let c = cand as usize;
            let mut len = len_l.min(len_r);
            len += common_len(data, c + len, pos + len, limit - len);
            if len > *best {
                *best = len;
                if let Some(o) = out.as_deref_mut() {
                    o.push(Match { len: len as u32, dist: (pos - c) as u32 });
                }
            }
            let cs = c % self.cyc;
            if len == limit {
                self.links[left] = self.links[2 * cs];
                self.links[right] = self.links[2 * cs + 1];
                return;
            }
            if data[c + len] < data[pos + len] {
                self.links[left] = cand;
                left = 2 * cs + 1;
                cand = self.links[left];
                len_l = len;
            } else {
                self.links[right] = cand;
                right = 2 * cs;
                cand = self.links[right];
                len_r = len;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encoder (resumable; LZMA2 drives it chunk by chunk)
// ---------------------------------------------------------------------------

/// One decided symbol. `dist == 0` is a literal; otherwise a match of `len`
/// bytes at actual distance `dist` (rep vs. normal is resolved when encoding).
#[derive(Debug, Clone, Copy)]
struct Op {
    len: u32,
    dist: u32,
}

#[derive(Clone, Copy)]
struct Node {
    price: u32,
    prev: u32,
    len: u32,
    dist: u32,
    state: u8,
    reps: [u32; 4],
}

const OPT_WIN: usize = 4096;
/// Worst-case bytes one symbol can add to the range coder output.
const OP_MARGIN: usize = 64;
const PRICE_REFRESH: usize = 4096;

struct Prices {
    match_len: Vec<[u32; LEN_SYMBOLS]>,
    rep_len: Vec<[u32; LEN_SYMBOLS]>,
    slot: [[u32; 64]; 4],
    small: [[u32; 128]; 4],
    align: [u32; 16],
}

#[inline]
fn dist_price(p: &Prices, d0: u32, len: usize) -> u32 {
    let ls = (len - 2).min(3);
    if d0 < 128 {
        p.small[ls][d0 as usize]
    } else {
        p.slot[ls][dist_slot(d0) as usize] + p.align[(d0 & 15) as usize]
    }
}

fn rep_choice_price(t: &[u32; 128], m: &Model, r: usize, s: usize, ps: usize) -> u32 {
    match r {
        0 => price(t, m.is_rep_g0[s], 0) + price(t, m.is_rep0_long[(s << 4) | ps], 1),
        1 => price(t, m.is_rep_g0[s], 1) + price(t, m.is_rep_g1[s], 0),
        _ => price(t, m.is_rep_g0[s], 1) + price(t, m.is_rep_g1[s], 1) + price(t, m.is_rep_g2[s], (r == 3) as u32),
    }
}

pub(crate) struct Encoder<'a> {
    data: &'a [u8],
    pos: usize,
    parse_pos: usize,
    model: Model,
    finder: Finder,
    dict: usize,
    nice: usize,
    mode: ParseMode,
    queue: Vec<Op>,
    queue_head: usize,
    matches: Vec<Match>,
    matches2: Vec<Match>,
    nodes: Vec<Node>,
    prices: Prices,
    prices_at: Option<usize>,
}

impl<'a> Encoder<'a> {
    /// `lc`/`lp` are passed separately so LZMA2 can enforce lc + lp <= 4.
    pub(crate) fn new(data: &'a [u8], opts: &LzmaEncoderOptions, lc: u8, lp: u8) -> Result<Self, LzmaEncodeError> {
        opts.validate()?;
        if data.len() > MAX_INPUT {
            return Err(LzmaEncodeError::InputTooLarge);
        }
        let dict = effective_dictionary_size(opts.dictionary_size, data.len()) as usize;
        let model = Model::new(lc, lp, opts.pb)?;
        let finder = Finder::new(data.len(), dict, opts.match_finder, opts.nice_len as usize, opts.depth)?;
        let mut queue = Vec::new();
        queue.try_reserve_exact(OPT_WIN + 1).map_err(|_| LzmaEncodeError::Allocation)?;
        let mut nodes = Vec::new();
        let n_nodes = if opts.mode == ParseMode::Optimal { OPT_WIN + MATCH_LEN_MAX + 2 } else { 0 };
        nodes.try_reserve_exact(n_nodes).map_err(|_| LzmaEncodeError::Allocation)?;
        nodes.resize(n_nodes, Node { price: INF, prev: 0, len: 0, dist: 0, state: 0, reps: [0; 4] });
        let mut matches = Vec::new();
        matches.try_reserve_exact(MATCH_LEN_MAX + 4).map_err(|_| LzmaEncodeError::Allocation)?;
        let mut matches2 = Vec::new();
        matches2.try_reserve_exact(MATCH_LEN_MAX + 4).map_err(|_| LzmaEncodeError::Allocation)?;
        let num_ps = 1usize << opts.pb;
        let mut match_len = Vec::new();
        let mut rep_len = Vec::new();
        match_len.try_reserve_exact(num_ps).map_err(|_| LzmaEncodeError::Allocation)?;
        rep_len.try_reserve_exact(num_ps).map_err(|_| LzmaEncodeError::Allocation)?;
        match_len.resize(num_ps, [0; LEN_SYMBOLS]);
        rep_len.resize(num_ps, [0; LEN_SYMBOLS]);
        Ok(Self {
            data,
            pos: 0,
            parse_pos: 0,
            model,
            finder,
            dict,
            nice: opts.nice_len as usize,
            mode: opts.mode,
            queue,
            queue_head: 0,
            matches,
            matches2,
            nodes,
            prices: Prices { match_len, rep_len, slot: [[0; 64]; 4], small: [[0; 128]; 4], align: [0; 16] },
            prices_at: None,
        })
    }

    /// Number of input bytes already encoded.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Reset probabilities, state and reps (LZMA2 state reset).
    pub(crate) fn reset_state(&mut self) {
        self.model.reset();
        self.prices_at = None;
    }

    /// Encode symbols until the input is exhausted, `max_unc` more bytes
    /// would be exceeded, or the coder output could exceed `max_packed`.
    pub(crate) fn encode_until(&mut self, rc: &mut RangeEncoder, max_unc: usize, max_packed: usize) -> Result<(), LzmaEncodeError> {
        let start = self.pos;
        loop {
            if self.queue_head >= self.queue.len() {
                if self.pos >= self.data.len() {
                    return Ok(());
                }
                self.queue.clear();
                self.queue_head = 0;
                match self.mode {
                    ParseMode::Optimal => self.parse_optimal(),
                    ParseMode::Greedy => self.parse_fast(false),
                    ParseMode::Lazy => self.parse_fast(true),
                }
            }
            let op = self.queue[self.queue_head];
            if self.pos - start + op.len as usize > max_unc || rc.pending_len().saturating_add(OP_MARGIN) > max_packed {
                return Ok(());
            }
            self.queue_head += 1;
            self.encode_op(rc, op);
            if rc.failed {
                return Err(LzmaEncodeError::Allocation);
            }
        }
    }

    pub(crate) fn encode_end_marker(&mut self, rc: &mut RangeEncoder) {
        let m = &mut self.model;
        let ps = self.pos & ((1 << m.pb) - 1);
        let st = m.state as usize;
        rc.bit(&mut m.is_match[(st << 4) | ps], 1);
        rc.bit(&mut m.is_rep[st], 0);
        m.len.encode(rc, 0, ps);
        m.encode_distance(rc, u32::MAX, 0);
        m.state = match_next(m.state);
    }

    fn encode_op(&mut self, rc: &mut RangeEncoder, op: Op) {
        let data = self.data;
        let pos = self.pos;
        let m = &mut self.model;
        let ps = pos & ((1 << m.pb) - 1);
        let st = m.state;
        let s = st as usize;
        let len = op.len;
        let literal = op.dist == 0 || (len == 1 && op.dist - 1 != m.reps[0]);
        if literal {
            rc.bit(&mut m.is_match[(s << 4) | ps], 0);
            let base = m.lit_base(data, pos);
            let probs = &mut m.literal[base..base + 0x300];
            let byte = data[pos] as u32;
            if st < 7 {
                rc.tree(probs, 8, byte);
            } else {
                let mb = data[pos - m.reps[0] as usize - 1] as u32;
                let mut idx = 1usize;
                let mut matched = true;
                for i in (0..8).rev() {
                    let b = (byte >> i) & 1;
                    if matched {
                        let mbit = (mb >> i) & 1;
                        rc.bit(&mut probs[(((1 + mbit) as usize) << 8) + idx], b);
                        matched = mbit == b;
                    } else {
                        rc.bit(&mut probs[idx], b);
                    }
                    idx = (idx << 1) | b as usize;
                }
            }
            m.state = LIT_NEXT[s];
            self.pos += 1;
            return;
        }
        let d0 = op.dist - 1;
        rc.bit(&mut m.is_match[(s << 4) | ps], 1);
        if len == 1 {
            rc.bit(&mut m.is_rep[s], 1);
            rc.bit(&mut m.is_rep_g0[s], 0);
            rc.bit(&mut m.is_rep0_long[(s << 4) | ps], 0);
            m.state = shortrep_next(st);
            self.pos += 1;
            return;
        }
        if let Some(r) = m.reps.iter().position(|&x| x == d0) {
            rc.bit(&mut m.is_rep[s], 1);
            if r == 0 {
                rc.bit(&mut m.is_rep_g0[s], 0);
                rc.bit(&mut m.is_rep0_long[(s << 4) | ps], 1);
            } else {
                rc.bit(&mut m.is_rep_g0[s], 1);
                if r == 1 {
                    rc.bit(&mut m.is_rep_g1[s], 0);
                } else {
                    rc.bit(&mut m.is_rep_g1[s], 1);
                    rc.bit(&mut m.is_rep_g2[s], (r == 3) as u32);
                }
                for k in (1..=r).rev() {
                    m.reps[k] = m.reps[k - 1];
                }
                m.reps[0] = d0;
            }
            m.rep_len.encode(rc, len - 2, ps);
            m.state = rep_next(st);
        } else {
            debug_assert!((d0 as usize) < pos && (d0 as usize) < self.dict);
            rc.bit(&mut m.is_rep[s], 0);
            m.len.encode(rc, len - 2, ps);
            m.encode_distance(rc, d0, len - 2);
            m.reps = [d0, m.reps[0], m.reps[1], m.reps[2]];
            m.state = match_next(st);
        }
        self.pos += len as usize;
    }

    fn refresh_prices(&mut self) {
        let t = price_table();
        let m = &self.model;
        let p = &mut self.prices;
        for ps in 0..p.match_len.len() {
            m.len.prices(t, ps, &mut p.match_len[ps]);
            m.rep_len.prices(t, ps, &mut p.rep_len[ps]);
        }
        for ls in 0..4 {
            for slot in 0..64u32 {
                let mut v = tree_price(t, &m.pos_slot[ls], 6, slot);
                if slot >= 14 {
                    v += ((slot >> 1) - 1 - 4) << 4;
                }
                p.slot[ls][slot as usize] = v;
            }
            for d0 in 0..128u32 {
                let slot = dist_slot(d0);
                let mut v = p.slot[ls][slot as usize];
                if slot >= 4 {
                    let direct = (slot >> 1) - 1;
                    let base = (2 | (slot & 1)) << direct;
                    v += reverse_tree_price(t, &m.pos_special[(base - slot) as usize..], direct, d0 - base);
                }
                p.small[ls][d0 as usize] = v;
            }
        }
        for (i, v) in p.align.iter_mut().enumerate() {
            *v = reverse_tree_price(t, &m.align, 4, i as u32);
        }
        self.prices_at = Some(self.pos);
    }

    /// Longest rep match at `cur` among `reps`: `(len, index)`.
    fn best_rep(&self, cur: usize, reps: &[u32; 4], max_len: usize) -> (usize, usize) {
        let mut best = (0, 0);
        if max_len < 2 {
            return best;
        }
        for (r, &d0) in reps.iter().enumerate() {
            let d0 = d0 as usize;
            if d0 >= cur || d0 >= self.dict {
                continue;
            }
            let src = cur - d0 - 1;
            if self.data[src] != self.data[cur] || self.data[src + 1] != self.data[cur + 1] {
                continue;
            }
            let l = common_len(self.data, src, cur, max_len);
            if l > best.0 {
                best = (l, r);
            }
        }
        best
    }

    fn parse_fast(&mut self, lazy: bool) {
        let data = self.data;
        let total = data.len();
        let start = self.parse_pos;
        let stop = (start + OPT_WIN).min(total);
        let mut reps = self.model.reps;
        let mut cur = start;
        let mut cached = false;
        loop {
            if !cached {
                self.finder.find(data, &mut self.matches);
            }
            cached = false;
            let max_len = (total - cur).min(MATCH_LEN_MAX);
            let (rlen, r) = self.best_rep(cur, &reps, max_len);
            let (mlen, mdist) = self.matches.last().map(|m| (m.len as usize, m.dist)).unwrap_or((0, 0));
            let mlen_ok = mlen >= 2 && !(mlen == 2 && mdist > 128) && !(mlen == 3 && mdist > (1 << 14));
            if rlen >= 2 && (rlen >= self.nice || rlen + 1 >= mlen || !mlen_ok) {
                let d0 = reps[r];
                self.queue.push(Op { len: rlen as u32, dist: d0 + 1 });
                for k in (1..=r).rev() {
                    reps[k] = reps[k - 1];
                }
                reps[0] = d0;
                self.finder.skip(data, rlen - 1);
                cur += rlen;
            } else if mlen_ok {
                if lazy && mlen < self.nice && cur + 1 < total {
                    self.finder.find(data, &mut self.matches2);
                    let next = self.matches2.last().map(|m| m.len as usize).unwrap_or(0);
                    if next > mlen {
                        self.queue.push(Op { len: 1, dist: 0 });
                        cur += 1;
                        std::mem::swap(&mut self.matches, &mut self.matches2);
                        cached = true;
                        continue;
                    }
                    self.finder.skip(data, mlen - 2);
                } else {
                    self.finder.skip(data, mlen - 1);
                }
                self.queue.push(Op { len: mlen as u32, dist: mdist });
                reps = [mdist - 1, reps[0], reps[1], reps[2]];
                cur += mlen;
            } else {
                self.queue.push(Op { len: 1, dist: 0 });
                cur += 1;
            }
            if cur >= stop {
                break;
            }
        }
        self.parse_pos = cur;
    }

    fn parse_optimal(&mut self) {
        let data = self.data;
        let total = data.len();
        let start = self.parse_pos;
        if self.prices_at.is_none_or(|p| self.pos - p >= PRICE_REFRESH) {
            self.refresh_prices();
        }
        let t = price_table();
        let pb_mask = (1usize << self.model.pb) - 1;
        let limit = OPT_WIN.min(total - start);
        self.nodes[0] = Node { price: 0, prev: 0, len: 0, dist: 0, state: self.model.state, reps: self.model.reps };
        let mut reach = 0usize;
        let mut i = 0usize;
        let end;
        loop {
            if (i == reach && i > 0) || i >= limit {
                end = i;
                break;
            }
            let cur = start + i;
            let mut matches = std::mem::take(&mut self.matches);
            self.finder.find(data, &mut matches);
            let node = self.nodes[i];
            let st = node.state;
            let s = st as usize;
            let ps = cur & pb_mask;
            let max_len = (total - cur).min(MATCH_LEN_MAX);
            let (rlen, r) = self.best_rep(cur, &node.reps, max_len);
            let mlen = matches.last().map(|m| m.len as usize).unwrap_or(0);
            let m = &self.model;
            let is_match1 = price(t, m.is_match[(s << 4) | ps], 1);

            if rlen >= self.nice || mlen >= self.nice {
                // Long match: take it and close the window after it.
                let (len, cand) = if rlen >= mlen {
                    let d0 = node.reps[r];
                    let mut reps = node.reps;
                    for k in (1..=r).rev() {
                        reps[k] = reps[k - 1];
                    }
                    reps[0] = d0;
                    let p = node.price
                        + is_match1
                        + price(t, m.is_rep[s], 1)
                        + rep_choice_price(t, m, r, s, ps)
                        + self.prices.rep_len[ps][rlen - 2];
                    (rlen, Node { price: p, prev: i as u32, len: rlen as u32, dist: d0 + 1, state: rep_next(st), reps })
                } else {
                    let mm = *matches.last().unwrap_or(&Match { len: 0, dist: 1 });
                    let d0 = mm.dist - 1;
                    let p = node.price
                        + is_match1
                        + price(t, m.is_rep[s], 0)
                        + self.prices.match_len[ps][mlen - 2]
                        + dist_price(&self.prices, d0, mlen);
                    let reps = [d0, node.reps[0], node.reps[1], node.reps[2]];
                    (mlen, Node { price: p, prev: i as u32, len: mlen as u32, dist: mm.dist, state: match_next(st), reps })
                };
                let j = i + len;
                while reach < j {
                    reach += 1;
                    self.nodes[reach].price = INF;
                }
                self.nodes[j] = cand;
                self.finder.skip(data, len - 1);
                self.matches = matches;
                end = j;
                break;
            }

            let nodes = &mut self.nodes;
            let mut relax = |j: usize, cand: Node| {
                while reach < j {
                    reach += 1;
                    nodes[reach].price = INF;
                }
                if cand.price < nodes[j].price {
                    nodes[j] = cand;
                }
            };

            // Literal.
            let lit = node.price + price(t, m.is_match[(s << 4) | ps], 0) + m.literal_price(t, data, cur, st, node.reps[0]);
            relax(i + 1, Node { price: lit, prev: i as u32, len: 1, dist: 0, state: LIT_NEXT[s], reps: node.reps });

            let rep_base = node.price + is_match1 + price(t, m.is_rep[s], 1);
            // Short rep.
            let r0 = node.reps[0] as usize;
            if r0 < cur && r0 < self.dict && data[cur] == data[cur - r0 - 1] {
                let p = rep_base + price(t, m.is_rep_g0[s], 0) + price(t, m.is_rep0_long[(s << 4) | ps], 0);
                relax(
                    i + 1,
                    Node { price: p, prev: i as u32, len: 1, dist: node.reps[0] + 1, state: shortrep_next(st), reps: node.reps },
                );
            }
            // Rep matches.
            if rlen >= 2 {
                for rr in 0..4 {
                    let d0 = node.reps[rr] as usize;
                    if d0 >= cur || d0 >= self.dict {
                        continue;
                    }
                    let src = cur - d0 - 1;
                    if data[src] != data[cur] || data[src + 1] != data[cur + 1] {
                        continue;
                    }
                    let l = common_len(data, src, cur, max_len);
                    let mut reps = node.reps;
                    for k in (1..=rr).rev() {
                        reps[k] = reps[k - 1];
                    }
                    reps[0] = d0 as u32;
                    let base = rep_base + rep_choice_price(t, m, rr, s, ps);
                    for len in 2..=l {
                        let p = base + self.prices.rep_len[ps][len - 2];
                        relax(
                            i + len,
                            Node { price: p, prev: i as u32, len: len as u32, dist: d0 as u32 + 1, state: rep_next(st), reps },
                        );
                    }
                }
            }
            // Normal matches.
            if !matches.is_empty() {
                let base = node.price + is_match1 + price(t, m.is_rep[s], 0);
                let mut from = 2usize;
                for mm in &matches {
                    let d0 = mm.dist - 1;
                    let reps = [d0, node.reps[0], node.reps[1], node.reps[2]];
                    for len in from..=mm.len as usize {
                        let p = base + self.prices.match_len[ps][len - 2] + dist_price(&self.prices, d0, len);
                        relax(
                            i + len,
                            Node { price: p, prev: i as u32, len: len as u32, dist: mm.dist, state: match_next(st), reps },
                        );
                    }
                    from = mm.len as usize + 1;
                }
            }
            self.matches = matches;
            i += 1;
        }

        // Backtrack: collect ops from `end` to 0, then reverse into the queue.
        let mut j = end;
        while j > 0 {
            let n = self.nodes[j];
            self.queue.push(Op { len: n.len, dist: n.dist });
            j = n.prev as usize;
        }
        self.queue.reverse();
        self.parse_pos = start + end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots() {
        assert_eq!(dist_slot(0), 0);
        assert_eq!(dist_slot(3), 3);
        assert_eq!(dist_slot(4), 4);
        assert_eq!(dist_slot(5), 4);
        assert_eq!(dist_slot(6), 5);
        assert_eq!(dist_slot(127), 13);
        assert_eq!(dist_slot(128), 14);
        assert_eq!(dist_slot(u32::MAX), 63);
    }

    #[test]
    fn dictionary_rounding() {
        assert_eq!(round_dictionary_size(1), 4096);
        assert_eq!(round_dictionary_size(4097), 6144);
        assert_eq!(round_dictionary_size(8 << 20), 8 << 20);
        assert_eq!(round_dictionary_size((8 << 20) + 1), 12 << 20);
        assert_eq!(effective_dictionary_size(8 << 20, 10), 4096);
        assert_eq!(effective_dictionary_size(1 << 20, 100_000), 1 << 17);
    }

    #[test]
    fn price_table_sane() {
        let t = price_table();
        assert_eq!(price(t, 1024, 0), 16);
        assert!(price(t, 2000, 0) < 2);
        assert!(price(t, 31, 0) > 100);
    }
}
