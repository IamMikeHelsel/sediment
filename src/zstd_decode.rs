// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zstandard (`.zst`) decoding: one or more concatenated frames, with
//! skippable frames ignored.
//!
//! Spec source: RFC 8878 "Zstandard Compression and the application/zstd
//! Media Type" (frames, frame header and window descriptor, block types,
//! literals section with Huffman-coded literals and the Huffman tree
//! description, FSE table description and decoding-table construction,
//! sequences section with the predefined distributions, the
//! literal-length/match-length/offset code tables and the repeat-offset
//! rules, and the XXH64-based content checksum).
//!
//! Supported: every block type, all literal-section types (raw, RLE,
//! Huffman with 1 or 4 streams, treeless), every sequence compression mode
//! (predefined, RLE, FSE, repeat), content checksums and frame content
//! sizes. Frames that name a dictionary (`Dictionary_ID != 0`) return
//! [`ZstdError::Unsupported`]; dictionaries are not available here.
//!
//! Limits: the caller caps total output with `max_output`; a declared frame
//! content size above the cap is rejected before any allocation. The whole
//! output is kept in memory (it is the window), so the window size declared
//! by a frame does not cause extra allocation. Every table and stream is
//! bounds-checked; malformed input returns an error and never panics.

use crate::hash_xxh64::Xxh64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstdError {
    /// Input ended inside a frame.
    Truncated,
    /// The input does not start with a zstd or skippable frame magic number.
    BadMagic,
    /// Reserved frame-header bit set or an invalid header field.
    InvalidHeader,
    /// Reserved block type, oversized block, or malformed block layout.
    InvalidBlock,
    /// Corrupt literals, Huffman/FSE tables, sequences or offsets.
    Corrupt,
    /// The content checksum does not match the decoded data.
    ChecksumMismatch,
    /// The decoded size differs from the declared frame content size.
    SizeMismatch,
    /// A feature this decoder does not provide (dictionaries).
    Unsupported,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
    /// Bytes after the last frame that are not a frame.
    TrailingData,
}

type R<T> = Result<T, ZstdError>;

/// Magic number of a zstd frame (little-endian on disk: 28 B5 2F FD).
pub const ZSTD_MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames use magic numbers `0x184D2A50..=0x184D2A5F`.
pub const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;
pub const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

const BLOCK_SIZE_MAX: usize = 128 * 1024;
const MAX_HUFFMAN_BITS: u32 = 11;
const LL_MAX_SYMBOL: usize = 35;
const ML_MAX_SYMBOL: usize = 52;
const OF_MAX_SYMBOL: usize = 31;
const LL_MAX_LOG: u32 = 9;
const ML_MAX_LOG: u32 = 9;
const OF_MAX_LOG: u32 = 8;

/// True when `b` starts with a zstd frame or a skippable frame magic.
pub fn is_zstd(b: &[u8]) -> bool {
    match read_u32(b, 0) {
        Some(m) => m == ZSTD_MAGIC || m & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC,
        None => false,
    }
}

/// Parsed frame header (RFC 8878 section 3.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Window size in bytes (for single-segment frames, the content size).
    pub window_size: u64,
    /// Declared decompressed size, if present.
    pub content_size: Option<u64>,
    /// Dictionary ID (0 = none).
    pub dictionary_id: u32,
    pub has_checksum: bool,
    pub single_segment: bool,
    /// Size of the header in bytes, including the 4-byte magic number.
    pub header_size: usize,
}

fn read_u32(b: &[u8], pos: usize) -> Option<u32> {
    let s = b.get(pos..pos.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_le(b: &[u8], pos: usize, n: usize) -> R<u64> {
    let end = pos.checked_add(n).ok_or(ZstdError::Truncated)?;
    let s = b.get(pos..end).ok_or(ZstdError::Truncated)?;
    Ok(s.iter().rev().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
}

/// Parse the header of the zstd frame at the start of `b`.
pub fn parse_frame_header(b: &[u8]) -> R<FrameHeader> {
    let magic = read_u32(b, 0).ok_or(ZstdError::Truncated)?;
    if magic != ZSTD_MAGIC {
        return Err(ZstdError::BadMagic);
    }
    let fhd = *b.get(4).ok_or(ZstdError::Truncated)?;
    let fcs_flag = fhd >> 6;
    let single_segment = fhd & 0x20 != 0;
    if fhd & 0x08 != 0 {
        return Err(ZstdError::InvalidHeader);
    }
    let has_checksum = fhd & 0x04 != 0;
    let did_size = [0usize, 1, 2, 4][usize::from(fhd & 3)];
    let fcs_size = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut pos = 5usize;
    let mut window_size = 0u64;
    if !single_segment {
        let wd = *b.get(pos).ok_or(ZstdError::Truncated)?;
        pos += 1;
        let exponent = u32::from(wd >> 3);
        let mantissa = u64::from(wd & 7);
        let window_log = 10 + exponent;
        let base = 1u64 << window_log;
        window_size = base + (base / 8) * mantissa;
    }
    let dictionary_id = read_le(b, pos, did_size)? as u32;
    pos += did_size;
    let content_size = if fcs_size == 0 {
        None
    } else {
        let v = read_le(b, pos, fcs_size)?;
        pos += fcs_size;
        Some(if fcs_size == 2 { v + 256 } else { v })
    };
    if single_segment {
        // The window is the whole content.
        window_size = content_size.unwrap_or(0);
    }
    Ok(FrameHeader { window_size, content_size, dictionary_id, has_checksum, single_segment, header_size: pos })
}

// ---------------------------------------------------------------------------
// Bit readers
// ---------------------------------------------------------------------------

/// Little-endian value of up to 8 bytes at `pos` (bytes past the end read
/// as zero).
fn load_le_padded(data: &[u8], pos: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        if let Some(&x) = data.get(pos + i) {
            v |= u64::from(x) << (8 * i);
        }
    }
    v
}

/// Backward bitstream (RFC 8878 section 4.1): the stream is read from its
/// last byte towards the first, starting just below the highest set bit of
/// the last byte (the end marker).
struct BackBits<'a> {
    data: &'a [u8],
    /// Number of unread bits (bit positions `0..remaining` are unread).
    remaining: usize,
}

impl<'a> BackBits<'a> {
    fn new(data: &'a [u8]) -> R<Self> {
        let &last = data.last().ok_or(ZstdError::Corrupt)?;
        if last == 0 {
            return Err(ZstdError::Corrupt);
        }
        let marker = 7 - last.leading_zeros() as usize;
        Ok(BackBits { data, remaining: (data.len() - 1) * 8 + marker })
    }

    /// The `n` (<= 56) bits just below the read position, zero-padded below
    /// bit 0; does not consume.
    fn peek(&self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let n = n as usize;
        let mask = (1u64 << n) - 1;
        if self.remaining >= n {
            let lo = self.remaining - n;
            (load_le_padded(self.data, lo / 8) >> (lo % 8)) & mask
        } else {
            // Fewer bits than requested: the missing low bits are zero.
            let have = self.remaining;
            let v = if have == 0 { 0 } else { load_le_padded(self.data, 0) & ((1u64 << have) - 1) };
            (v << (n - have)) & mask
        }
    }

    fn consume(&mut self, n: u32) -> R<()> {
        let n = n as usize;
        if n > self.remaining {
            return Err(ZstdError::Corrupt);
        }
        self.remaining -= n;
        Ok(())
    }

    fn read(&mut self, n: u32) -> R<u64> {
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }

    /// Like `read`, but reading past the start yields zero bits and is
    /// reported through the return flag instead of an error (used by the
    /// two-state Huffman-weight decoder, which stops on overflow).
    fn read_overflowing(&mut self, n: u32) -> (u64, bool) {
        let v = self.peek(n);
        let n = n as usize;
        if n > self.remaining {
            self.remaining = 0;
            (v, true)
        } else {
            self.remaining -= n;
            (v, false)
        }
    }
}

/// Forward little-endian bit reader used for FSE table descriptions.
struct FwdBits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl FwdBits<'_> {
    fn read(&mut self, n: u32) -> R<u32> {
        let end = self.bit.checked_add(n as usize).ok_or(ZstdError::Corrupt)?;
        if end > self.data.len() * 8 {
            return Err(ZstdError::Corrupt);
        }
        let v = (load_le_padded(self.data, self.bit / 8) >> (self.bit % 8)) & ((1u64 << n) - 1);
        self.bit = end;
        Ok(v as u32)
    }
    fn peek(&self, n: u32) -> u32 {
        ((load_le_padded(self.data, self.bit / 8) >> (self.bit % 8)) & ((1u64 << n) - 1)) as u32
    }
    fn skip(&mut self, n: u32) -> R<()> {
        let end = self.bit + n as usize;
        if end > self.data.len() * 8 {
            return Err(ZstdError::Corrupt);
        }
        self.bit = end;
        Ok(())
    }
}

fn highbit(x: u32) -> u32 {
    31 - x.leading_zeros()
}

// ---------------------------------------------------------------------------
// FSE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct FseEntry {
    symbol: u8,
    nb_bits: u8,
    baseline: u16,
}

#[derive(Debug, Clone, Default)]
struct FseTable {
    accuracy_log: u32,
    entries: Vec<FseEntry>,
}

impl FseTable {
    fn rle(symbol: u8) -> FseTable {
        FseTable { accuracy_log: 0, entries: vec![FseEntry { symbol, nb_bits: 0, baseline: 0 }] }
    }

    /// Build a decoding table from normalized probabilities (-1 = "less than
    /// one"), RFC 8878 section 4.1.1.
    fn build(probs: &[i16], accuracy_log: u32) -> R<FseTable> {
        let size = 1usize << accuracy_log;
        let mut entries = vec![FseEntry::default(); size];
        let mut next = [0u32; 256];
        let mut high = size; // first slot used by "-1" symbols
        let mut total = 0usize;
        for (s, &p) in probs.iter().enumerate() {
            if p == -1 {
                high = high.checked_sub(1).ok_or(ZstdError::Corrupt)?;
                entries[high].symbol = s as u8;
                next[s] = 1;
                total += 1;
            } else if p > 0 {
                next[s] = p as u32;
                total += p as usize;
            } else if p < -1 {
                return Err(ZstdError::Corrupt);
            }
        }
        if total != size {
            return Err(ZstdError::Corrupt);
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &p) in probs.iter().enumerate() {
            for _ in 0..p.max(0) {
                entries[pos].symbol = s as u8;
                pos = (pos + step) & mask;
                while pos >= high {
                    pos = (pos + step) & mask;
                }
            }
        }
        if pos != 0 {
            return Err(ZstdError::Corrupt);
        }
        for e in entries.iter_mut() {
            let s = usize::from(e.symbol);
            let state = next[s];
            next[s] += 1;
            let nb = accuracy_log - highbit(state);
            e.nb_bits = nb as u8;
            e.baseline = ((state << nb) as usize - size) as u16;
        }
        Ok(FseTable { accuracy_log, entries })
    }

    /// Read an FSE table description (section 4.1.1) from the start of `b`;
    /// returns the table and the number of bytes used.
    fn read(b: &[u8], max_symbol: usize, max_log: u32) -> R<(FseTable, usize)> {
        let mut br = FwdBits { data: b, bit: 0 };
        let accuracy_log = br.read(4)? + 5;
        if accuracy_log > max_log {
            return Err(ZstdError::Corrupt);
        }
        let mut probs: Vec<i16> = Vec::with_capacity(max_symbol + 1);
        let mut remaining: i32 = (1 << accuracy_log) + 1;
        let mut threshold: i32 = 1 << accuracy_log;
        let mut nb_bits = accuracy_log + 1;
        while remaining > 1 {
            if probs.len() > max_symbol {
                return Err(ZstdError::Corrupt);
            }
            let max = (2 * threshold - 1) - remaining;
            let low = br.peek(nb_bits - 1) as i32;
            let value = if low < max {
                br.skip(nb_bits - 1)?;
                low
            } else {
                let mut v = br.read(nb_bits)? as i32;
                if v >= threshold {
                    v -= max;
                }
                v
            };
            let prob = value - 1;
            remaining -= prob.abs();
            probs.push(prob as i16);
            if prob == 0 {
                loop {
                    let repeat = br.read(2)?;
                    for _ in 0..repeat {
                        if probs.len() > max_symbol {
                            return Err(ZstdError::Corrupt);
                        }
                        probs.push(0);
                    }
                    if repeat != 3 {
                        break;
                    }
                }
            }
            while remaining < threshold && nb_bits > 1 {
                nb_bits -= 1;
                threshold >>= 1;
            }
        }
        if remaining != 1 || probs.len() > max_symbol + 1 {
            return Err(ZstdError::Corrupt);
        }
        let used = br.bit.div_ceil(8);
        Ok((FseTable::build(&probs, accuracy_log)?, used))
    }
}

struct FseState {
    state: usize,
}

impl FseState {
    fn init(t: &FseTable, bits: &mut BackBits) -> R<Self> {
        Ok(FseState { state: bits.read(t.accuracy_log)? as usize })
    }
    fn symbol(&self, t: &FseTable) -> u8 {
        t.entries[self.state].symbol
    }
    fn update(&mut self, t: &FseTable, bits: &mut BackBits) -> R<()> {
        let e = t.entries[self.state];
        let v = bits.read(u32::from(e.nb_bits))? as usize;
        self.state = usize::from(e.baseline) + v;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Huffman (literals)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct HuffTable {
    max_bits: u32,
    /// (symbol, number of bits) indexed by the next `max_bits` bits.
    table: Vec<(u8, u8)>,
}

/// Decode the Huffman tree description (section 4.2.1); returns the table
/// and the number of bytes consumed.
fn read_huffman_tree(b: &[u8]) -> R<(HuffTable, usize)> {
    let header = *b.first().ok_or(ZstdError::Corrupt)?;
    let mut weights: Vec<u8> = Vec::with_capacity(256);
    let used = if header >= 128 {
        let n = usize::from(header) - 127;
        let nbytes = n.div_ceil(2);
        let data = b.get(1..1 + nbytes).ok_or(ZstdError::Corrupt)?;
        for i in 0..n {
            let byte = data[i / 2];
            weights.push(if i % 2 == 0 { byte >> 4 } else { byte & 15 });
        }
        1 + nbytes
    } else {
        let size = usize::from(header);
        let data = b.get(1..1 + size).ok_or(ZstdError::Corrupt)?;
        let (table, hdr) = FseTable::read(data, 255, 6)?;
        let stream = data.get(hdr..).ok_or(ZstdError::Corrupt)?;
        let mut bits = BackBits::new(stream)?;
        let mut s1 = FseState::init(&table, &mut bits)?;
        let mut s2 = FseState::init(&table, &mut bits)?;
        // Two interleaved states share one stream; decoding stops once a
        // state update reads past the start of the stream, after emitting
        // the other state's current symbol.
        loop {
            if weights.len() >= 255 {
                return Err(ZstdError::Corrupt);
            }
            weights.push(s1.symbol(&table));
            let e = table.entries[s1.state];
            let (v, over) = bits.read_overflowing(u32::from(e.nb_bits));
            s1.state = usize::from(e.baseline) + v as usize;
            if over {
                weights.push(s2.symbol(&table));
                break;
            }
            if weights.len() >= 255 {
                return Err(ZstdError::Corrupt);
            }
            weights.push(s2.symbol(&table));
            let e = table.entries[s2.state];
            let (v, over) = bits.read_overflowing(u32::from(e.nb_bits));
            s2.state = usize::from(e.baseline) + v as usize;
            if over {
                weights.push(s1.symbol(&table));
                break;
            }
        }
        if weights.len() > 255 {
            return Err(ZstdError::Corrupt);
        }
        1 + size
    };
    Ok((build_huffman(&weights)?, used))
}

fn build_huffman(weights: &[u8]) -> R<HuffTable> {
    let mut total: u32 = 0;
    for &w in weights {
        if u32::from(w) > MAX_HUFFMAN_BITS {
            return Err(ZstdError::Corrupt);
        }
        if w > 0 {
            total += 1 << (w - 1);
        }
    }
    if total == 0 {
        return Err(ZstdError::Corrupt);
    }
    let max_bits = highbit(total) + 1;
    if max_bits > MAX_HUFFMAN_BITS {
        return Err(ZstdError::Corrupt);
    }
    let rest = (1u32 << max_bits) - total;
    if !rest.is_power_of_two() {
        return Err(ZstdError::Corrupt);
    }
    let last_weight = highbit(rest) + 1;
    let mut all: Vec<u8> = weights.to_vec();
    all.push(last_weight as u8);
    if all.len() > 256 {
        return Err(ZstdError::Corrupt);
    }
    let size = 1usize << max_bits;
    let mut table = vec![(0u8, 0u8); size];
    let mut pos = 0usize;
    // Ascending weight (longest codes first), ascending symbol within a
    // weight.
    for w in 1..=max_bits {
        for (s, &sw) in all.iter().enumerate() {
            if u32::from(sw) != w {
                continue;
            }
            let nb = max_bits + 1 - w;
            let span = 1usize << (max_bits - nb);
            let end = pos + span;
            if end > size {
                return Err(ZstdError::Corrupt);
            }
            for slot in &mut table[pos..end] {
                *slot = (s as u8, nb as u8);
            }
            pos = end;
        }
    }
    if pos != size {
        return Err(ZstdError::Corrupt);
    }
    Ok(HuffTable { max_bits, table })
}

fn huffman_stream(t: &HuffTable, stream: &[u8], count: usize, out: &mut Vec<u8>) -> R<()> {
    let mut bits = BackBits::new(stream)?;
    for _ in 0..count {
        let idx = bits.peek(t.max_bits) as usize;
        let (sym, nb) = t.table[idx];
        bits.consume(u32::from(nb))?;
        out.push(sym);
    }
    if bits.remaining != 0 {
        return Err(ZstdError::Corrupt);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sequences tables
// ---------------------------------------------------------------------------

const LL_DEFAULT: [i16; 36] =
    [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] =
    [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];

/// (baseline, extra bits) for literal-length codes 16..=35.
const LL_CODES: [(u32, u8); 20] = [
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];
/// (baseline, extra bits) for match-length codes 32..=52.
const ML_CODES: [(u32, u8); 21] = [
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

fn ll_code(c: u8) -> (u32, u8) {
    if c < 16 { (u32::from(c), 0) } else { LL_CODES[usize::from(c - 16)] }
}
fn ml_code(c: u8) -> (u32, u8) {
    if c < 32 { (u32::from(c) + 3, 0) } else { ML_CODES[usize::from(c - 32)] }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    LiteralLength,
    Offset,
    MatchLength,
}

fn predefined(kind: Kind) -> FseTable {
    // The predefined distributions are valid by construction.
    let r = match kind {
        Kind::LiteralLength => FseTable::build(&LL_DEFAULT, 6),
        Kind::MatchLength => FseTable::build(&ML_DEFAULT, 6),
        Kind::Offset => FseTable::build(&OF_DEFAULT, 5),
    };
    r.unwrap_or_default()
}

/// Per-frame decoder state carried between blocks.
#[derive(Default)]
struct FrameState {
    huffman: Option<HuffTable>,
    ll: Option<FseTable>,
    of: Option<FseTable>,
    ml: Option<FseTable>,
    rep: [usize; 3],
}

/// Read one sequence table per its compression mode; returns bytes used.
fn read_seq_table(kind: Kind, mode: u8, b: &[u8], slot: &mut Option<FseTable>) -> R<usize> {
    let (max_symbol, max_log) = match kind {
        Kind::LiteralLength => (LL_MAX_SYMBOL, LL_MAX_LOG),
        Kind::Offset => (OF_MAX_SYMBOL, OF_MAX_LOG),
        Kind::MatchLength => (ML_MAX_SYMBOL, ML_MAX_LOG),
    };
    match mode {
        0 => {
            *slot = Some(predefined(kind));
            Ok(0)
        }
        1 => {
            let &s = b.first().ok_or(ZstdError::Corrupt)?;
            if usize::from(s) > max_symbol {
                return Err(ZstdError::Corrupt);
            }
            *slot = Some(FseTable::rle(s));
            Ok(1)
        }
        2 => {
            let (t, used) = FseTable::read(b, max_symbol, max_log)?;
            *slot = Some(t);
            Ok(used)
        }
        _ => {
            if slot.is_none() {
                return Err(ZstdError::Corrupt);
            }
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

fn decode_literals(b: &[u8], st: &mut FrameState, lit: &mut Vec<u8>) -> R<usize> {
    let b0 = *b.first().ok_or(ZstdError::InvalidBlock)?;
    let ltype = b0 & 3;
    let size_format = (b0 >> 2) & 3;
    lit.clear();
    if ltype < 2 {
        let (hsize, regen) = match size_format {
            0 | 2 => (1usize, usize::from(b0 >> 3)),
            1 => (2, read_le(b, 0, 2).map_err(|_| ZstdError::InvalidBlock)? as usize >> 4),
            _ => (3, read_le(b, 0, 3).map_err(|_| ZstdError::InvalidBlock)? as usize >> 4),
        };
        if regen > BLOCK_SIZE_MAX {
            return Err(ZstdError::Corrupt);
        }
        if ltype == 0 {
            let data = b.get(hsize..hsize + regen).ok_or(ZstdError::InvalidBlock)?;
            lit.extend_from_slice(data);
            return Ok(hsize + regen);
        }
        let &v = b.get(hsize).ok_or(ZstdError::InvalidBlock)?;
        lit.resize(regen, v);
        return Ok(hsize + 1);
    }
    let (hsize, field_bits, four) = match size_format {
        0 => (3usize, 10u32, false),
        1 => (3, 10, true),
        2 => (4, 14, true),
        _ => (5, 18, true),
    };
    let h = read_le(b, 0, hsize).map_err(|_| ZstdError::InvalidBlock)?;
    let mask = (1u64 << field_bits) - 1;
    let regen = ((h >> 4) & mask) as usize;
    let comp = ((h >> (4 + field_bits)) & mask) as usize;
    if regen > BLOCK_SIZE_MAX {
        return Err(ZstdError::Corrupt);
    }
    let end = hsize.checked_add(comp).ok_or(ZstdError::InvalidBlock)?;
    let mut data = b.get(hsize..end).ok_or(ZstdError::InvalidBlock)?;
    if ltype == 2 {
        let (t, used) = read_huffman_tree(data)?;
        st.huffman = Some(t);
        data = &data[used..];
    }
    let t = st.huffman.as_ref().ok_or(ZstdError::Corrupt)?;
    lit.try_reserve(regen).map_err(|_| ZstdError::Allocation)?;
    if !four {
        huffman_stream(t, data, regen, lit)?;
    } else {
        if data.len() < 6 {
            return Err(ZstdError::Corrupt);
        }
        let s1 = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let s2 = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let s3 = usize::from(u16::from_le_bytes([data[4], data[5]]));
        let streams = &data[6..];
        let s4 = streams.len().checked_sub(s1 + s2 + s3).ok_or(ZstdError::Corrupt)?;
        let seg = regen.div_ceil(4);
        let last = regen.checked_sub(3 * seg).ok_or(ZstdError::Corrupt)?;
        let mut off = 0usize;
        for (len, count) in [(s1, seg), (s2, seg), (s3, seg), (s4, last)] {
            huffman_stream(t, &streams[off..off + len], count, lit)?;
            off += len;
        }
    }
    Ok(end)
}

fn push_checked(out: &mut Vec<u8>, extra: usize, max_output: usize) -> R<()> {
    let need = out.len().checked_add(extra).ok_or(ZstdError::LimitExceeded)?;
    if need > max_output {
        return Err(ZstdError::LimitExceeded);
    }
    out.try_reserve(extra).map_err(|_| ZstdError::Allocation)
}

/// Append `len` bytes copied from `offset` bytes back (`1 <= offset <=
/// out.len()`, capacity already reserved). Overlapping copies repeat the
/// period; each pass copies from the period start, doubling the run.
pub(crate) fn copy_match(out: &mut Vec<u8>, offset: usize, len: usize) {
    let start = out.len() - offset;
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(out.len() - start);
        out.extend_from_within(start..start + n);
        remaining -= n;
    }
}

fn decode_compressed_block(
    b: &[u8],
    st: &mut FrameState,
    lit: &mut Vec<u8>,
    out: &mut Vec<u8>,
    frame_start: usize,
    block_max: usize,
    max_output: usize,
) -> R<()> {
    let block_start = out.len();
    let lsize = decode_literals(b, st, lit)?;
    let s = &b[lsize..];
    let &b0 = s.first().ok_or(ZstdError::InvalidBlock)?;
    let (nb_seq, mut pos) = match b0 {
        0 => (0usize, 1usize),
        1..=127 => (usize::from(b0), 1),
        128..=254 => {
            let &b1 = s.get(1).ok_or(ZstdError::InvalidBlock)?;
            (((usize::from(b0) - 128) << 8) + usize::from(b1), 2)
        }
        255 => (read_le(s, 1, 2).map_err(|_| ZstdError::InvalidBlock)? as usize + 0x7F00, 3),
    };
    if nb_seq == 0 {
        if pos != s.len() {
            return Err(ZstdError::InvalidBlock);
        }
        if lit.len() > block_max {
            return Err(ZstdError::InvalidBlock);
        }
        push_checked(out, lit.len(), max_output)?;
        out.extend_from_slice(lit);
        return Ok(());
    }
    let &modes = s.get(pos).ok_or(ZstdError::InvalidBlock)?;
    pos += 1;
    if modes & 3 != 0 {
        return Err(ZstdError::Corrupt);
    }
    pos += read_seq_table(Kind::LiteralLength, modes >> 6, &s[pos..], &mut st.ll)?;
    pos += read_seq_table(Kind::Offset, (modes >> 4) & 3, s.get(pos..).ok_or(ZstdError::Corrupt)?, &mut st.of)?;
    pos += read_seq_table(Kind::MatchLength, (modes >> 2) & 3, s.get(pos..).ok_or(ZstdError::Corrupt)?, &mut st.ml)?;
    let stream = s.get(pos..).ok_or(ZstdError::Corrupt)?;
    let (Some(ll_t), Some(of_t), Some(ml_t)) = (st.ll.as_ref(), st.of.as_ref(), st.ml.as_ref()) else {
        return Err(ZstdError::Corrupt);
    };
    let mut bits = BackBits::new(stream)?;
    let mut ll_s = FseState::init(ll_t, &mut bits)?;
    let mut of_s = FseState::init(of_t, &mut bits)?;
    let mut ml_s = FseState::init(ml_t, &mut bits)?;
    let mut lit_pos = 0usize;
    for i in 0..nb_seq {
        let of_code = of_s.symbol(of_t);
        let ll_c = ll_s.symbol(ll_t);
        let ml_c = ml_s.symbol(ml_t);
        if usize::from(ll_c) > LL_MAX_SYMBOL || usize::from(ml_c) > ML_MAX_SYMBOL || usize::from(of_code) > OF_MAX_SYMBOL
        {
            return Err(ZstdError::Corrupt);
        }
        let of_value = (1u64 << of_code) + bits.read(u32::from(of_code))?;
        let (ml_base, ml_bits) = ml_code(ml_c);
        let ml = (ml_base as usize) + bits.read(u32::from(ml_bits))? as usize;
        let (ll_base, ll_bits) = ll_code(ll_c);
        let ll = (ll_base as usize) + bits.read(u32::from(ll_bits))? as usize;
        // Offset resolution with repeat offsets (section 3.1.1.5).
        let offset = if of_value > 3 {
            let o = (of_value - 3) as usize;
            st.rep = [o, st.rep[0], st.rep[1]];
            o
        } else {
            let idx = of_value as usize - if ll == 0 { 0 } else { 1 };
            match idx {
                0 => st.rep[0],
                1 => {
                    st.rep.swap(0, 1);
                    st.rep[0]
                }
                2 => {
                    st.rep = [st.rep[2], st.rep[0], st.rep[1]];
                    st.rep[0]
                }
                _ => {
                    let o = st.rep[0].checked_sub(1).filter(|&o| o != 0).ok_or(ZstdError::Corrupt)?;
                    st.rep = [o, st.rep[0], st.rep[1]];
                    o
                }
            }
        };
        // Execute: literals, then the match.
        let lit_end = lit_pos.checked_add(ll).ok_or(ZstdError::Corrupt)?;
        if lit_end > lit.len() {
            return Err(ZstdError::Corrupt);
        }
        let add = ll.checked_add(ml).ok_or(ZstdError::Corrupt)?;
        if out.len() - block_start + add > block_max {
            return Err(ZstdError::Corrupt);
        }
        push_checked(out, add, max_output)?;
        out.extend_from_slice(&lit[lit_pos..lit_end]);
        lit_pos = lit_end;
        if offset == 0 || offset > out.len() - frame_start {
            return Err(ZstdError::Corrupt);
        }
        copy_match(out, offset, ml);
        if i + 1 < nb_seq {
            ll_s.update(ll_t, &mut bits)?;
            ml_s.update(ml_t, &mut bits)?;
            of_s.update(of_t, &mut bits)?;
        }
    }
    if bits.remaining != 0 {
        return Err(ZstdError::Corrupt);
    }
    let rest = lit.len() - lit_pos;
    if out.len() - block_start + rest > block_max {
        return Err(ZstdError::Corrupt);
    }
    push_checked(out, rest, max_output)?;
    out.extend_from_slice(&lit[lit_pos..]);
    Ok(())
}

/// Decode the zstd frame at the start of `input`, appending its content to
/// `out` (whose total length may not exceed `max_output`). Returns the
/// number of input bytes the frame occupied.
pub fn decode_frame_into(input: &[u8], out: &mut Vec<u8>, max_output: usize) -> R<usize> {
    let h = parse_frame_header(input)?;
    if h.dictionary_id != 0 {
        return Err(ZstdError::Unsupported);
    }
    let frame_start = out.len();
    if let Some(cs) = h.content_size {
        let total = (frame_start as u64).checked_add(cs).ok_or(ZstdError::LimitExceeded)?;
        if total > max_output as u64 {
            return Err(ZstdError::LimitExceeded);
        }
        // Preallocate at most one block's worth beyond what is present;
        // growth is otherwise driven by decoded data, not by the header.
        out.try_reserve(cs.min(BLOCK_SIZE_MAX as u64) as usize).map_err(|_| ZstdError::Allocation)?;
    }
    let block_max = h.window_size.min(BLOCK_SIZE_MAX as u64) as usize;
    let mut st = FrameState { rep: [1, 4, 8], ..FrameState::default() };
    let mut lit = Vec::new();
    let mut pos = h.header_size;
    loop {
        let bh = read_le(input, pos, 3)? as u32;
        pos += 3;
        let last = bh & 1 != 0;
        let btype = (bh >> 1) & 3;
        let bsize = (bh >> 3) as usize;
        match btype {
            0 => {
                if bsize > block_max {
                    return Err(ZstdError::InvalidBlock);
                }
                let data = input.get(pos..pos + bsize).ok_or(ZstdError::Truncated)?;
                push_checked(out, bsize, max_output)?;
                out.extend_from_slice(data);
                pos += bsize;
            }
            1 => {
                if bsize > block_max {
                    return Err(ZstdError::InvalidBlock);
                }
                let &v = input.get(pos).ok_or(ZstdError::Truncated)?;
                push_checked(out, bsize, max_output)?;
                out.resize(out.len() + bsize, v);
                pos += 1;
            }
            2 => {
                if bsize > block_max {
                    return Err(ZstdError::InvalidBlock);
                }
                let data = input.get(pos..pos + bsize).ok_or(ZstdError::Truncated)?;
                decode_compressed_block(data, &mut st, &mut lit, out, frame_start, block_max, max_output)?;
                pos += bsize;
            }
            _ => return Err(ZstdError::InvalidBlock),
        }
        if let Some(cs) = h.content_size
            && (out.len() - frame_start) as u64 > cs
        {
            return Err(ZstdError::SizeMismatch);
        }
        if last {
            break;
        }
    }
    let produced = &out[frame_start..];
    if let Some(cs) = h.content_size
        && produced.len() as u64 != cs
    {
        return Err(ZstdError::SizeMismatch);
    }
    if h.has_checksum {
        let stored = read_u32(input, pos).ok_or(ZstdError::Truncated)?;
        pos += 4;
        let mut x = Xxh64::with_seed(0);
        x.update(produced);
        if x.finalize() as u32 != stored {
            return Err(ZstdError::ChecksumMismatch);
        }
    }
    Ok(pos)
}

/// Decode a complete `.zst` file: one or more zstd frames, optionally
/// interleaved with skippable frames (a file of only skippable frames
/// decodes to nothing). Output is capped at `max_output` bytes.
pub fn decode_zstd(input: &[u8], max_output: usize) -> R<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut frames = 0usize;
    if input.is_empty() {
        return Err(ZstdError::Truncated);
    }
    while pos < input.len() {
        let rest = &input[pos..];
        let Some(magic) = read_u32(rest, 0) else {
            return Err(if frames == 0 { ZstdError::Truncated } else { ZstdError::TrailingData });
        };
        if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC {
            let len = read_u32(rest, 4).ok_or(ZstdError::Truncated)? as usize;
            let end = 8usize.checked_add(len).ok_or(ZstdError::Truncated)?;
            if end > rest.len() {
                return Err(ZstdError::Truncated);
            }
            pos += end;
            frames += 1;
            continue;
        }
        if magic != ZSTD_MAGIC {
            return Err(if frames == 0 { ZstdError::BadMagic } else { ZstdError::TrailingData });
        }
        pos += decode_frame_into(rest, &mut out, max_output)?;
        frames += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predefined_tables_build() {
        assert_eq!(FseTable::build(&LL_DEFAULT, 6).unwrap().entries.len(), 64);
        assert_eq!(FseTable::build(&ML_DEFAULT, 6).unwrap().entries.len(), 64);
        assert_eq!(FseTable::build(&OF_DEFAULT, 5).unwrap().entries.len(), 32);
    }

    #[test]
    fn rfc_huffman_example() {
        // RFC 8878 4.2.1.3: weights 4,3,2,0,1 (+ implicit 1 for symbol 5).
        let t = build_huffman(&[4, 3, 2, 0, 1]).unwrap();
        assert_eq!(t.max_bits, 4);
        assert_eq!(t.table[0b1000], (0, 1));
        assert_eq!(t.table[0b0100], (1, 2));
        assert_eq!(t.table[0b0010], (2, 3));
        assert_eq!(t.table[0b0000], (4, 4));
        assert_eq!(t.table[0b0001], (5, 4));
    }

    #[test]
    fn back_bits() {
        // 0b0000_0101: marker at bit 2, then bits "01" -> read(1)=0, read(1)=1.
        let mut b = BackBits::new(&[0b0000_0101]).unwrap();
        assert_eq!(b.remaining, 2);
        assert_eq!(b.read(1).unwrap(), 0);
        assert_eq!(b.read(1).unwrap(), 1);
        assert!(b.read(1).is_err());
        assert!(BackBits::new(&[0]).is_err());
        assert!(BackBits::new(&[]).is_err());
    }
}
