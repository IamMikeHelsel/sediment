// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZX decoder (the Microsoft LZ77 + Huffman format used by CAB folders of
//! compression type 3 and by the CHM "MSCompressed" section).
//!
//! Spec sources: the LZX bitstream description in [MS-PATCH] (LZX DELTA
//! Compression and Decompression) section 2, which LZX DELTA extends, and the
//! Microsoft Cabinet SDK description of LZX as referenced by [MS-CAB]
//! section 2.1 (typeCompress = 3, window 2^15..2^21). Implemented from those
//! documents; no other decoder's source was consulted.
//!
//! Format summary, as implemented:
//! - The bitstream is a sequence of 16-bit little-endian words whose bits are
//!   consumed most-significant first.
//! - A stream (and, in CHM, every reset point) starts with a 1-bit E8 flag; if
//!   set, a 32-bit translation size follows (high 16 bits first).
//! - Each block: 3-bit type (1 verbatim, 2 aligned offset, 3 uncompressed) and
//!   a 24-bit uncompressed block size. Verbatim and aligned blocks carry the
//!   main tree (256 literals + 8 symbols per position slot) and the 249-symbol
//!   length tree, each delta-coded through a 20-symbol pretree against the
//!   previous block's lengths; aligned blocks first carry an 8-symbol aligned
//!   offset tree (3-bit lengths). Uncompressed blocks pad to the next 16-bit
//!   boundary (1..16 bits), store R0, R1, R2 as 32-bit LE values, then the raw
//!   bytes, plus one pad byte when the block size is odd.
//! - Output is produced in 32 KiB frames; after each frame the bitstream is
//!   realigned to a 16-bit boundary. Blocks and matches may span frames.
//! - Position slots 0..2 reuse the three most recent offsets (R0..R2); other
//!   slots carry footer bits (low 3 through the aligned tree in aligned blocks
//!   when the slot has at least 3 footer bits).
//! - E8 call translation is undone per frame for the first 32768 frames of
//!   frames longer than 10 bytes; positions are counted from the start of the
//!   stream (or the most recent CHM reset point).
//!
//! The whole output is held in memory; it doubles as the history window, so
//! `output_len` (an explicit caller limit) bounds memory. Malformed input
//! returns an error; nothing panics and nothing is allocated beyond
//! `output_len` plus one maximal match.

/// Uncompressed bytes per LZX frame.
pub const FRAME_SIZE: usize = 32768;
const MIN_MATCH: usize = 2;
const NUM_CHARS: usize = 256;
const PRETREE_SIZE: usize = 20;
const LENGTH_SIZE: usize = 249;
const ALIGNED_SIZE: usize = 8;
const MAX_CODE_LEN: usize = 16;
/// Main tree size for the largest window (2^21, 50 position slots).
const MAX_MAIN: usize = NUM_CHARS + 8 * 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzxError {
    /// Window size outside 2^15..=2^21.
    InvalidWindow,
    /// Input ended before the requested output was produced.
    Truncated,
    /// Block type 0 or 4..7, or a zero-length block.
    InvalidBlock,
    /// Over-subscribed Huffman code lengths or a malformed length run.
    InvalidTree,
    /// A bit pattern that maps to no symbol (including use of an empty tree).
    InvalidCode,
    /// Match offset beyond the available history, or a match that runs past
    /// the end of its block.
    InvalidMatch,
    /// A reset point fell inside a match.
    InvalidReset,
    /// The caller's output limit is too large to address.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

/// Number of position slots for a window of `2^window_bits` bytes.
pub fn position_slots(window_bits: u8) -> Result<usize, LzxError> {
    match window_bits {
        15 => Ok(30),
        16 => Ok(32),
        17 => Ok(34),
        18 => Ok(36),
        19 => Ok(38),
        20 => Ok(42),
        21 => Ok(50),
        _ => Err(LzxError::InvalidWindow),
    }
}

const fn extra_bits_table() -> [u8; 52] {
    let mut t = [0u8; 52];
    let mut i = 0;
    let mut j = 0u8;
    while i < 52 {
        t[i] = j;
        t[i + 1] = j;
        if i != 0 && j < 17 {
            j += 1;
        }
        i += 2;
    }
    t
}

const EXTRA_BITS: [u8; 52] = extra_bits_table();

const fn position_base_table() -> [u32; 52] {
    let mut t = [0u32; 52];
    let mut i = 1;
    while i < 52 {
        t[i] = t[i - 1] + (1u32 << EXTRA_BITS[i - 1]);
        i += 1;
    }
    t
}

const POSITION_BASE: [u32; 52] = position_base_table();

/// MSB-first reader over 16-bit little-endian words.
struct BitIn<'a> {
    data: &'a [u8],
    /// Byte index of the next word to load.
    pos: usize,
    buf: u64,
    nbits: u32,
    /// Bits of zero padding loaded past the end of `data`.
    pad_bits: u32,
}

impl<'a> BitIn<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitIn { data, pos: 0, buf: 0, nbits: 0, pad_bits: 0 }
    }

    fn refill(&mut self) {
        while self.nbits <= 48 {
            let word = match (self.data.get(self.pos), self.data.get(self.pos + 1)) {
                (Some(&a), Some(&b)) => u16::from_le_bytes([a, b]),
                (Some(&a), None) => {
                    // odd trailing byte: low byte only, the rest is padding
                    self.pad_bits += 8;
                    u16::from(a)
                }
                _ => {
                    self.pad_bits += 16;
                    0
                }
            };
            self.pos += 2;
            self.buf |= u64::from(word) << (48 - self.nbits);
            self.nbits += 16;
        }
    }

    /// Next 16 bits without consuming them (zero past the end of input).
    fn peek16(&mut self) -> u32 {
        if self.nbits < 16 {
            self.refill();
        }
        (self.buf >> 48) as u32
    }

    fn consume(&mut self, n: u32) -> Result<(), LzxError> {
        if n == 0 {
            return Ok(());
        }
        if self.nbits < n {
            self.refill();
        }
        if self.nbits.saturating_sub(n) < self.pad_bits {
            return Err(LzxError::Truncated);
        }
        self.buf <<= n;
        self.nbits -= n;
        Ok(())
    }

    fn read(&mut self, n: u32) -> Result<u32, LzxError> {
        if n == 0 {
            return Ok(0);
        }
        if self.nbits < n {
            self.refill();
        }
        let v = (self.buf >> (64 - n)) as u32;
        self.consume(n)?;
        Ok(v)
    }

    /// Drop the unread rest of the current 16-bit word.
    fn align16(&mut self) {
        let r = self.nbits % 16;
        self.buf <<= r;
        self.nbits -= r;
    }

    /// Enter byte mode for an uncompressed block: skip 1..16 padding bits.
    fn enter_bytes(&mut self) -> Result<(), LzxError> {
        let r = self.nbits % 16;
        if r != 0 {
            self.consume(r)?;
        } else {
            self.consume(16)?;
        }
        // `nbits` is now a whole number of buffered words; give them back.
        let back = (self.nbits / 8) as usize;
        let pos = self.pos.checked_sub(back).ok_or(LzxError::Truncated)?;
        if pos > self.data.len() {
            return Err(LzxError::Truncated);
        }
        self.pos = pos;
        self.buf = 0;
        self.nbits = 0;
        self.pad_bits = 0;
        Ok(())
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], LzxError> {
        debug_assert!(self.nbits == 0);
        let end = self.pos.checked_add(n).ok_or(LzxError::Truncated)?;
        let s = self.data.get(self.pos..end).ok_or(LzxError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
}

/// Canonical Huffman decoder for MSB-first codes up to 16 bits.
struct Huffman {
    counts: [u16; MAX_CODE_LEN + 1],
    symbols: [u16; MAX_MAIN],
    /// Fast path: first 10 bits -> (symbol << 5) | length, 0 = slow path.
    fast: [u16; 1 << FAST_BITS],
}

const FAST_BITS: u32 = 10;

impl Huffman {
    fn new() -> Self {
        Huffman { counts: [0; MAX_CODE_LEN + 1], symbols: [0; MAX_MAIN], fast: [0; 1 << FAST_BITS] }
    }

    fn build(&mut self, lens: &[u8]) -> Result<(), LzxError> {
        if lens.len() > MAX_MAIN {
            return Err(LzxError::InvalidTree);
        }
        self.counts = [0; MAX_CODE_LEN + 1];
        for &l in lens {
            if l as usize > MAX_CODE_LEN {
                return Err(LzxError::InvalidTree);
            }
            self.counts[l as usize] += 1;
        }
        self.counts[0] = 0;
        // Kraft check: reject over-subscribed sets, allow incomplete ones.
        let mut left: i64 = 1;
        for len in 1..=MAX_CODE_LEN {
            left <<= 1;
            left -= i64::from(self.counts[len]);
            if left < 0 {
                return Err(LzxError::InvalidTree);
            }
        }
        let mut offs = [0u16; MAX_CODE_LEN + 2];
        for len in 1..=MAX_CODE_LEN {
            offs[len + 1] = offs[len] + self.counts[len];
        }
        for (sym, &l) in lens.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[l as usize];
                self.symbols[*o as usize] = sym as u16;
                *o += 1;
            }
        }
        // fast table
        self.fast = [0; 1 << FAST_BITS];
        let mut code: u32 = 0;
        let mut index: usize = 0;
        for len in 1..=FAST_BITS as usize {
            for k in 0..self.counts[len] as usize {
                let sym = self.symbols[index + k];
                let c = code + k as u32;
                let shift = FAST_BITS - len as u32;
                let start = (c << shift) as usize;
                let entry = (sym << 5) | len as u16;
                for slot in &mut self.fast[start..start + (1usize << shift)] {
                    *slot = entry;
                }
            }
            index += self.counts[len] as usize;
            code = (code + u32::from(self.counts[len])) << 1;
        }
        Ok(())
    }

    fn decode(&self, bits: &mut BitIn<'_>) -> Result<u16, LzxError> {
        let v = bits.peek16();
        let e = self.fast[(v >> (16 - FAST_BITS)) as usize];
        if e != 0 {
            bits.consume(u32::from(e & 31))?;
            return Ok(e >> 5);
        }
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for len in 1..=MAX_CODE_LEN as u32 {
            let code = v >> (16 - len);
            let count = u32::from(self.counts[len as usize]);
            if code - first < count {
                bits.consume(len)?;
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
        }
        Err(LzxError::InvalidCode)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockType {
    None,
    Verbatim,
    Aligned,
    Uncompressed,
}

struct State {
    main_elems: usize,
    window: usize,
    r: [u32; 3],
    main_lens: [u8; MAX_MAIN],
    len_lens: [u8; LENGTH_SIZE],
    main: Huffman,
    length: Huffman,
    aligned: Huffman,
    pretree: Huffman,
    block: BlockType,
    block_len: u32,
    block_remaining: u32,
    header_read: bool,
    e8_size: Option<u32>,
}

impl State {
    fn reset(&mut self) {
        self.r = [1, 1, 1];
        self.main_lens = [0; MAX_MAIN];
        self.len_lens = [0; LENGTH_SIZE];
        self.block = BlockType::None;
        self.block_len = 0;
        self.block_remaining = 0;
        self.header_read = false;
        self.e8_size = None;
    }

    fn read_lengths(&mut self, bits: &mut BitIn<'_>, which: Which, first: usize, last: usize) -> Result<(), LzxError> {
        let mut pl = [0u8; PRETREE_SIZE];
        for l in pl.iter_mut() {
            *l = bits.read(4)? as u8;
        }
        self.pretree.build(&pl)?;
        let lens: &mut [u8] = match which {
            Which::Main => &mut self.main_lens[..],
            Which::Length => &mut self.len_lens[..],
        };
        let mut x = first;
        while x < last {
            let z = self.pretree.decode(bits)? as usize;
            match z {
                17 | 18 => {
                    let n = if z == 17 { 4 + bits.read(4)? } else { 20 + bits.read(5)? } as usize;
                    if x + n > last {
                        return Err(LzxError::InvalidTree);
                    }
                    lens[x..x + n].fill(0);
                    x += n;
                }
                19 => {
                    let n = 4 + bits.read(1)? as usize;
                    if x + n > last {
                        return Err(LzxError::InvalidTree);
                    }
                    let z2 = self.pretree.decode(bits)? as usize;
                    if z2 > 16 {
                        return Err(LzxError::InvalidTree);
                    }
                    let v = ((lens[x] as usize + 17 - z2) % 17) as u8;
                    lens[x..x + n].fill(v);
                    x += n;
                }
                _ => {
                    lens[x] = ((lens[x] as usize + 17 - z) % 17) as u8;
                    x += 1;
                }
            }
        }
        Ok(())
    }

    fn read_block_header(&mut self, bits: &mut BitIn<'_>) -> Result<(), LzxError> {
        if self.block == BlockType::Uncompressed && self.block_len & 1 == 1 {
            // pad byte after an odd-sized uncompressed block
            bits.bytes(1)?;
        }
        let t = bits.read(3)?;
        let hi = bits.read(16)?;
        let lo = bits.read(8)?;
        let size = (hi << 8) | lo;
        if size == 0 {
            return Err(LzxError::InvalidBlock);
        }
        match t {
            1 | 2 => {
                if t == 2 {
                    let mut al = [0u8; ALIGNED_SIZE];
                    for l in al.iter_mut() {
                        *l = bits.read(3)? as u8;
                    }
                    self.aligned.build(&al)?;
                }
                self.read_lengths(bits, Which::Main, 0, NUM_CHARS)?;
                self.read_lengths(bits, Which::Main, NUM_CHARS, self.main_elems)?;
                self.main.build(&self.main_lens[..self.main_elems])?;
                self.read_lengths(bits, Which::Length, 0, LENGTH_SIZE)?;
                self.length.build(&self.len_lens)?;
                self.block = if t == 1 { BlockType::Verbatim } else { BlockType::Aligned };
            }
            3 => {
                bits.enter_bytes()?;
                let r = bits.bytes(12)?;
                for (i, c) in r.chunks_exact(4).enumerate() {
                    self.r[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                }
                self.block = BlockType::Uncompressed;
            }
            _ => return Err(LzxError::InvalidBlock),
        }
        self.block_len = size;
        self.block_remaining = size;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Which {
    Main,
    Length,
}

/// Decompress an LZX stream into exactly `output_len` bytes.
///
/// `window_bits` is 15..=21 (the CAB `typeCompress` window field or the CHM
/// LZXC window size). `reset_interval_frames` is the CHM reset interval in
/// 32 KiB frames (0 = no resets, as in CAB): at every multiple the decoder
/// state (R0..R2, tree lengths, E8 header) restarts.
///
/// For exact E8 translation `output_len` should be the full stream length or
/// a multiple of [`FRAME_SIZE`]; stopping inside a frame translates that
/// frame as if it ended there. Trailing input after `output_len` bytes is
/// ignored.
pub fn lzx_decompress(
    input: &[u8],
    window_bits: u8,
    output_len: usize,
    reset_interval_frames: u32,
) -> Result<Vec<u8>, LzxError> {
    let slots = position_slots(window_bits)?;
    if output_len > isize::MAX as usize / 2 {
        return Err(LzxError::LimitExceeded);
    }
    let mut st = State {
        main_elems: NUM_CHARS + 8 * slots,
        window: 1usize << window_bits,
        r: [1, 1, 1],
        main_lens: [0; MAX_MAIN],
        len_lens: [0; LENGTH_SIZE],
        main: Huffman::new(),
        length: Huffman::new(),
        aligned: Huffman::new(),
        pretree: Huffman::new(),
        block: BlockType::None,
        block_len: 0,
        block_remaining: 0,
        header_read: false,
        e8_size: None,
    };
    let mut bits = BitIn::new(input);
    let mut out: Vec<u8> = Vec::new();
    // (segment start, E8 translation size) for each reset segment
    let mut segments: Vec<(usize, Option<u32>)> = Vec::new();
    let mut reset_base = 0usize;
    let mut frame_start = 0usize;
    let mut frame_index: u64 = 0;

    while out.len() < output_len {
        if reset_interval_frames != 0 && frame_index != 0 && frame_index.is_multiple_of(u64::from(reset_interval_frames)) {
            if out.len() != frame_start {
                return Err(LzxError::InvalidReset);
            }
            st.reset();
            reset_base = frame_start;
        }
        if !st.header_read {
            st.header_read = true;
            if bits.read(1)? == 1 {
                let hi = bits.read(16)?;
                let lo = bits.read(16)?;
                st.e8_size = Some((hi << 16) | lo);
            } else {
                st.e8_size = None;
            }
            segments.try_reserve(1).map_err(|_| LzxError::Allocation)?;
            segments.push((reset_base, st.e8_size));
        }
        let frame_end = frame_start.saturating_add(FRAME_SIZE).min(output_len);
        out.try_reserve(frame_end.saturating_sub(out.len()) + 257).map_err(|_| LzxError::Allocation)?;
        while out.len() < frame_end {
            if st.block_remaining == 0 {
                st.read_block_header(&mut bits)?;
            }
            let run_end = out.len() + (st.block_remaining as usize).min(frame_end - out.len());
            if st.block == BlockType::Uncompressed {
                let n = run_end - out.len();
                let raw = bits.bytes(n)?;
                out.extend_from_slice(raw);
                st.block_remaining -= n as u32;
                continue;
            }
            let aligned = st.block == BlockType::Aligned;
            while out.len() < run_end {
                let sym = st.main.decode(&mut bits)? as usize;
                if sym < NUM_CHARS {
                    out.push(sym as u8);
                    st.block_remaining -= 1;
                    continue;
                }
                let s = sym - NUM_CHARS;
                let mut len = s & 7;
                if len == 7 {
                    len += st.length.decode(&mut bits)? as usize;
                }
                len += MIN_MATCH;
                let slot = s >> 3;
                let off = match slot {
                    0 => st.r[0],
                    1 => {
                        st.r.swap(0, 1);
                        st.r[0]
                    }
                    2 => {
                        st.r.swap(0, 2);
                        st.r[0]
                    }
                    _ => {
                        let extra = u32::from(EXTRA_BITS[slot]);
                        let footer = if aligned && extra >= 3 {
                            let hi = bits.read(extra - 3)?;
                            let lo = u32::from(st.aligned.decode(&mut bits)?);
                            (hi << 3) | lo
                        } else {
                            bits.read(extra)?
                        };
                        let o = POSITION_BASE[slot] + footer - 2;
                        st.r = [o, st.r[0], st.r[1]];
                        o
                    }
                } as usize;
                if len > st.block_remaining as usize {
                    return Err(LzxError::InvalidMatch);
                }
                if off == 0 || off > out.len() - reset_base || off > st.window {
                    return Err(LzxError::InvalidMatch);
                }
                if out.capacity() - out.len() < len {
                    out.try_reserve(len).map_err(|_| LzxError::Allocation)?;
                }
                let start = out.len() - off;
                if off >= len {
                    out.extend_from_within(start..start + len);
                } else {
                    for k in 0..len {
                        let b = out[start + k];
                        out.push(b);
                    }
                }
                st.block_remaining -= len as u32;
            }
        }
        if st.block != BlockType::Uncompressed {
            bits.align16();
        }
        frame_start += FRAME_SIZE;
        frame_index += 1;
    }
    out.truncate(output_len);
    // Undo E8 translation, frame by frame within each reset segment.
    for (i, &(seg_start, e8)) in segments.iter().enumerate() {
        let Some(tsize) = e8 else { continue };
        let seg_end = segments.get(i + 1).map_or(out.len(), |s| s.0).min(out.len());
        let mut fs = seg_start;
        let mut frame_no = 0usize;
        while fs < seg_end && frame_no < 32768 {
            let flen = (seg_end - fs).min(FRAME_SIZE);
            if flen > 10 {
                e8_undo(&mut out[fs..fs + flen], fs - seg_start, tsize);
            }
            fs += FRAME_SIZE;
            frame_no += 1;
        }
    }
    Ok(out)
}

fn e8_undo(frame: &mut [u8], frame_pos: usize, tsize: u32) {
    let tsize = i64::from(tsize);
    let end = frame.len() - 10;
    let mut i = 0;
    while i < end {
        if frame[i] != 0xE8 {
            i += 1;
            continue;
        }
        let cur = (frame_pos + i) as i64;
        let abs = i64::from(i32::from_le_bytes([frame[i + 1], frame[i + 2], frame[i + 3], frame[i + 4]]));
        if abs >= -cur && abs < tsize {
            let rel = if abs >= 0 { abs - cur } else { abs + tsize };
            frame[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        }
        i += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        assert_eq!(&EXTRA_BITS[..10], &[0, 0, 0, 0, 1, 1, 2, 2, 3, 3]);
        assert_eq!(EXTRA_BITS[51], 17);
        assert_eq!(&POSITION_BASE[..8], &[0, 1, 2, 3, 4, 6, 8, 12]);
        // the largest slot of each window covers exactly window - 3 offsets
        for wb in 15..=21u8 {
            let n = position_slots(wb).unwrap();
            assert!(POSITION_BASE[n] as usize >= (1usize << wb), "wb {wb}");
        }
    }

    #[test]
    fn huffman_rejects_oversubscribed() {
        let mut h = Huffman::new();
        assert_eq!(h.build(&[1, 1, 1]), Err(LzxError::InvalidTree));
        assert!(h.build(&[1, 2]).is_ok());
        assert!(h.build(&[0, 0, 0]).is_ok());
    }
}
