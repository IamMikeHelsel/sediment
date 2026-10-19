// SPDX-License-Identifier: MIT OR Apache-2.0
//! BZip2 (`.bz2`) decoder.
//!
//! Implemented from the publicly documented bzip2 format: the bzip2 manual's
//! description of the pipeline (RLE1, Burrows-Wheeler transform, move-to-front,
//! RUNA/RUNB zero-run coding, multi-table Huffman coding), Joe Tsai's
//! "BZip2 format specification" write-up, and Burrows & Wheeler's 1994 report
//! for the inverse transform. No bzip2 or 7-Zip source code was consulted.
//!
//! Layout decoded here, all fields MSB-first:
//! - stream: `"BZh"` + level digit `'1'..='9'`, blocks, then the end-of-stream
//!   marker `0x177245385090`, a 32-bit combined CRC, and zero padding to a byte.
//! - block: magic `0x314159265359`, 32-bit block CRC (CRC-32/BZIP2 of the
//!   block's original bytes), 1 randomised bit (unsupported, rejected),
//!   24-bit BWT origin pointer, symbol map, 3-bit group count (2..=6),
//!   15-bit selector count, MTF-coded unary selectors, delta-coded code
//!   lengths (1..=20) per group, then Huffman symbols in 50-symbol groups.
//!
//! Concatenated streams are decoded in order. Bytes after the last stream
//! that do not form another complete stream are rejected (`TrailingData` if
//! they do not start with the `BZh` signature).

use crate::crc32_bzip2::crc32_bzip2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bzip2DecodeError {
    /// Input ended before the stream was complete.
    Truncated,
    /// Missing `BZh` signature or invalid level digit.
    BadSignature,
    /// A block or end-of-stream magic did not match.
    BadMagic,
    /// Randomised blocks (obsolete bzip2 0.9.0 feature) are not supported.
    Randomized,
    /// Symbol map, group count, selector or code-length data is invalid.
    BadTables,
    /// Huffman data could not be decoded or ran past its selectors.
    BadHuffmanData,
    /// The block exceeds the size declared in the stream header.
    BlockTooLarge,
    /// The BWT origin pointer is out of range.
    BadOrigPtr,
    /// A block CRC did not match its decoded data.
    BlockCrcMismatch,
    /// The combined stream CRC did not match.
    StreamCrcMismatch,
    /// Bytes after the final stream are not a bzip2 stream.
    TrailingData,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

type R<T> = Result<T, Bzip2DecodeError>;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const MAX_CODE_LEN: u32 = 20;
const GROUP_SIZE: usize = 50;
/// Selectors beyond this count are read but ignored (enough for 900k blocks).
const MAX_SELECTORS: usize = 18002;

struct MsbReader<'a> {
    data: &'a [u8],
    pos: usize, // bit position
}

impl<'a> MsbReader<'a> {
    fn bit(&mut self) -> R<u32> {
        let byte = *self.data.get(self.pos >> 3).ok_or(Bzip2DecodeError::Truncated)?;
        let b = (byte >> (7 - (self.pos & 7))) & 1;
        self.pos += 1;
        Ok(b as u32)
    }

    fn bits(&mut self, n: u32) -> R<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Ok(v)
    }

    fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }

    fn byte_pos(&self) -> usize {
        self.pos >> 3
    }
}

/// Canonical Huffman decoding table for one group.
struct Table {
    /// Number of codes of each length 0..=20.
    count: [u32; 21],
    /// Symbols sorted by (length, symbol).
    perm: [u16; MAX_ALPHA],
}

impl Table {
    fn new(lengths: &[u8]) -> Table {
        let mut count = [0u32; 21];
        for &l in lengths {
            count[l as usize] += 1;
        }
        let mut perm = [0u16; MAX_ALPHA];
        let mut k = 0;
        for len in 1..=MAX_CODE_LEN as u8 {
            for (sym, &l) in lengths.iter().enumerate() {
                if l == len {
                    perm[k] = sym as u16;
                    k += 1;
                }
            }
        }
        Table { count, perm }
    }

    fn decode(&self, r: &mut MsbReader) -> R<u16> {
        let mut code: u64 = 0;
        let mut first: u64 = 0;
        let mut index: u64 = 0;
        for len in 1..=MAX_CODE_LEN as usize {
            code |= r.bit()? as u64;
            let c = self.count[len] as u64;
            if code < first + c {
                let i = (index + code - first) as usize;
                return self.perm.get(i).copied().ok_or(Bzip2DecodeError::BadHuffmanData);
            }
            index += c;
            first = (first + c) << 1;
            code <<= 1;
        }
        Err(Bzip2DecodeError::BadHuffmanData)
    }
}

/// Decodes one or more concatenated bzip2 streams, producing at most
/// `max_output` bytes.
pub fn decode_bzip2(input: &[u8], max_output: usize) -> R<Vec<u8>> {
    let mut out = Vec::new();
    let mut r = MsbReader { data: input, pos: 0 };
    if input.is_empty() {
        return Err(Bzip2DecodeError::Truncated);
    }
    loop {
        decode_stream(&mut r, &mut out, max_output)?;
        r.align();
        let rest = &input[r.byte_pos()..];
        if rest.is_empty() {
            return Ok(out);
        }
        if rest.len() >= 3 && &rest[..3] != b"BZh" || rest.len() < 3 && !b"BZh".starts_with(rest) {
            return Err(Bzip2DecodeError::TrailingData);
        }
    }
}

fn decode_stream(r: &mut MsbReader, out: &mut Vec<u8>, max_output: usize) -> R<()> {
    let sig = r.bits(24)?;
    if sig != 0x425A68 {
        return Err(Bzip2DecodeError::BadSignature);
    }
    let level = r.bits(8)? as u8;
    if !(b'1'..=b'9').contains(&level) {
        return Err(Bzip2DecodeError::BadSignature);
    }
    let max_block = (level - b'0') as usize * 100_000;
    let mut combined: u32 = 0;
    let mut block = Vec::new();
    let mut tt: Vec<u32> = Vec::new();
    loop {
        let magic = r.bits(48)?;
        if magic == EOS_MAGIC {
            let stored = r.bits(32)? as u32;
            if stored != combined {
                return Err(Bzip2DecodeError::StreamCrcMismatch);
            }
            return Ok(());
        }
        if magic != BLOCK_MAGIC {
            return Err(Bzip2DecodeError::BadMagic);
        }
        let stored_crc = r.bits(32)? as u32;
        let start = out.len();
        decode_block(r, max_block, &mut block, &mut tt, out, max_output)?;
        let crc = crc32_bzip2(&out[start..]);
        if crc != stored_crc {
            return Err(Bzip2DecodeError::BlockCrcMismatch);
        }
        combined = combined.rotate_left(1) ^ crc;
    }
}

fn decode_block(
    r: &mut MsbReader,
    max_block: usize,
    block: &mut Vec<u8>,
    tt: &mut Vec<u32>,
    out: &mut Vec<u8>,
    max_output: usize,
) -> R<()> {
    use Bzip2DecodeError::*;
    if r.bit()? != 0 {
        return Err(Randomized);
    }
    let orig_ptr = r.bits(24)? as usize;

    // Symbol map.
    let ranges = r.bits(16)?;
    let mut seq_to_unseq = [0u8; 256];
    let mut n_in_use = 0usize;
    for i in 0..16 {
        if ranges & (1 << (15 - i)) != 0 {
            let bits = r.bits(16)?;
            for j in 0..16 {
                if bits & (1 << (15 - j)) != 0 {
                    seq_to_unseq[n_in_use] = (i * 16 + j) as u8;
                    n_in_use += 1;
                }
            }
        }
    }
    if n_in_use == 0 {
        return Err(BadTables);
    }
    let alpha = n_in_use + 2;

    let n_groups = r.bits(3)? as usize;
    if !(2..=MAX_GROUPS).contains(&n_groups) {
        return Err(BadTables);
    }
    let n_selectors = r.bits(15)? as usize;
    if n_selectors == 0 {
        return Err(BadTables);
    }
    let mut mtf_groups = [0u8, 1, 2, 3, 4, 5];
    let mut selectors: Vec<u8> = Vec::new();
    selectors
        .try_reserve_exact(n_selectors.min(MAX_SELECTORS))
        .map_err(|_| Allocation)?;
    for _ in 0..n_selectors {
        let mut j = 0usize;
        while r.bit()? == 1 {
            j += 1;
            if j >= n_groups {
                return Err(BadTables);
            }
        }
        let v = mtf_groups[j];
        mtf_groups.copy_within(0..j, 1);
        mtf_groups[0] = v;
        if selectors.len() < MAX_SELECTORS {
            selectors.push(v);
        }
    }

    let mut tables = Vec::with_capacity(n_groups);
    let mut lengths = [0u8; MAX_ALPHA];
    for _ in 0..n_groups {
        let mut curr = r.bits(5)? as i32;
        for len in lengths.iter_mut().take(alpha) {
            loop {
                if !(1..=MAX_CODE_LEN as i32).contains(&curr) {
                    return Err(BadTables);
                }
                if r.bit()? == 0 {
                    break;
                }
                if r.bit()? == 0 {
                    curr += 1;
                } else {
                    curr -= 1;
                }
            }
            *len = curr as u8;
        }
        tables.push(Table::new(&lengths[..alpha]));
    }

    // Huffman + RUNA/RUNB + MTF decode into the BWT last column.
    block.clear();
    let mut counts = [0u32; 256];
    let mut mtf: [u8; 256] = [0; 256];
    for (i, m) in mtf.iter_mut().enumerate() {
        *m = i as u8;
    }
    let eob = (alpha - 1) as u16;
    let mut group_left = 0usize;
    let mut sel_index = 0usize;
    let mut table = &tables[0];
    let mut run: usize = 0;
    let mut weight: usize = 1;
    loop {
        if group_left == 0 {
            let sel = *selectors.get(sel_index).ok_or(BadHuffmanData)? as usize;
            table = tables.get(sel).ok_or(BadTables)?;
            sel_index += 1;
            group_left = GROUP_SIZE;
        }
        group_left -= 1;
        let sym = table.decode(r)?;
        if sym <= 1 {
            run += weight << sym;
            weight <<= 1;
            if run > max_block {
                return Err(BlockTooLarge);
            }
            continue;
        }
        if run > 0 {
            let b = seq_to_unseq[mtf[0] as usize];
            if block.len() + run > max_block {
                return Err(BlockTooLarge);
            }
            block.try_reserve(run).map_err(|_| Allocation)?;
            block.resize(block.len() + run, b);
            counts[b as usize] += run as u32;
            run = 0;
            weight = 1;
        }
        if sym == eob {
            break;
        }
        let idx = (sym - 1) as usize;
        if idx >= n_in_use {
            return Err(BadHuffmanData);
        }
        let v = mtf[idx];
        mtf.copy_within(0..idx, 1);
        mtf[0] = v;
        if block.len() >= max_block {
            return Err(BlockTooLarge);
        }
        let b = seq_to_unseq[v as usize];
        block.try_reserve(1).map_err(|_| Allocation)?;
        block.push(b);
        counts[b as usize] += 1;
    }

    let n = block.len();
    if orig_ptr >= n {
        return Err(BadOrigPtr);
    }

    // Inverse BWT: T maps each sorted-row index to the row holding the
    // following character.
    let mut cum = [0u32; 256];
    let mut sum = 0u32;
    for i in 0..256 {
        cum[i] = sum;
        sum += counts[i];
    }
    tt.clear();
    tt.try_reserve_exact(n).map_err(|_| Allocation)?;
    tt.resize(n, 0);
    for (i, &b) in block.iter().enumerate() {
        let c = &mut cum[b as usize];
        tt[*c as usize] = i as u32;
        *c += 1;
    }

    // Undo RLE1 while walking the inverse BWT.
    let mut pos = tt[orig_ptr] as usize;
    let mut last: i32 = -1;
    let mut same = 0u32;
    let mut i = 0;
    while i < n {
        let b = block[pos];
        pos = tt[pos] as usize;
        i += 1;
        if same == 4 {
            let extra = b as usize;
            if out.len().checked_add(extra).is_none_or(|t| t > max_output) {
                return Err(LimitExceeded);
            }
            out.try_reserve(extra).map_err(|_| Allocation)?;
            let lb = last as u8;
            out.resize(out.len() + extra, lb);
            same = 0;
            last = -1;
            continue;
        }
        if b as i32 == last {
            same += 1;
        } else {
            last = b as i32;
            same = 1;
        }
        if out.len() >= max_output {
            return Err(LimitExceeded);
        }
        out.try_reserve(1).map_err(|_| Allocation)?;
        out.push(b);
    }
    Ok(())
}
