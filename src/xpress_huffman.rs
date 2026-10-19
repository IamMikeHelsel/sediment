// SPDX-License-Identifier: MIT OR Apache-2.0
//! XPRESS Huffman ("LZ77+Huffman") decompression, as used for WIM chunks.
//!
//! Spec source: [MS-XCA] "Xpress Compression Algorithm", section 2.1-2.2
//! (LZ77+Huffman): each 65536-byte block of output starts with a 256-byte
//! table of 512 four-bit code lengths (low nibble = even symbol), followed
//! by a bitstream of 16-bit little-endian words read most-significant bit
//! first. Symbols 0-255 are literals; symbol 256 + (offset_bits << 4) +
//! length_nibble is a match whose offset is `(1 << offset_bits) + bits`
//! and whose length extension bytes (1, then 2, then 4 bytes) are read
//! from the byte stream between words. Codes are canonical (shorter codes
//! first, ties by symbol value), at most 15 bits.
//!
//! The decoder produces exactly `out_len` bytes. Matches may not reach
//! before the start of the output or past `out_len`. A stream that runs
//! out of input yields [`XpressError::Truncated`]; bitstream refills past
//! the end read as zero for at most two words (an encoder may end with a
//! partially used word pair), beyond that the stream is truncated.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpressError {
    /// Input ended before `out_len` bytes were produced.
    Truncated,
    /// Invalid code-length table (over-subscribed or empty) or an
    /// undecodable bit pattern.
    InvalidTable,
    /// A match points before the start of the output, runs past `out_len`
    /// or has an invalid length encoding.
    InvalidMatch,
    /// `out_len` exceeds the caller's limit.
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
}

const TABLE_BYTES: usize = 256;
const NUM_SYMBOLS: usize = 512;
const MAX_CODE_LEN: u32 = 15;
const BLOCK_OUTPUT: usize = 65536;
/// Zero words a refill may supply past the end of the input.
const MAX_OVERRUN_WORDS: u32 = 2;

/// Lookup table indexed by the next 15 bits: `(symbol << 4) | length`, or
/// 0 for an unassigned pattern (length 0 never occurs for a real code).
fn build_table(lengths: &[u8; NUM_SYMBOLS], table: &mut [u16]) -> Result<(), XpressError> {
    let mut count = [0u32; 16];
    for &l in lengths.iter() {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    // Kraft check: no over-subscription; at least one code.
    let mut left: i64 = 1;
    for &c in &count[1..=MAX_CODE_LEN as usize] {
        left = (left << 1) - i64::from(c);
        if left < 0 {
            return Err(XpressError::InvalidTable);
        }
    }
    if count.iter().all(|&c| c == 0) {
        return Err(XpressError::InvalidTable);
    }
    table.fill(0);
    let mut pos = 0usize;
    for len in 1..=MAX_CODE_LEN {
        let span = 1usize << (MAX_CODE_LEN - len);
        for (sym, &l) in lengths.iter().enumerate() {
            if u32::from(l) != len {
                continue;
            }
            let entry = ((sym as u16) << 4) | len as u16;
            table[pos..pos + span].fill(entry);
            pos += span;
        }
    }
    Ok(())
}

struct Input<'a> {
    data: &'a [u8],
    pos: usize,
    overrun: u32,
}

impl Input<'_> {
    fn word(&mut self) -> Result<u32, XpressError> {
        if let Some(w) = self.data.get(self.pos..self.pos + 2) {
            self.pos += 2;
            Ok(u32::from(u16::from_le_bytes([w[0], w[1]])))
        } else {
            self.overrun += 1;
            if self.overrun > MAX_OVERRUN_WORDS {
                return Err(XpressError::Truncated);
            }
            // Keep `pos` at the end; a later block table would be truncated.
            self.pos = self.data.len();
            Ok(0)
        }
    }
    fn bytes(&mut self, n: usize) -> Result<u32, XpressError> {
        let s = self.data.get(self.pos..self.pos + n).ok_or(XpressError::Truncated)?;
        self.pos += n;
        Ok(s.iter().rev().fold(0u32, |a, &b| (a << 8) | u32::from(b)))
    }
}

/// Decompress an XPRESS Huffman stream into exactly `out_len` bytes.
/// `max_output` bounds `out_len` before anything is allocated.
pub fn decompress(input: &[u8], out_len: usize, max_output: usize) -> Result<Vec<u8>, XpressError> {
    if out_len > max_output {
        return Err(XpressError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(out_len).map_err(|_| XpressError::Allocation)?;
    decompress_into(input, out_len, &mut out)?;
    Ok(out)
}

/// Like [`decompress`], appending to `out`; matches may only reference the
/// bytes produced by this call.
pub fn decompress_into(input: &[u8], out_len: usize, out: &mut Vec<u8>) -> Result<(), XpressError> {
    let base = out.len();
    let end = base.checked_add(out_len).ok_or(XpressError::LimitExceeded)?;
    out.try_reserve(out_len).map_err(|_| XpressError::Allocation)?;
    let mut table = vec![0u16; 1 << MAX_CODE_LEN];
    let mut inp = Input { data: input, pos: 0, overrun: 0 };
    while out.len() < end {
        // Code-length table for this block.
        let t = input.get(inp.pos..inp.pos + TABLE_BYTES).ok_or(XpressError::Truncated)?;
        let mut lengths = [0u8; NUM_SYMBOLS];
        for (i, &b) in t.iter().enumerate() {
            lengths[2 * i] = b & 15;
            lengths[2 * i + 1] = b >> 4;
        }
        build_table(&lengths, &mut table)?;
        inp.pos += TABLE_BYTES;
        let mut next_bits: u32 = (inp.word()? << 16) | inp.word()?;
        let mut extra: i32 = 16;
        let block_end = (out.len() + BLOCK_OUTPUT).min(end);
        while out.len() < block_end {
            let entry = table[(next_bits >> (32 - MAX_CODE_LEN)) as usize];
            if entry == 0 {
                return Err(XpressError::InvalidTable);
            }
            let len = u32::from(entry & 15);
            let sym = usize::from(entry >> 4);
            next_bits <<= len;
            extra -= len as i32;
            if extra < 0 {
                next_bits |= inp.word()? << (-extra) as u32;
                extra += 16;
            }
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let sym = sym - 256;
            let mut length = (sym & 15) as u32;
            let offset_bits = (sym >> 4) as u32;
            if length == 15 {
                length = inp.bytes(1)?;
                if length == 255 {
                    length = inp.bytes(2)?;
                    if length == 0 {
                        length = inp.bytes(4)?;
                    }
                    if length < 15 {
                        return Err(XpressError::InvalidMatch);
                    }
                    length -= 15;
                }
                length = length.checked_add(15).ok_or(XpressError::InvalidMatch)?;
            }
            let length = (length as usize).checked_add(3).ok_or(XpressError::InvalidMatch)?;
            let offset_extra = if offset_bits == 0 { 0 } else { next_bits >> (32 - offset_bits) };
            let offset = (1usize << offset_bits) + offset_extra as usize;
            if offset_bits > 0 {
                next_bits = next_bits.checked_shl(offset_bits).unwrap_or(0);
                extra -= offset_bits as i32;
                if extra < 0 {
                    next_bits |= inp.word()? << (-extra) as u32;
                    extra += 16;
                }
            }
            if offset > out.len() - base || length > end - out.len() {
                return Err(XpressError::InvalidMatch);
            }
            crate::zstd_decode::copy_match(out, offset, length);
        }
        if inp.overrun > 0 && out.len() < end {
            return Err(XpressError::Truncated);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_tables() {
        // All lengths zero.
        let mut input = vec![0u8; 260];
        assert_eq!(decompress(&input, 1, 10), Err(XpressError::InvalidTable));
        // Three 1-bit codes: over-subscribed.
        input[0] = 0x11;
        input[1] = 0x01;
        assert_eq!(decompress(&input, 1, 10), Err(XpressError::InvalidTable));
        assert_eq!(decompress(&input[..100], 1, 10), Err(XpressError::Truncated));
        assert_eq!(decompress(&input, 11, 10), Err(XpressError::LimitExceeded));
        assert_eq!(decompress(&[], 0, 10), Ok(Vec::new()));
    }

    #[test]
    fn two_literals() {
        // Symbols 'a' (0x61) and 'b' (0x62) with 1-bit codes: 'a' = 0, 'b' = 1.
        let mut input = vec![0u8; 256];
        input[0x61 / 2] = 0x10; // odd symbol 0x61 -> high nibble
        input[0x62 / 2] = 0x01; // even symbol 0x62 -> low nibble
        // Bits "0110" then padding: word0 = 0b0110_0000_0000_0000.
        input.extend_from_slice(&0x6000u16.to_le_bytes());
        input.extend_from_slice(&[0, 0]);
        assert_eq!(decompress(&input, 4, 10).unwrap(), b"abba");
    }
}
