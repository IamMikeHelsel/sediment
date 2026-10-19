// SPDX-License-Identifier: MIT OR Apache-2.0
//! Static-Huffman LZ77 decoder shared by LHA/LZH (`-lh4-` .. `-lh7-`) and
//! ARJ (methods 1..3), plus ARJ method 4 ("fastest").
//!
//! Spec sources: the LHa header/format notes and the public description of
//! Okumura's ar002 block format (block = 16-bit code count, a "T" table
//! that codes the literal/length code lengths, the "C" table itself and the
//! "P" position-bit-length table; MSB-first bit order; canonical codes),
//! and Robert Jung's ARJ technical notes for ARJ's 26624-byte window and
//! the method-4 unary-prefixed length/pointer coding. Implemented from
//! those descriptions; no third-party decoder source was consulted.
//!
//! Parameters (`dicbit`, NP, PBIT): lh4 = 12/13/4, lh5 = 13/14/4,
//! lh6 = 15/16/5, lh7 = 16/17/5, ARJ 1-3 = window 26624, NP 17, PBIT 5.
//!
//! Limits: `out_size` must not exceed the caller's `max_output`; output is
//! reserved once and never grows past `out_size`. Matches that reach before
//! the start of the output, past the window, or past `out_size` are
//! rejected. Incomplete or oversubscribed Huffman tables are rejected.
//! Reading past the end of the input is `Truncated`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzhDecodeError {
    /// The compressed stream ended before `out_size` bytes were produced.
    Truncated,
    /// Malformed code tables, codes or match references.
    InvalidData,
    /// `out_size` exceeds the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

/// LHA static-Huffman method variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LhMethod {
    Lh4,
    Lh5,
    Lh6,
    Lh7,
}

impl LhMethod {
    /// Parse a 5-byte method id such as `-lh5-`.
    pub fn from_id(id: &[u8]) -> Option<Self> {
        match id {
            b"-lh4-" => Some(LhMethod::Lh4),
            b"-lh5-" => Some(LhMethod::Lh5),
            b"-lh6-" => Some(LhMethod::Lh6),
            b"-lh7-" => Some(LhMethod::Lh7),
            _ => None,
        }
    }

    /// (window size, NP, PBIT)
    pub fn params(self) -> (usize, usize, u32) {
        match self {
            LhMethod::Lh4 => (1 << 12, 13, 4),
            LhMethod::Lh5 => (1 << 13, 14, 4),
            LhMethod::Lh6 => (1 << 15, 16, 5),
            LhMethod::Lh7 => (1 << 16, 17, 5),
        }
    }
}

/// ARJ's sliding dictionary size for methods 1..4.
pub const ARJ_WINDOW: usize = 26624;
const NC: usize = 510;
const NT: usize = 19;
const TBIT: u32 = 5;
const CBIT: u32 = 9;
const MAX_NP: usize = 17;
const MAX_LEN: usize = 16;
const THRESHOLD: usize = 3;

/// MSB-first bit reader. Bits past the end read as zero but consuming them
/// is an error.
struct MsbBits<'a> {
    data: &'a [u8],
    pos: usize,
    total: usize,
}

impl<'a> MsbBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        MsbBits { data, pos: 0, total: data.len().saturating_mul(8) }
    }

    /// The next 16 bits, MSB first, zero-padded past the end.
    fn peek16(&self) -> u32 {
        let byte = self.pos / 8;
        let shift = self.pos % 8;
        let b = |i: usize| u32::from(self.data.get(byte + i).copied().unwrap_or(0));
        let v = (b(0) << 16) | (b(1) << 8) | b(2);
        (v >> (8 - shift)) & 0xFFFF
    }

    fn consume(&mut self, n: u32) -> Result<(), LzhDecodeError> {
        self.pos = self.pos.saturating_add(n as usize);
        if self.pos > self.total { Err(LzhDecodeError::Truncated) } else { Ok(()) }
    }

    /// Read `n` (0..=16) bits.
    fn bits(&mut self, n: u32) -> Result<u32, LzhDecodeError> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.peek16() >> (16 - n);
        self.consume(n)?;
        Ok(v)
    }
}

/// Canonical Huffman decoding table (codes assigned shortest-first, then by
/// symbol), or a degenerate single symbol that consumes no bits.
struct Huff {
    single: Option<u16>,
    counts: [u16; MAX_LEN + 1],
    symbols: Vec<u16>,
}

impl Huff {
    fn single(sym: u16) -> Self {
        Huff { single: Some(sym), counts: [0; MAX_LEN + 1], symbols: Vec::new() }
    }

    fn from_lengths(lens: &[u8]) -> Result<Self, LzhDecodeError> {
        let mut counts = [0u16; MAX_LEN + 1];
        for &l in lens {
            if l as usize > MAX_LEN {
                return Err(LzhDecodeError::InvalidData);
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // The code must be complete: sum of 2^(16-len) == 2^16.
        let mut space: u32 = 0;
        for (l, &c) in counts.iter().enumerate().skip(1) {
            space += u32::from(c) << (MAX_LEN - l);
        }
        if space != 1 << MAX_LEN {
            return Err(LzhDecodeError::InvalidData);
        }
        let mut offs = [0u16; MAX_LEN + 2];
        for l in 1..=MAX_LEN {
            offs[l + 1] = offs[l] + counts[l];
        }
        let mut symbols = vec![0u16; offs[MAX_LEN + 1] as usize];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { single: None, counts, symbols })
    }

    fn decode(&self, br: &mut MsbBits<'_>) -> Result<u16, LzhDecodeError> {
        if let Some(s) = self.single {
            return Ok(s);
        }
        let v = br.peek16();
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for len in 1..=MAX_LEN {
            code |= (v >> (MAX_LEN - len)) & 1;
            let count = u32::from(self.counts[len]);
            if code < first + count {
                br.consume(len as u32)?;
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(LzhDecodeError::InvalidData)
    }
}

/// Read a T or P length table (`nn` symbols, `nbit`-bit count). After
/// `i_special` lengths a 2-bit count of zero lengths follows.
fn read_pt_len(br: &mut MsbBits<'_>, nn: usize, nbit: u32, i_special: Option<usize>) -> Result<Huff, LzhDecodeError> {
    let n = br.bits(nbit)? as usize;
    if n == 0 {
        let c = br.bits(nbit)? as usize;
        if c >= nn {
            return Err(LzhDecodeError::InvalidData);
        }
        return Ok(Huff::single(c as u16));
    }
    if n > nn {
        return Err(LzhDecodeError::InvalidData);
    }
    let mut lens = [0u8; NT]; // NT (19) >= MAX_NP (17)
    let mut i = 0usize;
    while i < n {
        let v = br.peek16();
        let mut c = (v >> 13) as usize;
        if c == 7 {
            let mut mask = 1u32 << 12;
            while v & mask != 0 {
                mask >>= 1;
                c += 1;
                if c > MAX_LEN {
                    return Err(LzhDecodeError::InvalidData);
                }
            }
        }
        br.consume(if c < 7 { 3 } else { (c - 3) as u32 })?;
        lens[i] = c as u8;
        i += 1;
        if Some(i) == i_special {
            let z = br.bits(2)? as usize;
            if i + z > nn {
                return Err(LzhDecodeError::InvalidData);
            }
            i += z; // those lengths stay zero
        }
    }
    Huff::from_lengths(&lens[..nn])
}

fn read_c_len(br: &mut MsbBits<'_>, t: &Huff) -> Result<Huff, LzhDecodeError> {
    let n = br.bits(CBIT)? as usize;
    if n == 0 {
        let c = br.bits(CBIT)? as usize;
        if c >= NC {
            return Err(LzhDecodeError::InvalidData);
        }
        return Ok(Huff::single(c as u16));
    }
    if n > NC {
        return Err(LzhDecodeError::InvalidData);
    }
    let mut lens = [0u8; NC];
    let mut i = 0usize;
    while i < n {
        let c = t.decode(br)? as usize;
        if c <= 2 {
            let run = match c {
                0 => 1,
                1 => br.bits(4)? as usize + 3,
                _ => br.bits(CBIT)? as usize + 20,
            };
            if i + run > NC {
                return Err(LzhDecodeError::InvalidData);
            }
            i += run;
        } else {
            lens[i] = (c - 2) as u8;
            i += 1;
        }
    }
    Huff::from_lengths(&lens)
}

fn reserve_output(out_size: usize, max_output: usize) -> Result<Vec<u8>, LzhDecodeError> {
    if out_size > max_output {
        return Err(LzhDecodeError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(out_size).map_err(|_| LzhDecodeError::Allocation)?;
    Ok(out)
}

fn copy_match(out: &mut Vec<u8>, dist: usize, len: usize, window: usize, out_size: usize) -> Result<(), LzhDecodeError> {
    if dist == 0 || dist > out.len() || dist > window || len > out_size - out.len() {
        return Err(LzhDecodeError::InvalidData);
    }
    let start = out.len() - dist;
    for k in 0..len {
        let b = out[start + k];
        out.push(b);
    }
    Ok(())
}

/// Decode a static-Huffman stream with an explicit window, NP and PBIT
/// (the shared core of `-lh4-`..`-lh7-` and ARJ methods 1..3).
pub fn decode_static_huffman(
    input: &[u8],
    window: usize,
    np: usize,
    pbit: u32,
    out_size: usize,
    max_output: usize,
) -> Result<Vec<u8>, LzhDecodeError> {
    if np == 0 || np > MAX_NP || pbit == 0 || pbit > 5 || window == 0 {
        return Err(LzhDecodeError::InvalidData);
    }
    let mut out = reserve_output(out_size, max_output)?;
    let mut br = MsbBits::new(input);
    let mut remaining: u32 = 0;
    let mut tables: Option<(Huff, Huff)> = None;
    while out.len() < out_size {
        if remaining == 0 {
            // A stored count of 0 means 65536 codes (16-bit wraparound).
            let bs = br.bits(16)?;
            remaining = if bs == 0 { 1 << 16 } else { bs };
            let t = read_pt_len(&mut br, NT, TBIT, Some(3))?;
            let c = read_c_len(&mut br, &t)?;
            let p = read_pt_len(&mut br, np, pbit, None)?;
            tables = Some((c, p));
        }
        remaining -= 1;
        let (c_table, p_table) = tables.as_ref().ok_or(LzhDecodeError::InvalidData)?;
        let c = c_table.decode(&mut br)? as usize;
        if c < 256 {
            out.push(c as u8);
        } else {
            let len = c - 256 + THRESHOLD;
            let j = p_table.decode(&mut br)? as u32;
            let p = if j == 0 { 0 } else { (1usize << (j - 1)) + br.bits(j - 1)? as usize };
            copy_match(&mut out, p + 1, len, window, out_size)?;
        }
    }
    Ok(out)
}

/// Decode an LHA `-lh4-`..`-lh7-` payload to exactly `out_size` bytes.
pub fn decode_lh(input: &[u8], method: LhMethod, out_size: usize, max_output: usize) -> Result<Vec<u8>, LzhDecodeError> {
    let (window, np, pbit) = method.params();
    decode_static_huffman(input, window, np, pbit, out_size, max_output)
}

/// Decode an ARJ method 1, 2 or 3 payload.
pub fn decode_arj_huffman(input: &[u8], out_size: usize, max_output: usize) -> Result<Vec<u8>, LzhDecodeError> {
    decode_static_huffman(input, ARJ_WINDOW, MAX_NP, 5, out_size, max_output)
}

/// Unary-prefixed value used by ARJ method 4: up to `stop - start` one bits
/// (each adding the next power of two, starting at `2^start`), a zero bit
/// unless the maximum was reached, then `width` literal bits.
fn arj4_value(br: &mut MsbBits<'_>, start: u32, stop: u32) -> Result<usize, LzhDecodeError> {
    let mut plus = 0usize;
    let mut pwr = 1usize << start;
    let mut width = start;
    while width < stop {
        if br.bits(1)? == 0 {
            break;
        }
        plus += pwr;
        pwr <<= 1;
        width += 1;
    }
    Ok(plus + br.bits(width)? as usize)
}

/// Decode an ARJ method 4 payload to exactly `out_size` bytes.
pub fn decode_arj_fastest(input: &[u8], out_size: usize, max_output: usize) -> Result<Vec<u8>, LzhDecodeError> {
    let mut out = reserve_output(out_size, max_output)?;
    let mut br = MsbBits::new(input);
    while out.len() < out_size {
        let c = arj4_value(&mut br, 0, 7)?;
        if c == 0 {
            out.push(br.bits(8)? as u8);
        } else {
            let len = c - 1 + THRESHOLD;
            let pos = arj4_value(&mut br, 9, 13)?;
            copy_match(&mut out, pos + 1, len, ARJ_WINDOW, out_size)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msb_bits() {
        let mut b = MsbBits::new(&[0b1010_0000, 0xFF]);
        assert_eq!(b.bits(3), Ok(0b101));
        assert_eq!(b.bits(5), Ok(0));
        assert_eq!(b.bits(8), Ok(0xFF));
        assert_eq!(b.bits(1), Err(LzhDecodeError::Truncated));
    }

    #[test]
    fn huffman_completeness() {
        assert!(Huff::from_lengths(&[1, 1]).is_ok());
        assert!(Huff::from_lengths(&[1, 2, 2]).is_ok());
        assert_eq!(Huff::from_lengths(&[1, 0]).err(), Some(LzhDecodeError::InvalidData));
        assert_eq!(Huff::from_lengths(&[1, 1, 1]).err(), Some(LzhDecodeError::InvalidData));
        assert_eq!(Huff::from_lengths(&[0, 0]).err(), Some(LzhDecodeError::InvalidData));
    }

    #[test]
    fn canonical_decode() {
        // lengths a=1 b=2 c=2 -> a=0, b=10, c=11
        let h = Huff::from_lengths(&[1, 2, 2]).unwrap();
        let data = [0b0101_1000];
        let mut br = MsbBits::new(&data);
        assert_eq!(h.decode(&mut br), Ok(0));
        assert_eq!(h.decode(&mut br), Ok(1));
        assert_eq!(h.decode(&mut br), Ok(2));
    }

    #[test]
    fn arj4_literals() {
        // two literals 'A','B': 0 + 8 bits each
        let mut w: u32 = 0;
        w = (w << 9) | 0x41;
        w = (w << 9) | 0x42;
        let bits = w << (32 - 18);
        let data = bits.to_be_bytes();
        assert_eq!(decode_arj_fastest(&data[..3], 2, 10), Ok(b"AB".to_vec()));
        assert_eq!(decode_arj_fastest(&data[..3], 2, 1), Err(LzhDecodeError::LimitExceeded));
        assert_eq!(decode_arj_fastest(&data[..1], 2, 10), Err(LzhDecodeError::Truncated));
    }

    #[test]
    fn empty_output_reads_nothing() {
        assert_eq!(decode_lh(&[], LhMethod::Lh5, 0, 0), Ok(Vec::new()));
        assert_eq!(decode_lh(&[], LhMethod::Lh5, 1, 1), Err(LzhDecodeError::Truncated));
    }
}
