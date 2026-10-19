// SPDX-License-Identifier: MIT OR Apache-2.0
//! Decoders for the legacy ZIP compression methods 1 (Shrink) and 6
//! (Implode).
//!
//! Spec source: PKWARE APPNOTE.TXT 6.3.x, section 5.1 (Shrinking: dynamic
//! LZW, 9..13-bit LSB-first codes, code 256 followed by 1 widens the code
//! size, 256 followed by 2 partially clears the table by freeing every leaf
//! node; freed codes are reused lowest first) and section 5.3 (Imploding:
//! 4K or 8K sliding dictionary selected by general-purpose flag bit 1, two or
//! three Shannon-Fano trees selected by bit 2, the tree encoding and the
//! code-assignment procedure). Implemented from the text; behaviour on the
//! points APPNOTE leaves open (a new Shrink entry whose prefix code was just
//! freed is still added; Implode back-references before the start of the
//! output read as zero bytes) was confirmed black-box against 7-Zip 26.04.
//!
//! Limits: `out_size` (the entry's declared uncompressed size) must not
//! exceed `max_output`; the output buffer is reserved once. String
//! reconstruction in Shrink is bounded by the table size, so cyclic prefix
//! chains are rejected rather than looped on.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipLegacyError {
    /// Compressed data ended before `out_size` bytes were produced.
    Truncated,
    /// Malformed trees, codes or control sequences.
    InvalidData,
    /// `out_size` exceeds `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

/// ZIP method number for Shrink.
pub const METHOD_SHRINK: u16 = 1;
/// ZIP method number for Implode.
pub const METHOD_IMPLODE: u16 = 6;
/// Implode: 8K dictionary (else 4K).
pub const FLAG_IMPLODE_8K: u16 = 0x0002;
/// Implode: three trees, literal tree present (else two).
pub const FLAG_IMPLODE_LITERAL_TREE: u16 = 0x0004;

struct LsbBits<'a> {
    data: &'a [u8],
    pos: usize,
    total: usize,
}

impl<'a> LsbBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        LsbBits { data, pos: 0, total: data.len().saturating_mul(8) }
    }

    fn remaining(&self) -> usize {
        self.total - self.pos
    }

    /// Read `n` (0..=16) bits, LSB first.
    fn bits(&mut self, n: u32) -> Result<u32, ZipLegacyError> {
        if n as usize > self.remaining() {
            return Err(ZipLegacyError::Truncated);
        }
        if n == 0 {
            return Ok(0);
        }
        let byte = self.pos / 8;
        let mut v = 0u32;
        for i in 0..3 {
            v |= u32::from(self.data.get(byte + i).copied().unwrap_or(0)) << (8 * i);
        }
        self.pos += n as usize;
        Ok((v >> ((self.pos - n as usize) % 8)) & ((1u32 << n) - 1))
    }
}

fn reserve_output(out_size: usize, max_output: usize) -> Result<Vec<u8>, ZipLegacyError> {
    if out_size > max_output {
        return Err(ZipLegacyError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(out_size).map_err(|_| ZipLegacyError::Allocation)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shrink (method 1)
// ---------------------------------------------------------------------------

const SHRINK_MAX_BITS: u32 = 13;
const SHRINK_TABLE: usize = 1 << SHRINK_MAX_BITS;
const SHRINK_FIRST: usize = 257;

struct ShrinkTable {
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    in_use: Vec<bool>,
    next_free: usize,
}

impl ShrinkTable {
    fn new() -> Result<Self, ZipLegacyError> {
        let mut prefix = Vec::new();
        let mut suffix = Vec::new();
        let mut in_use = Vec::new();
        prefix.try_reserve_exact(SHRINK_TABLE).map_err(|_| ZipLegacyError::Allocation)?;
        suffix.try_reserve_exact(SHRINK_TABLE).map_err(|_| ZipLegacyError::Allocation)?;
        in_use.try_reserve_exact(SHRINK_TABLE).map_err(|_| ZipLegacyError::Allocation)?;
        prefix.resize(SHRINK_TABLE, 0);
        suffix.resize(SHRINK_TABLE, 0);
        in_use.resize(SHRINK_TABLE, false);
        for c in 0..256 {
            suffix[c] = c as u8;
            in_use[c] = true;
        }
        Ok(ShrinkTable { prefix, suffix, in_use, next_free: SHRINK_FIRST })
    }

    fn advance_free(&mut self, from: usize) {
        let mut c = from;
        while c < SHRINK_TABLE && self.in_use[c] {
            c += 1;
        }
        self.next_free = c;
    }

    /// Free every code >= 257 that is not the prefix of another live code.
    fn partial_clear(&mut self) {
        let mut is_prefix = vec![false; SHRINK_TABLE];
        for c in SHRINK_FIRST..SHRINK_TABLE {
            if self.in_use[c] {
                is_prefix[self.prefix[c] as usize] = true;
            }
        }
        for (used, &prefix) in self.in_use.iter_mut().zip(&is_prefix).skip(SHRINK_FIRST) {
            if !prefix {
                *used = false;
            }
        }
        self.advance_free(SHRINK_FIRST);
    }

    /// Write the string for `code` into `scratch` (reversed order) and
    /// return its length. Prefix chains are followed through the stored
    /// links; a chain longer than the table is cyclic and invalid.
    fn expand(&self, code: usize, scratch: &mut [u8]) -> Result<usize, ZipLegacyError> {
        let mut c = code;
        let mut n = 0usize;
        loop {
            if n >= scratch.len() {
                return Err(ZipLegacyError::InvalidData);
            }
            scratch[n] = self.suffix[c];
            n += 1;
            if c < 256 {
                return Ok(n);
            }
            if c == 256 {
                return Err(ZipLegacyError::InvalidData);
            }
            c = self.prefix[c] as usize;
        }
    }
}

/// Decode a Shrink (method 1) payload to exactly `out_size` bytes.
pub fn unshrink(input: &[u8], out_size: usize, max_output: usize) -> Result<Vec<u8>, ZipLegacyError> {
    let mut out = reserve_output(out_size, max_output)?;
    let mut t = ShrinkTable::new()?;
    let mut scratch = vec![0u8; SHRINK_TABLE];
    let mut br = LsbBits::new(input);
    let mut width: u32 = 9;
    let mut prev: Option<usize> = None;
    while out.len() < out_size {
        let code = br.bits(width)? as usize;
        if code == 256 {
            match br.bits(width)? {
                1 => {
                    if width >= SHRINK_MAX_BITS {
                        return Err(ZipLegacyError::InvalidData);
                    }
                    width += 1;
                }
                2 => t.partial_clear(),
                _ => return Err(ZipLegacyError::InvalidData),
            }
            continue;
        }
        let Some(p) = prev else {
            if code >= 256 {
                return Err(ZipLegacyError::InvalidData);
            }
            out.push(code as u8);
            prev = Some(code);
            continue;
        };
        let (len, first) = if t.in_use[code] {
            let n = t.expand(code, &mut scratch)?;
            (n, scratch[n - 1])
        } else if code == t.next_free {
            // KwKwK: the code being defined right now = prev + first(prev).
            let n = t.expand(p, &mut scratch[1..])?;
            let first = scratch[n];
            scratch[0] = first;
            (n + 1, first)
        } else {
            return Err(ZipLegacyError::InvalidData);
        };
        if t.next_free < SHRINK_TABLE {
            let nf = t.next_free;
            t.prefix[nf] = p as u16;
            t.suffix[nf] = first;
            t.in_use[nf] = true;
            t.advance_free(nf + 1);
        }
        if len > out_size - out.len() {
            return Err(ZipLegacyError::InvalidData);
        }
        out.extend(scratch[..len].iter().rev());
        prev = Some(code);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Implode (method 6)
// ---------------------------------------------------------------------------

/// A Shannon-Fano tree: for each code length, the first code value and the
/// symbols in increasing code order.
struct SfTree {
    base: [u32; 17],
    syms: [Vec<u16>; 17],
}

fn read_sf_tree(input: &[u8], pos: &mut usize, nsym: usize) -> Result<SfTree, ZipLegacyError> {
    let nbytes = usize::from(*input.get(*pos).ok_or(ZipLegacyError::Truncated)?) + 1;
    *pos += 1;
    let bytes = input.get(*pos..*pos + nbytes).ok_or(ZipLegacyError::Truncated)?;
    *pos += nbytes;
    let mut lens: Vec<u8> = Vec::with_capacity(nsym);
    for &b in bytes {
        let count = usize::from(b >> 4) + 1;
        let len = (b & 0x0F) + 1;
        if lens.len() + count > nsym {
            return Err(ZipLegacyError::InvalidData);
        }
        lens.extend(std::iter::repeat_n(len, count));
    }
    if lens.len() != nsym {
        return Err(ZipLegacyError::InvalidData);
    }
    // APPNOTE 5.3: sort by (length, symbol); walk from the end assigning
    // 16-bit left-justified codes, adding 2^(16-len) per step.
    let mut order: Vec<u16> = (0..nsym as u16).collect();
    order.sort_by_key(|&s| (lens[s as usize], s));
    let mut tree = SfTree { base: [0; 17], syms: Default::default() };
    let mut code: u32 = 0;
    let mut inc: u32 = 0;
    let mut last: u8 = 0;
    let mut first_of_len = [None::<u32>; 17];
    for &s in order.iter().rev() {
        let l = lens[s as usize];
        code += inc;
        if l != last {
            last = l;
            inc = 1 << (16 - u32::from(l));
        }
        if code + inc > 1 << 16 {
            return Err(ZipLegacyError::InvalidData); // oversubscribed
        }
        let li = l as usize;
        let c = code >> (16 - u32::from(l));
        if first_of_len[li].is_none() {
            first_of_len[li] = Some(c);
        }
        tree.syms[li].push(s);
    }
    for (base, first) in tree.base.iter_mut().zip(first_of_len) {
        *base = first.unwrap_or(0);
    }
    Ok(tree)
}

impl SfTree {
    fn decode(&self, br: &mut LsbBits<'_>) -> Result<u16, ZipLegacyError> {
        let mut code = 0u32;
        for l in 1..=16 {
            code = (code << 1) | br.bits(1)?;
            let n = self.syms[l].len() as u32;
            if n != 0 && code >= self.base[l] && code < self.base[l] + n {
                return Ok(self.syms[l][(code - self.base[l]) as usize]);
            }
        }
        Err(ZipLegacyError::InvalidData)
    }
}

/// Decode an Implode (method 6) payload. `flags` is the entry's general
/// purpose bit flag (bits 1 and 2 select the dictionary and tree count).
pub fn explode(input: &[u8], flags: u16, out_size: usize, max_output: usize) -> Result<Vec<u8>, ZipLegacyError> {
    let big = flags & FLAG_IMPLODE_8K != 0;
    let lit = flags & FLAG_IMPLODE_LITERAL_TREE != 0;
    let mut out = reserve_output(out_size, max_output)?;
    let mut pos = 0usize;
    let lit_tree = if lit { Some(read_sf_tree(input, &mut pos, 256)?) } else { None };
    let len_tree = read_sf_tree(input, &mut pos, 64)?;
    let dist_tree = read_sf_tree(input, &mut pos, 64)?;
    let dbits: u32 = if big { 7 } else { 6 };
    let min_match: usize = if lit { 3 } else { 2 };
    let mut br = LsbBits::new(&input[pos..]);
    while out.len() < out_size {
        if br.bits(1)? == 1 {
            let b = match &lit_tree {
                Some(t) => t.decode(&mut br)? as u8,
                None => br.bits(8)? as u8,
            };
            out.push(b);
        } else {
            let low = br.bits(dbits)? as usize;
            let high = dist_tree.decode(&mut br)? as usize;
            let dist = ((high << dbits) | low) + 1;
            let mut len = len_tree.decode(&mut br)? as usize;
            if len == 63 {
                len += br.bits(8)? as usize;
            }
            len += min_match;
            // A final match may run past the declared size; keep the prefix.
            let len = len.min(out_size - out.len());
            for _ in 0..len {
                let b = if dist > out.len() { 0 } else { out[out.len() - dist] };
                out.push(b);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrink_literals_and_widen() {
        // codes (9 bits, LSB first): 'A', 256, 1 (widen), 'B' at 10 bits
        let mut acc: u64 = 0;
        let mut n: u64 = 0;
        for (v, w) in [(65u64, 9), (256, 9), (1, 9), (66, 10)] {
            acc |= v << n;
            n += w;
        }
        let bytes: Vec<u8> = (0..n.div_ceil(8)).map(|i| (acc >> (8 * i)) as u8).collect();
        assert_eq!(unshrink(&bytes, 2, 10), Ok(b"AB".to_vec()));
        assert_eq!(unshrink(&bytes, 3, 10), Err(ZipLegacyError::Truncated));
        assert_eq!(unshrink(&bytes, 3, 2), Err(ZipLegacyError::LimitExceeded));
    }

    #[test]
    fn shrink_bad_control_and_first_code() {
        // 256 then 3: invalid control
        let bytes = [0x00, 0x07, 0x06, 0x00];
        assert_eq!(unshrink(&bytes, 1, 10), Err(ZipLegacyError::InvalidData));
        // first code 300 (not a literal)
        let v: u32 = 300;
        assert_eq!(unshrink(&[v as u8, (v >> 8) as u8], 1, 10), Err(ZipLegacyError::InvalidData));
    }

    #[test]
    fn shrink_kwkwk() {
        // 'a', 257 (KwKwK => "aa") => "aaa"
        let acc: u32 = 97 | (257 << 9);
        let bytes = acc.to_le_bytes();
        assert_eq!(unshrink(&bytes[..3], 3, 10), Ok(b"aaa".to_vec()));
        // 258 would be beyond next_free
        let acc: u32 = 97 | (258 << 9);
        assert_eq!(unshrink(&acc.to_le_bytes()[..3], 3, 10), Err(ZipLegacyError::InvalidData));
    }

    #[test]
    fn sf_tree_reading() {
        // 64 symbols all length 6: four runs of 16
        let t = [3u8, 0xF5, 0xF5, 0xF5, 0xF5];
        let mut pos = 0;
        let tree = read_sf_tree(&t, &mut pos, 64).unwrap();
        assert_eq!(pos, 5);
        assert_eq!(tree.syms[6].len(), 64);
        // too many symbols
        let mut pos = 0;
        assert!(read_sf_tree(&[4u8, 0xF5, 0xF5, 0xF5, 0xF5, 0x05], &mut pos, 64).is_err());
        // oversubscribed: 64 symbols of length 5
        let mut pos = 0;
        assert!(read_sf_tree(&[3u8, 0xF4, 0xF4, 0xF4, 0xF4], &mut pos, 64).is_err());
        let mut pos = 0;
        assert_eq!(read_sf_tree(&[3u8, 0xF5], &mut pos, 64).err(), Some(ZipLegacyError::Truncated));
    }
}
