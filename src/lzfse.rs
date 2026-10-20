// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZFSE and LZVN decoding (Apple's `bvx` block framing).
//!
//! Spec source: the format as published with Apple's BSD-3-Clause lzfse
//! reference (github.com/lzfse/lzfse: block magics `bvx-`/`bvx1`/`bvx2`/
//! `bvxn`/`bvx$`, the v1/v2 compressed block headers and the v2 packed
//! frequency-table encoding, the tANS/FSE decoding-table construction, the
//! L/M/D value tables, and the LZVN opcode set). Written from that format
//! description; no 7-Zip source was used.
//!
//! A frame is a sequence of blocks ended by `bvx$`:
//! - `bvx-`: `n_raw_bytes` (u32) then that many literal bytes;
//! - `bvx1`/`bvx2`: an LZFSE block (FSE-coded literals plus an FSE-coded
//!   literal/match/distance stream, both read backwards);
//! - `bvxn`: `n_raw_bytes`, `n_payload_bytes`, then an LZVN stream.
//!
//! Matches may reach back into earlier blocks of the same frame.
//! Concatenated frames are not accepted: data after `bvx$` is ignored only
//! when it is absent (`decode_lzfse`) or by the prefix variant.
//!
//! Limits: total output is capped by `max_output`; every count is checked
//! before allocating, and malformed input returns an error, never panics.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzfseError {
    /// Input ended inside a block.
    Truncated,
    /// Unknown block magic.
    BadMagic,
    /// Invalid header field or frequency table.
    InvalidHeader,
    /// Corrupt payload (bad state, distance, opcode or size).
    Corrupt,
    /// Output would exceed `max_output`.
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
}

type R<T> = Result<T, LzfseError>;

pub const MAGIC_END: u32 = 0x2478_7662; // "bvx$"
pub const MAGIC_RAW: u32 = 0x2d78_7662; // "bvx-"
pub const MAGIC_V1: u32 = 0x3178_7662; // "bvx1"
pub const MAGIC_V2: u32 = 0x3278_7662; // "bvx2"
pub const MAGIC_LZVN: u32 = 0x6e78_7662; // "bvxn"

const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LIT_SYMBOLS: usize = 256;
const L_STATES: u32 = 64;
const M_STATES: u32 = 64;
const D_STATES: u32 = 256;
const LIT_STATES: u32 = 1024;
/// Size of the in-memory v1 header (`struct` with 4-byte alignment).
const V1_HEADER_SIZE: usize = 772;
/// Generous caps on per-block counts (the reference encoder uses 40000
/// literals and 10000 matches per block).
const MAX_LITERALS: u32 = 1 << 20;
const MAX_MATCHES: u32 = 1 << 20;

const L_EXTRA: [u8; L_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const M_EXTRA: [u8; M_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];

fn bases(extra: &[u8]) -> Vec<i32> {
    let mut v = Vec::with_capacity(extra.len());
    let mut b = 0i32;
    for &e in extra {
        v.push(b);
        b += 1 << e;
    }
    v
}

fn d_extra() -> [u8; D_SYMBOLS] {
    let mut d = [0u8; D_SYMBOLS];
    for (i, x) in d.iter_mut().enumerate() {
        *x = if i < 4 { 0 } else { ((i - 4) / 4 + 1) as u8 };
    }
    d
}

fn rd32(b: &[u8], at: usize) -> R<u32> {
    let s = b.get(at..at.checked_add(4).ok_or(LzfseError::Truncated)?).ok_or(LzfseError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd16(b: &[u8], at: usize) -> R<u16> {
    let s = b.get(at..at.checked_add(2).ok_or(LzfseError::Truncated)?).ok_or(LzfseError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd64(b: &[u8], at: usize) -> R<u64> {
    let s = b.get(at..at.checked_add(8).ok_or(LzfseError::Truncated)?).ok_or(LzfseError::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

// ---------------------------------------------------------------------------
// Backward bit stream
// ---------------------------------------------------------------------------

struct InStream<'a> {
    buf: &'a [u8],
    /// Bytes `buf[..pos]` are not yet consumed.
    pos: usize,
    accum: u64,
    nbits: u32,
    /// Low bits of `accum` that lie before the buffer start.
    phantom: u32,
}

impl<'a> InStream<'a> {
    fn new(buf: &'a [u8], n: i32) -> R<Self> {
        let (take, nbits) = if n != 0 { (8usize, n + 64) } else { (7usize, 56) };
        if buf.len() < take || !(56..64).contains(&nbits) {
            return Err(LzfseError::Corrupt);
        }
        let pos = buf.len() - take;
        let mut accum = 0u64;
        for (i, &b) in buf[pos..].iter().enumerate() {
            accum |= u64::from(b) << (8 * i);
        }
        let nbits = nbits as u32;
        if accum >> nbits != 0 {
            return Err(LzfseError::Corrupt);
        }
        Ok(InStream { buf, pos, accum, nbits, phantom: 0 })
    }

    /// Refill to at least 56 bits. Near the start of the buffer the
    /// encoder's final partial bits sit in the low bytes; missing bytes
    /// below the buffer start are shifted in as zero "phantom" bits, and
    /// any pull that would reach into them is an error.
    fn flush(&mut self) -> R<()> {
        let nbits = (63 - self.nbits) & !7;
        let nbytes = (nbits / 8) as usize;
        if nbytes == 0 {
            return Ok(());
        }
        let real = nbytes.min(self.pos);
        let start = self.pos - real;
        let mut incoming = 0u64;
        for (i, &b) in self.buf[start..self.pos].iter().enumerate() {
            incoming |= u64::from(b) << (8 * (i + nbytes - real));
        }
        self.accum = (self.accum << nbits) | incoming;
        self.nbits += nbits;
        self.phantom = self.phantom.saturating_add(((nbytes - real) * 8) as u32);
        if self.phantom > 0 {
            self.phantom = self.phantom.min(self.nbits);
        }
        self.pos = start;
        Ok(())
    }

    fn pull(&mut self, n: u32) -> R<u64> {
        if n > self.nbits {
            return Err(LzfseError::Corrupt);
        }
        self.nbits -= n;
        if self.nbits < self.phantom {
            return Err(LzfseError::Corrupt);
        }
        let r = self.accum >> self.nbits;
        self.accum &= if self.nbits == 0 { 0 } else { u64::MAX >> (64 - self.nbits) };
        Ok(r)
    }
}

// ---------------------------------------------------------------------------
// FSE tables
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct LitEntry {
    k: u8,
    symbol: u8,
    delta: i32,
}

#[derive(Clone, Copy, Default)]
struct ValEntry {
    total_bits: u8,
    value_bits: u8,
    delta: i32,
    vbase: i32,
}

/// Visit every (symbol, j, k, delta) slot of the tANS decoding table.
fn build_slots(nstates: u32, freq: &[u16], mut f: impl FnMut(usize, u32, i32)) -> R<()> {
    let n_clz = nstates.leading_zeros() as i32;
    let mut sum = 0u32;
    for (sym, &fr) in freq.iter().enumerate() {
        let fr = u32::from(fr);
        if fr == 0 {
            continue;
        }
        sum += fr;
        if sum > nstates {
            return Err(LzfseError::InvalidHeader);
        }
        let k = fr.leading_zeros() as i32 - n_clz;
        let j0 = ((2 * nstates) >> k) as i32 - fr as i32;
        for j in 0..fr as i32 {
            if j < j0 {
                let delta = ((fr as i32 + j) << k) - nstates as i32;
                f(sym, k as u32, delta);
            } else {
                if k < 1 {
                    return Err(LzfseError::InvalidHeader);
                }
                let delta = (j - j0) << (k - 1);
                f(sym, (k - 1) as u32, delta);
            }
        }
    }
    Ok(())
}

fn lit_table(freq: &[u16]) -> R<Vec<LitEntry>> {
    let mut t = Vec::with_capacity(LIT_STATES as usize);
    build_slots(LIT_STATES, freq, |sym, k, delta| t.push(LitEntry { k: k as u8, symbol: sym as u8, delta }))?;
    t.resize(LIT_STATES as usize, LitEntry::default());
    Ok(t)
}

fn val_table(nstates: u32, freq: &[u16], extra: &[u8], base: &[i32]) -> R<Vec<ValEntry>> {
    let mut t = Vec::with_capacity(nstates as usize);
    build_slots(nstates, freq, |sym, k, delta| {
        t.push(ValEntry { total_bits: (k + u32::from(extra[sym])) as u8, value_bits: extra[sym], delta, vbase: base[sym] })
    })?;
    t.resize(nstates as usize, ValEntry::default());
    Ok(t)
}

fn lit_decode(state: &mut u32, t: &[LitEntry], s: &mut InStream) -> R<u8> {
    let e = t.get(*state as usize).ok_or(LzfseError::Corrupt)?;
    let ns = i64::from(e.delta) + s.pull(u32::from(e.k))? as i64;
    if !(0..i64::from(LIT_STATES)).contains(&ns) {
        return Err(LzfseError::Corrupt);
    }
    *state = ns as u32;
    Ok(e.symbol)
}

fn val_decode(state: &mut u32, t: &[ValEntry], s: &mut InStream) -> R<i64> {
    let e = *t.get(*state as usize).ok_or(LzfseError::Corrupt)?;
    let bits = s.pull(u32::from(e.total_bits))?;
    let ns = i64::from(e.delta) + (bits >> e.value_bits) as i64;
    if !(0..t.len() as i64).contains(&ns) {
        return Err(LzfseError::Corrupt);
    }
    *state = ns as u32;
    let vmask = if e.value_bits == 0 { 0 } else { (1u64 << e.value_bits) - 1 };
    Ok(i64::from(e.vbase) + (bits & vmask) as i64)
}

// ---------------------------------------------------------------------------
// LZFSE block
// ---------------------------------------------------------------------------

struct BlockHeader {
    n_raw_bytes: u32,
    n_literals: u32,
    n_matches: u32,
    n_literal_payload_bytes: u32,
    n_lmd_payload_bytes: u32,
    literal_bits: i32,
    literal_state: [u16; 4],
    lmd_bits: i32,
    l_state: u16,
    m_state: u16,
    d_state: u16,
    /// l(20) m(20) d(64) literal(256)
    freq: Vec<u16>,
    header_size: usize,
}

const FREQ_TOTAL: usize = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LIT_SYMBOLS;

fn field(v: u64, off: u32, n: u32) -> u64 {
    (v >> off) & ((1u64 << n) - 1)
}

fn freq_value(bits: u32) -> (u16, u32) {
    const NBITS: [u8; 32] = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14];
    const VALUE: [i8; 32] = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1];
    let b = (bits & 31) as usize;
    let n = u32::from(NBITS[b]);
    let v = match n {
        8 => 8 + ((bits >> 4) & 0xf) as u16,
        14 => 24 + ((bits >> 4) & 0x3ff) as u16,
        _ => VALUE[b] as u16,
    };
    (v, n)
}

fn parse_v2(b: &[u8]) -> R<BlockHeader> {
    let n_raw_bytes = rd32(b, 4)?;
    let v0 = rd64(b, 8)?;
    let v1 = rd64(b, 16)?;
    let v2 = rd64(b, 24)?;
    let header_size = field(v2, 0, 32) as usize;
    if header_size < 32 || header_size > b.len() {
        return Err(if header_size > b.len() { LzfseError::Truncated } else { LzfseError::InvalidHeader });
    }
    let mut freq = vec![0u16; FREQ_TOTAL];
    let src = &b[32..header_size];
    let mut pos = 0usize;
    let mut accum = 0u32;
    let mut nbits = 0u32;
    for f in freq.iter_mut() {
        while pos < src.len() && nbits + 8 <= 32 {
            accum |= u32::from(src[pos]) << nbits;
            nbits += 8;
            pos += 1;
        }
        let (v, n) = freq_value(accum);
        if n > nbits {
            return Err(LzfseError::InvalidHeader);
        }
        *f = v;
        accum >>= n;
        nbits -= n;
    }
    if nbits >= 8 || pos != src.len() {
        return Err(LzfseError::InvalidHeader);
    }
    Ok(BlockHeader {
        n_raw_bytes,
        n_literals: field(v0, 0, 20) as u32,
        n_literal_payload_bytes: field(v0, 20, 20) as u32,
        n_matches: field(v0, 40, 20) as u32,
        literal_bits: field(v0, 60, 3) as i32 - 7,
        literal_state: [field(v1, 0, 10) as u16, field(v1, 10, 10) as u16, field(v1, 20, 10) as u16, field(v1, 30, 10) as u16],
        n_lmd_payload_bytes: field(v1, 40, 20) as u32,
        lmd_bits: field(v1, 60, 3) as i32 - 7,
        l_state: field(v2, 32, 10) as u16,
        m_state: field(v2, 42, 10) as u16,
        d_state: field(v2, 52, 10) as u16,
        freq,
        header_size,
    })
}

fn parse_v1(b: &[u8]) -> R<BlockHeader> {
    if b.len() < V1_HEADER_SIZE {
        return Err(LzfseError::Truncated);
    }
    let n_raw_bytes = rd32(b, 4)?;
    let n_payload = rd32(b, 8)?;
    let n_literals = rd32(b, 12)?;
    let n_matches = rd32(b, 16)?;
    let n_lit_payload = rd32(b, 20)?;
    let n_lmd_payload = rd32(b, 24)?;
    if u64::from(n_lit_payload) + u64::from(n_lmd_payload) != u64::from(n_payload) {
        return Err(LzfseError::InvalidHeader);
    }
    let literal_bits = rd32(b, 28)? as i32;
    let literal_state = [rd16(b, 32)?, rd16(b, 34)?, rd16(b, 36)?, rd16(b, 38)?];
    let lmd_bits = rd32(b, 40)? as i32;
    let mut freq = vec![0u16; FREQ_TOTAL];
    for (i, f) in freq.iter_mut().enumerate() {
        *f = rd16(b, 50 + 2 * i)?;
    }
    Ok(BlockHeader {
        n_raw_bytes,
        n_literals,
        n_matches,
        n_literal_payload_bytes: n_lit_payload,
        n_lmd_payload_bytes: n_lmd_payload,
        literal_bits,
        literal_state,
        lmd_bits,
        l_state: rd16(b, 44)?,
        m_state: rd16(b, 46)?,
        d_state: rd16(b, 48)?,
        freq,
        header_size: V1_HEADER_SIZE,
    })
}

/// Decode one LZFSE block (header at `b[0]`), appending to `out`.
/// Returns the number of input bytes consumed.
fn decode_lzfse_block(b: &[u8], v2: bool, out: &mut Vec<u8>, max_output: usize) -> R<usize> {
    let h = if v2 { parse_v2(b)? } else { parse_v1(b)? };
    if h.n_literals > MAX_LITERALS || h.n_matches > MAX_MATCHES {
        return Err(LzfseError::InvalidHeader);
    }
    if !(-7..=0).contains(&h.literal_bits) || !(-7..=0).contains(&h.lmd_bits) {
        return Err(LzfseError::InvalidHeader);
    }
    if h.literal_state.iter().any(|&s| u32::from(s) >= LIT_STATES)
        || u32::from(h.l_state) >= L_STATES
        || u32::from(h.m_state) >= M_STATES
        || u32::from(h.d_state) >= D_STATES
    {
        return Err(LzfseError::InvalidHeader);
    }
    let lit_start = h.header_size;
    let lmd_start = lit_start.checked_add(h.n_literal_payload_bytes as usize).ok_or(LzfseError::Truncated)?;
    let end = lmd_start.checked_add(h.n_lmd_payload_bytes as usize).ok_or(LzfseError::Truncated)?;
    if end > b.len() {
        return Err(LzfseError::Truncated);
    }
    let raw = h.n_raw_bytes as usize;
    let target = out.len().checked_add(raw).ok_or(LzfseError::LimitExceeded)?;
    if target > max_output {
        return Err(LzfseError::LimitExceeded);
    }
    out.try_reserve(raw).map_err(|_| LzfseError::Allocation)?;

    // Literals: four interleaved FSE states.
    let (l_freq, rest) = h.freq.split_at(L_SYMBOLS);
    let (m_freq, rest) = rest.split_at(M_SYMBOLS);
    let (d_freq, lit_freq) = rest.split_at(D_SYMBOLS);
    let lt = lit_table(lit_freq)?;
    let n_lit = (h.n_literals as usize).div_ceil(4) * 4;
    let mut literals = Vec::new();
    literals.try_reserve_exact(n_lit).map_err(|_| LzfseError::Allocation)?;
    {
        let mut s = InStream::new(&b[lit_start..lmd_start], h.literal_bits)?;
        let mut st = h.literal_state.map(u32::from);
        for _ in 0..n_lit / 4 {
            s.flush()?;
            for state in st.iter_mut() {
                literals.push(lit_decode(state, &lt, &mut s)?);
            }
        }
    }
    literals.truncate(h.n_literals as usize);

    // L/M/D stream.
    let l_base = bases(&L_EXTRA);
    let m_base = bases(&M_EXTRA);
    let dx = d_extra();
    let d_base = bases(&dx);
    let ltab = val_table(L_STATES, l_freq, &L_EXTRA, &l_base)?;
    let mtab = val_table(M_STATES, m_freq, &M_EXTRA, &m_base)?;
    let dtab = val_table(D_STATES, d_freq, &dx, &d_base)?;
    let mut s = InStream::new(&b[lmd_start..end], h.lmd_bits)?;
    let (mut ls, mut ms, mut ds) = (u32::from(h.l_state), u32::from(h.m_state), u32::from(h.d_state));
    let mut lit_pos = 0usize;
    let mut d: i64 = -1;
    for _ in 0..h.n_matches {
        s.flush()?;
        let l = val_decode(&mut ls, &ltab, &mut s)? as usize;
        let m = val_decode(&mut ms, &mtab, &mut s)? as usize;
        let nd = val_decode(&mut ds, &dtab, &mut s)?;
        if nd != 0 {
            d = nd;
        }
        let lit_end = lit_pos.checked_add(l).ok_or(LzfseError::Corrupt)?;
        if lit_end > literals.len() || out.len() + l + m > target {
            return Err(LzfseError::Corrupt);
        }
        out.extend_from_slice(&literals[lit_pos..lit_end]);
        lit_pos = lit_end;
        if m > 0 {
            copy_match(out, d, m)?;
        }
    }
    if out.len() != target {
        return Err(LzfseError::Corrupt);
    }
    Ok(end)
}

fn copy_match(out: &mut Vec<u8>, d: i64, m: usize) -> R<()> {
    if d <= 0 || d as u64 > out.len() as u64 {
        return Err(LzfseError::Corrupt);
    }
    let start = out.len() - d as usize;
    if d as usize >= m {
        out.extend_from_within(start..start + m);
    } else {
        for i in 0..m {
            let c = out[start + i];
            out.push(c);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LZVN
// ---------------------------------------------------------------------------

/// Decode an LZVN stream (`src`, ending at its end-of-stream opcode)
/// that produces exactly `n_raw` bytes, appending to `out`. Matches may
/// reference anything already in `out`.
pub fn decode_lzvn_into(src: &[u8], n_raw: usize, out: &mut Vec<u8>) -> R<()> {
    let target = out.len().checked_add(n_raw).ok_or(LzfseError::LimitExceeded)?;
    out.try_reserve(n_raw).map_err(|_| LzfseError::Allocation)?;
    let mut p = 0usize;
    let mut d: usize = 0;
    let get = |i: usize| src.get(i).copied().ok_or(LzfseError::Truncated);
    loop {
        let op = get(p)?;
        let (len, l, m, nd): (usize, usize, usize, Option<usize>) = match op {
            0x06 => break,
            0x0e | 0x16 => (1, 0, 0, None),
            0x70..=0x7f => return Err(LzfseError::Corrupt),
            0xa0..=0xbf => {
                let b1 = usize::from(get(p + 1)?);
                let b2 = usize::from(get(p + 2)?);
                let l = usize::from((op >> 3) & 3);
                let m = ((usize::from(op & 7) << 2) | (b1 & 3)) + 3;
                (3, l, m, Some((b1 >> 2) | (b2 << 6)))
            }
            0xe0 => (2, usize::from(get(p + 1)?) + 16, 0, None),
            0xe1..=0xef => (1, usize::from(op & 15), 0, None),
            0xf0 => (2, 0, usize::from(get(p + 1)?) + 16, None),
            0xf1..=0xff => (1, 0, usize::from(op & 15), None),
            _ => {
                let l = usize::from(op >> 6);
                let m = usize::from((op >> 3) & 7) + 3;
                match op & 7 {
                    6 => {
                        if op < 0x40 {
                            // 0x1e..0x3e: undefined
                            return Err(LzfseError::Corrupt);
                        }
                        (1, l, m, None)
                    }
                    7 => (3, l, m, Some(usize::from(get(p + 1)?) | (usize::from(get(p + 2)?) << 8))),
                    _ => (2, l, m, Some((usize::from(op & 7) << 8) | usize::from(get(p + 1)?))),
                }
            }
        };
        p += len;
        if l > 0 {
            let lit = src.get(p..p + l).ok_or(LzfseError::Truncated)?;
            if out.len() + l > target {
                return Err(LzfseError::Corrupt);
            }
            out.extend_from_slice(lit);
            p += l;
        }
        if let Some(nd) = nd {
            d = nd;
        }
        if m > 0 {
            if out.len() + m > target {
                return Err(LzfseError::Corrupt);
            }
            copy_match(out, d as i64, m)?;
        }
    }
    if out.len() != target {
        return Err(LzfseError::Corrupt);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// True when `b` starts with an LZFSE block magic.
pub fn is_lzfse(b: &[u8]) -> bool {
    matches!(rd32(b, 0), Ok(MAGIC_END | MAGIC_RAW | MAGIC_V1 | MAGIC_V2 | MAGIC_LZVN))
}

/// Decode one LZFSE frame from the start of `src`. Returns the output and
/// the number of input bytes consumed (through the `bvx$` marker).
pub fn decode_lzfse_prefix(src: &[u8], max_output: usize) -> R<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut p = 0usize;
    loop {
        let magic = rd32(src, p)?;
        let b = &src[p..];
        match magic {
            MAGIC_END => return Ok((out, p + 4)),
            MAGIC_RAW => {
                let n = rd32(b, 4)? as usize;
                if out.len().checked_add(n).is_none_or(|t| t > max_output) {
                    return Err(LzfseError::LimitExceeded);
                }
                let data = b.get(8..8usize.checked_add(n).ok_or(LzfseError::Truncated)?).ok_or(LzfseError::Truncated)?;
                out.try_reserve(n).map_err(|_| LzfseError::Allocation)?;
                out.extend_from_slice(data);
                p += 8 + n;
            }
            MAGIC_V1 | MAGIC_V2 => {
                p += decode_lzfse_block(b, magic == MAGIC_V2, &mut out, max_output)?;
            }
            MAGIC_LZVN => {
                let n_raw = rd32(b, 4)? as usize;
                let n_payload = rd32(b, 8)? as usize;
                if out.len().checked_add(n_raw).is_none_or(|t| t > max_output) {
                    return Err(LzfseError::LimitExceeded);
                }
                let payload = b.get(12..12usize.checked_add(n_payload).ok_or(LzfseError::Truncated)?).ok_or(LzfseError::Truncated)?;
                decode_lzvn_into(payload, n_raw, &mut out)?;
                p += 12 + n_payload;
            }
            _ => return Err(LzfseError::BadMagic),
        }
    }
}

/// Decode a complete LZFSE frame; bytes after the end marker are an error.
pub fn decode_lzfse(src: &[u8], max_output: usize) -> R<Vec<u8>> {
    let (out, used) = decode_lzfse_prefix(src, max_output)?;
    if used != src.len() {
        return Err(LzfseError::Corrupt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_end() {
        let mut f = b"bvx-".to_vec();
        f.extend_from_slice(&3u32.to_le_bytes());
        f.extend_from_slice(b"abc");
        f.extend_from_slice(b"bvx$");
        assert_eq!(decode_lzfse(&f, 10).unwrap(), b"abc");
        assert_eq!(decode_lzfse(&f, 2), Err(LzfseError::LimitExceeded));
        assert_eq!(decode_lzfse(&f[..9], 10), Err(LzfseError::Truncated));
        assert_eq!(decode_lzfse(b"bvxZ", 10), Err(LzfseError::BadMagic));
    }

    #[test]
    fn d_tables() {
        let db = bases(&d_extra());
        assert_eq!(db[4], 4);
        assert_eq!(db[8], 12);
        assert_eq!(db[63], 229_372);
        assert_eq!(bases(&M_EXTRA)[19], 312);
        assert_eq!(bases(&L_EXTRA)[19], 60);
    }

    #[test]
    fn lzvn_small() {
        // sml_l "abcd", sml_m 4 (repeat D undefined -> error), then valid.
        let mut out = Vec::new();
        assert!(decode_lzvn_into(&[0xe4, b'a', b'b', b'c', b'd', 0xf4, 6, 0, 0, 0, 0, 0, 0, 0], 8, &mut out).is_err());
        // sml_d: L=0 M=3 D=1 after literal 'a': op = 0b00_000_000 | D high bits, b1 = 1.
        let mut out = Vec::new();
        decode_lzvn_into(&[0xe1, b'a', 0x00, 0x01, 0x06, 0, 0, 0, 0, 0, 0, 0], 4, &mut out).unwrap();
        assert_eq!(out, b"aaaa");
    }
}
