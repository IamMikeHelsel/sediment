// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA decoding: range coder, literal/match/rep symbol decoding, and the
//! `.lzma` ("LZMA-alone") container.
//!
//! Spec sources: the public-domain `lzma-specification.txt` from the LZMA SDK
//! (Igor Pavlov), which documents the range decoder, the probability model and
//! the reference decoding loop; and the `.lzma` header layout described there
//! (properties byte, 32-bit dictionary size, 64-bit unpacked size).
//!
//! The decoded output itself serves as the sliding window, so memory use is
//! bounded by `max_output`. The declared dictionary size is still validated
//! against the caller's `max_dictionary` cap and enforced as the maximum
//! match distance.

use crate::lzma_properties::LzmaProperties;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzmaError {
    UnexpectedEof,
    InvalidProperties,
    InvalidData,
    LimitExceeded,
    Allocation,
    TrailingData,
}

/// Unknown-size marker in the `.lzma` header.
const UNKNOWN_SIZE: u64 = u64::MAX;
const PROB_INIT: u16 = 1024;
const NUM_STATES: usize = 12;
const POS_STATES_MAX: usize = 16;
const END_MARKER_DISTANCE: u32 = 0xFFFF_FFFF;

/// Split an LZMA properties byte into `(lc, lp, pb)`.
/// Accepts the full LZMA range: lc <= 8, lp <= 4, pb <= 4.
pub fn decode_props_byte(byte: u8) -> Result<(u8, u8, u8), LzmaError> {
    if byte >= 9 * 5 * 5 {
        return Err(LzmaError::InvalidProperties);
    }
    let lc = byte % 9;
    let rest = byte / 9;
    Ok((lc, rest % 5, rest / 5))
}

// ---------------------------------------------------------------------------
// Range decoder
// ---------------------------------------------------------------------------

pub(crate) struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
    overrun: bool,
}

impl<'a> RangeDecoder<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self, LzmaError> {
        if input.len() < 5 {
            return Err(LzmaError::UnexpectedEof);
        }
        if input[0] != 0 {
            return Err(LzmaError::InvalidData);
        }
        let code = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if code == 0xFFFF_FFFF {
            return Err(LzmaError::InvalidData);
        }
        Ok(Self { input, pos: 5, range: 0xFFFF_FFFF, code, overrun: false })
    }

    pub(crate) fn consumed(&self) -> usize {
        self.pos
    }

    pub(crate) fn overrun(&self) -> bool {
        self.overrun
    }

    pub(crate) fn finished_ok(&self) -> bool {
        self.code == 0
    }

    #[inline]
    fn next_byte(&mut self) -> u32 {
        match self.input.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b as u32
            }
            None => {
                self.overrun = true;
                0
            }
        }
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < (1 << 24) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.next_byte();
        }
    }

    #[inline]
    fn bit(&mut self, prob: &mut u16) -> u32 {
        let p = *prob as u32;
        let bound = (self.range >> 11) * p;
        let bit = if self.code < bound {
            self.range = bound;
            *prob = (p + ((2048 - p) >> 5)) as u16;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob = (p - (p >> 5)) as u16;
            1
        };
        self.normalize();
        bit
    }

    fn direct_bits(&mut self, count: u32) -> u32 {
        let mut res = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            self.normalize();
            res = (res << 1).wrapping_add(t.wrapping_add(1));
        }
        res
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) + self.bit(&mut probs[m]) as usize;
        }
        (m - (1 << bits)) as u32
    }

    fn reverse_tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        let mut sym = 0u32;
        for i in 0..bits {
            let b = self.bit(&mut probs[m]);
            m = (m << 1) + b as usize;
            sym |= b << i;
        }
        sym
    }
}

// ---------------------------------------------------------------------------
// Length decoder
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LenDecoder {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES_MAX],
    mid: [[u16; 8]; POS_STATES_MAX],
    high: [u16; 256],
}

impl LenDecoder {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; 8]; POS_STATES_MAX],
            mid: [[PROB_INIT; 8]; POS_STATES_MAX],
            high: [PROB_INIT; 256],
        }
    }

    fn decode(&mut self, rc: &mut RangeDecoder<'_>, pos_state: usize) -> u32 {
        if rc.bit(&mut self.choice) == 0 {
            return rc.tree(&mut self.low[pos_state], 3);
        }
        if rc.bit(&mut self.choice2) == 0 {
            return 8 + rc.tree(&mut self.mid[pos_state], 3);
        }
        16 + rc.tree(&mut self.high, 8)
    }
}

// ---------------------------------------------------------------------------
// Decoder state (probabilities + LZ state), reusable across LZMA2 chunks.
// ---------------------------------------------------------------------------

pub(crate) struct LzmaState {
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: u32,
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
    len: LenDecoder,
    rep_len: LenDecoder,
    state: usize,
    reps: [u32; 4],
}

/// Outcome of one decoding run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunEnd {
    /// The known size was reached without an end marker.
    SizeReached,
    /// An end-of-payload marker was decoded.
    Marker,
}

impl LzmaState {
    pub(crate) fn new(dict_size: u32) -> Self {
        Self {
            lc: 0,
            lp: 0,
            pb: 0,
            dict_size,
            literal: Vec::new(),
            is_match: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
            is_rep: [PROB_INIT; NUM_STATES],
            is_rep_g0: [PROB_INIT; NUM_STATES],
            is_rep_g1: [PROB_INIT; NUM_STATES],
            is_rep_g2: [PROB_INIT; NUM_STATES],
            is_rep0_long: [PROB_INIT; NUM_STATES * POS_STATES_MAX],
            pos_slot: [[PROB_INIT; 64]; 4],
            pos_special: [PROB_INIT; 115],
            align: [PROB_INIT; 16],
            len: LenDecoder::new(),
            rep_len: LenDecoder::new(),
            state: 0,
            reps: [0; 4],
        }
    }

    /// Set lc/lp/pb (resizes the literal table) and reset all state.
    pub(crate) fn set_props(&mut self, lc: u8, lp: u8, pb: u8) -> Result<(), LzmaError> {
        if lc > 8 || lp > 4 || pb > 4 {
            return Err(LzmaError::InvalidProperties);
        }
        self.lc = lc as u32;
        self.lp = lp as u32;
        self.pb = pb as u32;
        let n = 0x300usize << (self.lc + self.lp);
        self.literal.clear();
        self.literal.try_reserve_exact(n).map_err(|_| LzmaError::Allocation)?;
        self.literal.resize(n, PROB_INIT);
        self.reset();
        Ok(())
    }

    /// Reset probabilities, state and reps (keeps lc/lp/pb).
    pub(crate) fn reset(&mut self) {
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
        self.len = LenDecoder::new();
        self.rep_len = LenDecoder::new();
        self.state = 0;
        self.reps = [0; 4];
    }

    fn decode_distance(&mut self, rc: &mut RangeDecoder<'_>, len: u32) -> u32 {
        let len_state = len.min(3) as usize;
        let slot = rc.tree(&mut self.pos_slot[len_state], 6);
        if slot < 4 {
            return slot;
        }
        let direct = (slot >> 1) - 1;
        let mut dist = (2 | (slot & 1)) << direct;
        if slot < 14 {
            let base = (dist - slot) as usize;
            // base + (1 << direct) <= 115 for slot < 14.
            dist += rc.reverse_tree(&mut self.pos_special[base..], direct);
        } else {
            dist = dist.wrapping_add(rc.direct_bits(direct - 4) << 4);
            dist = dist.wrapping_add(rc.reverse_tree(&mut self.align, 4));
        }
        dist
    }

    /// Decode symbols, appending to `out`. `dict_start` is the index in `out`
    /// where the current dictionary begins (matches may not reach before it).
    /// `end` is the known final length of `out`, if any. `allow_marker` permits
    /// an end-of-payload marker (mandatory when `end` is `None`).
    pub(crate) fn run(
        &mut self,
        rc: &mut RangeDecoder<'_>,
        out: &mut Vec<u8>,
        dict_start: usize,
        end: Option<usize>,
        allow_marker: bool,
        max_output: usize,
    ) -> Result<RunEnd, LzmaError> {
        let pb_mask = (1usize << self.pb) - 1;
        let lp_mask = (1usize << self.lp) - 1;
        let lc = self.lc;
        loop {
            if rc.overrun {
                return Err(LzmaError::UnexpectedEof);
            }
            let at_end = end == Some(out.len());
            if at_end && (!allow_marker || rc.finished_ok()) {
                return Ok(RunEnd::SizeReached);
            }
            let filled = out.len() - dict_start;
            let pos_state = filled & pb_mask;
            let st = self.state;
            if rc.bit(&mut self.is_match[(st << 4) | pos_state]) == 0 {
                if at_end {
                    return Err(LzmaError::InvalidData);
                }
                if out.len() >= max_output {
                    return Err(LzmaError::LimitExceeded);
                }
                let prev = if filled > 0 { out[out.len() - 1] as usize } else { 0 };
                let lit_state = ((filled & lp_mask) << lc) + (prev >> (8 - lc));
                let base = lit_state * 0x300;
                let probs = &mut self.literal[base..base + 0x300];
                let mut sym = 1usize;
                if st >= 7 {
                    let rep0 = self.reps[0] as usize;
                    if rep0 >= filled {
                        return Err(LzmaError::InvalidData);
                    }
                    let mut match_byte = out[out.len() - rep0 - 1] as usize;
                    while sym < 0x100 {
                        let match_bit = (match_byte >> 7) & 1;
                        match_byte <<= 1;
                        let b = rc.bit(&mut probs[((1 + match_bit) << 8) + sym]) as usize;
                        sym = (sym << 1) | b;
                        if match_bit != b {
                            break;
                        }
                    }
                }
                while sym < 0x100 {
                    sym = (sym << 1) | rc.bit(&mut probs[sym]) as usize;
                }
                reserve(out, 1, max_output)?;
                out.push((sym - 0x100) as u8);
                self.state = if st < 4 {
                    0
                } else if st < 10 {
                    st - 3
                } else {
                    st - 6
                };
                continue;
            }

            let len;
            if rc.bit(&mut self.is_rep[st]) == 0 {
                // Simple match.
                len = self.len.decode(rc, pos_state);
                self.state = if st < 7 { 7 } else { 10 };
                let dist = self.decode_distance(rc, len);
                if dist == END_MARKER_DISTANCE {
                    if !allow_marker {
                        return Err(LzmaError::InvalidData);
                    }
                    if rc.overrun {
                        return Err(LzmaError::UnexpectedEof);
                    }
                    if !rc.finished_ok() {
                        return Err(LzmaError::InvalidData);
                    }
                    return Ok(RunEnd::Marker);
                }
                if at_end {
                    return Err(LzmaError::InvalidData);
                }
                self.reps = [dist, self.reps[0], self.reps[1], self.reps[2]];
            } else {
                if at_end || filled == 0 {
                    return Err(LzmaError::InvalidData);
                }
                if rc.bit(&mut self.is_rep_g0[st]) == 0 {
                    if rc.bit(&mut self.is_rep0_long[(st << 4) | pos_state]) == 0 {
                        // Short rep: one byte at distance rep0.
                        self.state = if st < 7 { 9 } else { 11 };
                        let rep0 = self.reps[0] as usize;
                        if rep0 >= filled || self.reps[0] >= self.dict_size {
                            return Err(LzmaError::InvalidData);
                        }
                        if out.len() >= max_output {
                            return Err(LzmaError::LimitExceeded);
                        }
                        reserve(out, 1, max_output)?;
                        let b = out[out.len() - rep0 - 1];
                        out.push(b);
                        continue;
                    }
                } else {
                    let dist;
                    if rc.bit(&mut self.is_rep_g1[st]) == 0 {
                        dist = self.reps[1];
                    } else {
                        if rc.bit(&mut self.is_rep_g2[st]) == 0 {
                            dist = self.reps[2];
                        } else {
                            dist = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = dist;
                }
                len = self.rep_len.decode(rc, pos_state);
                self.state = if st < 7 { 8 } else { 11 };
            }

            if rc.overrun {
                return Err(LzmaError::UnexpectedEof);
            }
            let rep0 = self.reps[0] as usize;
            if rep0 >= filled || self.reps[0] >= self.dict_size {
                return Err(LzmaError::InvalidData);
            }
            let n = len as usize + 2;
            if let Some(e) = end
                && out.len() + n > e
            {
                return Err(LzmaError::InvalidData);
            }
            if out.len() + n > max_output {
                return Err(LzmaError::LimitExceeded);
            }
            reserve(out, n, max_output)?;
            let src = out.len() - rep0 - 1;
            if rep0 + 1 >= n {
                out.extend_from_within(src..src + n);
            } else {
                for i in 0..n {
                    let b = out[src + i];
                    out.push(b);
                }
            }
        }
    }
}

/// Grow `out` so that `extra` more bytes fit, never beyond `max_output`.
pub(crate) fn reserve(out: &mut Vec<u8>, extra: usize, max_output: usize) -> Result<(), LzmaError> {
    if out.capacity() - out.len() >= extra {
        return Ok(());
    }
    let room = max_output.saturating_sub(out.len());
    if extra > room {
        return Err(LzmaError::LimitExceeded);
    }
    let want = out.len().clamp(4096, 1 << 24).max(extra).min(room);
    out.try_reserve(want).map_err(|_| LzmaError::Allocation)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Decode a raw LZMA stream (no header). With `unpacked_size == None` the
/// stream must end with an end marker; with a known size an end marker is
/// optional. Returns the output and the number of input bytes consumed.
pub fn decode_lzma_raw(
    input: &[u8],
    props: LzmaProperties,
    unpacked_size: Option<u64>,
    max_dictionary: u64,
    max_output: usize,
) -> Result<(Vec<u8>, usize), LzmaError> {
    if props.lc > 8 || props.lp > 4 || props.pb > 4 {
        return Err(LzmaError::InvalidProperties);
    }
    let dict_size = props.dictionary_size.max(4096);
    if dict_size as u64 > max_dictionary {
        return Err(LzmaError::LimitExceeded);
    }
    let end = match unpacked_size {
        Some(n) => {
            let n = usize::try_from(n).map_err(|_| LzmaError::LimitExceeded)?;
            if n > max_output {
                return Err(LzmaError::LimitExceeded);
            }
            Some(n)
        }
        None => None,
    };
    let mut state = LzmaState::new(dict_size);
    state.set_props(props.lc, props.lp, props.pb)?;
    let mut out = Vec::new();
    if let Some(n) = end {
        out.try_reserve(n.min(1 << 24)).map_err(|_| LzmaError::Allocation)?;
    }
    let mut rc = RangeDecoder::new(input)?;
    state.run(&mut rc, &mut out, 0, end, true, max_output)?;
    if rc.overrun() {
        return Err(LzmaError::UnexpectedEof);
    }
    if let Some(n) = end
        && out.len() != n
    {
        // End marker arrived before the declared size was reached.
        return Err(LzmaError::InvalidData);
    }
    Ok((out, rc.consumed()))
}

/// Decode a complete `.lzma` (LZMA-alone) file: 13-byte header followed by
/// the LZMA stream. Trailing bytes after the stream are rejected.
pub fn decode_lzma_alone(input: &[u8], max_dictionary: u64, max_output: usize) -> Result<Vec<u8>, LzmaError> {
    if input.len() < 13 {
        return Err(LzmaError::UnexpectedEof);
    }
    let (lc, lp, pb) = decode_props_byte(input[0])?;
    let dictionary_size = u32::from_le_bytes([input[1], input[2], input[3], input[4]]);
    let mut size_bytes = [0u8; 8];
    size_bytes.copy_from_slice(&input[5..13]);
    let size = u64::from_le_bytes(size_bytes);
    let unpacked = if size == UNKNOWN_SIZE { None } else { Some(size) };
    let props = LzmaProperties { lc, lp, pb, dictionary_size };
    let (out, used) = decode_lzma_raw(&input[13..], props, unpacked, max_dictionary, max_output)?;
    if 13 + used != input.len() {
        return Err(LzmaError::TrailingData);
    }
    Ok(out)
}
