// SPDX-License-Identifier: MIT OR Apache-2.0
//! BCJ2 x86 branch converter decoder (7z method `03 03 01 1B`).
//!
//! BCJ2 splits x86 code into four streams: the main byte stream, a stream of
//! absolute CALL (`E8`) targets, a stream of absolute JMP / Jcc (`E9`,
//! `0F 8x`) targets, and a range-coded stream of one flag bit per candidate
//! opcode saying whether its 32-bit operand was moved to the call/jump
//! stream. The decoder copies main-stream bytes; after every candidate
//! opcode byte it decodes one adaptive bit and, if set, reads a big-endian
//! absolute address from the call or jump stream and writes it back as a
//! little-endian displacement relative to the end of the instruction.
//!
//! Probability contexts: 256 for `E8` (selected by the byte before the
//! opcode), one for `E9`, one for `0F 8x`. Each is an 11-bit adaptive bit
//! model with shift 5 driven by the LZMA-style range decoder (5 init bytes,
//! normalised at 2^24).
//!
//! Sources: the 7z format documentation (method ID list and the four-input
//! BCJ2 coder layout), the public LZMA specification (range decoder and
//! adaptive bit model), and the behaviour of archives produced by `7zz
//! -mf=BCJ2` (fixtures in `tests/fixtures/sevenz/oracle/`). No 7-Zip source
//! was consulted.
//!
//! Malformed input returns `Err`, never panics; output is bounded by the
//! caller's exact `out_size`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bcj2Error {
    /// The main, call, jump or range-coded stream ended early.
    UnexpectedEof,
    /// The range-coded stream is not valid (bad first byte).
    CorruptData,
    /// Memory reservation failed.
    Allocation,
}

/// The 7z method ID of BCJ2 as a big-endian integer.
pub const BCJ2_METHOD_ID: u64 = 0x0303_011B;
/// The 7z method ID bytes of BCJ2.
pub const BCJ2_METHOD_ID_BYTES: [u8; 4] = [0x03, 0x03, 0x01, 0x1B];

const NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_TOTAL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

struct RangeDecoder<'a> {
    src: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(src: &'a [u8]) -> Result<Self, Bcj2Error> {
        if src.len() < 5 {
            return Err(Bcj2Error::UnexpectedEof);
        }
        if src[0] != 0 {
            return Err(Bcj2Error::CorruptData);
        }
        let code = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        Ok(RangeDecoder { src, pos: 5, range: 0xFFFF_FFFF, code })
    }

    fn bit(&mut self, prob: &mut u16) -> Result<bool, Bcj2Error> {
        if self.range < TOP_VALUE {
            let b = *self.src.get(self.pos).ok_or(Bcj2Error::UnexpectedEof)?;
            self.pos += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(b);
        }
        let p = u32::from(*prob);
        let bound = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * p;
        if self.code < bound {
            self.range = bound;
            *prob = (p + ((BIT_MODEL_TOTAL - p) >> NUM_MOVE_BITS)) as u16;
            Ok(false)
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob = (p - (p >> NUM_MOVE_BITS)) as u16;
            Ok(true)
        }
    }
}

#[inline]
fn is_jump(prev: u8, b: u8) -> bool {
    (b & 0xFE) == 0xE8 || (prev == 0x0F && (b & 0xF0) == 0x80)
}

fn read_be32(src: &[u8], pos: &mut usize) -> Result<u32, Bcj2Error> {
    let end = pos.checked_add(4).ok_or(Bcj2Error::UnexpectedEof)?;
    let s = src.get(*pos..end).ok_or(Bcj2Error::UnexpectedEof)?;
    *pos = end;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode a BCJ2 coder: `main`, `call`, `jump` and `rc` are the coder's
/// four input streams in 7z order; exactly `out_size` bytes are produced.
pub fn bcj2_decode(main: &[u8], call: &[u8], jump: &[u8], rc: &[u8], out_size: usize) -> Result<Vec<u8>, Bcj2Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(out_size).map_err(|_| Bcj2Error::Allocation)?;
    let mut rc = RangeDecoder::new(rc)?;
    let mut probs = [(BIT_MODEL_TOTAL >> 1) as u16; 2 + 256];
    let (mut mp, mut cp, mut jp) = (0usize, 0usize, 0usize);
    let mut prev: u8 = 0;
    while out.len() < out_size {
        // Copy plain bytes up to and including the next candidate opcode.
        let b = *main.get(mp).ok_or(Bcj2Error::UnexpectedEof)?;
        mp += 1;
        out.push(b);
        if !is_jump(prev, b) {
            prev = b;
            continue;
        }
        if out.len() == out_size {
            break;
        }
        let idx = match b {
            0xE8 => prev as usize,
            0xE9 => 256,
            _ => 257,
        };
        if rc.bit(&mut probs[idx])? {
            let src = if b == 0xE8 { read_be32(call, &mut cp)? } else { read_be32(jump, &mut jp)? };
            let next = (out.len() as u32).wrapping_add(4);
            let dest = src.wrapping_sub(next).to_le_bytes();
            let room = (out_size - out.len()).min(4);
            out.extend_from_slice(&dest[..room]);
            prev = dest[3];
        } else {
            prev = b;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes_pass_through() {
        let main = b"hello world";
        let rc = [0u8, 0, 0, 0, 0];
        assert_eq!(bcj2_decode(main, &[], &[], &rc, main.len()).unwrap(), main);
    }

    #[test]
    fn truncated_streams_err() {
        assert_eq!(bcj2_decode(b"abc", &[], &[], &[0, 0, 0], 3), Err(Bcj2Error::UnexpectedEof));
        assert_eq!(bcj2_decode(b"abc", &[], &[], &[1, 0, 0, 0, 0], 3), Err(Bcj2Error::CorruptData));
        assert_eq!(bcj2_decode(b"abc", &[], &[], &[0; 5], 4), Err(Bcj2Error::UnexpectedEof));
        // A converted call whose call stream is empty.
        let main = [0x90, 0xE8, 0x90, 0x90];
        let rc = [0u8, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(bcj2_decode(&main, &[], &[], &rc, 10), Err(Bcj2Error::UnexpectedEof));
    }
}
