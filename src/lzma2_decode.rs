// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA2 decoding: chunk parsing (uncompressed chunks, LZMA chunks with
//! state / property / dictionary resets) on top of `lzma_decode`.
//!
//! Spec sources: the LZMA2 chunk layout as documented in the public xz file
//! format specification (filter 0x21 and its dictionary-size property byte)
//! and the public LZMA SDK documentation of LZMA2 control bytes:
//! `0x00` end, `0x01` uncompressed + dictionary reset, `0x02` uncompressed,
//! `0x80..=0xFF` LZMA chunk where bits 5-6 select no reset / state reset /
//! state reset + new properties / everything reset, bits 0-4 are the high
//! bits of (unpacked size - 1), followed by 16-bit big-endian (unpacked - 1),
//! 16-bit big-endian (packed - 1) and an optional properties byte.

use crate::lzma_decode::{LzmaError, LzmaState, RangeDecoder, RunEnd, decode_props_byte, reserve};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lzma2Error {
    UnexpectedEof,
    InvalidControl,
    InvalidProperties,
    InvalidData,
    LimitExceeded,
    Allocation,
}

impl From<LzmaError> for Lzma2Error {
    fn from(e: LzmaError) -> Self {
        match e {
            LzmaError::UnexpectedEof => Lzma2Error::InvalidData,
            LzmaError::InvalidProperties => Lzma2Error::InvalidProperties,
            LzmaError::InvalidData | LzmaError::TrailingData => Lzma2Error::InvalidData,
            LzmaError::LimitExceeded => Lzma2Error::LimitExceeded,
            LzmaError::Allocation => Lzma2Error::Allocation,
        }
    }
}

/// Decode the LZMA2 dictionary-size property byte (xz filter properties).
pub fn dictionary_size_from_byte(byte: u8) -> Result<u32, Lzma2Error> {
    let bits = (byte & 0x3F) as u32;
    if byte & 0xC0 != 0 || bits > 40 {
        return Err(Lzma2Error::InvalidProperties);
    }
    if bits == 40 {
        return Ok(u32::MAX);
    }
    Ok((2 | (bits & 1)) << (bits / 2 + 11))
}

/// Decode a raw LZMA2 stream into a new vector. Returns the output and the
/// number of input bytes consumed (through the 0x00 end byte).
pub fn decode_lzma2(
    input: &[u8],
    dictionary_size: u32,
    max_dictionary: u64,
    max_output: usize,
) -> Result<(Vec<u8>, usize), Lzma2Error> {
    let mut out = Vec::new();
    let used = decode_lzma2_into(input, dictionary_size, max_dictionary, &mut out, max_output)?;
    Ok((out, used))
}

/// Decode a raw LZMA2 stream, appending to `out`. Bytes already in `out` are
/// never referenced as dictionary. `max_output` caps the total `out.len()`.
/// Returns the number of input bytes consumed.
pub fn decode_lzma2_into(
    input: &[u8],
    dictionary_size: u32,
    max_dictionary: u64,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<usize, Lzma2Error> {
    let dict_size = dictionary_size.max(4096);
    if dict_size as u64 > max_dictionary {
        return Err(Lzma2Error::LimitExceeded);
    }
    let mut state = LzmaState::new(dict_size);
    let mut dict_start = out.len();
    let mut need_dict_reset = true;
    let mut need_props = true;
    let mut pos = 0usize;

    loop {
        let control = *input.get(pos).ok_or(Lzma2Error::UnexpectedEof)?;
        pos += 1;
        if control == 0x00 {
            return Ok(pos);
        }
        if (0x03..0x80).contains(&control) {
            return Err(Lzma2Error::InvalidControl);
        }
        if control >= 0xE0 || control == 0x01 {
            need_props = true;
            need_dict_reset = false;
            dict_start = out.len();
        } else if need_dict_reset {
            return Err(Lzma2Error::InvalidData);
        }

        if control >= 0x80 {
            let hdr = input.get(pos..pos + 4).ok_or(Lzma2Error::UnexpectedEof)?;
            pos += 4;
            let unpacked = (((control & 0x1F) as usize) << 16) + ((hdr[0] as usize) << 8) + hdr[1] as usize + 1;
            let packed = ((hdr[2] as usize) << 8) + hdr[3] as usize + 1;
            if control >= 0xC0 {
                let pbyte = *input.get(pos).ok_or(Lzma2Error::UnexpectedEof)?;
                pos += 1;
                let (lc, lp, pb) = decode_props_byte(pbyte).map_err(|_| Lzma2Error::InvalidProperties)?;
                if lc + lp > 4 {
                    return Err(Lzma2Error::InvalidProperties);
                }
                state.set_props(lc, lp, pb)?;
                need_props = false;
            } else if need_props {
                return Err(Lzma2Error::InvalidData);
            } else if control >= 0xA0 {
                state.reset();
            }
            let chunk = input.get(pos..pos + packed).ok_or(Lzma2Error::UnexpectedEof)?;
            pos += packed;
            let end = out.len().checked_add(unpacked).ok_or(Lzma2Error::LimitExceeded)?;
            if end > max_output {
                return Err(Lzma2Error::LimitExceeded);
            }
            let mut rc = RangeDecoder::new(chunk)?;
            let how = state.run(&mut rc, out, dict_start, Some(end), false, max_output)?;
            if how != RunEnd::SizeReached
                || rc.overrun()
                || !rc.finished_ok()
                || rc.consumed() != chunk.len()
            {
                return Err(Lzma2Error::InvalidData);
            }
        } else {
            let hdr = input.get(pos..pos + 2).ok_or(Lzma2Error::UnexpectedEof)?;
            pos += 2;
            let size = ((hdr[0] as usize) << 8) + hdr[1] as usize + 1;
            let data = input.get(pos..pos + size).ok_or(Lzma2Error::UnexpectedEof)?;
            pos += size;
            if out.len() + size > max_output {
                return Err(Lzma2Error::LimitExceeded);
            }
            reserve(out, size, max_output)?;
            out.extend_from_slice(data);
        }
    }
}
