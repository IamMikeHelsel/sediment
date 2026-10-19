// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA2 encoding: splits the LZMA symbol stream into chunks (at most 2 MiB
//! unpacked, 64 KiB packed), falls back to uncompressed chunks when LZMA does
//! not help, and emits the required dictionary / property / state resets.
//!
//! Spec sources: the LZMA2 chunk layout as documented in the public xz file
//! format specification (filter 0x21 and its dictionary-size property byte)
//! and the public LZMA SDK documentation of LZMA2 control bytes: `0x00` end,
//! `0x01` uncompressed + dictionary reset, `0x02` uncompressed, `0x80..=0xFF`
//! LZMA chunk where bits 5-6 select no reset / state reset / state reset + new
//! properties / everything reset, bits 0-4 are the high bits of
//! (unpacked size - 1), followed by 16-bit big-endian (unpacked - 1), 16-bit
//! big-endian (packed - 1) and an optional properties byte.
//!
//! The encoder never emits a dictionary reset after the first chunk, so the
//! whole input is one LZMA2 dictionary; the declared size is
//! [`effective_dictionary_size`] of the options and input length.

use crate::lzma_encode::{
    Encoder, LzmaEncodeError, LzmaEncoderOptions, RangeEncoder, effective_dictionary_size, props_byte,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lzma2EncodeError {
    /// Invalid LZMA options, or lc + lp > 4.
    InvalidOptions,
    /// Input longer than [`crate::lzma_encode::MAX_INPUT`].
    InputTooLarge,
    Allocation,
}

impl From<LzmaEncodeError> for Lzma2EncodeError {
    fn from(e: LzmaEncodeError) -> Self {
        match e {
            LzmaEncodeError::InvalidOptions => Lzma2EncodeError::InvalidOptions,
            LzmaEncodeError::InputTooLarge => Lzma2EncodeError::InputTooLarge,
            LzmaEncodeError::Allocation => Lzma2EncodeError::Allocation,
        }
    }
}

/// Maximum unpacked bytes in one LZMA chunk.
pub const CHUNK_MAX_UNPACKED: usize = 1 << 21;
/// Maximum packed bytes in one LZMA chunk, and unpacked bytes in one
/// uncompressed chunk.
pub const CHUNK_MAX_PACKED: usize = 1 << 16;

/// Encode the LZMA2 dictionary-size property byte: the smallest byte whose
/// decoded size (`(2 | (b & 1)) << (b / 2 + 11)`, 40 = 4 GiB - 1) is at
/// least `dictionary_size`.
pub fn dictionary_size_to_byte(dictionary_size: u32) -> u8 {
    for b in 0u8..40 {
        let d = (2u64 | (b & 1) as u64) << (b / 2 + 11);
        if d >= dictionary_size as u64 {
            return b;
        }
    }
    40
}

/// Encode `input` as a raw LZMA2 stream (terminated by the 0x00 end byte).
/// Returns the stream and the dictionary property byte a container (xz, 7z)
/// must declare for it.
pub fn encode_lzma2(input: &[u8], opts: &LzmaEncoderOptions) -> Result<(Vec<u8>, u8), Lzma2EncodeError> {
    opts.validate()?;
    if opts.lc + opts.lp > 4 {
        return Err(Lzma2EncodeError::InvalidOptions);
    }
    let dict = effective_dictionary_size(opts.dictionary_size, input.len());
    let dict_byte = dictionary_size_to_byte(dict);
    let mut out = Vec::new();
    // Typical output is smaller than the input; grow on demand beyond that.
    out.try_reserve(input.len().min(1 << 24) / 2 + 16).map_err(|_| Lzma2EncodeError::Allocation)?;

    let mut enc = Encoder::new(input, opts, opts.lc, opts.lp)?;
    let props = props_byte(opts.lc, opts.lp, opts.pb);
    let mut need_dict_reset = true;
    let mut need_props = true;
    let mut need_state_reset = false;

    while enc.position() < input.len() {
        let start = enc.position();
        let mut rc = RangeEncoder::new();
        enc.encode_until(&mut rc, CHUNK_MAX_UNPACKED, CHUNK_MAX_PACKED)?;
        let unpacked = enc.position() - start;
        let packed = rc.finish()?;
        if unpacked == 0 {
            // Cannot happen with the limits above; refuse rather than loop.
            return Err(Lzma2EncodeError::InvalidOptions);
        }
        if packed.len() < unpacked && packed.len() <= CHUNK_MAX_PACKED {
            let control: u8 = if need_dict_reset {
                0xE0
            } else if need_props {
                0xC0
            } else if need_state_reset {
                0xA0
            } else {
                0x80
            };
            let u = unpacked - 1;
            let p = packed.len() - 1;
            reserve(&mut out, packed.len() + 6)?;
            out.push(control | (u >> 16) as u8);
            out.extend_from_slice(&[(u >> 8) as u8, u as u8, (p >> 8) as u8, p as u8]);
            if control >= 0xC0 {
                out.push(props);
            }
            out.extend_from_slice(&packed);
            need_dict_reset = false;
            need_props = false;
            need_state_reset = false;
        } else {
            for piece in input[start..start + unpacked].chunks(CHUNK_MAX_PACKED) {
                let s = piece.len() - 1;
                reserve(&mut out, piece.len() + 3)?;
                out.push(if need_dict_reset { 0x01 } else { 0x02 });
                out.extend_from_slice(&[(s >> 8) as u8, s as u8]);
                out.extend_from_slice(piece);
                need_dict_reset = false;
            }
            // The discarded LZMA attempt advanced the model; the decoder's
            // model did not, so both restart from a state reset.
            enc.reset_state();
            need_state_reset = true;
        }
    }
    reserve(&mut out, 1)?;
    out.push(0x00);
    Ok((out, dict_byte))
}

fn reserve(out: &mut Vec<u8>, extra: usize) -> Result<(), Lzma2EncodeError> {
    if out.capacity() - out.len() < extra {
        let add = extra.max(out.len().clamp(4096, 1 << 24));
        out.try_reserve(add).map_err(|_| Lzma2EncodeError::Allocation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dict_bytes() {
        assert_eq!(dictionary_size_to_byte(0), 0);
        assert_eq!(dictionary_size_to_byte(4096), 0);
        assert_eq!(dictionary_size_to_byte(4097), 1);
        assert_eq!(dictionary_size_to_byte(8 << 20), 22);
        assert_eq!(dictionary_size_to_byte(64 << 20), 28);
        assert_eq!(dictionary_size_to_byte(u32::MAX), 40);
    }
}
