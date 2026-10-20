// SPDX-License-Identifier: MIT OR Apache-2.0
//! Apple Data Compression (ADC) decoding, as used by UDIF `UDCO` images
//! (chunk type `0x80000004`).
//!
//! Spec source: the publicly documented ADC byte format (as described in
//! the UDIF/DMG format write-ups, e.g. Jonathan Levin's "Demystifying the
//! DMG File Format" and the libdmg-hfsplus notes). Each opcode byte `op`:
//! - `op & 0x80`: literal run of `(op & 0x7f) + 1` bytes;
//! - `op & 0x40`: three-byte match, length `(op & 0x3f) + 4`, distance
//!   `u16be(next two bytes) + 1`;
//! - otherwise: two-byte match, length `((op >> 2) & 0xf) + 3`, distance
//!   `((op & 3) << 8 | next byte) + 1`.
//!
//! Distances count back from the current output position. Output is
//! capped by `max_output`; malformed input returns an error.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdcError {
    /// Input ended inside an opcode or literal run.
    Truncated,
    /// A match reaches before the start of the output.
    BadDistance,
    /// Output would exceed `max_output`.
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
}

/// Decode ADC data until the input is exhausted or `max_output` bytes have
/// been produced (UDIF chunks record the exact output size; trailing
/// input after the output is full is ignored).
pub fn decode_adc(src: &[u8], max_output: usize) -> Result<Vec<u8>, AdcError> {
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(max_output.min(src.len().saturating_mul(32)).min(1 << 26)).map_err(|_| AdcError::Allocation)?;
    let mut p = 0usize;
    while p < src.len() && out.len() < max_output {
        let op = src[p];
        if op & 0x80 != 0 {
            let n = usize::from(op & 0x7f) + 1;
            let lit = src.get(p + 1..p + 1 + n).ok_or(AdcError::Truncated)?;
            if out.len() + n > max_output {
                return Err(AdcError::LimitExceeded);
            }
            out.try_reserve(n).map_err(|_| AdcError::Allocation)?;
            out.extend_from_slice(lit);
            p += 1 + n;
            continue;
        }
        let (len, dist, used) = if op & 0x40 != 0 {
            let b = src.get(p + 1..p + 3).ok_or(AdcError::Truncated)?;
            (usize::from(op & 0x3f) + 4, ((usize::from(b[0]) << 8) | usize::from(b[1])) + 1, 3)
        } else {
            let b = *src.get(p + 1).ok_or(AdcError::Truncated)?;
            (usize::from((op >> 2) & 0xf) + 3, ((usize::from(op & 3) << 8) | usize::from(b)) + 1, 2)
        };
        if dist > out.len() {
            return Err(AdcError::BadDistance);
        }
        if out.len() + len > max_output {
            return Err(AdcError::LimitExceeded);
        }
        out.try_reserve(len).map_err(|_| AdcError::Allocation)?;
        let start = out.len() - dist;
        for i in 0..len {
            let c = out[start + i];
            out.push(c);
        }
        p += used;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_matches() {
        // "abc" literal, 2-byte match len 3 dist 3, 3-byte match len 4 dist 1.
        let src = [0x82, b'a', b'b', b'c', 0x00, 0x02, 0x40, 0x00, 0x00];
        assert_eq!(decode_adc(&src, 100).unwrap(), b"abcabccccc");
        assert_eq!(decode_adc(&src, 5), Err(AdcError::LimitExceeded));
        assert_eq!(decode_adc(&src, 6).unwrap(), b"abcabc");
        assert_eq!(decode_adc(&[0x00, 0x00], 10), Err(AdcError::BadDistance));
        assert_eq!(decode_adc(&[0x85, 1], 10), Err(AdcError::Truncated));
        assert_eq!(decode_adc(&[0x82, b'a', b'b', b'c', 0x40], 10), Err(AdcError::Truncated));
    }
}
