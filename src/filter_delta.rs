// SPDX-License-Identifier: MIT OR Apache-2.0

//! Delta filter (xz filter ID 0x03, 7z method ID 0x03).
//!
//! Encoding replaces each byte with its difference (mod 256) from the byte
//! `distance` positions earlier; bytes before the start of the stream count
//! as zero. Decoding adds the history back. Distance is 1..=256 and is
//! stored in the one-byte properties as `distance - 1`.
//!
//! Sources: the .xz file format specification (section 5.3.3, Delta) and the
//! 7z format documentation. Verified against Python's `lzma` (FILTER_DELTA)
//! via `tests/fixtures/filters/`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaError {
    /// Distance outside 1..=256.
    InvalidDistance,
    /// Properties are not exactly one byte.
    InvalidProperties,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

pub const DELTA_MIN_DISTANCE: usize = 1;
pub const DELTA_MAX_DISTANCE: usize = 256;

/// Parse the one-byte Delta properties into a distance (1..=256).
pub fn parse_delta_properties(props: &[u8]) -> Result<usize, DeltaError> {
    match props {
        [b] => Ok(*b as usize + 1),
        _ => Err(DeltaError::InvalidProperties),
    }
}

/// Encode a distance (1..=256) as the one-byte Delta properties.
pub fn delta_properties(distance: usize) -> Result<[u8; 1], DeltaError> {
    check_distance(distance)?;
    Ok([(distance - 1) as u8])
}

fn check_distance(distance: usize) -> Result<(), DeltaError> {
    if !(DELTA_MIN_DISTANCE..=DELTA_MAX_DISTANCE).contains(&distance) {
        return Err(DeltaError::InvalidDistance);
    }
    Ok(())
}

/// Streaming delta coder; state is the last 256 bytes of plain data.
#[derive(Debug, Clone)]
pub struct DeltaCoder {
    distance: usize,
    history: [u8; 256],
    pos: u8,
    encoding: bool,
}

impl DeltaCoder {
    pub fn new(distance: usize, encoding: bool) -> Result<DeltaCoder, DeltaError> {
        check_distance(distance)?;
        Ok(DeltaCoder {
            distance,
            history: [0; 256],
            pos: 0,
            encoding,
        })
    }

    pub fn distance(&self) -> usize {
        self.distance
    }

    /// Convert `buf` in place. Every byte is final; chunking does not matter.
    pub fn convert(&mut self, buf: &mut [u8]) {
        // history[pos] is where the next plain byte is stored; the byte
        // `distance` back is at pos - distance (mod 256).
        for b in buf.iter_mut() {
            let back = self.pos.wrapping_sub(self.distance as u8) as usize;
            // distance == 256 wraps to 0, i.e. the slot about to be overwritten.
            let prev = self.history[back];
            let plain = if self.encoding {
                let p = *b;
                *b = p.wrapping_sub(prev);
                p
            } else {
                let p = b.wrapping_add(prev);
                *b = p;
                p
            };
            self.history[self.pos as usize] = plain;
            self.pos = self.pos.wrapping_add(1);
        }
    }
}

fn one_shot(distance: usize, input: &[u8], max_output: usize, encoding: bool) -> Result<Vec<u8>, DeltaError> {
    let mut coder = DeltaCoder::new(distance, encoding)?;
    if input.len() > max_output {
        return Err(DeltaError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(|_| DeltaError::Allocation)?;
    out.extend_from_slice(input);
    coder.convert(&mut out);
    Ok(out)
}

pub fn delta_encode(distance: usize, input: &[u8], max_output: usize) -> Result<Vec<u8>, DeltaError> {
    one_shot(distance, input, max_output, true)
}

pub fn delta_decode(distance: usize, input: &[u8], max_output: usize) -> Result<Vec<u8>, DeltaError> {
    one_shot(distance, input, max_output, false)
}
