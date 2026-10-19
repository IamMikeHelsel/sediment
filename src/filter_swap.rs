// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte-swap filters from the 7z format: Swap2 (method ID 02 03 02) reverses
//! the bytes of every 16-bit unit and Swap4 (02 03 04) of every 32-bit unit.
//! A trailing partial unit is passed through unchanged. The transform is its
//! own inverse, so encode and decode are the same operation, and output never
//! depends on chunk boundaries as long as chunks are unit-aligned
//! ([`SwapStream`] handles arbitrary chunking).
//!
//! Source: the 7z format documentation (method ID list).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    /// Unknown method ID or non-empty properties.
    UnsupportedFilter,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapWidth {
    Swap2,
    Swap4,
}

impl SwapWidth {
    pub fn unit(self) -> usize {
        match self {
            SwapWidth::Swap2 => 2,
            SwapWidth::Swap4 => 4,
        }
    }

    pub fn sevenz_method_id(self) -> u64 {
        match self {
            SwapWidth::Swap2 => 0x02_0302,
            SwapWidth::Swap4 => 0x02_0304,
        }
    }

    pub fn from_sevenz_method_id(id: u64) -> Result<SwapWidth, SwapError> {
        match id {
            0x02_0302 => Ok(SwapWidth::Swap2),
            0x02_0304 => Ok(SwapWidth::Swap4),
            _ => Err(SwapError::UnsupportedFilter),
        }
    }
}

/// Swap all complete units in place; returns the number of bytes converted
/// (a multiple of the unit size).
pub fn swap_in_place(width: SwapWidth, buf: &mut [u8]) -> usize {
    let unit = width.unit();
    let mut chunks = buf.chunks_exact_mut(unit);
    for c in &mut chunks {
        c.reverse();
    }
    buf.len() - buf.len() % unit
}

/// Swap a complete buffer (trailing partial unit copied unchanged).
pub fn swap_convert(width: SwapWidth, input: &[u8], max_output: usize) -> Result<Vec<u8>, SwapError> {
    if input.len() > max_output {
        return Err(SwapError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(|_| SwapError::Allocation)?;
    out.extend_from_slice(input);
    swap_in_place(width, &mut out);
    Ok(out)
}

/// Chunked swap filter tolerant of arbitrary chunk boundaries.
#[derive(Debug, Clone)]
pub struct SwapStream {
    width: SwapWidth,
    pending: [u8; 4],
    pending_len: usize,
    produced: usize,
    max_output: usize,
}

impl SwapStream {
    pub fn new(width: SwapWidth, max_output: usize) -> SwapStream {
        SwapStream {
            width,
            pending: [0; 4],
            pending_len: 0,
            produced: 0,
            max_output,
        }
    }

    pub fn total_out(&self) -> usize {
        self.produced
    }

    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), SwapError> {
        let total = self
            .pending_len
            .checked_add(input.len())
            .ok_or(SwapError::LimitExceeded)?;
        if self.produced.checked_add(total).is_none_or(|t| t > self.max_output) {
            return Err(SwapError::LimitExceeded);
        }
        out.try_reserve(total).map_err(|_| SwapError::Allocation)?;
        let start = out.len();
        out.extend_from_slice(&self.pending[..self.pending_len]);
        out.extend_from_slice(input);
        let done = swap_in_place(self.width, &mut out[start..]);
        let rest = total - done;
        let tail = out.len() - rest;
        self.pending[..rest].copy_from_slice(&out[tail..]);
        self.pending_len = rest;
        out.truncate(tail);
        self.produced += done;
        Ok(())
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), SwapError> {
        let n = self.pending_len;
        out.try_reserve(n).map_err(|_| SwapError::Allocation)?;
        out.extend_from_slice(&self.pending[..n]);
        self.pending_len = 0;
        self.produced += n;
        Ok(())
    }
}
