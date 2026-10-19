// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitError {
    TooLarge,
    InvalidWidth,
    UnexpectedEof,
}

impl fmt::Display for BitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitError::TooLarge => write!(f, "BitError::TooLarge"),
            BitError::InvalidWidth => write!(f, "BitError::InvalidWidth"),
            BitError::UnexpectedEof => write!(f, "BitError::UnexpectedEof"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, BitError> {
        let total_bits = bytes.len().checked_mul(8).ok_or(BitError::TooLarge)?;
        Ok(BitReader {
            bytes,
            bit_pos: 0,
        })
    }

    pub fn position(&self) -> usize {
        self.bit_pos
    }

    pub fn remaining(&self) -> usize {
        let total_bits = self.bytes.len() * 8;
        if self.bit_pos > total_bits {
            0
        } else {
            total_bits - self.bit_pos
        }
    }

    pub fn read_bits(&mut self, width: u8) -> Result<u32, BitError> {
        if width == 0 {
            return Ok(0);
        }
        if width > 32 {
            return Err(BitError::InvalidWidth);
        }

        let width_usize = width as usize;
        let current_pos = self.bit_pos;
        let total_bits = self.bytes.len() * 8;

        if width_usize > total_bits - current_pos {
            return Err(BitError::UnexpectedEof);
        }

        let mut result: u32 = 0;
        for i in 0..width_usize {
            let bit_index = current_pos + i;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;
            let bit = (self.bytes[byte_index] >> bit_offset) & 1;
            result |= (bit as u32) << i;
        }

        self.bit_pos += width_usize;
        Ok(result)
    }

    pub fn align_byte(&mut self) {
        let remainder = self.bit_pos % 8;
        if remainder != 0 {
            self.bit_pos += 8 - remainder;
        }
    }
}
