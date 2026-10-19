// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWriteError {
    TooLarge,
    InvalidWidth,
    ValueOutOfRange,
    LimitExceeded,
}

#[derive(Debug)]
pub struct BitWriter<'a> {
    output: &'a mut [u8],
    max_bits: usize,
    position: usize,
}

impl<'a> BitWriter<'a> {
    pub fn new(output: &'a mut [u8], max_bits: usize) -> Result<Self, BitWriteError> {
        let capacity = output.len().checked_mul(8).ok_or(BitWriteError::TooLarge)?;
        if max_bits > capacity {
            return Err(BitWriteError::LimitExceeded);
        }
        Ok(BitWriter {
            output,
            max_bits,
            position: 0,
        })
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.max_bits - self.position
    }

    pub fn written(&self) -> &[u8] {
        let byte_pos = self.position / 8;
        let remainder = self.position % 8;
        if remainder > 0 {
            return &self.output[..byte_pos + 1];
        }
        &self.output[..byte_pos]
    }

    pub fn write_bits(&mut self, value: u32, width: u8) -> Result<(), BitWriteError> {
        if width > 32 {
            return Err(BitWriteError::InvalidWidth);
        }
        if width == 0 {
            if value != 0 {
                return Err(BitWriteError::ValueOutOfRange);
            }
            return Ok(());
        }
        if width < 32 && value >= (1u32 << width) {
            return Err(BitWriteError::ValueOutOfRange);
        }
        let width_usize = width as usize;
        if self.remaining().checked_sub(width_usize).is_none() {
            return Err(BitWriteError::LimitExceeded);
        }

        let mut current_pos = self.position;
        let mut val = value;
        let mut bits_left = width_usize;

        while bits_left > 0 {
            let byte_idx = current_pos / 8;
            let bit_idx = current_pos % 8;
            let bits_in_byte = 8 - bit_idx;
            let bits_to_write = bits_left.min(bits_in_byte);

            let mask = (1u32 << bits_to_write) - 1;
            let bits = (val & mask) as u8;

            if byte_idx < self.output.len() {
                if bit_idx == 0 {
                    self.output[byte_idx] = bits;
                } else {
                    self.output[byte_idx] |= bits << bit_idx;
                }
            }

            val >>= bits_to_write;
            bits_left -= bits_to_write;
            current_pos += bits_to_write;
        }

        self.position = current_pos;
        Ok(())
    }

    pub fn align_byte(&mut self) -> Result<(), BitWriteError> {
        let remainder = self.position % 8;
        if remainder == 0 {
            return Ok(());
        }
        let padding = 8 - remainder;
        if self.remaining().checked_sub(padding).is_none() {
            return Err(BitWriteError::LimitExceeded);
        }
        self.write_bits(0, padding as u8)?;
        Ok(())
    }
}