// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::bit_reader::BitReader;
use crate::huffman::canonical_codes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    InvalidTree,
    Allocation,
    UnexpectedEof,
    InvalidCode,
}

#[derive(Debug)]
pub struct HuffmanDecoder {
    max_bits: u8,
    counts: [u16; 16],
    first_codes: [u16; 16],
    start_offsets: [u16; 16],
    symbols: [u16; 288],
}

impl HuffmanDecoder {
    pub fn new(lengths: &[u8], max_bits: u8) -> Result<Self, DecodeError> {
        if max_bits < 1 || max_bits > 15 {
            return Err(DecodeError::InvalidTree);
        }
        if lengths.len() > 288 {
            return Err(DecodeError::InvalidTree);
        }

        let canonical_result = canonical_codes(lengths, max_bits);
        let codes = match canonical_result {
            Ok(c) => c,
            Err(e) => {
                if matches!(e, crate::huffman::HuffmanError::Allocation) {
                    return Err(DecodeError::Allocation);
                }
                return Err(DecodeError::InvalidTree);
            }
        };

        let mut counts = [0u16; 16];
        let mut first_codes = [0u16; 16];
        let mut start_offsets = [0u16; 16];
        let mut symbols = [0u16; 288];
        let mut symbol_idx = 0u16;

        for depth in 1..=max_bits {
            let d = depth as usize;
            let start = symbol_idx;
            for i in 0..lengths.len() {
                if lengths[i] == depth {
                    if counts[d] == 0 {
                        first_codes[d] = codes[i].unwrap();
                        start_offsets[d] = start;
                    }
                    symbols[symbol_idx as usize] = i as u16;
                    counts[d] += 1;
                    symbol_idx += 1;
                }
            }
        }

        Ok(HuffmanDecoder {
            max_bits,
            counts,
            first_codes,
            start_offsets,
            symbols,
        })
    }

    pub fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, DecodeError> {
        let mut acc = 0u32;
        let mut bits_read = 0u8;
        let mut cloned_reader = reader.clone();

        loop {
            if bits_read >= self.max_bits {
                return Err(DecodeError::InvalidCode);
            }

            let bit = match cloned_reader.read_bits(1) {
                Ok(b) => b,
                Err(_) => return Err(DecodeError::UnexpectedEof),
            };

            acc = (acc << 1) | bit;
            bits_read += 1;

            let depth = bits_read as usize;
            if self.counts[depth] > 0 {
                let code = acc as u16;
                if code >= self.first_codes[depth] {
                    let offset = code - self.first_codes[depth];
                    if offset < self.counts[depth] {
                        let sym_idx = self.start_offsets[depth] + offset;
                        *reader = cloned_reader;
                        return Ok(self.symbols[sym_idx as usize]);
                    }
                }
            }
        }
    }
}
