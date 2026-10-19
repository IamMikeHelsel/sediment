// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanError {
    InvalidMaxBits,
    TooManySymbols,
    InvalidLength,
    Empty,
    Oversubscribed,
    Allocation,
}

pub fn canonical_codes(lengths: &[u8], max_bits: u8) -> Result<Vec<Option<u16>>, HuffmanError> {
    if !(1..=15).contains(&max_bits) {
        return Err(HuffmanError::InvalidMaxBits);
    }
    if lengths.len() > 288 {
        return Err(HuffmanError::TooManySymbols);
    }

    let mut counts = [0u32; 16];
    let mut has_symbol = false;

    for (i, &len) in lengths.iter().enumerate() {
        if len > max_bits {
            return Err(HuffmanError::InvalidLength);
        }
        if len > 0 {
            counts[len as usize] += 1;
            has_symbol = true;
        }
    }

    if !has_symbol {
        return Err(HuffmanError::Empty);
    }

    let mut codes = [0u16; 288];
    let mut code = 0u32;

    for bits in 1..=max_bits {
        let n = counts[bits as usize];
        if n > 0 {
            if code + n > (1u32 << bits) {
                return Err(HuffmanError::Oversubscribed);
            }
            for (i, &len) in lengths.iter().enumerate() {
                if len == bits {
                    codes[i] = code as u16;
                    code += 1;
                }
            }
        }
        code <<= 1;
    }

    let mut result = Vec::new();
    result.try_reserve(lengths.len()).map_err(|_| HuffmanError::Allocation)?;
    result.resize(lengths.len(), None);
    for (i, &len) in lengths.iter().enumerate() {
        if len > 0 {
            result[i] = Some(codes[i]);
        }
    }

    Ok(result)
}