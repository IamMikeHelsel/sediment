// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VliError {
    UnexpectedEof,
    NonCanonical,
    Overflow,
}

pub fn decode_vli(bytes: &[u8]) -> Result<(u64, usize), VliError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i: usize = 0;

    loop {
        if i >= bytes.len() {
            return Err(VliError::UnexpectedEof);
        }

        let byte = bytes[i];
        let digit = (byte & 0x7F) as u64;

        if shift == 63 {
            if digit != 0 {
                return Err(VliError::Overflow);
            }
            if i == 0 {
                return Ok((0, 1));
            }
            return Err(VliError::NonCanonical);
        }

        value |= digit << shift;

        if byte & 0x80 == 0 {
            if i > 0 && digit == 0 {
                return Err(VliError::NonCanonical);
            }
            return Ok((value, i + 1));
        }

        shift += 7;
        i += 1;

        if i == 9 {
            return Err(VliError::Overflow);
        }
    }
}