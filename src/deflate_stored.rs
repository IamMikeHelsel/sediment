// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::bit_reader::{BitReader, BitError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredError {
    UnexpectedEof,
    InvalidLength,
    LimitExceeded,
    Allocation,
}

impl From<BitError> for StoredError {
    fn from(_: BitError) -> Self {
        StoredError::UnexpectedEof
    }
}

pub fn read_stored_block(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), StoredError> {
    let mut cursor = reader.clone();
    cursor.align_byte();

    let len = cursor.read_bits(16)?;
    let nlen = cursor.read_bits(16)?;

    if (len as u16) ^ (nlen as u16) != 0xFFFF {
        return Err(StoredError::InvalidLength);
    }

    let len = len as usize;
    if len > 65535 {
        return Err(StoredError::InvalidLength);
    }

    if cursor.remaining() < len * 8 {
        return Err(StoredError::UnexpectedEof);
    }

    let final_len = output.len().checked_add(len).ok_or(StoredError::LimitExceeded)?;
    if final_len > max_output {
        return Err(StoredError::LimitExceeded);
    }

    output.try_reserve(len).map_err(|_| StoredError::Allocation)?;

    for _ in 0..len {
        let byte = cursor.read_bits(8)?;
        output.push(byte as u8);
    }

    *reader = cursor;
    Ok(())
}