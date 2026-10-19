// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    UnexpectedEof,
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ReadError> {
        if count > self.remaining() {
            return Err(ReadError::UnexpectedEof);
        }
        let start = self.pos;
        let end = start + count;
        // Check for overflow in addition
        if end < start {
            return Err(ReadError::UnexpectedEof);
        }
        let slice = &self.bytes[start..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn skip(&mut self, count: usize) -> Result<(), ReadError> {
        if count > self.remaining() {
            return Err(ReadError::UnexpectedEof);
        }
        let new_pos = self.pos.checked_add(count).ok_or(ReadError::UnexpectedEof)?;
        if new_pos < self.pos {
            return Err(ReadError::UnexpectedEof);
        }
        self.pos = new_pos;
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8, ReadError> {
        let b = self.read_bytes(1)?;
        Ok(b[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16, ReadError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, ReadError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64_le(&mut self) -> Result<u64, ReadError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}