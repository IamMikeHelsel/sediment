// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::reader::{Reader, ReadError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipError {
    Truncated,
    Invalid,
    Unsupported,
    LimitExceeded,
    CrcMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryInfo {
    pub entries: u16,
    pub offset: usize,
    pub size: usize,
    pub eocd_offset: usize,
}

impl From<ReadError> for ZipError {
    fn from(_: ReadError) -> Self {
        ZipError::Truncated
    }
}

pub fn parse_eocd(bytes: &[u8]) -> Result<DirectoryInfo, ZipError> {
    let len = bytes.len();
    if len < 22 {
        return Err(ZipError::Invalid);
    }

    let min_pos = len.saturating_sub(65557).min(len.saturating_sub(22));

    for position in (min_pos..len.saturating_sub(21)).rev() {

        let mut reader = Reader::new(&bytes[position..]);

        let signature = reader.read_u32_le()?;
        if signature != 0x06054b50 {
            continue;
        }

        let disk = reader.read_u16_le()?;
        let central_disk = reader.read_u16_le()?;
        let entries_disk = reader.read_u16_le()?;
        let entries_total = reader.read_u16_le()?;
        let central_size = reader.read_u32_le()? as u64;
        let central_offset = reader.read_u32_le()? as u64;
        let comment_length = reader.read_u16_le()? as usize;

        if position.checked_add(22).and_then(|p| p.checked_add(comment_length)).filter(|&end| end == len).is_none() {
            continue;
        }

        if central_offset.checked_add(central_size).filter(|&end| end == position as u64).is_none() {
            continue;
        }

        if disk != 0
            || central_disk != 0
            || entries_disk != entries_total
            || entries_total == 0xffff
            || central_size == 0xffffffff
            || central_offset == 0xffffffff
        {
            return Err(ZipError::Unsupported);
        }

        return Ok(DirectoryInfo {
            entries: entries_total,
            offset: central_offset as usize,
            size: central_size as usize,
            eocd_offset: position,
        });
    }

    Err(ZipError::Invalid)
}