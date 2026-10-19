// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::zip::{parse_eocd, ZipError};
use crate::zip_central::parse_central;
use crate::zip_local::parse_local;
use crate::zip_ranges::validate_ranges;

#[derive(Debug, Clone, Copy)]
pub struct ZipLimits {
    pub max_entries: usize,
    pub max_total_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub crc32: u32,
    pub size: usize,
    pub data_offset: usize,
}

pub fn parse_stored_entries<'a>(
    bytes: &'a [u8],
    limits: ZipLimits,
) -> Result<Vec<StoredEntry<'a>>, ZipError> {
    let eocd = parse_eocd(bytes)?;
    let count = eocd.entries as usize;

    if count > limits.max_entries {
        return Err(ZipError::LimitExceeded);
    }

    if count == 0 {
        if eocd.offset != 0 || eocd.size != 0 {
            return Err(ZipError::Invalid);
        }
        return Ok(Vec::new());
    }

    let dir_end = eocd.offset.checked_add(eocd.size).ok_or(ZipError::Truncated)?;
    let dir_slice = bytes
        .get(eocd.offset..dir_end)
        .ok_or(ZipError::Truncated)?;

    let local_end = eocd.offset;
    let local_region = &bytes[0..local_end];

    let mut entries: Vec<StoredEntry<'a>> = Vec::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    entries.try_reserve(count).map_err(|_| ZipError::LimitExceeded)?;
    ranges.try_reserve(count).map_err(|_| ZipError::LimitExceeded)?;

    let mut cursor = 0;
    let mut total_size: usize = 0;

    for _ in 0..count {
        let central = parse_central(dir_slice, cursor)?;
        cursor = central.next_offset;

        let local = parse_local(local_region, central.local_offset)?;

        if central.version != local.version
            || central.flags != local.flags
            || central.method != local.method
            || central.crc32 != local.crc32
            || central.compressed_size != local.compressed_size
            || central.size != local.size
            || central.name != local.name
        {
            return Err(ZipError::Invalid);
        }

        let size_usize = usize::try_from(local.size).map_err(|_| ZipError::Invalid)?;


        total_size = total_size.checked_add(size_usize).ok_or(ZipError::LimitExceeded)?;
        if total_size > limits.max_total_size {
            return Err(ZipError::LimitExceeded);
        }

        entries.push(StoredEntry {
            name: central.name,
            crc32: central.crc32,
            size: size_usize,
            data_offset: local.data_offset,
        });

        ranges.push((central.local_offset, local.end));
    }

    if cursor != dir_slice.len() {
        return Err(ZipError::Invalid);
    }

    validate_ranges(&ranges, local_end, limits.max_entries)?;

    Ok(entries)
}