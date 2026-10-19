// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::zip::{parse_eocd, ZipError};
use crate::zip_central::{parse_central, parse_central_supported};
use crate::zip_local::{parse_local, parse_local_supported};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry<'a> {
    pub name: &'a [u8],
    pub crc32: u32,
    pub size: usize,
    pub compressed_size: usize,
    pub data_offset: usize,
    pub method: u16,
}

pub fn parse_stored_entries<'a>(
    bytes: &'a [u8],
    limits: ZipLimits,
) -> Result<Vec<StoredEntry<'a>>, ZipError> {
    let entries = parse_entries_impl(bytes, limits, false)?;
    let mut result = Vec::new();
    result.try_reserve(entries.len()).map_err(|_| ZipError::LimitExceeded)?;
    for e in entries {
        result.push(StoredEntry {
            name: e.name,
            crc32: e.crc32,
            size: e.size,
            data_offset: e.data_offset,
        });
    }
    Ok(result)
}

pub fn parse_entries<'a>(
    bytes: &'a [u8],
    limits: ZipLimits,
) -> Result<Vec<ZipEntry<'a>>, ZipError> {
    parse_entries_impl(bytes, limits, true)
}

fn parse_entries_impl<'a>(
    bytes: &'a [u8],
    limits: ZipLimits,
    allow_deflate: bool,
) -> Result<Vec<ZipEntry<'a>>, ZipError> {
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

    let mut entries: Vec<ZipEntry<'a>> = Vec::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    entries.try_reserve(count).map_err(|_| ZipError::LimitExceeded)?;
    ranges.try_reserve(count).map_err(|_| ZipError::LimitExceeded)?;

    let mut cursor = 0;
    let mut total_size: usize = 0;

    for _ in 0..count {
        let central = if allow_deflate {
            parse_central_supported(dir_slice, cursor)?
        } else {
            parse_central(dir_slice, cursor)?
        };
        cursor = central.next_offset;

        let local = if allow_deflate {
            parse_local_supported(local_region, central.local_offset)?
        } else {
            parse_local(local_region, central.local_offset)?
        };

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

        if !allow_deflate && central.method == 8 {
            return Err(ZipError::Invalid);
        }

        let size_usize = usize::try_from(local.size).map_err(|_| ZipError::Invalid)?;
        let compressed_size_usize =
            usize::try_from(local.compressed_size).map_err(|_| ZipError::Invalid)?;

        total_size = total_size.checked_add(size_usize).ok_or(ZipError::LimitExceeded)?;
        if total_size > limits.max_total_size {
            return Err(ZipError::LimitExceeded);
        }

        entries.push(ZipEntry {
            name: central.name,
            crc32: central.crc32,
            size: size_usize,
            compressed_size: compressed_size_usize,
            data_offset: local.data_offset,
            method: central.method,
        });

        ranges.push((central.local_offset, local.end));
    }

    if cursor != dir_slice.len() {
        return Err(ZipError::Invalid);
    }

    validate_ranges(&ranges, local_end, limits.max_entries)?;

    Ok(entries)
}