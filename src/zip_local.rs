// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::reader::Reader;
use crate::zip::ZipError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord<'a> {
    pub version: u16,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub size: u32,
    pub name: &'a [u8],
    pub data_offset: usize,
    pub end: usize,
}

const HEADER_SIZE: usize = 30;
const SIGNATURE: u32 = 0x04034b50;

pub fn parse_local<'a>(region: &'a [u8], offset: usize) -> Result<LocalRecord<'a>, ZipError> {
    parse_local_impl(region, offset, false)
}

fn parse_local_impl<'a>(region: &'a [u8], offset: usize, allow_deflate: bool) -> Result<LocalRecord<'a>, ZipError> {
    if offset > region.len() {
        return Err(ZipError::Truncated);
    }
    let mut r = Reader::new(&region[offset..]);

    let sig = r.read_u32_le()?;
    if sig != SIGNATURE {
        return Err(ZipError::Invalid);
    }

    let version = r.read_u16_le()?;
    let flags = r.read_u16_le()?;
    let method = r.read_u16_le()?;

    if !is_supported_version_method_flags(version, flags, method, allow_deflate) {
        return Err(ZipError::Unsupported);
    }

    // Skip time (2) and date (2)
    r.skip(4)?;

    let crc32 = r.read_u32_le()?;
    let compressed_size = r.read_u32_le()?;
    let uncompressed_size = r.read_u32_le()?;

    if compressed_size == 0xFFFFFFFF || uncompressed_size == 0xFFFFFFFF {
        return Err(ZipError::Unsupported);
    }

    if method == 0 && compressed_size != uncompressed_size {
        return Err(ZipError::Invalid);
    }

    let name_len = r.read_u16_le()? as usize;
    if name_len == 0 {
        return Err(ZipError::Invalid);
    }

    let extra_len = r.read_u16_le()? as usize;

    let name = r.read_bytes(name_len)?;
    let extra = r.read_bytes(extra_len)?;

    validate_extra(extra)?;

    let data_offset = r.position().checked_add(offset).ok_or(ZipError::Truncated)?;
    let payload_end = data_offset.checked_add(usize::try_from(compressed_size).map_err(|_| ZipError::LimitExceeded)?).ok_or(ZipError::LimitExceeded)?;
    if payload_end > region.len() {
        return Err(ZipError::LimitExceeded);
    }

    Ok(LocalRecord {
        version,
        flags,
        method,
        crc32,
        compressed_size,
        size: uncompressed_size,
        name,
        data_offset,
        end: payload_end,
    })
}

pub fn parse_local_supported<'a>(region: &'a [u8], offset: usize) -> Result<LocalRecord<'a>, ZipError> {
    parse_local_impl(region, offset, true)
}

fn is_supported_version_method_flags(version: u16, flags: u16, method: u16, allow_deflate: bool) -> bool {
    if method == 0 {
        if version != 10 && version != 20 {
            return false;
        }
        if flags & !0x0800 != 0 {
            return false;
        }
        return true;
    }
    if method == 8 && allow_deflate {
        if version != 20 {
            return false;
        }
        if flags & !0x0806 != 0 {
            return false;
        }
        return true;
    }
    false
}

fn validate_extra(data: &[u8]) -> Result<(), ZipError> {
    let mut r = Reader::new(data);
    while r.remaining() > 0 {
        if r.remaining() < 4 {
            return Err(ZipError::Truncated);
        }
        let id = r.read_u16_le()?;
        let length = r.read_u16_le()? as usize;
        if r.remaining() < length {
            return Err(ZipError::Truncated);
        }
        if id == 1 {
            return Err(ZipError::Unsupported);
        }
        r.skip(length)?;
    }
    Ok(())
}