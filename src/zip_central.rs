// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::reader::Reader;
use crate::zip::ZipError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralRecord<'a> {
    pub version: u16,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub size: u32,
    pub name: &'a [u8],
    pub local_offset: usize,
    pub next_offset: usize,
}

pub fn parse_central<'a>(directory: &'a [u8], offset: usize) -> Result<CentralRecord<'a>, ZipError> {
    parse_central_impl(directory, offset, false)
}

pub fn parse_central_supported<'a>(directory: &'a [u8], offset: usize) -> Result<CentralRecord<'a>, ZipError> {
    parse_central_impl(directory, offset, true)
}

fn parse_central_impl<'a>(directory: &'a [u8], offset: usize, allow_deflate: bool) -> Result<CentralRecord<'a>, ZipError> {
    let mut r = Reader::new(directory);
    r.skip(offset)?;

    let sig = r.read_u32_le()?;
    if sig != 0x02014b50 {
        return Err(ZipError::Invalid);
    }

    let version_made_by = r.read_u16_le()?;
    let _ = version_made_by;
    let version_needed = r.read_u16_le()?;
    let flags = r.read_u16_le()?;
    let method = r.read_u16_le()?;
    let _ = r.read_u16_le()?; // time
    let _ = r.read_u16_le()?; // date

    let crc32 = r.read_u32_le()?;
    let compressed_size = r.read_u32_le()?;
    let size = r.read_u32_le()?;
    let name_len = r.read_u16_le()?;
    let extra_len = r.read_u16_le()?;
    let comment_len = r.read_u16_le()?;
    let disk = r.read_u16_le()?;
    let _ = r.read_u16_le()?; // internal attributes
    let _ = r.read_u32_le()?; // external attributes

    let local_offset = usize::try_from(r.read_u32_le()?).map_err(|_| ZipError::Invalid)?;

    if version_needed != 10 && version_needed != 20 {
        return Err(ZipError::Unsupported);
    }
    if compressed_size == 0xFFFFFFFF || size == 0xFFFFFFFF || local_offset == 0xFFFFFFFF {
        return Err(ZipError::Unsupported);
    }
    if method == 8 {
        if !allow_deflate {
            return Err(ZipError::Unsupported);
        }
        if version_needed != 20 {
            return Err(ZipError::Unsupported);
        }
        if flags & !0x0806 != 0 {
            return Err(ZipError::Unsupported);
        }
    } else if method == 0 {
        if version_needed != 10 && version_needed != 20 {
            return Err(ZipError::Unsupported);
        }
        if flags & !0x0800 != 0 {
            return Err(ZipError::Unsupported);
        }
        if compressed_size != size {
            return Err(ZipError::Invalid);
        }
    } else {
        return Err(ZipError::Unsupported);
    }
    if disk != 0 {
        return Err(ZipError::Unsupported);
    }

    let name = r.read_bytes(name_len as usize)?;
    if name.is_empty() {
        return Err(ZipError::Invalid);
    }

    let extra_data = r.read_bytes(extra_len as usize)?;


    let mut extra_r = Reader::new(extra_data);
    let mut extra_consumed = 0;
    while extra_consumed < extra_len as usize {
        if extra_r.remaining() < 4 {
            return Err(ZipError::Truncated);
        }
        let id = extra_r.read_u16_le()?;
        let length = extra_r.read_u16_le()?;
        if id == 1 {
            return Err(ZipError::Unsupported);
        }
        let payload = extra_r.read_bytes(length as usize)?;
        let _ = payload;
        extra_consumed += 4 + length as usize;
    }
    if extra_consumed != extra_len as usize {
        return Err(ZipError::Invalid);
    }

    r.skip(comment_len as usize)?;

    let next_offset = r.position();

    Ok(CentralRecord {
        version: version_needed,
        flags,
        method,
        crc32,
        compressed_size,
        size,
        name,
        local_offset,
        next_offset,
    })
}