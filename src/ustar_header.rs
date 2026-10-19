// SPDX-License-Identifier: MIT OR Apache-2.0

use std::result::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarError {
    UnexpectedEof,
    InvalidHeader,
    ChecksumMismatch,
    Unsupported,
    LimitExceeded,
    Allocation,
    TrailingData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarHeader<'a> {
    pub name: &'a [u8],
    pub prefix: &'a [u8],
    pub size: u64,
    pub kind: TarKind,
}

fn parse_octal(s: &[u8]) -> Result<u64, TarError> {
    let mut trimmed = s;
    // Trim leading spaces/NULs
    while let Some(&b) = trimmed.first() {
        if b == b' ' || b == 0 {
            trimmed = &trimmed[1..];
        } else {
            break;
        }
    }
    // Trim trailing spaces/NULs
    while let Some(&b) = trimmed.last() {
        if b == b' ' || b == 0 {
            trimmed = &trimmed[..trimmed.len() - 1];
        } else {
            break;
        }
    }

    if trimmed.is_empty() {
        return Ok(0);
    }

    // Check for high bit (base256) -> Unsupported
    // Must check original first byte before trimming
    if s.first().map_or(false, |&b| b & 0x80 != 0) {
        return Err(TarError::Unsupported);
    }

    let mut val: u64 = 0;
    for &b in trimmed {
        if b < b'0' || b > b'7' {
            return Err(TarError::InvalidHeader);
        }
        val = val.checked_mul(8).ok_or(TarError::LimitExceeded)?;
        val += (b - b'0') as u64;
    }
    Ok(val)
}

pub fn parse_header(block: &[u8]) -> Result<Option<TarHeader<'_>>, TarError> {
    if block.len() < 512 {
        return Err(TarError::UnexpectedEof);
    }
    if block.len() > 512 {
        return Err(TarError::InvalidHeader);
    }

    // Check if all zeros
    if block.iter().all(|&b| b == 0) {
        return Ok(None);
    }

    // Validate Checksum
    let mut sum: u64 = 256;
    for (i, &byte) in block.iter().enumerate() {
        if i >= 148 && i < 156 {
            continue;
        }
        sum += byte as u64;
    }

    let chksum_bytes = &block[148..156];
    let parsed_chksum = parse_octal(chksum_bytes)?;
    if sum != parsed_chksum {
        return Err(TarError::ChecksumMismatch);
    }

    // Validate Magic and Version
    let magic = &block[257..263];
    if magic != b"ustar\0" {
        return Err(TarError::Unsupported);
    }
    let version = &block[263..265];
    if version != b"00" {
        return Err(TarError::Unsupported);
    }

    // Validate Type
    let type_byte = block[156];
    let kind = if type_byte == b'0' || type_byte == 0 {
        TarKind::File
    } else if type_byte == b'5' {
        TarKind::Directory
    } else {
        return Err(TarError::Unsupported);
    };

    // Validate Linkname (157..257)
    let linkname = &block[157..257];
    if linkname.iter().any(|&b| b != 0) {
        return Err(TarError::InvalidHeader);
    }

    // Validate Tail (500..512)
    let tail = &block[500..512];
    if tail.iter().any(|&b| b != 0) {
        return Err(TarError::InvalidHeader);
    }

    // Parse Name (0..100)
    let name_raw = &block[0..100];
    let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(100);
    if name_end > 100 {
        return Err(TarError::InvalidHeader);
    }
    let name = &name_raw[..name_end];
    if name.is_empty() {
        return Err(TarError::InvalidHeader);
    }
    // Check remaining name bytes are zero
    if name_end < 100 && name_raw[name_end + 1..].iter().any(|&b| b != 0) {
        return Err(TarError::InvalidHeader);
    }

    // Parse Prefix (345..500)
    let prefix_raw = &block[345..500];
    let prefix_end = prefix_raw.iter().position(|&b| b == 0).unwrap_or(155);
    if prefix_end > 155 {
        return Err(TarError::InvalidHeader);
    }
    let prefix = &prefix_raw[..prefix_end];
    // Check remaining prefix bytes are zero
    if prefix_end < 155 && prefix_raw[prefix_end + 1..].iter().any(|&b| b != 0) {
        return Err(TarError::InvalidHeader);
    }

    // Parse Size (124..136)
    let size = parse_octal(&block[124..136])?;

    // Validate Directory Size
    if kind == TarKind::Directory && size != 0 {
        return Err(TarError::InvalidHeader);
    }

    // Parse other numeric fields to ensure validity (even if not returned)
    let _mode = parse_octal(&block[100..108])?;
    let _uid = parse_octal(&block[108..116])?;
    let _gid = parse_octal(&block[116..124])?;
    let _mtime = parse_octal(&block[136..148])?;
    let _devmajor = parse_octal(&block[329..337])?;
    let _devminor = parse_octal(&block[337..345])?;

    // Validate Uname (265..297) and Gname (297..329) padding
    let uname_raw = &block[265..297];
    if uname_raw.iter().any(|&b| b != 0) {
        let _ = uname_raw.iter().position(|&b| b == 0).map(|p| &uname_raw[..p]);
        // Just check if it has valid padding structure (simplified: ensure no garbage after NUL)
        if let Some(p) = uname_raw.iter().position(|&b| b == 0) {
            if uname_raw[p+1..].iter().any(|&b| b != 0) {
                return Err(TarError::InvalidHeader);
            }
        }
    }
    let gname_raw = &block[297..329];
    if gname_raw.iter().any(|&b| b != 0) {
        if let Some(p) = gname_raw.iter().position(|&b| b == 0) {
            if gname_raw[p+1..].iter().any(|&b| b != 0) {
                return Err(TarError::InvalidHeader);
            }
        }
    }

    Ok(Some(TarHeader {
        name,
        prefix,
        size,
        kind,
    }))
}