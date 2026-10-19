// SPDX-License-Identifier: MIT OR Apache-2.0

/// Errors that can occur when encoding a ustar header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarWriteError {
    /// The name or prefix field is invalid (wrong length or contains NUL).
    InvalidName,
    /// The size is invalid (directory with non-zero size, or file too large).
    InvalidSize,
    /// The size exceeds the maximum supported value for ustar format.
    Unsupported,
}

/// The kind of entry being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarWriteKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// A ustar header structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarWriteHeader<'a> {
    /// The file name.
    pub name: &'a [u8],
    /// The file name prefix.
    pub prefix: &'a [u8],
    /// The file size.
    pub size: u64,
    /// The kind of entry.
    pub kind: TarWriteKind,
}

/// Encodes a ustar header into a 512-byte buffer.
///
/// Returns the buffer on success, or an error if the input is invalid.
pub fn encode_header(header: &TarWriteHeader<'_>) -> Result<[u8; 512], TarWriteError> {
    // Validate name
    if header.name.is_empty() || header.name.len() > 100 || header.name.contains(&0) {
        return Err(TarWriteError::InvalidName);
    }
    // Validate prefix
    if header.prefix.len() > 155 || header.prefix.contains(&0) {
        return Err(TarWriteError::InvalidName);
    }
    // Validate size
    if header.kind == TarWriteKind::Directory && header.size != 0 {
        return Err(TarWriteError::InvalidSize);
    }
    const MAX_SIZE: u64 = 8589934591; // 2^33 - 1
    if header.size > MAX_SIZE {
        return Err(TarWriteError::Unsupported);
    }

    let mut buf = [0u8; 512];

    // Name: 0..100
    let name_len = header.name.len();
    buf[0..name_len].copy_from_slice(header.name);

    // Prefix: 345..500
    let prefix_len = header.prefix.len();
    buf[345..345 + prefix_len].copy_from_slice(header.prefix);

    // Mode: 100..108
    let mode_bytes = if header.kind == TarWriteKind::File {
        b"0000644\0"
    } else {
        b"0000755\0"
    };
    buf[100..108].copy_from_slice(mode_bytes);

    // UID: 108..116
    buf[108..116].copy_from_slice(b"0000000\0");

    // GID: 116..124
    buf[116..124].copy_from_slice(b"0000000\0");

    // Size: 124..136
    let size_str = format_octal(header.size);
    buf[124..135].copy_from_slice(&size_str);
    buf[135] = 0;

    // Mtime: 136..148
    buf[136..148].copy_from_slice(b"00000000000\0");

    // Checksum placeholder: 148..156 (treated as spaces later)
    // Type: 156
    buf[156] = if header.kind == TarWriteKind::File { b'0' } else { b'5' };

    // Linkname: 157..257 (already zero)
    // Magic: 257..263
    buf[257..263].copy_from_slice(b"ustar\0");

    // Version: 263..265
    buf[263..265].copy_from_slice(b"00");

    // Uname: 265..297 (already zero)
    // Gname: 297..329 (already zero)
    // Devmajor: 329..337 (already zero)
    // Devminor: 337..345 (already zero)

    // Tail: 500..512 (already zero)

    // Calculate checksum
    let mut sum: u32 = 0;
    for i in 0..512 {
        sum += buf[i] as u32;
    }
    // The checksum field (148..156) is currently zero. We need to treat it as spaces for calculation.
    // But we already calculated sum with zeros. So we add the difference.
    // Space is 32, zero is 0. Difference is 32 per byte. 8 bytes.
    sum += 32 * 8;

    let checksum_str = format_octal_6(sum);
    buf[148..154].copy_from_slice(&checksum_str);
    buf[154] = 0;
    buf[155] = 32; // Space after checksum

    Ok(buf)
}

fn format_octal(val: u64) -> [u8; 11] {
    let mut buf = [b'0'; 11];
    let mut v = val;
    for i in (0..=10).rev() {
        buf[i] = b'0' + (v & 7) as u8;
        v >>= 3;
    }
    buf
}

fn format_octal_6(val: u32) -> [u8; 6] {
    let mut buf = [b'0'; 6];
    let mut v = val;
    for i in (0..=5).rev() {
        buf[i] = b'0' + (v & 7) as u8;
        v >>= 3;
    }
    buf
}