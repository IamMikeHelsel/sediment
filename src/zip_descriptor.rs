// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZIP data descriptors (general purpose flag bit 3).
//!
//! Spec source: PKWARE APPNOTE.TXT 6.3.x section 4.3.9. The descriptor
//! follows the compressed data and holds CRC-32, compressed size and
//! uncompressed size. The optional signature 0x08074b50 is "commonly
//! adopted" but not required. Sizes are 8 bytes each when the local header
//! carries a ZIP64 extra field (4.3.9.2), else 4 bytes.
//!
//! Because a CRC value may equal the signature value, an unsigned
//! descriptor can look signed. [`match_descriptor`] resolves that by checking
//! each candidate layout against the values recorded in the central
//! directory.

pub const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    /// The descriptor runs past the end of the input.
    Truncated,
    /// No layout matches the expected values.
    Mismatch,
    /// The descriptor bytes are structurally wrong.
    Invalid,
}

/// Physical layout of a data descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorLayout {
    pub signature: bool,
    pub zip64: bool,
}

impl DescriptorLayout {
    /// Length in bytes of a descriptor in this layout.
    pub fn len(&self) -> usize {
        let sizes = if self.zip64 { 16 } else { 8 };
        (if self.signature { 4 } else { 0 }) + 4 + sizes
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

/// A decoded data descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDescriptor {
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub layout: DescriptorLayout,
    /// Offset of the first byte after the descriptor.
    pub end: usize,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Decode a descriptor at `offset` in the given `layout`. When the layout
/// says the signature is present it must be present.
pub fn parse_descriptor(bytes: &[u8], offset: usize, layout: DescriptorLayout) -> Result<DataDescriptor, DescriptorError> {
    let end = offset.checked_add(layout.len()).ok_or(DescriptorError::Truncated)?;
    if end > bytes.len() {
        return Err(DescriptorError::Truncated);
    }
    let mut pos = offset;
    if layout.signature {
        if u32_at(bytes, pos) != Some(DESCRIPTOR_SIGNATURE) {
            return Err(DescriptorError::Invalid);
        }
        pos += 4;
    }
    let crc32 = u32_at(bytes, pos).ok_or(DescriptorError::Truncated)?;
    pos += 4;
    let (compressed_size, uncompressed_size) = if layout.zip64 {
        (u64_at(bytes, pos).ok_or(DescriptorError::Truncated)?, u64_at(bytes, pos + 8).ok_or(DescriptorError::Truncated)?)
    } else {
        (
            u32_at(bytes, pos).ok_or(DescriptorError::Truncated)? as u64,
            u32_at(bytes, pos + 4).ok_or(DescriptorError::Truncated)? as u64,
        )
    };
    Ok(DataDescriptor { crc32, compressed_size, uncompressed_size, layout, end })
}

/// Values a descriptor is expected to carry (from the central directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedDescriptor {
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Find the descriptor layout at `offset` whose values equal `expected`.
///
/// `zip64` selects 8-byte sizes (true when the local header has a ZIP64
/// extra). If `zip64` is `None` both widths are tried, wider first. Signed
/// layouts are tried before unsigned ones when the signature bytes are
/// present. Returns `Mismatch` if no layout agrees, `Truncated` if not even
/// the shortest candidate fits.
pub fn match_descriptor(
    bytes: &[u8],
    offset: usize,
    zip64: Option<bool>,
    expected: ExpectedDescriptor,
) -> Result<DataDescriptor, DescriptorError> {
    let widths: &[bool] = match zip64 {
        Some(true) => &[true],
        Some(false) => &[false],
        None => &[true, false],
    };
    let signed_first = u32_at(bytes, offset) == Some(DESCRIPTOR_SIGNATURE);
    let sigs: &[bool] = if signed_first { &[true, false] } else { &[false] };
    let mut any_fit = false;
    for &signature in sigs {
        for &wide in widths {
            let layout = DescriptorLayout { signature, zip64: wide };
            match parse_descriptor(bytes, offset, layout) {
                Ok(d) => {
                    any_fit = true;
                    if d.crc32 == expected.crc32
                        && d.compressed_size == expected.compressed_size
                        && d.uncompressed_size == expected.uncompressed_size
                    {
                        return Ok(d);
                    }
                }
                Err(DescriptorError::Truncated) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if any_fit { Err(DescriptorError::Mismatch) } else { Err(DescriptorError::Truncated) }
}
