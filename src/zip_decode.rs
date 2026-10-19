// SPDX-License-Identifier: MIT OR Apache-2.0
use std::borrow::Cow;

pub fn entry_data<'a>(
    bytes: &'a [u8],
    entry: &crate::zip_index::ZipEntry<'_>,
    max_output: usize,
    max_blocks: usize,
) -> Result<Cow<'a, [u8]>, crate::zip::ZipError> {
    if entry.size > max_output {
        return Err(crate::zip::ZipError::LimitExceeded);
    }

    match entry.method {
        0 => {
            if entry.compressed_size != entry.size {
                return Err(crate::zip::ZipError::Invalid);
            }
            let stored = crate::zip_index::StoredEntry {
                name: entry.name,
                crc32: entry.crc32,
                size: entry.size,
                data_offset: entry.data_offset,
            };
            crate::zip_payload::stored_data(bytes, &stored).map(Cow::Borrowed)
        }
        8 => {
            let end = entry.data_offset.checked_add(entry.compressed_size).ok_or(crate::zip::ZipError::LimitExceeded)?;
            let compressed_slice = bytes.get(entry.data_offset..end).ok_or(crate::zip::ZipError::Truncated)?;
            
            let decoded = crate::inflate::inflate_raw(compressed_slice, entry.size, max_blocks)
                .map_err(|e| match e {
                    crate::inflate::InflateError::LimitExceeded => crate::zip::ZipError::LimitExceeded,
                    crate::inflate::InflateError::Allocation => crate::zip::ZipError::LimitExceeded,
                    crate::inflate::InflateError::UnsupportedBlock => crate::zip::ZipError::Unsupported,
                    _ => crate::zip::ZipError::Invalid,
                })?;

            if decoded.len() != entry.size {
                return Err(crate::zip::ZipError::Invalid);
            }

            if crate::crc32::crc32(&decoded) != entry.crc32 {
                return Err(crate::zip::ZipError::CrcMismatch);
            }

            Ok(Cow::Owned(decoded))
        }
        _ => Err(crate::zip::ZipError::Unsupported),
    }
}