// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::zip::ZipError;
use crate::zip_index::StoredEntry;
use crate::crc32::crc32;

pub fn stored_data<'a>(
    bytes: &'a [u8],
    entry: &StoredEntry<'_>,
) -> Result<&'a [u8], ZipError> {
    let end = entry.data_offset.checked_add(entry.size).ok_or(ZipError::Truncated)?;
    if end > bytes.len() {
        return Err(ZipError::Truncated);
    }
    let payload = &bytes[entry.data_offset..end];
    if entry.crc32 != crc32(payload) {
        return Err(ZipError::CrcMismatch);
    }
    Ok(payload)
}