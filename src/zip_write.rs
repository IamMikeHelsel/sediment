// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::crc32::crc32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    InvalidName,
    Unsupported,
    LimitExceeded,
    Allocation,
}

#[derive(Debug, Clone, Copy)]
pub struct WriteEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct WriteLimits {
    pub max_entries: usize,
    pub max_total_size: u64,
    pub max_archive_bytes: usize,
}

const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_DIR_SIG: u32 = 0x02014b50;
const EOCD_SIG: u32 = 0x06054b50;

const VERSION_NEEDED: u16 = 20;
const VERSION_MADE: u16 = 20;
const DOS_HOST: u16 = 0;
const METHOD_STORED: u16 = 0;
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = 33;

const LOCAL_HEADER_SIZE: usize = 30;
const CENTRAL_DIR_ENTRY_SIZE: usize = 46;
const EOCD_SIZE: usize = 22;

pub fn write_stored(entries: &[WriteEntry<'_>], limits: WriteLimits) -> Result<Vec<u8>, WriteError> {
    if entries.len() >= 65535 {
        return Err(WriteError::Unsupported);
    }
    if entries.len() > limits.max_entries {
        return Err(WriteError::LimitExceeded);
    }

    let num_entries: u16 = entries.len() as u16;

    let mut total_data_size: u64 = 0;
    let mut local_records_size: usize = 0;
    let mut central_dir_size: usize = 0;
    let mut current_offset: usize = 0;
    let mut central_dir_offset: usize = 0;

    for entry in entries.iter() {
        if entry.name.is_empty() || entry.name.len() > 65535 {
            return Err(WriteError::InvalidName);
        }
        if entry.name.contains(&0) {
            return Err(WriteError::InvalidName);
        }

        let name_len = entry.name.len();
        let data_len = entry.data.len();

        if data_len >= u32::MAX as usize {
            return Err(WriteError::Unsupported);
        }

        total_data_size = total_data_size.checked_add(data_len as u64).ok_or(WriteError::LimitExceeded)?;

        let local_rec_size = LOCAL_HEADER_SIZE.checked_add(name_len).ok_or(WriteError::LimitExceeded)?
            .checked_add(data_len).ok_or(WriteError::LimitExceeded)?;
        let central_rec_size = CENTRAL_DIR_ENTRY_SIZE.checked_add(name_len).ok_or(WriteError::LimitExceeded)?;

        current_offset = current_offset.checked_add(local_rec_size).ok_or(WriteError::LimitExceeded)?;
        central_dir_offset = central_dir_offset.checked_add(central_rec_size).ok_or(WriteError::LimitExceeded)?;
        central_dir_size = central_dir_size.checked_add(central_rec_size).ok_or(WriteError::LimitExceeded)?;
        local_records_size = local_records_size.checked_add(local_rec_size).ok_or(WriteError::LimitExceeded)?;
    }

    if total_data_size > limits.max_total_size {
        return Err(WriteError::LimitExceeded);
    }

    let total_archive_size = local_records_size.checked_add(central_dir_size).ok_or(WriteError::LimitExceeded)?
        .checked_add(EOCD_SIZE).ok_or(WriteError::LimitExceeded)?;

    if total_archive_size > limits.max_archive_bytes {
        return Err(WriteError::LimitExceeded);
    }

    if total_archive_size >= u32::MAX as usize {
        return Err(WriteError::Unsupported);
    }

    let required_bytes = total_archive_size;
    let mut buf = Vec::new();
    buf.try_reserve_exact(required_bytes).map_err(|_| WriteError::Allocation)?;

    let mut write_offset: u32 = 0;

    for entry in entries.iter() {
        let name_len: u16 = entry.name.len() as u16;
        let data_len: u32 = entry.data.len() as u32;
        let crc = crc32(entry.data);

        buf.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        buf.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&METHOD_STORED.to_le_bytes());
        buf.extend_from_slice(&DOS_TIME.to_le_bytes());
        buf.extend_from_slice(&DOS_DATE.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(entry.name);
        buf.extend_from_slice(entry.data);

        write_offset += (LOCAL_HEADER_SIZE as u32) + name_len as u32 + data_len;
    }

    let central_dir_start_offset: u32 = write_offset;

    let mut current_offset_in_archive: u32 = 0;
    for entry in entries.iter() {
        let name_len: u16 = entry.name.len() as u16;
        let data_len: u32 = entry.data.len() as u32;
        let crc = crc32(entry.data);

        buf.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        buf.extend_from_slice(&VERSION_MADE.to_le_bytes());
        buf.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&METHOD_STORED.to_le_bytes());
        buf.extend_from_slice(&DOS_TIME.to_le_bytes());
        buf.extend_from_slice(&DOS_DATE.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&current_offset_in_archive.to_le_bytes());
        buf.extend_from_slice(entry.name);

        current_offset_in_archive += (LOCAL_HEADER_SIZE as u32) + name_len as u32 + data_len;
    }

    let central_dir_size_u32: u32 = central_dir_size as u32;
    let central_dir_start_offset_u32: u32 = central_dir_start_offset;

    buf.extend_from_slice(&EOCD_SIG.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&num_entries.to_le_bytes());
    buf.extend_from_slice(&num_entries.to_le_bytes());
    buf.extend_from_slice(&central_dir_size_u32.to_le_bytes());
    buf.extend_from_slice(&central_dir_start_offset_u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    Ok(buf)
}