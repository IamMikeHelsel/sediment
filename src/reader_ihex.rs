//! Intel HEX archive reader.
//!
//! Parses an Intel HEX file (per the "Hexadecimal Object File Format Specification" rev A) and
//! exposes each contiguous memory segment as a separate archive entry (`.bin` file).
//! Start-address records (03/05) produce no entry; an EOF-only file yields an empty archive.

use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::ihex_decode::{decode_ihex, HexImage, IhexError};

/// Open an Intel HEX file as an archive where each memory segment becomes one entry.
pub fn open_ihex(bytes: Vec<u8>, limits: ReaderLimits) -> Result<Box<dyn ArchiveReader>, ReaderError> {
    let max_output = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
    let image = decode_ihex(&bytes, max_output).map_err(|e| match e {
        IhexError::LimitExceeded => ReaderError::LimitExceeded,
        _ => ReaderError::Invalid,
    })?;

    if image.segments.len() > limits.max_entries {
        return Err(ReaderError::LimitExceeded);
    }

    let mut total: u64 = 0;
    for seg in &image.segments {
        total = total.checked_add(seg.data.len() as u64).ok_or(ReaderError::LimitExceeded)?;
    }
    if total > limits.max_total_size {
        return Err(ReaderError::LimitExceeded);
    }

    let mut entries: Vec<PlannedEntry> = Vec::with_capacity(image.segments.len());
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(image.segments.len());
    for seg in &image.segments {
        let path = format!("{:08X}.bin", seg.address).into_bytes();
        entries.push(PlannedEntry {
            path,
            kind: EntryKind::File,
            size: seg.data.len() as u64,
            mode: None,
            mtime: None,
        });
        data.push(seg.data.clone());
    }

    Ok(Box::new(IhexReader { entries, data, max_entry_size: limits.max_entry_size }))
}

struct IhexReader {
    entries: Vec<PlannedEntry>,
    data: Vec<Vec<u8>>,
    max_entry_size: u64,
}

impl ArchiveReader for IhexReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }

    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }

    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let entry = self.entries.get(index).ok_or(ReaderError::OutOfRange)?;
        if entry.size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(self.data[index].clone())
    }
}
