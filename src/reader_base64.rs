//! Archive reader adapter: decodes Base64 text as a single-file archive.
//!
//! Implements the 7-Zip Base64 handler model (RFC 4648 section 4): the input
//! is treated as Base64-encoded text (standard alphabet, optional padding,
//! whitespace ignored) and the decoded bytes become one entry named `data.bin`.

use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::base64_codec::{Alphabet, Base64Error, DecodeOptions, Padding};
use crate::extract_plan::{EntryKind, PlannedEntry};

/// A single-entry archive backed by Base64-decoded bytes.
pub struct Base64Reader {
    entries: Vec<PlannedEntry>,
    data: Vec<u8>,
    max_entry_size: u64,
}

/// Open a Base64-encoded text blob as an archive with one decoded file.
pub fn open_base64(bytes: Vec<u8>, limits: ReaderLimits) -> Result<Box<dyn ArchiveReader>, ReaderError> {
    if limits.max_entries == 0 {
        return Err(ReaderError::LimitExceeded);
    }
    let cap = limits.max_entry_size.min(limits.max_total_size);
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let opts = DecodeOptions {
        alphabet: Alphabet::Standard,
        padding: Padding::Optional,
        ignore_whitespace: true,
        max_output: cap,
    };
    let decoded = crate::base64_codec::decode(&bytes, &opts).map_err(|e| match e {
        Base64Error::LimitExceeded => ReaderError::LimitExceeded,
        _ => ReaderError::Invalid,
    })?;
    let entry = PlannedEntry {
        path: b"data.bin".to_vec(),
        kind: EntryKind::File,
        size: decoded.len() as u64,
        mode: None,
        mtime: None,
    };
    Ok(Box::new(Base64Reader { entries: vec![entry], data: decoded, max_entry_size: limits.max_entry_size }))
}

impl ArchiveReader for Base64Reader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        if index != 0 {
            return Err(ReaderError::OutOfRange);
        }
        if self.data.len() as u64 > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(self.data.clone())
    }
}
