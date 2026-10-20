//! QEMU qcow2 image reader: exposes a qcow2 image as an archive with one
//! entry (`disk.img`) via the [`ArchiveReader`] trait.

use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::qcow2_header::{self, Qcow2Error, Qcow2Image};

/// L1 size cap passed to `qcow2_header::open_qcow2`.
pub const MAX_L1_ENTRIES: u32 = 1 << 20;

/// Map a [`Qcow2Error`] into a [`ReaderError`].
fn map_err(e: Qcow2Error) -> ReaderError {
    match e {
        Qcow2Error::Truncated => ReaderError::Truncated,
        Qcow2Error::LimitExceeded => ReaderError::LimitExceeded,
        Qcow2Error::UnsupportedVersion
        | Qcow2Error::Encrypted
        | Qcow2Error::UnsupportedFeature
        | Qcow2Error::Compressed => ReaderError::Unsupported,
        Qcow2Error::BadMagic
        | Qcow2Error::BadHeader
        | Qcow2Error::BadClusterBits
        | Qcow2Error::BadL1
        | Qcow2Error::BadL2
        | Qcow2Error::OutOfRange => ReaderError::Invalid,
    }
}

/// A qcow2-backed [`ArchiveReader`].
struct Qcow2Reader {
    bytes: Vec<u8>,
    image: Qcow2Image,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

/// Open a qcow2 image and expose it as a single-entry archive.
pub fn open_qcow2(
    bytes: Vec<u8>,
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader>, ReaderError> {
    // 1. Parse the image (reads the L1 table).
    let image = qcow2_header::open_qcow2(&bytes, MAX_L1_ENTRIES).map_err(map_err)?;

    // 2. Backing files are not followed.
    if image.header.backing_file_offset != 0 {
        return Err(ReaderError::Unsupported);
    }

    // 3. Limits.
    if limits.max_entries < 1 {
        return Err(ReaderError::LimitExceeded);
    }
    if image.header.size > limits.max_total_size {
        return Err(ReaderError::LimitExceeded);
    }

    // 4. Exactly one entry.
    let entries = vec![PlannedEntry {
        path: b"disk.img".to_vec(),
        kind: EntryKind::File,
        size: image.header.size,
        mode: None,
        mtime: None,
    }];

    Ok(Box::new(Qcow2Reader {
        bytes,
        image,
        entries,
        max_entry_size: limits.max_entry_size,
    }))
}

impl ArchiveReader for Qcow2Reader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }

    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }

    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        // Index out of range.
        if index >= self.entries.len() {
            return Err(ReaderError::OutOfRange);
        }

        let size = self.entries[index].size;

        // Check size against max_entry_size before reading.
        if size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }

        // Convert size to usize; failure means the image is too large.
        let len: usize = size.try_into().map_err(|_| ReaderError::LimitExceeded)?;

        // Delegate to the leaf reader (same error mapping).
        self.image
            .read_at(&self.bytes, 0, len)
            .map_err(map_err)
    }

    fn crc32(&self, _index: usize) -> Option<u32> {
        None
    }
}
