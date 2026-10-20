//! VHD (Virtual Hard Disk) archive reader: exposes a fixed or dynamic VHD
//! image as a single-member archive containing `disk.img`.

use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::vhd_footer::{self, VhdDiskType, VhdError, VhdImage};

/// BAT size cap passed to `vhd_footer::open_vhd`.
pub const MAX_BAT_ENTRIES: u32 = 1 << 20;

/// Convert a `VhdError` into a `ReaderError`.
fn vhd_to_reader(e: VhdError) -> ReaderError {
    match e {
        VhdError::Truncated => ReaderError::Truncated,
        VhdError::LimitExceeded => ReaderError::LimitExceeded,
        VhdError::UnsupportedVersion | VhdError::UnsupportedDiskType => ReaderError::Unsupported,
        _ => ReaderError::Invalid,
    }
}

/// A VHD archive reader holding the raw bytes and parsed image.
struct VhdArchive {
    bytes: Vec<u8>,
    image: VhdImage,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
}

/// Open a VHD image and expose it as a single-member archive.
pub fn open_vhd(bytes: Vec<u8>, limits: ReaderLimits) -> Result<Box<dyn ArchiveReader>, ReaderError> {
    let image = vhd_footer::open_vhd(&bytes, MAX_BAT_ENTRIES).map_err(vhd_to_reader)?;

    // Differencing disks are not supported (no parent chain resolution).
    if image.footer.disk_type == VhdDiskType::Differencing {
        return Err(ReaderError::Unsupported);
    }

    // Limit checks.
    if limits.max_entries < 1 {
        return Err(ReaderError::LimitExceeded);
    }
    if image.footer.current_size > limits.max_total_size {
        return Err(ReaderError::LimitExceeded);
    }

    // Exactly one entry.
    let mtime = 946_684_800 + i64::from(image.footer.timestamp);
    let entries = vec![PlannedEntry {
        path: b"disk.img".to_vec(),
        kind: EntryKind::File,
        size: image.footer.current_size,
        mode: None,
        mtime: Some(mtime),
    }];

    Ok(Box::new(VhdArchive {
        bytes,
        image,
        entries,
        max_entry_size: limits.max_entry_size,
    }))
}

impl ArchiveReader for VhdArchive {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }

    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }

    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        if index >= self.entries.len() {
            return Err(ReaderError::OutOfRange);
        }
        let size = self.entries[index].size;
        if size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        let size_usize: usize = usize::try_from(size).map_err(|_| ReaderError::LimitExceeded)?;
        self.image.read_at(&self.bytes, 0, size_usize).map_err(vhd_to_reader)
    }

    fn crc32(&self, _index: usize) -> Option<u32> {
        None
    }
}
