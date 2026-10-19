// SPDX-License-Identifier: MIT OR Apache-2.0
//! Format dispatch for archive update operations: detect the container of an
//! existing archive (ZIP, tar, tar inside gzip/bzip2/xz, 7z), list it for the
//! planners in [`crate::archive_update`], and apply an [`EditPlan`] with the
//! matching rewriter, re-compressing compressed tar archives.
//!
//! Detection is by magic bytes ([`crate::archive_detect`]); a gzip, bzip2 or
//! xz stream is accepted only when its decompressed content is a tar archive
//! (single compressed files have no members to update). A ZIP archive behind
//! a prefix (self-extractor stub) is recognised by its end record.

use std::borrow::Cow;
use std::path::Path;

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::decompress;
use crate::archive_reader::ArchiveFormat as ReaderFormat;
use crate::archive_update::{EditPlan, ExistingEntry, UpdateError, UpdateLimits};
use crate::cli_add::{ArchiveFormat as AddFormat, format_from_name};
use crate::compress_wrap::{Compression, WrapError, compress, compress_bound_for};
use crate::sevenz_update::{apply_7z, sevenz_entries};
use crate::sevenz_write::SevenZWriteOptions;
use crate::tar_update::{apply_tar, tar_entries};
use crate::zip64::locate_central_directory;
use crate::zip_update::{ZipUpdateOptions, apply_zip, zip_entries};

/// Container formats that can be updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditFormat {
    Zip,
    /// Tar, optionally wrapped in a single compressed stream.
    Tar(Compression),
    SevenZ,
}

/// An existing archive ready for planning: its format and the bytes the
/// rewriter works on (decompressed for compressed tar).
#[derive(Debug, Clone)]
pub struct EditSource<'a> {
    pub format: EditFormat,
    pub data: Cow<'a, [u8]>,
}

/// Choose the format for a new archive from its file name (`.zip`, `.tar`,
/// `.tar.gz`/`.tgz`, `.tar.xz`/`.txz`, `.tar.bz2`/`.tbz2`/`.tbz`, `.7z`).
pub fn format_for_new(path: &Path) -> Option<EditFormat> {
    if let Some(f) = format_from_name(path) {
        return Some(match f {
            AddFormat::Zip => EditFormat::Zip,
            AddFormat::Tar(c) => EditFormat::Tar(c),
        });
    }
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    (name.len() > 3 && name.ends_with(".7z")).then_some(EditFormat::SevenZ)
}

/// Detect the format of an existing archive and decompress a compressed tar.
/// `max_tar` caps the decompressed tar size.
pub fn open_source(bytes: &[u8], max_tar: usize) -> Result<EditSource<'_>, UpdateError> {
    let compressed = match detect_format(bytes) {
        Detected::Zip => return Ok(EditSource { format: EditFormat::Zip, data: Cow::Borrowed(bytes) }),
        Detected::SevenZip => return Ok(EditSource { format: EditFormat::SevenZ, data: Cow::Borrowed(bytes) }),
        Detected::Tar | Detected::TarHeuristic => {
            return Ok(EditSource { format: EditFormat::Tar(Compression::None), data: Cow::Borrowed(bytes) });
        }
        Detected::Gzip => (ReaderFormat::Gzip, Compression::Gzip),
        Detected::Bzip2 => (ReaderFormat::Bzip2, Compression::Bzip2),
        Detected::Xz => (ReaderFormat::Xz, Compression::Xz),
        Detected::Cpio | Detected::Ar | Detected::Rpm | Detected::Xar => return Err(UpdateError::Unsupported),
        Detected::LzmaAlone | Detected::Unknown => {
            // A ZIP behind a prefix (self-extractor stub) is found by its
            // end of central directory record.
            if locate_central_directory(bytes).is_ok() {
                return Ok(EditSource { format: EditFormat::Zip, data: Cow::Borrowed(bytes) });
            }
            // An empty tar archive is all zero blocks.
            if !bytes.is_empty() && bytes.len().is_multiple_of(512) && bytes.iter().all(|&b| b == 0) {
                return Ok(EditSource { format: EditFormat::Tar(Compression::None), data: Cow::Borrowed(bytes) });
            }
            return Err(UpdateError::Unsupported);
        }
    };
    let inner = decompress(compressed.0, bytes, max_tar).map_err(|e| match e {
        crate::archive_reader::ReaderError::LimitExceeded => UpdateError::LimitExceeded,
        crate::archive_reader::ReaderError::Allocation => UpdateError::Allocation,
        _ => UpdateError::InvalidArchive,
    })?;
    if !is_tar_like(&inner) {
        return Err(UpdateError::Unsupported);
    }
    Ok(EditSource { format: EditFormat::Tar(compressed.1), data: Cow::Owned(inner) })
}

/// Tar by magic/checksum, or an empty tar (no bytes, or only zero blocks).
fn is_tar_like(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0) || matches!(detect_format(b), Detected::Tar | Detected::TarHeuristic)
}

/// List the entries of `src` for the planners.
pub fn list_source(src: &EditSource<'_>, limits: &UpdateLimits) -> Result<Vec<ExistingEntry>, UpdateError> {
    match src.format {
        EditFormat::Zip => zip_entries(&src.data, limits),
        EditFormat::Tar(_) => tar_entries(&src.data, limits),
        EditFormat::SevenZ => sevenz_entries(&src.data, limits),
    }
}

/// Result of [`apply_plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditResult {
    /// The complete new archive file.
    pub bytes: Vec<u8>,
    /// Names of members that the format could not store (ZIP symlinks).
    pub skipped: Vec<Vec<u8>>,
}

/// Apply `plan` to `src` (whose `data` may be empty for a new archive).
/// `level` (0..=9) selects compression for new or re-encoded members and
/// for re-compressing a compressed tar.
pub fn apply_plan(
    src: &EditSource<'_>,
    plan: &EditPlan<'_>,
    level: u8,
    limits: &UpdateLimits,
) -> Result<EditResult, UpdateError> {
    if level > 9 {
        return Err(UpdateError::EncodeFailed);
    }
    match src.format {
        EditFormat::Zip => {
            let r = apply_zip(&src.data, plan, ZipUpdateOptions { level }, limits)?;
            Ok(EditResult { bytes: r.bytes, skipped: r.skipped })
        }
        EditFormat::SevenZ => {
            let opts = SevenZWriteOptions::level(level).map_err(|_| UpdateError::EncodeFailed)?;
            Ok(EditResult { bytes: apply_7z(&src.data, plan, &opts, limits)?, skipped: Vec::new() })
        }
        EditFormat::Tar(c) => {
            let tar = apply_tar(&src.data, plan, limits)?;
            if c == Compression::None {
                return Ok(EditResult { bytes: tar, skipped: Vec::new() });
            }
            let max = usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX);
            let bound = compress_bound_for(c, tar.len()).unwrap_or(usize::MAX).min(max);
            let bytes = compress(c, &tar, level, bound).map_err(|e| match e {
                WrapError::LimitExceeded => UpdateError::LimitExceeded,
                WrapError::Allocation => UpdateError::Allocation,
                _ => UpdateError::EncodeFailed,
            })?;
            Ok(EditResult { bytes, skipped: Vec::new() })
        }
    }
}
