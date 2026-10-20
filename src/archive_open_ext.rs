// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opening of Zstandard (`.zst`, `.tar.zst`, `.tzst`) and WIM files as an
//! [`ArchiveReader`], in front of [`crate::archive_open::open_named`] for
//! every other format.
//!
//! Detection is by magic bytes: a zstd frame (`28 B5 2F FD`) or skippable
//! frame (`5x 2A 4D 18`), RFC 8878 section 3.1, and `MSWIM\0\0\0` for WIM.
//! As for gzip/bzip2/xz, a zstd stream is read as a tar archive when the
//! archive name ends in `.tar.zst`, `.tar.zstd`, `.tzst` or the member name
//! (archive name minus `.zst`/`.zstd`) ends in `.tar`.
//!
//! WIM: every image is listed; with more than one image, paths are
//! prefixed with the 1-based image number (`2/dir/file`). Named (alternate)
//! data streams are not listed ([`WimReader::skipped_streams`]); relative
//! symbolic-link reparse points become symlinks, other reparse points
//! (absolute links, junctions, ...) are left out
//! ([`WimReader::skipped_reparse`]).

use std::borrow::Cow;

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::{StreamReader, TarReader, open_named};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::sevenz_read::filetime_to_unix;
use crate::wim_read::{IO_REPARSE_TAG_SYMLINK, WimArchive, WimError, WimLimits, is_wim, symlink_target};
use crate::zstd_decode::{ZstdError, decode_zstd, is_zstd};

/// Largest reparse buffer read while listing.
const MAX_REPARSE_DATA: u64 = 64 * 1024;

impl From<ZstdError> for ReaderError {
    fn from(e: ZstdError) -> Self {
        match e {
            ZstdError::Truncated => ReaderError::Truncated,
            ZstdError::Unsupported => ReaderError::Unsupported,
            ZstdError::ChecksumMismatch => ReaderError::CrcMismatch,
            ZstdError::LimitExceeded => ReaderError::LimitExceeded,
            ZstdError::Allocation => ReaderError::Allocation,
            ZstdError::BadMagic
            | ZstdError::InvalidHeader
            | ZstdError::InvalidBlock
            | ZstdError::Corrupt
            | ZstdError::SizeMismatch
            | ZstdError::TrailingData => ReaderError::Invalid,
        }
    }
}

impl From<WimError> for ReaderError {
    fn from(e: WimError) -> Self {
        match e {
            WimError::Truncated => ReaderError::Truncated,
            WimError::Unsupported => ReaderError::Unsupported,
            WimError::HashMismatch => ReaderError::CrcMismatch,
            WimError::LimitExceeded => ReaderError::LimitExceeded,
            WimError::Allocation => ReaderError::Allocation,
            WimError::BadMagic | WimError::Invalid | WimError::NotFound => ReaderError::Invalid,
        }
    }
}

fn base_name(name: &[u8]) -> &[u8] {
    name.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(name)
}

fn ends_with_ci(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

const ZSTD_TAR_SUFFIXES: [(&[u8], &[u8]); 3] = [(b".tar.zst", b".tar"), (b".tar.zstd", b".tar"), (b".tzst", b".tar")];
const ZSTD_SUFFIXES: [&[u8]; 2] = [b".zst", b".zstd"];

/// True when the archive name says "zstd-compressed tar".
pub fn is_zstd_tar_name(archive_name: &[u8]) -> bool {
    let base = base_name(archive_name);
    ZSTD_TAR_SUFFIXES.iter().any(|(s, _)| ends_with_ci(base, s))
}

/// Member name of a single `.zst` stream: `x.tzst` -> `x.tar`,
/// `notes.txt.zst` -> `notes.txt`; other names are kept; an empty name
/// becomes `data`.
pub fn zstd_member_name(archive_name: &[u8]) -> Vec<u8> {
    let base = base_name(archive_name);
    for (s, r) in ZSTD_TAR_SUFFIXES {
        if ends_with_ci(base, s) {
            let mut v = base[..base.len() - s.len()].to_vec();
            v.extend_from_slice(r);
            return v;
        }
    }
    for s in ZSTD_SUFFIXES {
        if ends_with_ci(base, s) {
            return base[..base.len() - s.len()].to_vec();
        }
    }
    if base.is_empty() || base == b"." || base == b".." {
        return b"data".to_vec();
    }
    base.to_vec()
}

/// WIM archive as an [`ArchiveReader`].
pub struct WimReader<'a> {
    archive: WimArchive<'a>,
    /// Index into `archive.entries()` for each listed entry.
    map: Vec<usize>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
    skipped_streams: usize,
    skipped_reparse: usize,
}

impl<'a> WimReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let wl = WimLimits { max_entries: limits.max_entries, ..WimLimits::default() };
        let archive = WimArchive::open(bytes, wl)?;
        let multi = archive.image_count() > 1;
        let n = archive.entries().len();
        let mut map = Vec::new();
        map.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let (mut skipped_streams, mut skipped_reparse) = (0usize, 0usize);
        let mut total: u64 = 0;
        for (i, e) in archive.entries().iter().enumerate() {
            skipped_streams += e.named_streams.len();
            let kind = if e.is_dir() {
                EntryKind::Dir
            } else if let Some(tag) = e.reparse_tag {
                if tag != IO_REPARSE_TAG_SYMLINK || e.size > MAX_REPARSE_DATA {
                    skipped_reparse += 1;
                    continue;
                }
                let data = archive.read_entry(i, MAX_REPARSE_DATA)?;
                match symlink_target(&data) {
                    Ok((target, true)) => EntryKind::Symlink { target: target.into_bytes() },
                    _ => {
                        skipped_reparse += 1;
                        continue;
                    }
                }
            } else {
                EntryKind::File
            };
            let size = if matches!(kind, EntryKind::File) { e.size } else { 0 };
            total = total.checked_add(size).ok_or(ReaderError::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded);
            }
            let path = if multi { format!("{}/{}", e.image, e.path) } else { e.path.clone() };
            let mtime = if e.last_write_time == 0 { None } else { Some(filetime_to_unix(e.last_write_time).0) };
            entries.push(PlannedEntry { path: path.into_bytes(), kind, size, mode: None, mtime });
            map.push(i);
        }
        Ok(WimReader { archive, map, entries, max_entry_size: limits.max_entry_size, skipped_streams, skipped_reparse })
    }

    /// The underlying WIM (images, lookup table, named streams, XML).
    pub fn archive(&self) -> &WimArchive<'a> {
        &self.archive
    }

    /// Named data streams that are not listed as entries.
    pub fn skipped_streams(&self) -> usize {
        self.skipped_streams
    }

    /// Reparse points other than relative symbolic links.
    pub fn skipped_reparse(&self) -> usize {
        self.skipped_reparse
    }
}

impl ArchiveReader for WimReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Wim
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let &i = self.map.get(index).ok_or(ReaderError::OutOfRange)?;
        if !matches!(self.entries[index].kind, EntryKind::File) {
            return Ok(Vec::new());
        }
        if self.entries[index].size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        Ok(self.archive.read_entry(i, self.max_entry_size)?)
    }
}

/// Open `bytes` (the whole archive file) as an [`ArchiveReader`]: zstd
/// streams and WIM files here, every other format through
/// [`open_named`].
pub fn open_named_ext<'a>(
    bytes: &'a [u8],
    archive_name: &[u8],
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    if is_wim(bytes) {
        return Ok(Box::new(WimReader::new(bytes, limits)?));
    }
    // UDIF disk images are identified by their trailing `koly` block. The
    // data fork often starts with a bzip2/xz chunk, so magic-byte formats
    // are only tried when the image does not parse.
    if crate::dmg_read::is_dmg(bytes) {
        match crate::dmg_read::DmgReader::new(bytes, limits) {
            Ok(r) => return Ok(Box::new(r)),
            Err(e) if crate::archive_reader::detect_format(bytes).is_none() => return Err(e),
            Err(_) => {}
        }
    }
    if is_zstd(bytes) {
        let max = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
        let data = decode_zstd(bytes, max)?;
        let member = zstd_member_name(archive_name);
        if is_zstd_tar_name(archive_name) || ends_with_ci(&member, b".tar") {
            return Ok(Box::new(TarReader::new(Cow::Owned(data), limits)?));
        }
        if data.len() as u64 > limits.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        return Ok(Box::new(StreamReader::new(ArchiveFormat::Zstd, member, data, None, None)));
    }
    open_named(bytes, archive_name, limits)
}

/// Like [`open_named_ext`] for an archive read from standard input (no
/// file name): a zstd stream is a tar archive when its content is one
/// (ustar magic or a valid tar header checksum), as for gzip/bzip2/xz in
/// [`crate::cli_stdio::open_stdin_bytes`], which handles all other formats.
pub fn open_stdin_ext<'a>(bytes: &'a [u8], limits: ReaderLimits) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    if is_wim(bytes) {
        return Ok(Box::new(WimReader::new(bytes, limits)?));
    }
    if crate::dmg_read::is_dmg(bytes)
        && let Ok(r) = crate::dmg_read::DmgReader::new(bytes, limits)
    {
        return Ok(Box::new(r));
    }
    if is_zstd(bytes) {
        let max = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
        let data = decode_zstd(bytes, max)?;
        if matches!(detect_format(&data), Detected::Tar | Detected::TarHeuristic) {
            return Ok(Box::new(TarReader::new(Cow::Owned(data), limits)?));
        }
        if data.len() as u64 > limits.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        return Ok(Box::new(StreamReader::new(ArchiveFormat::Zstd, b"data".to_vec(), data, None, None)));
    }
    crate::cli_stdio::open_stdin_bytes(bytes, limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(zstd_member_name(b"a/b.tzst"), b"b.tar");
        assert_eq!(zstd_member_name(b"x.TAR.ZST"), b"x.tar");
        assert_eq!(zstd_member_name(b"notes.txt.zst"), b"notes.txt");
        assert_eq!(zstd_member_name(b"n.zstd"), b"n");
        assert_eq!(zstd_member_name(b".zst"), b".zst");
        assert_eq!(zstd_member_name(b""), b"data");
        assert!(is_zstd_tar_name(b"a.tar.zstd"));
        assert!(!is_zstd_tar_name(b"a.zst"));
    }
}
