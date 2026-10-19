// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z archive reader: listing and per-entry extraction on top of
//! [`crate::sevenz_header`].
//!
//! Spec source: the public "7z Format" description (`7zFormat.txt`) for the
//! file-to-folder/substream mapping (files with a stream consume substreams in
//! order; folders with zero substreams are skipped). Codecs other than Copy
//! plug in through [`FolderDecoder`]. Solid folders are decoded once and split
//! into substreams; folder and substream CRCs are verified.

use crate::crc32::crc32;
pub use crate::sevenz_header::{FolderDecoder, NoDecoder, SevenZLimits, SevenZReadError};
use crate::sevenz_header::{ATTR_DIRECTORY, ATTR_UNIX_EXTENSION, Folder, Header, decode_folder, parse_archive_header};

type Result<T> = core::result::Result<T, SevenZReadError>;

/// One listed archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZEntry {
    pub index: usize,
    pub name: String,
    pub is_dir: bool,
    pub has_stream: bool,
    pub is_anti: bool,
    /// Unpacked size (0 for entries without a stream).
    pub size: u64,
    pub crc: Option<u32>,
    pub attributes: Option<u32>,
    /// Windows FILETIME values (100 ns ticks since 1601-01-01 UTC).
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
    /// Folder (block) holding this entry's data.
    pub folder_index: Option<usize>,
    /// Substream position inside its folder.
    pub index_in_folder: Option<usize>,
    /// Global substream index.
    pub stream_index: Option<usize>,
}

impl SevenZEntry {
    /// Unix `st_mode` when the archiver stored the Unix extension.
    pub fn unix_mode(&self) -> Option<u32> {
        let a = self.attributes?;
        if a & ATTR_UNIX_EXTENSION != 0 { Some(a >> 16) } else { None }
    }
    /// True when the Windows directory attribute is set.
    pub fn has_dir_attribute(&self) -> bool {
        self.attributes.is_some_and(|a| a & ATTR_DIRECTORY != 0)
    }
}

/// Convert a Windows FILETIME to Unix seconds and nanoseconds.
pub fn filetime_to_unix(ft: u64) -> (i64, u32) {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    (secs, nanos)
}

/// An opened archive: parsed header plus the entry/stream mapping.
#[derive(Debug, Clone)]
pub struct SevenZArchive<'a> {
    bytes: &'a [u8],
    header: Header,
    entries: Vec<SevenZEntry>,
    /// Global index of each folder's first substream.
    folder_first_stream: Vec<usize>,
    limits: SevenZLimits,
}

impl<'a> SevenZArchive<'a> {
    /// Parse the archive header (decoding an encoded header via `decoder`)
    /// and build the entry list.
    pub fn open(bytes: &'a [u8], decoder: &dyn FolderDecoder, limits: SevenZLimits) -> Result<Self> {
        let header = parse_archive_header(bytes, decoder, &limits)?;
        let ss = &header.main_streams.substreams;
        let folders = &header.main_streams.folders;
        let mut folder_first_stream = Vec::new();
        folder_first_stream.try_reserve_exact(folders.len()).map_err(|_| SevenZReadError::Allocation)?;
        let mut acc = 0usize;
        for &n in &ss.num_unpack_streams {
            folder_first_stream.push(acc);
            acc = acc.checked_add(n).ok_or(SevenZReadError::Malformed)?;
        }
        if acc != ss.sizes.len() || ss.crcs.len() != ss.sizes.len() {
            return Err(SevenZReadError::Malformed);
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(header.files.len()).map_err(|_| SevenZReadError::Allocation)?;
        let mut folder = 0usize;
        let mut in_folder = 0usize;
        let mut stream = 0usize;
        for (i, f) in header.files.iter().enumerate() {
            let mut e = SevenZEntry {
                index: i,
                name: f.name.clone(),
                is_dir: f.is_dir,
                has_stream: f.has_stream,
                is_anti: f.is_anti,
                size: 0,
                crc: None,
                attributes: f.attributes,
                mtime: f.mtime,
                ctime: f.ctime,
                atime: f.atime,
                folder_index: None,
                index_in_folder: None,
                stream_index: None,
            };
            if f.has_stream {
                if in_folder == 0 {
                    while folder < folders.len() && ss.num_unpack_streams[folder] == 0 {
                        folder += 1;
                    }
                }
                if folder >= folders.len() {
                    return Err(SevenZReadError::Malformed);
                }
                e.size = ss.sizes[stream];
                e.crc = ss.crcs[stream];
                e.folder_index = Some(folder);
                e.index_in_folder = Some(in_folder);
                e.stream_index = Some(stream);
                stream += 1;
                in_folder += 1;
                if in_folder >= ss.num_unpack_streams[folder] {
                    folder += 1;
                    in_folder = 0;
                }
            }
            entries.push(e);
        }
        if stream != ss.sizes.len() {
            return Err(SevenZReadError::Malformed);
        }
        Ok(Self { bytes, header, entries, folder_first_stream, limits })
    }

    pub fn entries(&self) -> &[SevenZEntry] {
        &self.entries
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn folders(&self) -> &[Folder] {
        &self.header.main_streams.folders
    }

    /// Decode a whole folder and split it into its verified substreams.
    pub fn extract_folder(&self, folder_index: usize, decoder: &dyn FolderDecoder) -> Result<Vec<Vec<u8>>> {
        let data = self.decode(folder_index, decoder)?;
        let ss = &self.header.main_streams.substreams;
        let first = self.folder_first_stream[folder_index];
        let n = ss.num_unpack_streams[folder_index];
        let mut out = Vec::new();
        out.try_reserve_exact(n).map_err(|_| SevenZReadError::Allocation)?;
        let mut off = 0usize;
        for s in first..first + n {
            out.push(self.split(&data, &mut off, s)?);
        }
        Ok(out)
    }

    /// Extract one entry's bytes. Entries without a stream (directories,
    /// empty files) yield an empty vector.
    pub fn extract_entry(&self, index: usize, decoder: &dyn FolderDecoder) -> Result<Vec<u8>> {
        let e = self.entries.get(index).ok_or(SevenZReadError::IndexOutOfRange)?;
        let (Some(folder), Some(stream)) = (e.folder_index, e.stream_index) else {
            return Ok(Vec::new());
        };
        let data = self.decode(folder, decoder)?;
        let ss = &self.header.main_streams.substreams;
        let first = self.folder_first_stream[folder];
        let mut off = 0usize;
        for s in first..stream {
            off = off
                .checked_add(usize::try_from(ss.sizes[s]).map_err(|_| SevenZReadError::Malformed)?)
                .ok_or(SevenZReadError::Malformed)?;
        }
        self.split(&data, &mut off, stream)
    }

    fn decode(&self, folder_index: usize, decoder: &dyn FolderDecoder) -> Result<Vec<u8>> {
        if folder_index >= self.header.main_streams.folders.len() {
            return Err(SevenZReadError::IndexOutOfRange);
        }
        decode_folder(self.bytes, &self.header.main_streams, folder_index, decoder, &self.limits)
    }

    fn split(&self, data: &[u8], off: &mut usize, stream: usize) -> Result<Vec<u8>> {
        let ss = &self.header.main_streams.substreams;
        let size = usize::try_from(ss.sizes[stream]).map_err(|_| SevenZReadError::Malformed)?;
        let end = off.checked_add(size).ok_or(SevenZReadError::Malformed)?;
        let slice = data.get(*off..end).ok_or(SevenZReadError::SizeMismatch)?;
        if let Some(c) = ss.crcs[stream]
            && crc32(slice) != c
        {
            return Err(SevenZReadError::DataChecksum);
        }
        *off = end;
        let mut v = Vec::new();
        v.try_reserve_exact(size).map_err(|_| SevenZReadError::Allocation)?;
        v.extend_from_slice(slice);
        Ok(v)
    }
}

/// List all entries.
pub fn list(bytes: &[u8], decoder: &dyn FolderDecoder, limits: SevenZLimits) -> Result<Vec<SevenZEntry>> {
    Ok(SevenZArchive::open(bytes, decoder, limits)?.entries)
}

/// Extract one entry by index.
pub fn extract_entry(bytes: &[u8], index: usize, decoder: &dyn FolderDecoder, limits: SevenZLimits) -> Result<Vec<u8>> {
    SevenZArchive::open(bytes, decoder, limits)?.extract_entry(index, decoder)
}
