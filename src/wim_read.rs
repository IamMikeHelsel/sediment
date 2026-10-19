// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Imaging (WIM) archive reading: header, lookup (offset) table,
//! XML data, per-image metadata resources (security data + directory
//! entries) and file streams, with SHA-1 verification of every resource.
//!
//! Spec sources: Microsoft "Windows Imaging File Format (WIM)" white paper
//! (WIMHEADER_V1_PACKED, RESHDR_DISK_SHORT, the offset table entry, the
//! metadata resource with SECURITYBLOCK_DISK and DIRENTRY, alternate data
//! stream entries, chunked compressed resources with a chunk offset
//! table), [MS-XCA] for XPRESS Huffman chunks (see
//! [`crate::xpress_huffman`]), [MS-FSCC] 2.1.2 for reparse point buffers
//! and FIPS 180-4 for SHA-1.
//!
//! Supported: non-spanned WIMs (one part), uncompressed and XPRESS
//! resources, multiple images, directories, files, named (alternate) data
//! streams, hard links (shared data) and symbolic-link reparse points.
//! LZX and LZMS chunks, solid resources (`.esd`-style) and spanned sets
//! return [`WimError::Unsupported`]. Integrity tables are not checked (each
//! stream is verified against its SHA-1 instead).
//!
//! Limits: [`WimLimits`] bounds the number of directory entries, nesting
//! depth, the size of a decoded metadata resource and, per call, the size
//! of a decoded stream. Directory cycles are detected. Compressed chunk
//! tables are validated before any chunk is decoded.

use std::collections::{HashMap, HashSet};

use crate::hash_sha1::Sha1;
use crate::xpress_huffman::{self, XpressError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimError {
    /// A header, table or resource extends past the end of the file.
    Truncated,
    /// Not a WIM file (bad magic or header size).
    BadMagic,
    /// Malformed header, lookup table, chunk table, metadata or names.
    Invalid,
    /// A compression format or layout this reader does not provide.
    Unsupported,
    /// A resource's SHA-1 does not match the lookup table.
    HashMismatch,
    /// A limit in [`WimLimits`] or a caller's size cap was exceeded.
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
    /// Entry index or image number out of range, or a stream hash that is
    /// not in the lookup table.
    NotFound,
}

impl From<XpressError> for WimError {
    fn from(e: XpressError) -> Self {
        match e {
            XpressError::LimitExceeded => WimError::LimitExceeded,
            XpressError::Allocation => WimError::Allocation,
            XpressError::Truncated | XpressError::InvalidTable | XpressError::InvalidMatch => WimError::Invalid,
        }
    }
}

type R<T> = Result<T, WimError>;

pub const WIM_MAGIC: [u8; 8] = *b"MSWIM\0\0\0";
pub const HEADER_SIZE: usize = 208;

/// Header flags (WIMHEADER_V1_PACKED.dwFlags).
pub mod header_flag {
    pub const COMPRESSION: u32 = 0x0000_0002;
    pub const READONLY: u32 = 0x0000_0004;
    pub const SPANNED: u32 = 0x0000_0008;
    pub const RESOURCE_ONLY: u32 = 0x0000_0010;
    pub const METADATA_ONLY: u32 = 0x0000_0020;
    pub const WRITE_IN_PROGRESS: u32 = 0x0000_0040;
    pub const RP_FIX: u32 = 0x0000_0080;
    pub const COMPRESS_XPRESS: u32 = 0x0002_0000;
    pub const COMPRESS_LZX: u32 = 0x0004_0000;
    pub const COMPRESS_LZMS: u32 = 0x0008_0000;
}

/// Resource flags (RESHDR_DISK_SHORT.bFlags).
pub mod resource_flag {
    pub const FREE: u8 = 0x01;
    pub const METADATA: u8 = 0x02;
    pub const COMPRESSED: u8 = 0x04;
    pub const SPANNED: u8 = 0x08;
    pub const SOLID: u8 = 0x10;
}

/// File attribute bits used here ([MS-FSCC] 2.6).
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Reparse tags ([MS-FSCC] 2.1.2.1).
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimCompression {
    None,
    Xpress,
    Lzx,
    Lzms,
    /// Compression flag set without a known algorithm bit.
    Unknown,
}

/// RESHDR_DISK_SHORT: where a resource lives and how big it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceHeader {
    /// Stored (compressed) size, 56 bits on disk.
    pub size: u64,
    pub flags: u8,
    pub offset: u64,
    pub original_size: u64,
}

impl ResourceHeader {
    fn parse(b: &[u8]) -> ResourceHeader {
        let mut s = [0u8; 8];
        s[..7].copy_from_slice(&b[..7]);
        ResourceHeader { size: u64::from_le_bytes(s), flags: b[7], offset: le64(b, 8), original_size: le64(b, 16) }
    }
    pub fn is_compressed(&self) -> bool {
        self.flags & resource_flag::COMPRESSED != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimHeader {
    pub version: u32,
    pub flags: u32,
    pub chunk_size: u32,
    pub guid: [u8; 16],
    pub part_number: u16,
    pub total_parts: u16,
    pub image_count: u32,
    pub lookup_table: ResourceHeader,
    pub xml_data: ResourceHeader,
    pub boot_metadata: ResourceHeader,
    pub boot_index: u32,
    pub integrity: ResourceHeader,
    pub compression: WimCompression,
}

fn le16(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([b[p], b[p + 1]])
}
fn le32(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn le64(b: &[u8], p: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[p..p + 8]);
    u64::from_le_bytes(a)
}

/// True when `b` starts with the WIM magic.
pub fn is_wim(b: &[u8]) -> bool {
    b.len() >= 8 && b[..8] == WIM_MAGIC
}

/// Parse the 208-byte WIM header.
pub fn parse_header(b: &[u8]) -> R<WimHeader> {
    if b.len() < 8 {
        return Err(WimError::Truncated);
    }
    if !is_wim(b) {
        return Err(WimError::BadMagic);
    }
    if b.len() < HEADER_SIZE {
        return Err(WimError::Truncated);
    }
    if le32(b, 8) as usize != HEADER_SIZE {
        return Err(WimError::BadMagic);
    }
    let flags = le32(b, 16);
    let compression = if flags & header_flag::COMPRESSION == 0 {
        WimCompression::None
    } else if flags & header_flag::COMPRESS_XPRESS != 0 {
        WimCompression::Xpress
    } else if flags & header_flag::COMPRESS_LZX != 0 {
        WimCompression::Lzx
    } else if flags & header_flag::COMPRESS_LZMS != 0 {
        WimCompression::Lzms
    } else {
        WimCompression::Unknown
    };
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&b[24..40]);
    Ok(WimHeader {
        version: le32(b, 12),
        flags,
        chunk_size: le32(b, 20),
        guid,
        part_number: le16(b, 40),
        total_parts: le16(b, 42),
        image_count: le32(b, 44),
        lookup_table: ResourceHeader::parse(&b[48..72]),
        xml_data: ResourceHeader::parse(&b[72..96]),
        boot_metadata: ResourceHeader::parse(&b[96..120]),
        boot_index: le32(b, 120),
        integrity: ResourceHeader::parse(&b[124..148]),
        compression,
    })
}

/// One lookup (offset) table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupEntry {
    pub resource: ResourceHeader,
    pub part_number: u16,
    pub ref_count: u32,
    pub hash: [u8; 20],
}

const LOOKUP_ENTRY_SIZE: usize = 50;

/// A named (alternate) data stream of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimStream {
    /// Stream name (UTF-8; converted from UTF-16LE).
    pub name: String,
    pub size: u64,
    /// SHA-1 of the stream data; all zero for an empty stream.
    pub hash: [u8; 20],
}

/// One directory entry of an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimEntry {
    /// 1-based image number.
    pub image: u32,
    /// Path inside the image, components joined with `/`.
    pub path: String,
    pub attributes: u32,
    /// Size of the unnamed data stream (for reparse points: of the reparse
    /// data).
    pub size: u64,
    /// SHA-1 of the unnamed data stream; all zero when empty.
    pub hash: [u8; 20],
    pub creation_time: u64,
    pub last_access_time: u64,
    /// FILETIME (100 ns since 1601-01-01 UTC).
    pub last_write_time: u64,
    /// Reparse tag for reparse points.
    pub reparse_tag: Option<u32>,
    /// Hard link group id (0 = none); entries sharing it are one file.
    pub hard_link_group: u64,
    pub named_streams: Vec<WimStream>,
}

impl WimEntry {
    pub fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// Caller limits for [`WimArchive::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimLimits {
    /// Total directory entries across all images.
    pub max_entries: usize,
    /// Largest decoded metadata resource / lookup table / XML data.
    pub max_metadata_size: u64,
    /// Deepest directory nesting.
    pub max_depth: usize,
    /// Largest number of images.
    pub max_images: u32,
}

impl Default for WimLimits {
    fn default() -> Self {
        WimLimits { max_entries: 1_000_000, max_metadata_size: 512 << 20, max_depth: 512, max_images: 4096 }
    }
}

/// An opened WIM file.
#[derive(Debug, Clone)]
pub struct WimArchive<'a> {
    data: &'a [u8],
    header: WimHeader,
    lookup: Vec<LookupEntry>,
    by_hash: HashMap<[u8; 20], usize>,
    entries: Vec<WimEntry>,
}

fn align8(v: u64) -> Option<u64> {
    v.checked_add(7).map(|x| x & !7)
}

/// Read and decode one resource of a WIM file (`data` = whole file).
/// `max_output` bounds the decoded size.
pub fn read_resource(data: &[u8], header: &WimHeader, r: &ResourceHeader, max_output: u64) -> R<Vec<u8>> {
    if r.flags & (resource_flag::SOLID | resource_flag::SPANNED) != 0 {
        return Err(WimError::Unsupported);
    }
    if r.original_size > max_output {
        return Err(WimError::LimitExceeded);
    }
    let start = usize::try_from(r.offset).map_err(|_| WimError::Truncated)?;
    let len = usize::try_from(r.size).map_err(|_| WimError::Truncated)?;
    let end = start.checked_add(len).ok_or(WimError::Truncated)?;
    let raw = data.get(start..end).ok_or(WimError::Truncated)?;
    let orig = usize::try_from(r.original_size).map_err(|_| WimError::LimitExceeded)?;
    let mut out = Vec::new();
    if !r.is_compressed() {
        if len != orig {
            return Err(WimError::Invalid);
        }
        out.try_reserve_exact(orig).map_err(|_| WimError::Allocation)?;
        out.extend_from_slice(raw);
        return Ok(out);
    }
    match header.compression {
        WimCompression::Xpress => {}
        WimCompression::None => return Err(WimError::Invalid),
        WimCompression::Lzx | WimCompression::Lzms | WimCompression::Unknown => return Err(WimError::Unsupported),
    }
    let chunk = header.chunk_size as usize;
    if orig == 0 {
        return if len == 0 { Ok(out) } else { Err(WimError::Invalid) };
    }
    let n_chunks = orig.div_ceil(chunk);
    let entry_size = if r.original_size > u64::from(u32::MAX) { 8 } else { 4 };
    let table_len = (n_chunks - 1).checked_mul(entry_size).ok_or(WimError::Invalid)?;
    if table_len > len {
        return Err(WimError::Invalid);
    }
    let (table, body) = raw.split_at(table_len);
    let chunk_start = |i: usize| -> u64 {
        if i == 0 {
            0
        } else if entry_size == 4 {
            u64::from(le32(table, (i - 1) * 4))
        } else {
            le64(table, (i - 1) * 8)
        }
    };
    // Validate the whole chunk table first.
    let mut prev = 0u64;
    for i in 1..n_chunks {
        let s = chunk_start(i);
        if s < prev || s > body.len() as u64 {
            return Err(WimError::Invalid);
        }
        prev = s;
    }
    out.try_reserve_exact(orig).map_err(|_| WimError::Allocation)?;
    for i in 0..n_chunks {
        let s = chunk_start(i) as usize;
        let e = if i + 1 < n_chunks { chunk_start(i + 1) as usize } else { body.len() };
        let comp = &body[s..e];
        let ulen = if i + 1 < n_chunks { chunk } else { orig - chunk * (n_chunks - 1) };
        if comp.len() == ulen {
            out.extend_from_slice(comp);
        } else if comp.len() > ulen {
            return Err(WimError::Invalid);
        } else {
            xpress_huffman::decompress_into(comp, ulen, &mut out)?;
        }
    }
    Ok(out)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

/// UTF-16LE name of `nbytes` bytes at `p`; rejects odd lengths. Unpaired
/// surrogates become U+FFFD.
fn utf16_name(md: &[u8], p: usize, nbytes: usize) -> R<String> {
    if !nbytes.is_multiple_of(2) {
        return Err(WimError::Invalid);
    }
    let s = md.get(p..p + nbytes).ok_or(WimError::Invalid)?;
    let units: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// A single path component must be a plain name.
fn valid_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

const DENTRY_FIXED: usize = 102;
const ADS_FIXED: usize = 38;

struct RawDentry {
    attributes: u32,
    subdir_offset: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    hash: [u8; 20],
    reparse_tag: u32,
    hard_link_group: u64,
    name: String,
    streams: Vec<(String, [u8; 20])>,
    /// Offset just past this dentry and its stream entries.
    next: usize,
}

/// Parse the dentry at `off`; `None` at an end-of-directory marker.
fn parse_dentry(md: &[u8], off: usize) -> R<Option<RawDentry>> {
    let hdr = md.get(off..off + 8).ok_or(WimError::Invalid)?;
    let len = le64(hdr, 0);
    if len == 0 {
        return Ok(None);
    }
    if len < DENTRY_FIXED as u64 {
        return Err(WimError::Invalid);
    }
    let end = (off as u64).checked_add(len).ok_or(WimError::Invalid)?;
    if end > md.len() as u64 {
        return Err(WimError::Invalid);
    }
    let d = &md[off..end as usize];
    let attributes = le32(d, 8);
    let subdir_offset = le64(d, 16);
    let creation_time = le64(d, 40);
    let last_access_time = le64(d, 48);
    let last_write_time = le64(d, 56);
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&d[64..84]);
    let reparse_tag = le32(d, 88);
    let hard_link_group = le64(d, 88);
    let num_streams = usize::from(le16(d, 96));
    let short_len = usize::from(le16(d, 98));
    let name_len = usize::from(le16(d, 100));
    let name_end = DENTRY_FIXED + name_len + if name_len > 0 { 2 } else { 0 };
    let short_end = name_end + short_len + if short_len > 0 { 2 } else { 0 };
    if short_end > d.len() {
        return Err(WimError::Invalid);
    }
    let name = utf16_name(d, DENTRY_FIXED, name_len)?;
    let mut next = align8(end).ok_or(WimError::Invalid)?;
    let mut streams = Vec::new();
    for _ in 0..num_streams {
        let p = usize::try_from(next).map_err(|_| WimError::Invalid)?;
        let s = md.get(p..p + ADS_FIXED).ok_or(WimError::Invalid)?;
        let slen = le64(s, 0);
        if slen < ADS_FIXED as u64 {
            return Err(WimError::Invalid);
        }
        let send = next.checked_add(slen).ok_or(WimError::Invalid)?;
        if send > md.len() as u64 {
            return Err(WimError::Invalid);
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&s[16..36]);
        let nlen = usize::from(le16(s, 36));
        if (ADS_FIXED + nlen + if nlen > 0 { 2 } else { 0 }) as u64 > slen {
            return Err(WimError::Invalid);
        }
        let sname = utf16_name(md, p + ADS_FIXED, nlen)?;
        streams.push((sname, h));
        next = align8(send).ok_or(WimError::Invalid)?;
    }
    let next = usize::try_from(next).map_err(|_| WimError::Invalid)?;
    Ok(Some(RawDentry {
        attributes,
        subdir_offset,
        creation_time,
        last_access_time,
        last_write_time,
        hash,
        reparse_tag,
        hard_link_group,
        name,
        streams,
        next,
    }))
}

const ZERO_HASH: [u8; 20] = [0; 20];

impl<'a> WimArchive<'a> {
    /// Parse the header, lookup table and every image's directory tree.
    pub fn open(data: &'a [u8], limits: WimLimits) -> R<Self> {
        let header = parse_header(data)?;
        if header.flags & header_flag::SPANNED != 0 || header.total_parts != 1 || header.part_number != 1 {
            return Err(WimError::Unsupported);
        }
        if header.version >> 16 != 1 {
            return Err(WimError::Unsupported);
        }
        if header.compression != WimCompression::None {
            let c = header.chunk_size;
            if !c.is_power_of_two() || !(1 << 12..=1 << 26).contains(&c) {
                return Err(WimError::Invalid);
            }
        }
        if header.image_count > limits.max_images {
            return Err(WimError::LimitExceeded);
        }
        // Every resource named by the header must lie inside the file.
        for r in [&header.lookup_table, &header.xml_data, &header.boot_metadata, &header.integrity] {
            let end = r.offset.checked_add(r.size).ok_or(WimError::Truncated)?;
            if r.size != 0 && end > data.len() as u64 {
                return Err(WimError::Truncated);
            }
        }
        let lt = &header.lookup_table;
        if lt.is_compressed() && lt.original_size > limits.max_metadata_size {
            return Err(WimError::LimitExceeded);
        }
        let table = read_resource(data, &header, lt, limits.max_metadata_size)?;
        if table.len() % LOOKUP_ENTRY_SIZE != 0 {
            return Err(WimError::Invalid);
        }
        let n = table.len() / LOOKUP_ENTRY_SIZE;
        let mut lookup = Vec::new();
        lookup.try_reserve_exact(n).map_err(|_| WimError::Allocation)?;
        let mut by_hash = HashMap::new();
        by_hash.try_reserve(n).map_err(|_| WimError::Allocation)?;
        let mut metadata = Vec::new();
        for (i, e) in table.as_chunks::<LOOKUP_ENTRY_SIZE>().0.iter().enumerate() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&e[30..50]);
            let entry = LookupEntry {
                resource: ResourceHeader::parse(&e[..24]),
                part_number: le16(e, 24),
                ref_count: le32(e, 26),
                hash,
            };
            if entry.resource.flags & resource_flag::FREE != 0 {
                lookup.push(entry);
                continue;
            }
            if entry.resource.flags & resource_flag::METADATA != 0 {
                metadata.push(i);
            } else {
                by_hash.entry(hash).or_insert(i);
            }
            lookup.push(entry);
        }
        let images = header.image_count as usize;
        if metadata.len() < images {
            return Err(WimError::Invalid);
        }
        let mut archive = WimArchive { data, header, lookup, by_hash, entries: Vec::new() };
        for (k, &li) in metadata.iter().take(images).enumerate() {
            let e = archive.lookup[li];
            let md = read_resource(data, &archive.header, &e.resource, limits.max_metadata_size)?;
            if sha1(&md) != e.hash {
                return Err(WimError::HashMismatch);
            }
            archive.load_image(&md, k as u32 + 1, limits)?;
        }
        Ok(archive)
    }

    fn stream_size(&self, hash: &[u8; 20]) -> R<u64> {
        if *hash == ZERO_HASH {
            return Ok(0);
        }
        let &i = self.by_hash.get(hash).ok_or(WimError::NotFound)?;
        Ok(self.lookup[i].resource.original_size)
    }

    fn load_image(&mut self, md: &[u8], image: u32, limits: WimLimits) -> R<()> {
        if md.len() < 8 {
            return Err(WimError::Invalid);
        }
        let mut sec_len = u64::from(le32(md, 0));
        if sec_len == 0 {
            sec_len = 8;
        }
        if sec_len < 8 || sec_len > md.len() as u64 {
            return Err(WimError::Invalid);
        }
        let root_off = align8(sec_len).ok_or(WimError::Invalid)? as usize;
        let root = parse_dentry(md, root_off)?.ok_or(WimError::Invalid)?;
        if root.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(WimError::Invalid);
        }
        let mut visited = HashSet::new();
        // Work stack: (list offset, path prefix, depth).
        let mut stack: Vec<(u64, String, usize)> = Vec::new();
        if root.subdir_offset != 0 {
            stack.push((root.subdir_offset, String::new(), 1));
        }
        while let Some((list, prefix, depth)) = stack.pop() {
            if depth > limits.max_depth {
                return Err(WimError::LimitExceeded);
            }
            if !visited.insert(list) {
                return Err(WimError::Invalid);
            }
            let mut off = usize::try_from(list).map_err(|_| WimError::Invalid)?;
            let mut children = Vec::new();
            while let Some(d) = parse_dentry(md, off)? {
                off = d.next;
                if !valid_component(&d.name) {
                    return Err(WimError::Invalid);
                }
                if self.entries.len() >= limits.max_entries {
                    return Err(WimError::LimitExceeded);
                }
                let path = if prefix.is_empty() { d.name.clone() } else { format!("{prefix}/{}", d.name) };
                // The unnamed stream may live in a stream entry with an
                // empty name.
                let mut hash = d.hash;
                let mut named_streams = Vec::new();
                for (sname, sh) in &d.streams {
                    if sname.is_empty() {
                        if hash == ZERO_HASH {
                            hash = *sh;
                        }
                    } else {
                        named_streams.push(WimStream { name: sname.clone(), size: self.stream_size(sh)?, hash: *sh });
                    }
                }
                let is_dir = d.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
                let is_reparse = d.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
                self.entries.push(WimEntry {
                    image,
                    path: path.clone(),
                    attributes: d.attributes,
                    size: self.stream_size(&hash)?,
                    hash,
                    creation_time: d.creation_time,
                    last_access_time: d.last_access_time,
                    last_write_time: d.last_write_time,
                    reparse_tag: if is_reparse { Some(d.reparse_tag) } else { None },
                    hard_link_group: if is_reparse { 0 } else { d.hard_link_group },
                    named_streams,
                });
                if is_dir && d.subdir_offset != 0 {
                    children.push((d.subdir_offset, path, depth + 1));
                }
            }
            // Preserve directory order: process children in listing order.
            while let Some(c) = children.pop() {
                stack.push(c);
            }
        }
        Ok(())
    }

    pub fn header(&self) -> &WimHeader {
        &self.header
    }

    pub fn lookup_table(&self) -> &[LookupEntry] {
        &self.lookup
    }

    /// Directory entries of all images (directory-tree order, per image).
    pub fn entries(&self) -> &[WimEntry] {
        &self.entries
    }

    pub fn image_count(&self) -> u32 {
        self.header.image_count
    }

    /// Decode the stream with SHA-1 `hash` and verify it. `max_output`
    /// bounds the decoded size. The all-zero hash is the empty stream.
    pub fn read_stream(&self, hash: &[u8; 20], max_output: u64) -> R<Vec<u8>> {
        if *hash == ZERO_HASH {
            return Ok(Vec::new());
        }
        let &i = self.by_hash.get(hash).ok_or(WimError::NotFound)?;
        let data = read_resource(self.data, &self.header, &self.lookup[i].resource, max_output)?;
        if sha1(&data) != *hash {
            return Err(WimError::HashMismatch);
        }
        Ok(data)
    }

    /// Unnamed data stream of entry `index` (reparse data for reparse
    /// points, empty for directories).
    pub fn read_entry(&self, index: usize, max_output: u64) -> R<Vec<u8>> {
        let e = self.entries.get(index).ok_or(WimError::NotFound)?;
        self.read_stream(&e.hash, max_output)
    }

    /// The XML data resource decoded from UTF-16LE (BOM stripped; unpaired
    /// surrogates become U+FFFD). Empty when the WIM has none.
    pub fn xml(&self, max_size: u64) -> R<String> {
        let r = &self.header.xml_data;
        if r.size == 0 {
            return Ok(String::new());
        }
        let raw = read_resource(self.data, &self.header, r, max_size)?;
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let units = units.strip_prefix(&[0xFEFF]).unwrap_or(&units);
        Ok(String::from_utf16_lossy(units))
    }
}

/// Symbolic-link target from WIM reparse data (the reparse buffer without
/// its 8-byte tag/length header, [MS-FSCC] 2.1.2.4). Returns the print name
/// (or substitute name when empty) with `\` turned into `/`, and whether
/// the link is relative (`SYMLINK_FLAG_RELATIVE`).
pub fn symlink_target(reparse_data: &[u8]) -> R<(String, bool)> {
    if reparse_data.len() < 12 {
        return Err(WimError::Invalid);
    }
    let sub_off = usize::from(le16(reparse_data, 0));
    let sub_len = usize::from(le16(reparse_data, 2));
    let print_off = usize::from(le16(reparse_data, 4));
    let print_len = usize::from(le16(reparse_data, 6));
    let flags = le32(reparse_data, 8);
    let buf = &reparse_data[12..];
    let (off, len) = if print_len > 0 { (print_off, print_len) } else { (sub_off, sub_len) };
    let end = off.checked_add(len).ok_or(WimError::Invalid)?;
    if end > buf.len() || len == 0 {
        return Err(WimError::Invalid);
    }
    let name = utf16_name(buf, off, len)?;
    Ok((name.replace('\\', "/"), flags & 1 != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components() {
        assert!(valid_component("a.txt"));
        assert!(!valid_component(".."));
        assert!(!valid_component("."));
        assert!(!valid_component(""));
        assert!(!valid_component("a/b"));
        assert!(!valid_component("a\\b"));
        assert!(!valid_component("a\0"));
    }

    #[test]
    fn symlink_reparse() {
        let target: Vec<u8> = "..\\x".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut d = Vec::new();
        for v in [0u16, 8, 8, 8] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&target);
        d.extend_from_slice(&target);
        assert_eq!(symlink_target(&d).unwrap(), ("../x".to_string(), true));
        assert_eq!(symlink_target(&d[..14]), Err(WimError::Invalid));
        assert_eq!(symlink_target(&d[..5]), Err(WimError::Invalid));
    }
}
