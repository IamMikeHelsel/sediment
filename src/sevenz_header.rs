// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z archive structure layer: signature header, next-header CRC, and the
//! property-ID header tree (PackInfo, UnpackInfo, SubStreamsInfo, FilesInfo),
//! including encoded (packed) headers resolved through a pluggable
//! [`FolderDecoder`].
//!
//! Spec sources: the public "7z Format" description (`7zFormat.txt`, shipped
//! in the LZMA SDK `DOC/` directory and in the 7-Zip documentation), which
//! defines the signature header, the `NUMBER` encoding, the property IDs and
//! the record layouts. Windows FILETIME and file-attribute semantics follow the
//! public Win32 documentation. No 7-Zip source code was consulted.
//!
//! Everything is slice-in / `Vec`-out, every count is checked against
//! [`SevenZLimits`] before anything is allocated, and all arithmetic is
//! checked. Malformed input returns `Err`, never panics.

use std::borrow::Cow;

use crate::crc32::crc32;

/// The six signature bytes `'7' 'z' BC AF 27 1C`.
pub const SIGNATURE: [u8; 6] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
/// Size of the fixed signature header.
pub const SIGNATURE_HEADER_SIZE: usize = 32;

/// Property IDs from the 7z format description.
pub mod property_id {
    pub const END: u8 = 0x00;
    pub const HEADER: u8 = 0x01;
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    pub const ADDITIONAL_STREAMS_INFO: u8 = 0x03;
    pub const MAIN_STREAMS_INFO: u8 = 0x04;
    pub const FILES_INFO: u8 = 0x05;
    pub const PACK_INFO: u8 = 0x06;
    pub const UNPACK_INFO: u8 = 0x07;
    pub const SUBSTREAMS_INFO: u8 = 0x08;
    pub const SIZE: u8 = 0x09;
    pub const CRC: u8 = 0x0a;
    pub const FOLDER: u8 = 0x0b;
    pub const CODERS_UNPACK_SIZE: u8 = 0x0c;
    pub const NUM_UNPACK_STREAM: u8 = 0x0d;
    pub const EMPTY_STREAM: u8 = 0x0e;
    pub const EMPTY_FILE: u8 = 0x0f;
    pub const ANTI: u8 = 0x10;
    pub const NAME: u8 = 0x11;
    pub const CTIME: u8 = 0x12;
    pub const ATIME: u8 = 0x13;
    pub const MTIME: u8 = 0x14;
    pub const WIN_ATTRIBUTES: u8 = 0x15;
    pub const COMMENT: u8 = 0x16;
    pub const ENCODED_HEADER: u8 = 0x17;
    pub const START_POS: u8 = 0x18;
    pub const DUMMY: u8 = 0x19;
}

/// Well-known coder method IDs.
pub mod method_id {
    pub const COPY: &[u8] = &[0x00];
    pub const LZMA: &[u8] = &[0x03, 0x01, 0x01];
    pub const LZMA2: &[u8] = &[0x21];
}

/// Windows `FILE_ATTRIBUTE_DIRECTORY`.
pub const ATTR_DIRECTORY: u32 = 0x10;
/// Bit set by Unix archivers when the high 16 bits carry `st_mode`.
pub const ATTR_UNIX_EXTENSION: u32 = 0x8000;

/// Errors for the whole 7z read path (header parsing, decoding, extraction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZReadError {
    /// Input ends before a structure is complete.
    UnexpectedEof,
    /// The first six bytes are not the 7z signature.
    InvalidSignature,
    /// Major format version is not 0.
    UnsupportedVersion,
    /// The start-header CRC does not match.
    StartHeaderChecksum,
    /// The next-header CRC does not match.
    HeaderChecksum,
    /// Structurally invalid header data.
    Malformed,
    /// Valid but unsupported feature (external data, alternative methods,
    /// additional streams, multi-stream coders, ...).
    Unsupported,
    /// No decoder for a coder method.
    UnsupportedMethod,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// A file name is not valid UTF-16.
    InvalidName,
    /// A decoder reported corrupt input.
    DecoderFailed,
    /// Decoded or packed data has the wrong size.
    SizeMismatch,
    /// A folder or file CRC does not match.
    DataChecksum,
    /// A packed-stream CRC does not match.
    PackChecksum,
    /// An entry or folder index is out of range.
    IndexOutOfRange,
}

type Result<T> = core::result::Result<T, SevenZReadError>;

/// Pluggable codec hook. Copy is built in; everything else goes here.
///
/// `unpack_size` is the exact number of bytes the coder must produce; the
/// caller verifies the output length afterwards.
pub trait FolderDecoder {
    fn decode(&self, method_id: &[u8], props: &[u8], input: &[u8], unpack_size: u64) -> Result<Vec<u8>>;
}

/// A decoder that knows no methods beyond the built-in Copy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoDecoder;

impl FolderDecoder for NoDecoder {
    fn decode(&self, _method_id: &[u8], _props: &[u8], _input: &[u8], _unpack_size: u64) -> Result<Vec<u8>> {
        Err(SevenZReadError::UnsupportedMethod)
    }
}

/// Explicit caller limits. Every count read from the archive is checked
/// against these before allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZLimits {
    pub max_archive_bytes: usize,
    /// Raw or decoded header size.
    pub max_header_bytes: usize,
    pub max_files: usize,
    pub max_folders: usize,
    pub max_pack_streams: usize,
    pub max_coders_per_folder: usize,
    pub max_streams_per_coder: usize,
    /// Total substreams across all folders.
    pub max_substreams: usize,
    pub max_property_bytes: usize,
    /// Total UTF-16 code units across all names.
    pub max_name_units: usize,
    /// Maximum bytes any single coder or folder may produce.
    pub max_unpack_bytes: u64,
    /// Maximum chain of encoded headers.
    pub max_header_nesting: usize,
}

impl Default for SevenZLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: usize::MAX,
            max_header_bytes: 64 << 20,
            max_files: 1 << 20,
            max_folders: 1 << 20,
            max_pack_streams: 1 << 20,
            max_coders_per_folder: 32,
            max_streams_per_coder: 32,
            max_substreams: 1 << 22,
            max_property_bytes: 1 << 16,
            max_name_units: 1 << 24,
            max_unpack_bytes: 1 << 30,
            max_header_nesting: 4,
        }
    }
}

/// Parsed 32-byte signature header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub next_header_offset: u64,
    pub next_header_size: u64,
    pub next_header_crc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coder {
    pub method_id: Vec<u8>,
    pub num_in_streams: usize,
    pub num_out_streams: usize,
    pub properties: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindPair {
    pub in_index: usize,
    pub out_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub coders: Vec<Coder>,
    pub bind_pairs: Vec<BindPair>,
    /// Folder in-stream indices fed by packed streams, in pack order.
    pub packed_streams: Vec<usize>,
    /// One size per coder out stream (folder-wide numbering).
    pub unpack_sizes: Vec<u64>,
    pub unpack_crc: Option<u32>,
}

impl Folder {
    pub fn num_in_streams(&self) -> usize {
        self.coders.iter().map(|c| c.num_in_streams).sum()
    }
    pub fn num_out_streams(&self) -> usize {
        self.coders.iter().map(|c| c.num_out_streams).sum()
    }
    /// The out stream not consumed by any bind pair (the folder's output).
    pub fn main_out_index(&self) -> Option<usize> {
        (0..self.num_out_streams()).find(|o| !self.bind_pairs.iter().any(|b| b.out_index == *o))
    }
    /// Size of the folder's final output.
    pub fn unpack_size(&self) -> u64 {
        self.main_out_index().and_then(|i| self.unpack_sizes.get(i).copied()).unwrap_or(0)
    }
    fn coder_for_out(&self, out: usize) -> Option<(usize, usize)> {
        let mut base_in = 0usize;
        let mut base_out = 0usize;
        for (i, c) in self.coders.iter().enumerate() {
            if out < base_out + c.num_out_streams {
                return Some((i, base_in));
            }
            base_in += c.num_in_streams;
            base_out += c.num_out_streams;
        }
        None
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackInfo {
    /// Offset of the first packed stream, relative to the end of the
    /// signature header.
    pub pack_pos: u64,
    pub sizes: Vec<u64>,
    pub crcs: Vec<Option<u32>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubStreamsInfo {
    /// Number of substreams (files) per folder.
    pub num_unpack_streams: Vec<usize>,
    /// Flattened substream sizes, folder by folder.
    pub sizes: Vec<u64>,
    /// Flattened substream CRCs, folder by folder.
    pub crcs: Vec<Option<u32>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamsInfo {
    pub pack_info: PackInfo,
    pub folders: Vec<Folder>,
    pub substreams: SubStreamsInfo,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub name: String,
    pub has_stream: bool,
    pub is_dir: bool,
    pub is_empty_file: bool,
    pub is_anti: bool,
    pub attributes: Option<u32>,
    /// Windows FILETIME (100 ns ticks since 1601-01-01 UTC).
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
    pub mtime: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub main_streams: StreamsInfo,
    pub files: Vec<FileInfo>,
}

// ---------------------------------------------------------------------------
// Low-level cursor
// ---------------------------------------------------------------------------

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.p).ok_or(SevenZReadError::UnexpectedEof)?;
        self.p += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(SevenZReadError::UnexpectedEof)?;
        let s = self.b.get(self.p..end).ok_or(SevenZReadError::UnexpectedEof)?;
        self.p = end;
        Ok(s)
    }
    fn u32le(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64le(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn number(&mut self) -> Result<u64> {
        let (v, n) = read_number(&self.b[self.p..])?;
        self.p += n;
        Ok(v)
    }
    /// A NUMBER used as a count/size, bounded by `max`.
    fn count(&mut self, max: usize) -> Result<usize> {
        let v = self.number()?;
        let v = usize::try_from(v).map_err(|_| SevenZReadError::LimitExceeded)?;
        if v > max {
            return Err(SevenZReadError::LimitExceeded);
        }
        Ok(v)
    }
    /// A NUMBER used as an index, must be `< bound`.
    fn index(&mut self, bound: usize) -> Result<usize> {
        let v = self.number()?;
        match usize::try_from(v) {
            Ok(v) if v < bound => Ok(v),
            _ => Err(SevenZReadError::Malformed),
        }
    }
}

/// Decode a 7z `NUMBER` (1..=9 bytes). Returns the value and bytes consumed.
pub fn read_number(bytes: &[u8]) -> Result<(u64, usize)> {
    let first = *bytes.first().ok_or(SevenZReadError::UnexpectedEof)?;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 && first & mask != 0 {
        extra += 1;
        mask >>= 1;
    }
    if bytes.len() < 1 + extra {
        return Err(SevenZReadError::UnexpectedEof);
    }
    let mut value = 0u64;
    for i in 0..extra {
        value |= (bytes[1 + i] as u64) << (8 * i);
    }
    if extra < 8 {
        let high = (first & mask.wrapping_sub(1)) as u64;
        value |= high << (8 * extra);
    }
    Ok((value, 1 + extra))
}

fn alloc_vec<T: Clone>(n: usize, fill: T) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| SevenZReadError::Allocation)?;
    v.resize(n, fill);
    Ok(v)
}

fn read_bits(cur: &mut Cur<'_>, n: usize) -> Result<Vec<bool>> {
    let nbytes = n.div_ceil(8);
    let raw = cur.take(nbytes)?;
    let mut v = alloc_vec(n, false)?;
    for (i, slot) in v.iter_mut().enumerate() {
        *slot = raw[i / 8] & (0x80 >> (i % 8)) != 0;
    }
    Ok(v)
}

fn read_optional_bits(cur: &mut Cur<'_>, n: usize) -> Result<Vec<bool>> {
    let all = cur.byte()?;
    if all != 0 { alloc_vec(n, true) } else { read_bits(cur, n) }
}

fn read_digests(cur: &mut Cur<'_>, n: usize) -> Result<Vec<Option<u32>>> {
    let defined = read_optional_bits(cur, n)?;
    let mut out = alloc_vec(n, None)?;
    for (slot, d) in out.iter_mut().zip(defined) {
        if d {
            *slot = Some(cur.u32le()?);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Signature header
// ---------------------------------------------------------------------------

/// Parse and CRC-check the 32-byte signature header. Accepts major version 0
/// with any minor version.
pub fn parse_signature_header(bytes: &[u8]) -> Result<SignatureHeader> {
    if bytes.len() < 6 {
        return Err(SevenZReadError::UnexpectedEof);
    }
    if bytes[..6] != SIGNATURE {
        return Err(SevenZReadError::InvalidSignature);
    }
    if bytes.len() < SIGNATURE_HEADER_SIZE {
        return Err(SevenZReadError::UnexpectedEof);
    }
    if bytes[6] != 0 {
        return Err(SevenZReadError::UnsupportedVersion);
    }
    let mut c = Cur::new(&bytes[8..SIGNATURE_HEADER_SIZE]);
    let stored = c.u32le()?;
    if crc32(&bytes[12..SIGNATURE_HEADER_SIZE]) != stored {
        return Err(SevenZReadError::StartHeaderChecksum);
    }
    Ok(SignatureHeader {
        major_version: bytes[6],
        minor_version: bytes[7],
        next_header_offset: c.u64le()?,
        next_header_size: c.u64le()?,
        next_header_crc: c.u32le()?,
    })
}

/// Locate and CRC-check the next-header bytes.
pub fn next_header_slice<'a>(bytes: &'a [u8], sig: &SignatureHeader, limits: &SevenZLimits) -> Result<&'a [u8]> {
    let size = usize::try_from(sig.next_header_size).map_err(|_| SevenZReadError::LimitExceeded)?;
    if size > limits.max_header_bytes {
        return Err(SevenZReadError::LimitExceeded);
    }
    let start = (SIGNATURE_HEADER_SIZE as u64)
        .checked_add(sig.next_header_offset)
        .ok_or(SevenZReadError::UnexpectedEof)?;
    let end = start.checked_add(sig.next_header_size).ok_or(SevenZReadError::UnexpectedEof)?;
    if end > bytes.len() as u64 {
        return Err(SevenZReadError::UnexpectedEof);
    }
    let s = &bytes[start as usize..end as usize];
    if crc32(s) != sig.next_header_crc {
        return Err(SevenZReadError::HeaderChecksum);
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Streams info
// ---------------------------------------------------------------------------

fn parse_pack_info(cur: &mut Cur<'_>, limits: &SevenZLimits) -> Result<PackInfo> {
    let pack_pos = cur.number()?;
    let n = cur.count(limits.max_pack_streams)?;
    if n > cur.remaining() {
        // Every pack stream needs at least one size byte.
        return Err(SevenZReadError::UnexpectedEof);
    }
    let mut sizes = None;
    let mut crcs = None;
    loop {
        match cur.byte()? {
            property_id::END => break,
            property_id::SIZE if sizes.is_none() => {
                let mut v = alloc_vec(n, 0u64)?;
                for s in v.iter_mut() {
                    *s = cur.number()?;
                }
                sizes = Some(v);
            }
            property_id::CRC if crcs.is_none() => crcs = Some(read_digests(cur, n)?),
            _ => return Err(SevenZReadError::Malformed),
        }
    }
    let sizes = sizes.ok_or(SevenZReadError::Malformed)?;
    let crcs = match crcs {
        Some(c) => c,
        None => alloc_vec(n, None)?,
    };
    Ok(PackInfo { pack_pos, sizes, crcs })
}

fn parse_folder(cur: &mut Cur<'_>, limits: &SevenZLimits) -> Result<Folder> {
    let num_coders = cur.count(limits.max_coders_per_folder)?;
    if num_coders == 0 {
        return Err(SevenZReadError::Malformed);
    }
    let mut coders = Vec::new();
    coders.try_reserve_exact(num_coders).map_err(|_| SevenZReadError::Allocation)?;
    let mut in_total = 0usize;
    let mut out_total = 0usize;
    for _ in 0..num_coders {
        let flags = cur.byte()?;
        if flags & 0xc0 != 0 {
            // bit 7: alternative methods (never written), bit 6: reserved.
            return Err(SevenZReadError::Unsupported);
        }
        let id_size = (flags & 0x0f) as usize;
        let method_id = cur.take(id_size)?.to_vec();
        let (ni, no) = if flags & 0x10 != 0 {
            (cur.count(limits.max_streams_per_coder)?, cur.count(limits.max_streams_per_coder)?)
        } else {
            (1, 1)
        };
        let properties = if flags & 0x20 != 0 {
            let n = cur.count(limits.max_property_bytes)?;
            cur.take(n)?.to_vec()
        } else {
            Vec::new()
        };
        in_total = in_total.checked_add(ni).ok_or(SevenZReadError::LimitExceeded)?;
        out_total = out_total.checked_add(no).ok_or(SevenZReadError::LimitExceeded)?;
        coders.push(Coder { method_id, num_in_streams: ni, num_out_streams: no, properties });
    }
    if out_total == 0 {
        return Err(SevenZReadError::Malformed);
    }
    let num_bind = out_total - 1;
    let num_packed = in_total.checked_sub(num_bind).ok_or(SevenZReadError::Malformed)?;
    if num_packed == 0 {
        return Err(SevenZReadError::Malformed);
    }
    let mut in_used = alloc_vec(in_total, false)?;
    let mut out_used = alloc_vec(out_total, false)?;
    let mut bind_pairs = Vec::new();
    bind_pairs.try_reserve_exact(num_bind).map_err(|_| SevenZReadError::Allocation)?;
    for _ in 0..num_bind {
        let in_index = cur.index(in_total)?;
        let out_index = cur.index(out_total)?;
        if in_used[in_index] || out_used[out_index] {
            return Err(SevenZReadError::Malformed);
        }
        in_used[in_index] = true;
        out_used[out_index] = true;
        bind_pairs.push(BindPair { in_index, out_index });
    }
    let mut packed_streams = Vec::new();
    packed_streams.try_reserve_exact(num_packed).map_err(|_| SevenZReadError::Allocation)?;
    if num_packed == 1 {
        let free = in_used.iter().position(|u| !u).ok_or(SevenZReadError::Malformed)?;
        in_used[free] = true;
        packed_streams.push(free);
    } else {
        for _ in 0..num_packed {
            let i = cur.index(in_total)?;
            if in_used[i] {
                return Err(SevenZReadError::Malformed);
            }
            in_used[i] = true;
            packed_streams.push(i);
        }
    }
    Ok(Folder { coders, bind_pairs, packed_streams, unpack_sizes: Vec::new(), unpack_crc: None })
}

fn parse_unpack_info(cur: &mut Cur<'_>, limits: &SevenZLimits) -> Result<Vec<Folder>> {
    if cur.byte()? != property_id::FOLDER {
        return Err(SevenZReadError::Malformed);
    }
    let n = cur.count(limits.max_folders)?;
    if n > cur.remaining() {
        return Err(SevenZReadError::UnexpectedEof);
    }
    if cur.byte()? != 0 {
        return Err(SevenZReadError::Unsupported); // external folder data
    }
    let mut folders = Vec::new();
    folders.try_reserve_exact(n).map_err(|_| SevenZReadError::Allocation)?;
    for _ in 0..n {
        folders.push(parse_folder(cur, limits)?);
    }
    if cur.byte()? != property_id::CODERS_UNPACK_SIZE {
        return Err(SevenZReadError::Malformed);
    }
    for f in folders.iter_mut() {
        let outs = f.num_out_streams();
        let mut v = alloc_vec(outs, 0u64)?;
        for s in v.iter_mut() {
            *s = cur.number()?;
        }
        f.unpack_sizes = v;
    }
    let mut seen_crc = false;
    loop {
        match cur.byte()? {
            property_id::END => break,
            property_id::CRC if !seen_crc => {
                seen_crc = true;
                let d = read_digests(cur, n)?;
                for (f, c) in folders.iter_mut().zip(d) {
                    f.unpack_crc = c;
                }
            }
            _ => return Err(SevenZReadError::Malformed),
        }
    }
    Ok(folders)
}

fn default_substreams(folders: &[Folder]) -> Result<SubStreamsInfo> {
    let mut s = SubStreamsInfo {
        num_unpack_streams: alloc_vec(folders.len(), 1usize)?,
        sizes: alloc_vec(folders.len(), 0u64)?,
        crcs: alloc_vec(folders.len(), None)?,
    };
    for (i, f) in folders.iter().enumerate() {
        s.sizes[i] = f.unpack_size();
        s.crcs[i] = f.unpack_crc;
    }
    Ok(s)
}

fn parse_substreams_info(cur: &mut Cur<'_>, folders: &[Folder], limits: &SevenZLimits) -> Result<SubStreamsInfo> {
    let mut nums = alloc_vec(folders.len(), 1usize)?;
    let mut total = folders.len();
    let mut t = cur.byte()?;
    if t == property_id::NUM_UNPACK_STREAM {
        total = 0;
        for n in nums.iter_mut() {
            *n = cur.count(limits.max_substreams)?;
            total = total.checked_add(*n).ok_or(SevenZReadError::LimitExceeded)?;
            if total > limits.max_substreams {
                return Err(SevenZReadError::LimitExceeded);
            }
        }
        t = cur.byte()?;
    }
    if total > limits.max_substreams {
        return Err(SevenZReadError::LimitExceeded);
    }
    let has_sizes = t == property_id::SIZE;
    if has_sizes {
        // Each explicit size takes at least one byte.
        let explicit = total.saturating_sub(folders.len());
        if explicit > cur.remaining() {
            return Err(SevenZReadError::UnexpectedEof);
        }
    }
    let mut sizes = Vec::new();
    sizes.try_reserve_exact(total).map_err(|_| SevenZReadError::Allocation)?;
    for (f, &n) in folders.iter().zip(nums.iter()) {
        if n == 0 {
            continue;
        }
        let unpack = f.unpack_size();
        let mut sum = 0u64;
        if n > 1 && !has_sizes {
            return Err(SevenZReadError::Malformed);
        }
        for _ in 1..n {
            let s = cur.number()?;
            sum = sum.checked_add(s).ok_or(SevenZReadError::Malformed)?;
            sizes.push(s);
        }
        let last = unpack.checked_sub(sum).ok_or(SevenZReadError::Malformed)?;
        sizes.push(last);
    }
    if has_sizes {
        t = cur.byte()?;
    }
    let mut num_digests = 0usize;
    for (f, &n) in folders.iter().zip(nums.iter()) {
        if !(n == 1 && f.unpack_crc.is_some()) {
            num_digests += n;
        }
    }
    let mut digests = None;
    loop {
        match t {
            property_id::END => break,
            property_id::CRC if digests.is_none() => digests = Some(read_digests(cur, num_digests)?),
            _ => return Err(SevenZReadError::Malformed),
        }
        t = cur.byte()?;
    }
    let mut crcs = Vec::new();
    crcs.try_reserve_exact(total).map_err(|_| SevenZReadError::Allocation)?;
    let mut di = 0usize;
    for (f, &n) in folders.iter().zip(nums.iter()) {
        if n == 1 && f.unpack_crc.is_some() {
            crcs.push(f.unpack_crc);
        } else {
            for _ in 0..n {
                let c = digests.as_ref().and_then(|d| d.get(di).copied()).flatten();
                di += 1;
                crcs.push(c);
            }
        }
    }
    Ok(SubStreamsInfo { num_unpack_streams: nums, sizes, crcs })
}

fn parse_streams_info(cur: &mut Cur<'_>, limits: &SevenZLimits) -> Result<StreamsInfo> {
    let mut info = StreamsInfo::default();
    let mut t = cur.byte()?;
    if t == property_id::PACK_INFO {
        info.pack_info = parse_pack_info(cur, limits)?;
        t = cur.byte()?;
    }
    if t == property_id::UNPACK_INFO {
        info.folders = parse_unpack_info(cur, limits)?;
        t = cur.byte()?;
    }
    if t == property_id::SUBSTREAMS_INFO {
        info.substreams = parse_substreams_info(cur, &info.folders, limits)?;
        t = cur.byte()?;
    } else {
        info.substreams = default_substreams(&info.folders)?;
    }
    if t != property_id::END {
        return Err(SevenZReadError::Malformed);
    }
    let used: usize = info.folders.iter().map(|f| f.packed_streams.len()).sum();
    if used != info.pack_info.sizes.len() {
        return Err(SevenZReadError::Malformed);
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// Files info
// ---------------------------------------------------------------------------

fn read_times(data: &[u8], n: usize) -> Result<Vec<Option<u64>>> {
    let mut c = Cur::new(data);
    let defined = read_optional_bits(&mut c, n)?;
    if c.byte()? != 0 {
        return Err(SevenZReadError::Unsupported);
    }
    let mut out = alloc_vec(n, None)?;
    for (slot, d) in out.iter_mut().zip(defined) {
        if d {
            *slot = Some(c.u64le()?);
        }
    }
    Ok(out)
}

fn read_attributes(data: &[u8], n: usize) -> Result<Vec<Option<u32>>> {
    let mut c = Cur::new(data);
    let defined = read_optional_bits(&mut c, n)?;
    if c.byte()? != 0 {
        return Err(SevenZReadError::Unsupported);
    }
    let mut out = alloc_vec(n, None)?;
    for (slot, d) in out.iter_mut().zip(defined) {
        if d {
            *slot = Some(c.u32le()?);
        }
    }
    Ok(out)
}

fn read_names(data: &[u8], n: usize, limits: &SevenZLimits) -> Result<Vec<String>> {
    let mut c = Cur::new(data);
    if c.byte()? != 0 {
        return Err(SevenZReadError::Unsupported);
    }
    let body = &data[1..];
    if !body.len().is_multiple_of(2) {
        return Err(SevenZReadError::Malformed);
    }
    if body.len() / 2 > limits.max_name_units {
        return Err(SevenZReadError::LimitExceeded);
    }
    let mut names = Vec::new();
    names.try_reserve_exact(n).map_err(|_| SevenZReadError::Allocation)?;
    let mut units = body.as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p));
    for _ in 0..n {
        let mut s = String::new();
        let mut terminated = false;
        let it = core::iter::from_fn(|| {
            let u = units.next()?;
            if u == 0 {
                terminated = true;
                None
            } else {
                Some(u)
            }
        });
        for ch in char::decode_utf16(it) {
            let ch = ch.map_err(|_| SevenZReadError::InvalidName)?;
            s.try_reserve(ch.len_utf8()).map_err(|_| SevenZReadError::Allocation)?;
            s.push(ch);
        }
        if !terminated {
            return Err(SevenZReadError::Malformed);
        }
        names.push(s);
    }
    if units.next().is_some() {
        return Err(SevenZReadError::Malformed);
    }
    Ok(names)
}

fn parse_files_info(cur: &mut Cur<'_>, limits: &SevenZLimits) -> Result<Vec<FileInfo>> {
    let n = cur.count(limits.max_files)?;
    // Every file needs at least a two-byte name terminator.
    if n > cur.remaining() / 2 {
        return Err(SevenZReadError::UnexpectedEof);
    }
    let mut empty_stream: Option<Vec<bool>> = None;
    let mut empty_file: Option<Vec<bool>> = None;
    let mut anti: Option<Vec<bool>> = None;
    let mut names: Option<Vec<String>> = None;
    let mut attrs: Option<Vec<Option<u32>>> = None;
    let mut ctime: Option<Vec<Option<u64>>> = None;
    let mut atime: Option<Vec<Option<u64>>> = None;
    let mut mtime: Option<Vec<Option<u64>>> = None;
    let mut num_empty = 0usize;
    loop {
        let t = cur.byte()?;
        if t == property_id::END {
            break;
        }
        let size = cur.number()?;
        let size = usize::try_from(size).map_err(|_| SevenZReadError::UnexpectedEof)?;
        let data = cur.take(size)?;
        let dup = || SevenZReadError::Malformed;
        match t {
            property_id::EMPTY_STREAM => {
                if empty_stream.is_some() {
                    return Err(dup());
                }
                let v = read_bits(&mut Cur::new(data), n)?;
                num_empty = v.iter().filter(|b| **b).count();
                empty_stream = Some(v);
            }
            property_id::EMPTY_FILE | property_id::ANTI => {
                if empty_stream.is_none() {
                    return Err(SevenZReadError::Malformed);
                }
                let slot = if t == property_id::EMPTY_FILE { &mut empty_file } else { &mut anti };
                if slot.is_some() {
                    return Err(dup());
                }
                *slot = Some(read_bits(&mut Cur::new(data), num_empty)?);
            }
            property_id::NAME => {
                if names.is_some() {
                    return Err(dup());
                }
                names = Some(read_names(data, n, limits)?);
            }
            property_id::CTIME | property_id::ATIME | property_id::MTIME => {
                let slot = match t {
                    property_id::CTIME => &mut ctime,
                    property_id::ATIME => &mut atime,
                    _ => &mut mtime,
                };
                if slot.is_some() {
                    return Err(dup());
                }
                *slot = Some(read_times(data, n)?);
            }
            property_id::WIN_ATTRIBUTES => {
                if attrs.is_some() {
                    return Err(dup());
                }
                attrs = Some(read_attributes(data, n)?);
            }
            // kDummy padding, kStartPos, kComment and unknown properties are
            // skipped; their size is already bounded by the header.
            _ => {}
        }
    }
    if n > 0 && names.is_none() {
        return Err(SevenZReadError::Malformed);
    }
    let names = names.unwrap_or_default();
    let mut files = Vec::new();
    files.try_reserve_exact(n).map_err(|_| SevenZReadError::Allocation)?;
    let mut empty_idx = 0usize;
    for (i, name) in names.into_iter().enumerate() {
        let is_empty_stream = empty_stream.as_ref().is_some_and(|v| v[i]);
        let (is_empty_file, is_anti) = if is_empty_stream {
            let e = empty_file.as_ref().is_some_and(|v| v[empty_idx]);
            let a = anti.as_ref().is_some_and(|v| v[empty_idx]);
            empty_idx += 1;
            (e, a)
        } else {
            (false, false)
        };
        files.push(FileInfo {
            name,
            has_stream: !is_empty_stream,
            is_dir: is_empty_stream && !is_empty_file,
            is_empty_file,
            is_anti,
            attributes: attrs.as_ref().and_then(|v| v[i]),
            ctime: ctime.as_ref().and_then(|v| v[i]),
            atime: atime.as_ref().and_then(|v| v[i]),
            mtime: mtime.as_ref().and_then(|v| v[i]),
        });
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Parse a plain (not encoded) header. `bytes` starts with `kHeader`.
pub fn parse_plain_header(bytes: &[u8], limits: &SevenZLimits) -> Result<Header> {
    if bytes.len() > limits.max_header_bytes {
        return Err(SevenZReadError::LimitExceeded);
    }
    let mut cur = Cur::new(bytes);
    if cur.byte()? != property_id::HEADER {
        return Err(SevenZReadError::Malformed);
    }
    let mut t = cur.byte()?;
    if t == property_id::ARCHIVE_PROPERTIES {
        loop {
            let pt = cur.byte()?;
            if pt == property_id::END {
                break;
            }
            let size = usize::try_from(cur.number()?).map_err(|_| SevenZReadError::UnexpectedEof)?;
            cur.take(size)?;
        }
        t = cur.byte()?;
    }
    if t == property_id::ADDITIONAL_STREAMS_INFO {
        return Err(SevenZReadError::Unsupported);
    }
    let mut header = Header::default();
    if t == property_id::MAIN_STREAMS_INFO {
        header.main_streams = parse_streams_info(&mut cur, limits)?;
        t = cur.byte()?;
    }
    if t == property_id::FILES_INFO {
        header.files = parse_files_info(&mut cur, limits)?;
        t = cur.byte()?;
    }
    if t != property_id::END {
        return Err(SevenZReadError::Malformed);
    }
    let with_stream = header.files.iter().filter(|f| f.has_stream).count();
    if with_stream != header.main_streams.substreams.sizes.len() {
        return Err(SevenZReadError::Malformed);
    }
    Ok(header)
}

/// Parse the streams info that follows `kEncodedHeader`. `bytes` starts with
/// `kEncodedHeader`.
pub fn parse_encoded_header_info(bytes: &[u8], limits: &SevenZLimits) -> Result<StreamsInfo> {
    let mut cur = Cur::new(bytes);
    if cur.byte()? != property_id::ENCODED_HEADER {
        return Err(SevenZReadError::Malformed);
    }
    parse_streams_info(&mut cur, limits)
}

/// Absolute byte ranges of every packed stream.
pub fn pack_stream_ranges(archive_len: usize, info: &PackInfo) -> Result<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    out.try_reserve_exact(info.sizes.len()).map_err(|_| SevenZReadError::Allocation)?;
    let mut pos = (SIGNATURE_HEADER_SIZE as u64).checked_add(info.pack_pos).ok_or(SevenZReadError::UnexpectedEof)?;
    for &s in &info.sizes {
        let end = pos.checked_add(s).ok_or(SevenZReadError::UnexpectedEof)?;
        if end > archive_len as u64 {
            return Err(SevenZReadError::UnexpectedEof);
        }
        out.push((pos as usize, end as usize));
        pos = end;
    }
    Ok(out)
}

/// Index of the first packed stream used by each folder.
fn folder_first_pack(info: &StreamsInfo, folder_index: usize) -> Result<usize> {
    let mut first = 0usize;
    for f in info.folders.iter().take(folder_index) {
        first += f.packed_streams.len();
    }
    Ok(first)
}

/// One coder input stream: a packed stream, or the decoded output of the
/// coder bound to it.
fn coder_input<'p>(
    folder: &Folder,
    in_index: usize,
    packs: &[&'p [u8]],
    decoder: &dyn FolderDecoder,
    limits: &SevenZLimits,
    depth: usize,
) -> Result<Cow<'p, [u8]>> {
    if let Some(k) = folder.packed_streams.iter().position(|&p| p == in_index) {
        return Ok(Cow::Borrowed(packs.get(k).copied().ok_or(SevenZReadError::Malformed)?));
    }
    let bp = folder.bind_pairs.iter().find(|b| b.in_index == in_index).ok_or(SevenZReadError::Malformed)?;
    Ok(Cow::Owned(decode_out(folder, bp.out_index, packs, decoder, limits, depth + 1)?))
}

fn decode_out(
    folder: &Folder,
    out_index: usize,
    packs: &[&[u8]],
    decoder: &dyn FolderDecoder,
    limits: &SevenZLimits,
    depth: usize,
) -> Result<Vec<u8>> {
    if depth > folder.coders.len() {
        return Err(SevenZReadError::Malformed);
    }
    let (ci, first_in) = folder.coder_for_out(out_index).ok_or(SevenZReadError::Malformed)?;
    let coder = &folder.coders[ci];
    if coder.num_out_streams != 1 || coder.num_in_streams == 0 {
        return Err(SevenZReadError::Unsupported);
    }
    let size = *folder.unpack_sizes.get(out_index).ok_or(SevenZReadError::Malformed)?;
    if size > limits.max_unpack_bytes {
        return Err(SevenZReadError::LimitExceeded);
    }
    if coder.num_in_streams != 1 {
        // Multi-input coder graph (BCJ2): resolve every input stream, each
        // either a packed stream or the output of another coder via a bind pair.
        if coder.method_id != crate::bcj2::BCJ2_METHOD_ID_BYTES || coder.num_in_streams != 4 {
            return Err(SevenZReadError::Unsupported);
        }
        let mut inputs: Vec<Cow<'_, [u8]>> = Vec::new();
        inputs.try_reserve_exact(4).map_err(|_| SevenZReadError::Allocation)?;
        for k in 0..4 {
            inputs.push(coder_input(folder, first_in + k, packs, decoder, limits, depth)?);
        }
        let size = usize::try_from(size).map_err(|_| SevenZReadError::LimitExceeded)?;
        return crate::bcj2::bcj2_decode(&inputs[0], &inputs[1], &inputs[2], &inputs[3], size).map_err(|e| match e {
            crate::bcj2::Bcj2Error::Allocation => SevenZReadError::Allocation,
            _ => SevenZReadError::DecoderFailed,
        });
    }
    let input = coder_input(folder, first_in, packs, decoder, limits, depth)?;
    let input: &[u8] = &input;
    let out = if coder.method_id == method_id::COPY {
        if input.len() as u64 != size {
            return Err(SevenZReadError::SizeMismatch);
        }
        let mut v = Vec::new();
        v.try_reserve_exact(input.len()).map_err(|_| SevenZReadError::Allocation)?;
        v.extend_from_slice(input);
        v
    } else {
        decoder.decode(&coder.method_id, &coder.properties, input, size)?
    };
    if out.len() as u64 != size {
        return Err(SevenZReadError::SizeMismatch);
    }
    Ok(out)
}

/// Decode one folder of `info` from the archive bytes, verifying packed-stream
/// CRCs and the folder unpack CRC when present.
pub fn decode_folder(
    archive: &[u8],
    info: &StreamsInfo,
    folder_index: usize,
    decoder: &dyn FolderDecoder,
    limits: &SevenZLimits,
) -> Result<Vec<u8>> {
    let folder = info.folders.get(folder_index).ok_or(SevenZReadError::IndexOutOfRange)?;
    let ranges = pack_stream_ranges(archive.len(), &info.pack_info)?;
    let first = folder_first_pack(info, folder_index)?;
    let mut packs: Vec<&[u8]> = Vec::new();
    packs.try_reserve_exact(folder.packed_streams.len()).map_err(|_| SevenZReadError::Allocation)?;
    for k in 0..folder.packed_streams.len() {
        let idx = first.checked_add(k).ok_or(SevenZReadError::Malformed)?;
        let (s, e) = *ranges.get(idx).ok_or(SevenZReadError::Malformed)?;
        let data = &archive[s..e];
        if let Some(Some(c)) = info.pack_info.crcs.get(idx)
            && crc32(data) != *c
        {
            return Err(SevenZReadError::PackChecksum);
        }
        packs.push(data);
    }
    let main = folder.main_out_index().ok_or(SevenZReadError::Malformed)?;
    let out = decode_out(folder, main, &packs, decoder, limits, 0)?;
    if let Some(c) = folder.unpack_crc
        && crc32(&out) != c
    {
        return Err(SevenZReadError::DataChecksum);
    }
    Ok(out)
}

/// Parse the complete archive header: signature header, next-header CRC,
/// and any chain of encoded headers (decoded via `decoder`; Copy is built in).
pub fn parse_archive_header(archive: &[u8], decoder: &dyn FolderDecoder, limits: &SevenZLimits) -> Result<Header> {
    if archive.len() > limits.max_archive_bytes {
        return Err(SevenZReadError::LimitExceeded);
    }
    let sig = parse_signature_header(archive)?;
    if sig.next_header_size == 0 {
        // An empty archive has no header at all.
        return Ok(Header::default());
    }
    let raw = next_header_slice(archive, &sig, limits)?;
    let mut owned: Option<Vec<u8>> = None;
    for _ in 0..=limits.max_header_nesting {
        let cur: &[u8] = owned.as_deref().unwrap_or(raw);
        match cur.first() {
            Some(&property_id::HEADER) => return parse_plain_header(cur, limits),
            Some(&property_id::ENCODED_HEADER) => {
                let info = parse_encoded_header_info(cur, limits)?;
                if info.folders.len() != 1 {
                    return Err(SevenZReadError::Unsupported);
                }
                let mut l = *limits;
                l.max_unpack_bytes = l.max_unpack_bytes.min(limits.max_header_bytes as u64);
                let decoded = decode_folder(archive, &info, 0, decoder, &l)?;
                owned = Some(decoded);
            }
            Some(_) => return Err(SevenZReadError::Malformed),
            None => return Err(SevenZReadError::UnexpectedEof),
        }
    }
    Err(SevenZReadError::LimitExceeded)
}
