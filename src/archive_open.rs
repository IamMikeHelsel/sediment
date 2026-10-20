// SPDX-License-Identifier: MIT OR Apache-2.0
//! One entry point that opens any supported container as an
//! [`ArchiveReader`]: ZIP, tar (ustar/GNU/pax/v7), single-stream gzip,
//! bzip2 and xz files, tar inside gzip/bzip2/xz (`.tar.gz`, `.tgz`,
//! `.tar.bz2`, `.tbz2`, `.tbz`, `.tar.xz`, `.txz`), 7z, and the Unix
//! formats cpio (also `.cpio.gz`/`.cpio.bz2`/`.cpio.xz`), ar, Debian
//! packages, RPM packages and xar.
//!
//! Format detection is by magic bytes ([`crate::archive_detect`]); the
//! archive's file name only decides whether a decompressed stream is a tar
//! archive (see [`open_named`]) and names single-stream entries.
//!
//! Spec sources: RFC 1952 section 2.3 (gzip header fields FNAME, MTIME,
//! FEXTRA, FCOMMENT, FHCRC), the 7z format description (`7zFormat.txt`,
//! method IDs and coder properties: LZMA = props byte + 32-bit LE
//! dictionary size, LZMA2 = one dictionary byte, Delta = distance - 1,
//! BCJ = optional 32-bit start offset), and POSIX `st_mode` file-type bits
//! for the Unix extension of 7z attributes.
//!
//! Limits: every decoder runs with an explicit output cap derived from
//! [`ReaderLimits`]; decompressed data and decoded 7z folders are held in
//! memory, so `max_total_size` bounds peak memory per archive.

use std::borrow::Cow;
use std::cell::RefCell;

use crate::ar_archive::{ArReader, DebReader, is_deb};
use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::cpio_archive::{CpioReader, looks_like_cpio};
use crate::rpm_archive::RpmReader;
use crate::xar_archive::XarReader;
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits, ZipReader};
use crate::bzip2_decode::{Bzip2DecodeError, decode_bzip2};
use crate::deflate64::inflate64_raw_prefix;
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::filter_bcj::{BcjArch, bcj_decode, parse_bcj_properties};
use crate::filter_delta::{delta_decode, parse_delta_properties};
use crate::filter_swap::{SwapWidth, swap_convert};
use crate::gzip_members::decode_gzip_members;
use crate::gzip_wrapper::GzipError;
use crate::inflate::inflate_raw;
use crate::lzma_decode::{decode_lzma_raw, decode_props_byte};
use crate::lzma_properties::LzmaProperties;
use crate::lzma2_decode::{decode_lzma2, dictionary_size_from_byte};
use crate::sevenz_read::{FolderDecoder, SevenZArchive, SevenZLimits, SevenZReadError, filetime_to_unix};
use crate::tar_read::{TarEntryKind, TarReadError, TarReadLimits, read_entries};
use crate::xz_decode::{XzError, decode_xz};

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
/// Longest symlink target materialized while listing.
const MAX_LINK_TARGET: u64 = 4096;
/// Largest LZMA/LZMA2 dictionary accepted (the formats cap it at 4 GiB - 1;
/// the decoder does not preallocate it, so this only rejects nonsense).
const MAX_DICTIONARY: u64 = 1 << 32;
/// Default cap on the PPMd model memory a 7z coder may request. Unlike the
/// LZMA dictionary, the PPMd model is allocated (and zeroed) up front from the
/// header's property alone, so this must stay modest. 7-Zip's presets top out
/// at 192 MiB; larger values are refused as [`SevenZReadError::LimitExceeded`].
pub const DEFAULT_MAX_PPMD_MEMORY: u64 = 256 << 20;
/// Name used for a single-stream entry when no better name exists.
const FALLBACK_NAME: &[u8] = b"data";

impl From<TarReadError> for ReaderError {
    fn from(e: TarReadError) -> Self {
        match e {
            TarReadError::Truncated => ReaderError::Truncated,
            TarReadError::UnsupportedType => ReaderError::Unsupported,
            TarReadError::LimitExceeded => ReaderError::LimitExceeded,
            TarReadError::Allocation => ReaderError::Allocation,
            TarReadError::BadChecksum
            | TarReadError::InvalidHeader
            | TarReadError::InvalidNumber
            | TarReadError::NumericOverflow
            | TarReadError::InvalidSize
            | TarReadError::InvalidPax => ReaderError::Invalid,
        }
    }
}

impl From<GzipError> for ReaderError {
    fn from(e: GzipError) -> Self {
        match e {
            GzipError::UnexpectedEof => ReaderError::Truncated,
            GzipError::UnsupportedMethod => ReaderError::Unsupported,
            GzipError::ChecksumMismatch => ReaderError::CrcMismatch,
            GzipError::LimitExceeded => ReaderError::LimitExceeded,
            GzipError::Allocation => ReaderError::Allocation,
            GzipError::InvalidHeader | GzipError::InvalidData | GzipError::SizeMismatch | GzipError::TrailingData => {
                ReaderError::Invalid
            }
        }
    }
}

impl From<XzError> for ReaderError {
    fn from(e: XzError) -> Self {
        match e {
            XzError::UnexpectedEof => ReaderError::Truncated,
            XzError::ChecksumMismatch => ReaderError::CrcMismatch,
            XzError::Unsupported => ReaderError::Unsupported,
            XzError::LimitExceeded => ReaderError::LimitExceeded,
            XzError::Allocation => ReaderError::Allocation,
            XzError::InvalidMagic
            | XzError::InvalidHeader
            | XzError::InvalidData
            | XzError::InvalidIndex
            | XzError::InvalidPadding => ReaderError::Invalid,
        }
    }
}

impl From<Bzip2DecodeError> for ReaderError {
    fn from(e: Bzip2DecodeError) -> Self {
        match e {
            Bzip2DecodeError::Truncated => ReaderError::Truncated,
            Bzip2DecodeError::Randomized => ReaderError::Unsupported,
            Bzip2DecodeError::BlockCrcMismatch | Bzip2DecodeError::StreamCrcMismatch => ReaderError::CrcMismatch,
            Bzip2DecodeError::LimitExceeded => ReaderError::LimitExceeded,
            Bzip2DecodeError::Allocation => ReaderError::Allocation,
            Bzip2DecodeError::BadSignature
            | Bzip2DecodeError::BadMagic
            | Bzip2DecodeError::BadTables
            | Bzip2DecodeError::BadHuffmanData
            | Bzip2DecodeError::BlockTooLarge
            | Bzip2DecodeError::BadOrigPtr
            | Bzip2DecodeError::TrailingData => ReaderError::Invalid,
        }
    }
}

impl From<SevenZReadError> for ReaderError {
    fn from(e: SevenZReadError) -> Self {
        match e {
            SevenZReadError::UnexpectedEof => ReaderError::Truncated,
            SevenZReadError::UnsupportedVersion | SevenZReadError::Unsupported | SevenZReadError::UnsupportedMethod => {
                ReaderError::Unsupported
            }
            SevenZReadError::StartHeaderChecksum
            | SevenZReadError::HeaderChecksum
            | SevenZReadError::DataChecksum
            | SevenZReadError::PackChecksum => ReaderError::CrcMismatch,
            SevenZReadError::LimitExceeded => ReaderError::LimitExceeded,
            SevenZReadError::Allocation => ReaderError::Allocation,
            SevenZReadError::IndexOutOfRange => ReaderError::OutOfRange,
            SevenZReadError::InvalidSignature
            | SevenZReadError::Malformed
            | SevenZReadError::InvalidName
            | SevenZReadError::DecoderFailed
            | SevenZReadError::SizeMismatch => ReaderError::Invalid,
        }
    }
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn copy_vec(data: &[u8]) -> Result<Vec<u8>, ReaderError> {
    let mut v = Vec::new();
    v.try_reserve_exact(data.len()).map_err(|_| ReaderError::Allocation)?;
    v.extend_from_slice(data);
    Ok(v)
}

fn ends_with_ci(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Last path component of `name` (`/` and `\` are separators).
fn base_name(name: &[u8]) -> &[u8] {
    name.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(name)
}

// ---------------------------------------------------------------------------
// Naming of single-stream entries
// ---------------------------------------------------------------------------

/// Compressed-tar suffixes and the suffix that replaces them.
const TAR_SUFFIXES: [(&[u8], &[u8]); 7] = [
    (b".tar.gz", b".tar"),
    (b".tgz", b".tar"),
    (b".tar.bz2", b".tar"),
    (b".tbz2", b".tar"),
    (b".tbz", b".tar"),
    (b".tar.xz", b".tar"),
    (b".txz", b".tar"),
];

/// Plain compression suffixes stripped from a single-stream file name.
const STREAM_SUFFIXES: [&[u8]; 6] = [b".gz", b".gzip", b".bz2", b".bzip2", b".xz", b".z"];

/// True when the archive file name says "compressed tar".
pub fn is_compressed_tar_name(archive_name: &[u8]) -> bool {
    let base = base_name(archive_name);
    TAR_SUFFIXES.iter().any(|(s, _)| ends_with_ci(base, s))
}

/// The name of the decompressed member of a single-stream file, derived from
/// the archive file name: `x.tgz` -> `x.tar`, `x.txt.gz` -> `x.txt`, `x.bz2`
/// -> `x`. A name without a known suffix is returned unchanged (a bare
/// suffix such as `.gz` is kept as is); an empty name becomes `data`.
pub fn stream_member_name(archive_name: &[u8]) -> Vec<u8> {
    let base = base_name(archive_name);
    for (s, r) in TAR_SUFFIXES {
        if ends_with_ci(base, s) {
            let mut v = base[..base.len() - s.len()].to_vec();
            v.extend_from_slice(r);
            return v;
        }
    }
    for s in STREAM_SUFFIXES {
        if ends_with_ci(base, s) {
            return base[..base.len() - s.len()].to_vec();
        }
    }
    if base.is_empty() || base == b"." || base == b".." {
        return FALLBACK_NAME.to_vec();
    }
    base.to_vec()
}

/// Metadata from a gzip member header (RFC 1952, 2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GzipHeaderInfo {
    /// FNAME, if present (raw bytes, ISO 8859-1 by the spec).
    pub name: Option<Vec<u8>>,
    /// MTIME, if non-zero.
    pub mtime: Option<i64>,
}

/// Parse the fixed and optional gzip header fields. `max_name` bounds FNAME.
pub fn parse_gzip_header(b: &[u8], max_name: usize) -> Result<GzipHeaderInfo, ReaderError> {
    if b.len() < 10 {
        return Err(ReaderError::Truncated);
    }
    if b[0] != 0x1f || b[1] != 0x8b {
        return Err(ReaderError::Invalid);
    }
    if b[2] != 8 {
        return Err(ReaderError::Unsupported);
    }
    let flg = b[3];
    if flg & 0xe0 != 0 {
        return Err(ReaderError::Invalid);
    }
    let mtime = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        let x = b.get(pos..pos + 2).ok_or(ReaderError::Truncated)?;
        let xlen = usize::from(u16::from_le_bytes([x[0], x[1]]));
        pos = pos.checked_add(2 + xlen).ok_or(ReaderError::Truncated)?;
        if pos > b.len() {
            return Err(ReaderError::Truncated);
        }
    }
    let mut name = None;
    if flg & 0x08 != 0 {
        let rest = &b[pos..];
        let n = rest.iter().position(|&c| c == 0).ok_or(ReaderError::Truncated)?;
        if n > max_name {
            return Err(ReaderError::LimitExceeded);
        }
        name = Some(copy_vec(&rest[..n])?);
    }
    Ok(GzipHeaderInfo { name, mtime: if mtime == 0 { None } else { Some(i64::from(mtime)) } })
}

/// Sanitized member name from a gzip FNAME: only the last path component is
/// kept (gzip records a bare file name; anything else is hostile or
/// accidental). Returns `None` when nothing usable remains.
fn sanitize_fname(raw: &[u8]) -> Option<Vec<u8>> {
    let base = base_name(raw);
    if base.is_empty() || base.iter().all(|&c| c == b'.' || c == b' ') || base.len() > 255 {
        return None;
    }
    Some(base.to_vec())
}

// ---------------------------------------------------------------------------
// Tar
// ---------------------------------------------------------------------------

/// Tar archive held in memory (borrowed, or owned after decompression).
/// Device and FIFO entries are not representable as [`PlannedEntry`] and
/// are omitted; [`TarReader::skipped_special`] counts them.
pub struct TarReader<'a> {
    data: Cow<'a, [u8]>,
    entries: Vec<PlannedEntry>,
    ranges: Vec<std::ops::Range<usize>>,
    max_entry_size: u64,
    skipped_special: usize,
}

impl<'a> TarReader<'a> {
    pub fn new(data: Cow<'a, [u8]>, limits: ReaderLimits) -> Result<Self, ReaderError> {
        let tl = TarReadLimits { max_entries: limits.max_entries, max_total_size: limits.max_total_size, ..TarReadLimits::default() };
        let raw = read_entries(&data, tl)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(raw.len()).map_err(|_| ReaderError::Allocation)?;
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(raw.len()).map_err(|_| ReaderError::Allocation)?;
        let mut skipped_special = 0usize;
        for t in raw {
            let target = || t.link_target.clone().ok_or(ReaderError::Invalid);
            let kind = match t.kind {
                TarEntryKind::File => EntryKind::File,
                TarEntryKind::Directory => EntryKind::Dir,
                TarEntryKind::Symlink => EntryKind::Symlink { target: target()? },
                TarEntryKind::HardLink => EntryKind::Hardlink { target: target()? },
                TarEntryKind::CharDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
                    skipped_special += 1;
                    continue;
                }
            };
            let size = if matches!(kind, EntryKind::File) { t.size } else { 0 };
            if t.data_range.end > data.len() || (t.data_range.len() as u64) < size {
                return Err(ReaderError::Invalid);
            }
            let range = t.data_range.start..t.data_range.start + to_usize(size);
            // The extractor copies a hard link from its source member and
            // expects the source's size here; an unresolved target keeps 0
            // and is rejected by the planner.
            let size = match &kind {
                EntryKind::Hardlink { target } => hardlink_source_size(&entries, target),
                _ => size,
            };
            entries.push(PlannedEntry { path: t.path, kind, size, mode: Some(t.mode & 0o7777), mtime: Some(t.mtime) });
            ranges.push(range);
        }
        Ok(TarReader { data, entries, ranges, max_entry_size: limits.max_entry_size, skipped_special })
    }

    /// Number of device/FIFO entries that were left out.
    pub fn skipped_special(&self) -> usize {
        self.skipped_special
    }
}

fn trim_tar_path(p: &[u8]) -> &[u8] {
    let mut p = p;
    while let Some(r) = p.strip_prefix(b"./") {
        p = r;
    }
    while let Some(r) = p.strip_suffix(b"/") {
        p = r;
    }
    p
}

/// Size of the most recent earlier regular file named `target`.
fn hardlink_source_size(entries: &[PlannedEntry], target: &[u8]) -> u64 {
    let want = trim_tar_path(target);
    entries
        .iter()
        .rev()
        .find(|e| matches!(e.kind, EntryKind::File) && trim_tar_path(&e.path) == want)
        .map_or(0, |e| e.size)
}

impl ArchiveReader for TarReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let r = self.ranges.get(index).ok_or(ReaderError::OutOfRange)?;
        if r.len() as u64 > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        copy_vec(self.data.get(r.clone()).ok_or(ReaderError::Invalid)?)
    }
}

// ---------------------------------------------------------------------------
// Single-stream compressed files
// ---------------------------------------------------------------------------

/// A gzip/bzip2/xz file presented as a one-member archive. The stream is
/// decoded (and integrity-checked) when opened.
pub struct StreamReader {
    format: ArchiveFormat,
    entries: Vec<PlannedEntry>,
    data: Vec<u8>,
    crc: Option<u32>,
}

impl StreamReader {
    pub fn new(format: ArchiveFormat, name: Vec<u8>, data: Vec<u8>, mtime: Option<i64>, crc: Option<u32>) -> Self {
        let entry = PlannedEntry { path: name, kind: EntryKind::File, size: data.len() as u64, mode: None, mtime };
        StreamReader { format, entries: vec![entry], data, crc }
    }
}

impl ArchiveReader for StreamReader {
    fn format(&self) -> ArchiveFormat {
        self.format
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        if index != 0 {
            return Err(ReaderError::OutOfRange);
        }
        copy_vec(&self.data)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        if index == 0 { self.crc } else { None }
    }
}

/// Decompress a complete gzip, bzip2 or xz stream with output capped at
/// `max_output` bytes. Other formats return `Unsupported`.
pub fn decompress(format: ArchiveFormat, bytes: &[u8], max_output: usize) -> Result<Vec<u8>, ReaderError> {
    match format {
        ArchiveFormat::Gzip => {
            // Each DEFLATE block costs at least 3 bits of input.
            let max_blocks = bytes.len().saturating_mul(8) / 3 + 16;
            // RFC 1952 2.2: a gzip file is a series of members.
            Ok(decode_gzip_members(bytes, max_output, max_blocks)?.0)
        }
        ArchiveFormat::Bzip2 => Ok(decode_bzip2(bytes, max_output)?),
        ArchiveFormat::Xz => Ok(decode_xz(bytes, MAX_DICTIONARY, max_output)?),
        _ => Err(ReaderError::Unsupported),
    }
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

/// 7z method IDs (7zFormat.txt / Methods.txt), as big-endian integers.
pub mod sevenz_method {
    pub const COPY: u64 = 0x00;
    pub const DELTA: u64 = 0x03;
    pub const LZMA2: u64 = 0x21;
    pub const LZMA: u64 = 0x03_0101;
    pub const DEFLATE: u64 = 0x04_0108;
    pub const DEFLATE64: u64 = 0x04_0109;
    pub const BZIP2: u64 = 0x04_0202;
    pub const PPMD: u64 = 0x03_0401;
}

fn method_value(id: &[u8]) -> Option<u64> {
    if id.is_empty() || id.len() > 8 {
        return None;
    }
    Some(id.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// [`FolderDecoder`] for the 7z methods Sediment can decode: Copy, LZMA,
/// LZMA2, Deflate, Deflate64, BZip2, PPMd (var.H), Delta, the BCJ family (x86, PowerPC,
/// IA-64, ARM, ARM-Thumb, ARM64, SPARC, RISC-V) and Swap2/Swap4.
/// `max_output` caps any single coder output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZCodecs {
    pub max_output: u64,
    /// Largest PPMd model memory (bytes) accepted from a coder's properties.
    pub max_ppmd_memory: u64,
}

impl SevenZCodecs {
    /// Codecs capped at `max_output` bytes per coder, with the default
    /// PPMd memory cap ([`DEFAULT_MAX_PPMD_MEMORY`]).
    pub const fn new(max_output: u64) -> Self {
        Self { max_output, max_ppmd_memory: DEFAULT_MAX_PPMD_MEMORY }
    }
}

impl FolderDecoder for SevenZCodecs {
    fn decode(&self, method_id: &[u8], props: &[u8], input: &[u8], unpack_size: u64) -> Result<Vec<u8>, SevenZReadError> {
        use SevenZReadError as E;
        if unpack_size > self.max_output {
            return Err(E::LimitExceeded);
        }
        let size = usize::try_from(unpack_size).map_err(|_| E::LimitExceeded)?;
        let id = method_value(method_id).ok_or(E::UnsupportedMethod)?;
        let fail = |_| E::DecoderFailed;
        let out = match id {
            sevenz_method::COPY => {
                if input.len() != size {
                    return Err(E::SizeMismatch);
                }
                copy_vec(input).map_err(|_| E::Allocation)?
            }
            sevenz_method::LZMA => {
                if props.len() != 5 {
                    return Err(E::DecoderFailed);
                }
                let (lc, lp, pb) = decode_props_byte(props[0]).map_err(fail)?;
                let dictionary_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
                let p = LzmaProperties { lc, lp, pb, dictionary_size };
                decode_lzma_raw(input, p, Some(unpack_size), MAX_DICTIONARY, size).map_err(fail)?.0
            }
            sevenz_method::LZMA2 => {
                let [b] = props else { return Err(E::DecoderFailed) };
                let dict = dictionary_size_from_byte(*b).map_err(|_| E::DecoderFailed)?;
                decode_lzma2(input, dict, MAX_DICTIONARY, size).map_err(|_| E::DecoderFailed)?.0
            }
            sevenz_method::DEFLATE => {
                let max_blocks = input.len().saturating_mul(8) / 3 + 16;
                inflate_raw(input, size, max_blocks).map_err(|_| E::DecoderFailed)?
            }
            sevenz_method::DEFLATE64 => {
                let max_blocks = input.len().saturating_mul(8) / 3 + 16;
                inflate64_raw_prefix(input, size, max_blocks).map_err(|_| E::DecoderFailed)?.0
            }
            sevenz_method::BZIP2 => decode_bzip2(input, size).map_err(|_| E::DecoderFailed)?,
            sevenz_method::PPMD => {
                let p = crate::ppmd7::parse_properties(props).map_err(|_| E::DecoderFailed)?;
                crate::ppmd7::decode(p, input, size, self.max_ppmd_memory).map_err(|e| match e {
                    crate::ppmd7::Ppmd7Error::LimitExceeded => E::LimitExceeded,
                    crate::ppmd7::Ppmd7Error::Allocation => E::Allocation,
                    _ => E::DecoderFailed,
                })?
            }
            sevenz_method::DELTA => {
                let d = parse_delta_properties(props).map_err(|_| E::DecoderFailed)?;
                delta_decode(d, input, size).map_err(|_| E::DecoderFailed)?
            }
            _ => {
                if let Ok(arch) = BcjArch::from_sevenz_method_id(id) {
                    let start = parse_bcj_properties(arch, props).map_err(|_| E::DecoderFailed)?;
                    bcj_decode(arch, start, input, size).map_err(|_| E::DecoderFailed)?
                } else if let Ok(w) = SwapWidth::from_sevenz_method_id(id) {
                    if !props.is_empty() {
                        return Err(E::DecoderFailed);
                    }
                    swap_convert(w, input, size).map_err(|_| E::DecoderFailed)?
                } else {
                    return Err(E::UnsupportedMethod);
                }
            }
        };
        if out.len() != size {
            return Err(E::SizeMismatch);
        }
        Ok(out)
    }
}

/// 7z archive reader. Anti-items are omitted. Solid folders are decoded
/// once per run of reads from the same folder (the last folder is cached).
pub struct SevenZReader<'a> {
    archive: SevenZArchive<'a>,
    codecs: SevenZCodecs,
    /// Index into `archive.entries()` for each listed entry.
    map: Vec<usize>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
    cache: RefCell<Option<(usize, Vec<Vec<u8>>)>>,
}

impl<'a> SevenZReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let codecs = SevenZCodecs::new(limits.max_total_size);
        let sl = SevenZLimits {
            max_files: limits.max_entries,
            max_unpack_bytes: limits.max_total_size,
            ..SevenZLimits::default()
        };
        let archive = SevenZArchive::open(bytes, &codecs, sl)?;
        let n = archive.entries().len();
        let mut reader = SevenZReader {
            archive,
            codecs,
            map: Vec::new(),
            entries: Vec::new(),
            max_entry_size: limits.max_entry_size,
            cache: RefCell::new(None),
        };
        reader.map.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        reader.entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut total: u64 = 0;
        let mut links = Vec::new();
        for i in 0..n {
            let e = &reader.archive.entries()[i];
            if e.is_anti {
                continue;
            }
            let unix = e.unix_mode();
            let fmt = unix.map(|m| m & S_IFMT);
            let kind = if fmt == Some(S_IFLNK) && !e.is_dir {
                if e.size > MAX_LINK_TARGET {
                    return Err(ReaderError::LimitExceeded);
                }
                links.push(reader.entries.len());
                // Filled in below through the folder cache.
                EntryKind::Symlink { target: Vec::new() }
            } else if e.is_dir || e.has_dir_attribute() || fmt == Some(S_IFDIR) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let size = if matches!(kind, EntryKind::File) { e.size } else { 0 };
            total = total.checked_add(size).ok_or(ReaderError::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded);
            }
            let mode = unix.map(|m| m & 0o7777).filter(|&m| m != 0);
            let mtime = e.mtime.map(|ft| filetime_to_unix(ft).0);
            let path = e.name.as_bytes().to_vec();
            reader.entries.push(PlannedEntry { path, kind, size, mode, mtime });
            reader.map.push(i);
        }
        // Entries are in folder order, so the one-folder cache decodes each
        // folder holding links once.
        for k in links {
            let data = reader.read(k)?;
            if let Some(PlannedEntry { kind: EntryKind::Symlink { target }, .. }) = reader.entries.get_mut(k) {
                *target = data;
            }
        }
        Ok(reader)
    }
}

impl ArchiveReader for SevenZReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::SevenZ
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let &i = self.map.get(index).ok_or(ReaderError::OutOfRange)?;
        let e = &self.archive.entries()[i];
        if e.size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        let (Some(folder), Some(k)) = (e.folder_index, e.index_in_folder) else {
            return Ok(Vec::new());
        };
        let mut cache = self.cache.borrow_mut();
        if cache.as_ref().is_none_or(|(f, _)| *f != folder) {
            *cache = None;
            let parts = self.archive.extract_folder(folder, &self.codecs)?;
            *cache = Some((folder, parts));
        }
        let parts = &cache.as_ref().ok_or(ReaderError::Invalid)?.1;
        copy_vec(parts.get(k).ok_or(ReaderError::Invalid)?)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        let &i = self.map.get(index)?;
        self.archive.entries()[i].crc
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Open `bytes` (the whole archive file) as an [`ArchiveReader`].
///
/// `archive_name` is the archive's file name (any directory part is
/// ignored). The container is detected from magic bytes. A gzip/bzip2/xz
/// stream is treated as a tar archive when the archive name ends in a
/// compressed-tar suffix (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tbz`,
/// `.tar.xz`, `.txz`) or the member name (gzip FNAME, else the archive
/// name minus its compression suffix) ends in `.tar`; otherwise it is a
/// one-member archive whose member is named after the gzip FNAME (last
/// component only) or the archive name minus its compression suffix.
pub fn open_named<'a>(
    bytes: &'a [u8],
    archive_name: &[u8],
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    let max_stream = to_usize(limits.max_total_size);
    match detect_format(bytes) {
        Detected::Zip => match ZipReader::new(bytes, limits) {
            // Shrink/Reduce/Implode entries: the legacy reader decodes them.
            Ok(r) if r.has_legacy_method() => match crate::legacy_open::open_zip_fallback(bytes, limits) {
                Ok(l) => Ok(l),
                Err(_) => Ok(Box::new(r)),
            },
            Ok(r) => Ok(Box::new(r)),
            // Legacy methods (Shrink/Implode), ZIP64, descriptors: wider reader.
            Err(ReaderError::Unsupported) => crate::legacy_open::open_zip_fallback(bytes, limits),
            Err(e) => Err(e),
        },
        Detected::Tar | Detected::TarHeuristic => Ok(Box::new(TarReader::new(Cow::Borrowed(bytes), limits)?)),
        Detected::SevenZip => Ok(Box::new(SevenZReader::new(bytes, limits)?)),
        d @ (Detected::Gzip | Detected::Bzip2 | Detected::Xz) => {
            let format = match d {
                Detected::Gzip => ArchiveFormat::Gzip,
                Detected::Bzip2 => ArchiveFormat::Bzip2,
                _ => ArchiveFormat::Xz,
            };
            let (header_name, mtime, crc) = if format == ArchiveFormat::Gzip {
                let h = parse_gzip_header(bytes, 4096)?;
                let crc = bytes.len().checked_sub(8).map(|t| u32::from_le_bytes([bytes[t], bytes[t + 1], bytes[t + 2], bytes[t + 3]]));
                (h.name.as_deref().and_then(sanitize_fname), h.mtime, crc)
            } else {
                (None, None, None)
            };
            let member = header_name.unwrap_or_else(|| stream_member_name(archive_name));
            let data = decompress(format, bytes, max_stream)?;
            if is_compressed_tar_name(archive_name) || ends_with_ci(&member, b".tar") {
                return Ok(Box::new(TarReader::new(Cow::Owned(data), limits)?));
            }
            if ends_with_ci(&member, b".cpio") && looks_like_cpio(&data) {
                return Ok(Box::new(CpioReader::new(Cow::Owned(data), limits)?));
            }
            if data.len() as u64 > limits.max_entry_size {
                return Err(ReaderError::LimitExceeded);
            }
            // The last trailer only covers the last member of a multi-member
            // gzip file; list the CRC-32 of the whole (verified) output.
            let crc = crc.map(|_| crate::crc32::crc32(&data));
            Ok(Box::new(StreamReader::new(format, member, data, mtime, crc)))
        }
        Detected::Cpio => Ok(Box::new(CpioReader::new(Cow::Borrowed(bytes), limits)?)),
        Detected::Ar if is_deb(bytes) => Ok(Box::new(DebReader::new(bytes, limits)?)),
        Detected::Ar => Ok(Box::new(ArReader::new(bytes, limits)?)),
        Detected::Rpm => Ok(Box::new(RpmReader::new(bytes, limits)?)),
        Detected::Xar => Ok(Box::new(XarReader::new(bytes, limits)?)),
        // An empty tar archive is only its end-of-archive marker: two or
        // more zero blocks (POSIX ustar; `tar cf x.tar -T /dev/null`).
        Detected::Unknown if is_empty_tar(bytes) => Ok(Box::new(TarReader::new(Cow::Borrowed(bytes), limits)?)),
        Detected::LzmaAlone | Detected::Unknown => crate::legacy_open::open_legacy(bytes, archive_name, limits),
    }
}

/// True for a non-empty run of at least two all-zero 512-byte blocks.
fn is_empty_tar(bytes: &[u8]) -> bool {
    bytes.len() >= 1024 && bytes.len().is_multiple_of(512) && bytes.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tar() {
        assert!(is_empty_tar(&[0; 1024]));
        assert!(is_empty_tar(&[0; 10240]));
        assert!(!is_empty_tar(&[0; 512]));
        assert!(!is_empty_tar(&[0; 1000]));
        let mut b = vec![0u8; 1024];
        b[700] = 1;
        assert!(!is_empty_tar(&b));
        let r = open_named(&[0; 10240], b"e.tar", ReaderLimits::default()).unwrap();
        assert!(r.entries().is_empty());
    }

    #[test]
    fn member_names() {
        assert_eq!(stream_member_name(b"dir/x.tgz"), b"x.tar");
        assert_eq!(stream_member_name(b"x.TAR.GZ"), b"x.tar");
        assert_eq!(stream_member_name(b"notes.txt.gz"), b"notes.txt");
        assert_eq!(stream_member_name(b"a.bz2"), b"a");
        assert_eq!(stream_member_name(b"a.xz"), b"a");
        assert_eq!(stream_member_name(b"plain"), b"plain");
        assert_eq!(stream_member_name(b".gz"), b".gz");
        assert_eq!(stream_member_name(b""), FALLBACK_NAME);
        assert!(is_compressed_tar_name(b"a/b.tbz2"));
        assert!(!is_compressed_tar_name(b"b.tar"));
        assert!(!is_compressed_tar_name(b".tgz"));
    }

    #[test]
    fn fname_sanitizing() {
        assert_eq!(sanitize_fname(b"../../etc/passwd"), Some(b"passwd".to_vec()));
        assert_eq!(sanitize_fname(b"C:\\x\\y.txt"), Some(b"y.txt".to_vec()));
        assert_eq!(sanitize_fname(b".."), None);
        assert_eq!(sanitize_fname(b"a/"), None);
        assert_eq!(sanitize_fname(b""), None);
    }

    #[test]
    fn gzip_header_fields() {
        let mut h = vec![0x1f, 0x8b, 8, 0x08 | 0x04, 1, 0, 0, 0, 0, 3, 2, 0, 9, 9];
        h.extend_from_slice(b"name.txt\0");
        let i = parse_gzip_header(&h, 100).unwrap();
        assert_eq!(i.name.as_deref(), Some(&b"name.txt"[..]));
        assert_eq!(i.mtime, Some(1));
        assert_eq!(parse_gzip_header(&h, 3), Err(ReaderError::LimitExceeded));
        assert_eq!(parse_gzip_header(&h[..12], 100), Err(ReaderError::Truncated));
        assert_eq!(parse_gzip_header(&h[..h.len() - 1], 100), Err(ReaderError::Truncated));
    }

    #[test]
    fn method_ids() {
        assert_eq!(method_value(&[0x03, 0x01, 0x01]), Some(sevenz_method::LZMA));
        assert_eq!(method_value(&[]), None);
        assert_eq!(method_value(&[0; 9]), None);
        let c = SevenZCodecs::new(10);
        assert_eq!(c.decode(&[0], &[], b"abc", 3), Ok(b"abc".to_vec()));
        assert_eq!(c.decode(&[0], &[], b"abc", 4), Err(SevenZReadError::SizeMismatch));
        assert_eq!(c.decode(&[0], &[], b"abc", 11), Err(SevenZReadError::LimitExceeded));
        assert_eq!(c.decode(&[0x06, 0xf1, 0x07, 0x01], &[], b"abc", 3), Err(SevenZReadError::UnsupportedMethod));
        assert_eq!(c.decode(&[0x21], &[], b"abc", 3), Err(SevenZReadError::DecoderFailed));
        assert_eq!(c.decode(&[0x03, 0x01, 0x01], &[0; 4], b"abc", 3), Err(SevenZReadError::DecoderFailed));
    }
}
