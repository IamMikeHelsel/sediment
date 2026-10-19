// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z archive writer: signature header, PackInfo / UnpackInfo (folders,
//! coders, bind pairs) / SubStreamsInfo, FilesInfo (UTF-16 names, empty
//! stream / empty file vectors, Windows attributes with the Unix extension,
//! FILETIME timestamps), Copy / LZMA / LZMA2 coders with an optional BCJ
//! branch-converter filter in front, solid blocks with a configurable size,
//! CRC-32 for every file, and an LZMA-compressed ("encoded") header.
//!
//! Spec sources: the public "7z Format" description (`7zFormat.txt` from the
//! LZMA SDK `DOC/` directory): signature header layout, the `NUMBER`
//! variable-length integer, property IDs, the PackInfo / CodersInfo /
//! SubStreamsInfo / FilesInfo record layouts, coder flag bits and the
//! encoded-header indirection. Method IDs (Copy `00`, LZMA `03 01 01`,
//! LZMA2 `21`, BCJ x86 `03 03 01 03`, ...) and the LZMA (5-byte) / LZMA2
//! (1-byte) coder property layouts are from the same document and the LZMA
//! SDK `Methods.txt`. Windows FILETIME and attribute semantics follow the
//! public Win32 documentation; the Unix-mode-in-high-16-bits convention
//! (`0x8000` flag) is the widely documented p7zip/Info-ZIP convention. No
//! 7-Zip source code was consulted.
//!
//! Layout written: `[32-byte signature header][packed streams, one per folder]
//! [packed header (when compressed)][next header]`. Each folder holds one
//! solid block: a chain `filter? -> codec` with one packed stream. Files of
//! size zero and directories are "empty streams" and own no data.
//!
//! Folders are compressed in parallel on `std::thread::scope` workers; output
//! is byte-identical regardless of the thread count.
//!
//! Everything is slice-in / `Vec`-out; all sizes are checked against
//! [`SevenZWriteLimits`] with checked arithmetic, and buffers use
//! `try_reserve`. Invalid input returns `Err`, never panics.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::crc32::crc32;
use crate::filter_bcj::{BcjArch, bcj_encode};
use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::lzma_encode::{LzmaEncoderOptions, MAX_INPUT, effective_dictionary_size, encode_lzma_raw, props_byte};
use crate::lzma2_encode::{Lzma2EncodeError, encode_lzma2};
use crate::sevenz_header::{ATTR_DIRECTORY, ATTR_UNIX_EXTENSION, SIGNATURE, method_id, property_id as pid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZWriteError {
    /// Encoder options out of range (level, lc/lp/pb, dictionary, ...).
    InvalidOptions,
    /// A name is empty, contains NUL, or is not valid UTF-8.
    InvalidName,
    /// An entry is inconsistent (e.g. a directory with data).
    InvalidEntry,
    /// A caller limit (entries, input bytes, output bytes) was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// A codec or filter failed unexpectedly.
    EncoderFailed,
}

type Result<T> = core::result::Result<T, SevenZWriteError>;

/// Windows `FILE_ATTRIBUTE_READONLY`.
pub const ATTR_READONLY: u32 = 0x01;
/// Windows `FILE_ATTRIBUTE_ARCHIVE`.
pub const ATTR_ARCHIVE: u32 = 0x20;

/// Seconds between 1601-01-01 and 1970-01-01 (UTC).
const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;

/// Compression method of the main coder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZMethod {
    Copy,
    Lzma,
    Lzma2,
}

/// Writer options. [`SevenZWriteOptions::level`] gives 7-Zip-like presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZWriteOptions {
    pub method: SevenZMethod,
    /// LZMA parameters for `Lzma` / `Lzma2` (ignored for `Copy`).
    pub lzma: LzmaEncoderOptions,
    /// Optional branch-converter filter applied before the codec.
    pub filter: Option<BcjArch>,
    /// Pack several files into one folder (solid block).
    pub solid: bool,
    /// Maximum uncompressed bytes per solid block (0 = unlimited). A single
    /// file larger than this still gets its own block.
    pub solid_block_bytes: u64,
    /// Maximum files per solid block (0 = unlimited).
    pub solid_block_files: usize,
    /// Compress the archive header with LZMA (`-mhc=on`). Falls back to a
    /// plain header when compression does not make it smaller.
    pub compress_header: bool,
    /// Worker threads for folder compression (0 = available parallelism).
    pub threads: usize,
}

impl SevenZWriteOptions {
    /// Preset for 7-Zip-style level `0..=9`: 0 is Copy; 1..=9 are LZMA2 with
    /// [`LzmaEncoderOptions::preset`], solid, compressed header, and solid
    /// blocks of `4 * dictionary` bytes clamped to 16 MiB..=1 GiB.
    pub fn level(level: u8) -> Result<Self> {
        if level > 9 {
            return Err(SevenZWriteError::InvalidOptions);
        }
        let lzma = LzmaEncoderOptions::preset(level as u32).map_err(|_| SevenZWriteError::InvalidOptions)?;
        let block = (lzma.dictionary_size as u64 * 4).clamp(16 << 20, 1 << 30);
        Ok(Self {
            method: if level == 0 { SevenZMethod::Copy } else { SevenZMethod::Lzma2 },
            lzma,
            filter: None,
            solid: true,
            solid_block_bytes: block,
            solid_block_files: 0,
            compress_header: true,
            threads: 0,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.method != SevenZMethod::Copy {
            self.lzma.validate().map_err(|_| SevenZWriteError::InvalidOptions)?;
            if self.method == SevenZMethod::Lzma2 && self.lzma.lc + self.lzma.lp > 4 {
                return Err(SevenZWriteError::InvalidOptions);
            }
        }
        Ok(())
    }
}

impl Default for SevenZWriteOptions {
    fn default() -> Self {
        // Level 5 is always valid.
        Self::level(5).unwrap_or(Self {
            method: SevenZMethod::Copy,
            lzma: LzmaEncoderOptions {
                dictionary_size: 1 << 23,
                lc: 3,
                lp: 0,
                pb: 2,
                match_finder: crate::lzma_encode::MatchFinder::BinaryTree,
                mode: crate::lzma_encode::ParseMode::Optimal,
                nice_len: 48,
                depth: 32,
            },
            filter: None,
            solid: true,
            solid_block_bytes: 32 << 20,
            solid_block_files: 0,
            compress_header: true,
            threads: 0,
        })
    }
}

/// Explicit caller limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZWriteLimits {
    pub max_entries: usize,
    /// Total uncompressed bytes across all entries.
    pub max_input_bytes: u64,
    /// Size of the finished archive.
    pub max_output_bytes: u64,
    /// UTF-16 code units per name.
    pub max_name_units: usize,
}

impl Default for SevenZWriteLimits {
    fn default() -> Self {
        Self { max_entries: 1 << 20, max_input_bytes: 1 << 32, max_output_bytes: 1 << 33, max_name_units: 32768 }
    }
}

/// An extra coder applied to every packed stream after compression (the
/// innermost coder of each folder), e.g. 7zAES encryption
/// ([`crate::sevenz_aes_coder::SevenZAesEncoder`]). The coder's unpack size
/// is the length of its input; its output becomes the packed stream.
pub trait PackCoder: Sync {
    /// Encode one packed stream: returns (method ID, coder properties, output).
    fn encode(&self, packed: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
    /// Also apply the coder to the archive header. The header is then always
    /// written LZMA-compressed and encoded (`-mhe=on`), even when
    /// `compress_header` is off or compression does not shrink it.
    fn applies_to_header(&self) -> bool;
}

/// One archive member at the 7z level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZItem<'a> {
    /// Archive path with `/` separators, no trailing slash.
    pub name: &'a str,
    /// File contents (must be empty for directories).
    pub data: &'a [u8],
    pub is_dir: bool,
    /// Windows attributes (optionally with the Unix extension).
    pub attributes: Option<u32>,
    /// Windows FILETIME values (100 ns ticks since 1601-01-01 UTC).
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
}

/// Convert Unix time to a Windows FILETIME; `None` when out of range.
pub fn unix_to_filetime(secs: i64, nanos: u32) -> Option<u64> {
    if nanos >= 1_000_000_000 {
        return None;
    }
    let s = secs.checked_add(FILETIME_EPOCH_DIFF)?;
    let s = u64::try_from(s).ok()?;
    s.checked_mul(10_000_000)?.checked_add(nanos as u64 / 100)
}

/// Windows attributes with the Unix extension for an entry of `kind` with
/// permission bits `mode` (`& 0o7777` is applied).
pub fn unix_attributes(kind: EntryKind, mode: u32) -> u32 {
    let perm = mode & 0o7777;
    let (ftype, win) = match kind {
        EntryKind::File => (0o100000, ATTR_ARCHIVE),
        EntryKind::Directory => (0o040000, ATTR_DIRECTORY),
        EntryKind::Symlink => (0o120000, ATTR_ARCHIVE),
    };
    let ro = if kind != EntryKind::Symlink && perm & 0o200 == 0 { ATTR_READONLY } else { 0 };
    win | ro | ATTR_UNIX_EXTENSION | ((ftype | perm) << 16)
}

/// Build a 7z archive from filesystem-model entries ([`ArchiveEntry`]).
/// Symlinks are stored the way Unix 7-Zip stores them with `-snl`: a file
/// whose data is the link target and whose Unix mode says `S_IFLNK`.
/// Names must be valid UTF-8.
pub fn create_7z(entries: &[ArchiveEntry<'_>], opts: &SevenZWriteOptions, limits: SevenZWriteLimits) -> Result<Vec<u8>> {
    create_7z_with(entries, opts, limits, None)
}

/// [`create_7z`] with an optional [`PackCoder`] (e.g. encryption).
pub fn create_7z_with(
    entries: &[ArchiveEntry<'_>],
    opts: &SevenZWriteOptions,
    limits: SevenZWriteLimits,
    pack: Option<&dyn PackCoder>,
) -> Result<Vec<u8>> {
    if entries.len() > limits.max_entries {
        return Err(SevenZWriteError::LimitExceeded);
    }
    let mut items: Vec<SevenZItem<'_>> = Vec::new();
    items.try_reserve_exact(entries.len()).map_err(|_| SevenZWriteError::Allocation)?;
    for e in entries {
        let name = core::str::from_utf8(e.name).map_err(|_| SevenZWriteError::InvalidName)?;
        let data = match e.kind {
            EntryKind::File => e.data,
            EntryKind::Directory => {
                if !e.data.is_empty() {
                    return Err(SevenZWriteError::InvalidEntry);
                }
                &[][..]
            }
            EntryKind::Symlink => {
                if e.link_target.is_empty() {
                    return Err(SevenZWriteError::InvalidEntry);
                }
                e.link_target
            }
        };
        items.push(SevenZItem {
            name,
            data,
            is_dir: e.kind == EntryKind::Directory,
            attributes: Some(unix_attributes(e.kind, e.mode)),
            mtime: unix_to_filetime(e.mtime, 0),
            ctime: None,
            atime: None,
        });
    }
    write_7z_with(&items, opts, limits, pack)
}

// ---------------------------------------------------------------------------
// Byte-level helpers
// ---------------------------------------------------------------------------

/// Append a 7z `NUMBER`: the count of leading one bits in the first byte is
/// the number of extra little-endian bytes; the remaining first-byte bits
/// hold the value's high part.
pub fn write_number(out: &mut Vec<u8>, v: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if v < 1u64 << (7 * (extra + 1)) {
            first |= (v >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    out.push(first);
    for j in 0..extra {
        out.push((v >> (8 * j)) as u8);
    }
}

fn write_bits(out: &mut Vec<u8>, bits: &[bool]) {
    let mut cur = 0u8;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            cur |= 0x80 >> (i % 8);
        }
        if i % 8 == 7 {
            out.push(cur);
            cur = 0;
        }
    }
    if !bits.len().is_multiple_of(8) {
        out.push(cur);
    }
}

/// `AllAreDefined` byte, optional bit field.
fn write_defined(out: &mut Vec<u8>, defined: &[bool]) {
    if defined.iter().all(|&d| d) {
        out.push(1);
    } else {
        out.push(0);
        write_bits(out, defined);
    }
}

fn write_digests(out: &mut Vec<u8>, crcs: &[u32]) {
    out.push(1); // all defined
    for c in crcs {
        out.extend_from_slice(&c.to_le_bytes());
    }
}

/// Minimal big-endian bytes of a method ID held as an integer.
fn method_bytes(id: u64) -> Vec<u8> {
    let b = id.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(7);
    b[first..].to_vec()
}

fn reserve(v: &mut Vec<u8>, n: usize) -> Result<()> {
    v.try_reserve(n).map_err(|_| SevenZWriteError::Allocation)
}

// ---------------------------------------------------------------------------
// Folder encoding
// ---------------------------------------------------------------------------

struct CoderSpec {
    id: Vec<u8>,
    props: Vec<u8>,
}

struct FolderOut {
    /// Outermost first (coder 0 produces the folder output).
    coders: Vec<CoderSpec>,
    /// One per coder out stream, in coder order.
    unpack_sizes: Vec<u64>,
    packed: Vec<u8>,
}

fn write_folder(out: &mut Vec<u8>, coders: &[CoderSpec]) {
    write_number(out, coders.len() as u64);
    for c in coders {
        let mut flags = c.id.len() as u8;
        if !c.props.is_empty() {
            flags |= 0x20;
        }
        out.push(flags);
        out.extend_from_slice(&c.id);
        if !c.props.is_empty() {
            write_number(out, c.props.len() as u64);
            out.extend_from_slice(&c.props);
        }
    }
    // Chain: coder k's input is bound to coder k+1's output. With one packed
    // stream left over its index is implicit.
    for k in 0..coders.len().saturating_sub(1) {
        write_number(out, k as u64);
        write_number(out, k as u64 + 1);
    }
}

fn lzma_coder(input: &[u8], opts: &LzmaEncoderOptions) -> Result<(CoderSpec, Vec<u8>)> {
    if input.len() > MAX_INPUT {
        return Err(SevenZWriteError::LimitExceeded);
    }
    let dict = effective_dictionary_size(opts.dictionary_size, input.len());
    let packed = encode_lzma_raw(input, opts, false).map_err(|e| match e {
        crate::lzma_encode::LzmaEncodeError::InvalidOptions => SevenZWriteError::InvalidOptions,
        crate::lzma_encode::LzmaEncodeError::InputTooLarge => SevenZWriteError::LimitExceeded,
        crate::lzma_encode::LzmaEncodeError::Allocation => SevenZWriteError::Allocation,
    })?;
    let mut props = vec![props_byte(opts.lc, opts.lp, opts.pb)];
    props.extend_from_slice(&dict.to_le_bytes());
    Ok((CoderSpec { id: method_id::LZMA.to_vec(), props }, packed))
}

fn encode_folder(data: &[u8], opts: &SevenZWriteOptions) -> Result<FolderOut> {
    let len = data.len() as u64;
    let mut coders = Vec::new();
    let mut sizes = Vec::new();
    let filtered;
    let mut input = data;
    if let Some(arch) = opts.filter {
        filtered = bcj_encode(arch, 0, data, data.len()).map_err(|e| match e {
            crate::filter_bcj::BcjError::Allocation => SevenZWriteError::Allocation,
            _ => SevenZWriteError::EncoderFailed,
        })?;
        input = &filtered;
        coders.push(CoderSpec { id: method_bytes(arch.sevenz_method_id()), props: Vec::new() });
        sizes.push(len);
    }
    let packed = match opts.method {
        SevenZMethod::Copy => {
            let mut v = Vec::new();
            reserve(&mut v, input.len())?;
            v.extend_from_slice(input);
            coders.push(CoderSpec { id: method_id::COPY.to_vec(), props: Vec::new() });
            v
        }
        SevenZMethod::Lzma => {
            let (c, p) = lzma_coder(input, &opts.lzma)?;
            coders.push(c);
            p
        }
        SevenZMethod::Lzma2 => {
            if input.len() > MAX_INPUT {
                return Err(SevenZWriteError::LimitExceeded);
            }
            let (p, dict_byte) = encode_lzma2(input, &opts.lzma).map_err(|e| match e {
                Lzma2EncodeError::InvalidOptions => SevenZWriteError::InvalidOptions,
                Lzma2EncodeError::InputTooLarge => SevenZWriteError::LimitExceeded,
                Lzma2EncodeError::Allocation => SevenZWriteError::Allocation,
            })?;
            coders.push(CoderSpec { id: method_id::LZMA2.to_vec(), props: vec![dict_byte] });
            p
        }
    };
    sizes.push(len);
    Ok(FolderOut { coders, unpack_sizes: sizes, packed })
}

/// Concatenate the data of the files in one block (borrow when single).
fn block_data<'a>(items: &[SevenZItem<'a>], files: &[usize]) -> Result<std::borrow::Cow<'a, [u8]>> {
    if let [one] = files {
        return Ok(std::borrow::Cow::Borrowed(items[*one].data));
    }
    let total = files
        .iter()
        .try_fold(0usize, |acc, &i| acc.checked_add(items[i].data.len()))
        .ok_or(SevenZWriteError::LimitExceeded)?;
    let mut v = Vec::new();
    reserve(&mut v, total)?;
    for &i in files {
        v.extend_from_slice(items[i].data);
    }
    Ok(std::borrow::Cow::Owned(v))
}

/// Append `pack` as the innermost coder of a finished folder.
fn apply_pack(mut f: FolderOut, pack: Option<&dyn PackCoder>) -> Result<FolderOut> {
    if let Some(p) = pack {
        let (id, props, out) = p.encode(&f.packed)?;
        f.unpack_sizes.push(f.packed.len() as u64);
        f.coders.push(CoderSpec { id, props });
        f.packed = out;
    }
    Ok(f)
}

fn encode_all(
    items: &[SevenZItem<'_>],
    blocks: &[Vec<usize>],
    opts: &SevenZWriteOptions,
    pack: Option<&dyn PackCoder>,
) -> Result<Vec<FolderOut>> {
    let threads = if opts.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        opts.threads
    }
    .clamp(1, 256)
    .min(blocks.len().max(1));

    let work = |b: &Vec<usize>| -> Result<FolderOut> {
        let data = block_data(items, b)?;
        apply_pack(encode_folder(&data, opts)?, pack)
    };
    if threads <= 1 {
        return blocks.iter().map(work).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<Result<FolderOut>>>> = Mutex::new((0..blocks.len()).map(|_| None).collect());
    let failed = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= blocks.len() {
                        break;
                    }
                    let r = work(&blocks[i]);
                    if r.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    if let Ok(mut g) = slots.lock() {
                        g[i] = Some(r);
                    }
                }
            });
        }
    });
    let slots = slots.into_inner().map_err(|_| SevenZWriteError::EncoderFailed)?;
    // Report the first error in block order; otherwise every slot is filled.
    let mut out = Vec::new();
    out.try_reserve_exact(slots.len()).map_err(|_| SevenZWriteError::Allocation)?;
    let mut first_err = None;
    for s in slots {
        match s {
            Some(Ok(f)) => out.push(f),
            Some(Err(e)) => {
                first_err.get_or_insert(e);
            }
            None => {
                first_err.get_or_insert(SevenZWriteError::EncoderFailed);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// Split the indices of non-empty files into blocks (folders).
fn plan_blocks(items: &[SevenZItem<'_>], opts: &SevenZWriteOptions) -> Vec<Vec<usize>> {
    let mut blocks: Vec<Vec<usize>> = Vec::new();
    let cap_bytes = if opts.method == SevenZMethod::Copy { u64::MAX } else { MAX_INPUT as u64 };
    let max_bytes = if opts.solid_block_bytes == 0 { cap_bytes } else { opts.solid_block_bytes.min(cap_bytes) };
    let max_files = if opts.solid_block_files == 0 { usize::MAX } else { opts.solid_block_files };
    let mut cur: Vec<usize> = Vec::new();
    let mut cur_bytes = 0u64;
    for (i, it) in items.iter().enumerate() {
        if it.is_dir || it.data.is_empty() {
            continue;
        }
        let n = it.data.len() as u64;
        if !opts.solid {
            blocks.push(vec![i]);
            continue;
        }
        if !cur.is_empty() && (cur_bytes.saturating_add(n) > max_bytes || cur.len() >= max_files) {
            blocks.push(core::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur.push(i);
        cur_bytes = cur_bytes.saturating_add(n);
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

// ---------------------------------------------------------------------------
// Header records
// ---------------------------------------------------------------------------

type TimeGetter = fn(&SevenZItem<'_>) -> Option<u64>;

fn write_files_info(out: &mut Vec<u8>, items: &[SevenZItem<'_>]) -> Result<()> {
    out.push(pid::FILES_INFO);
    write_number(out, items.len() as u64);

    let empty_stream: Vec<bool> = items.iter().map(|it| it.is_dir || it.data.is_empty()).collect();
    if empty_stream.iter().any(|&b| b) {
        let mut v = Vec::new();
        write_bits(&mut v, &empty_stream);
        out.push(pid::EMPTY_STREAM);
        write_number(out, v.len() as u64);
        out.extend_from_slice(&v);
        let empty_file: Vec<bool> = items
            .iter()
            .zip(&empty_stream)
            .filter(|(_, e)| **e)
            .map(|(it, _)| !it.is_dir)
            .collect();
        if empty_file.iter().any(|&b| b) {
            let mut v = Vec::new();
            write_bits(&mut v, &empty_file);
            out.push(pid::EMPTY_FILE);
            write_number(out, v.len() as u64);
            out.extend_from_slice(&v);
        }
    }

    let mut names = vec![0u8]; // External = 0
    for it in items {
        for u in it.name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    out.push(pid::NAME);
    write_number(out, names.len() as u64);
    reserve(out, names.len())?;
    out.extend_from_slice(&names);

    let times: [(u8, TimeGetter); 3] =
        [(pid::CTIME, |i| i.ctime), (pid::ATIME, |i| i.atime), (pid::MTIME, |i| i.mtime)];
    for (id, get) in times {
        let vals: Vec<Option<u64>> = items.iter().map(get).collect();
        if vals.iter().all(Option::is_none) {
            continue;
        }
        let mut v = Vec::new();
        write_defined(&mut v, &vals.iter().map(Option::is_some).collect::<Vec<_>>());
        v.push(0); // External
        for t in vals.iter().flatten() {
            v.extend_from_slice(&t.to_le_bytes());
        }
        out.push(id);
        write_number(out, v.len() as u64);
        out.extend_from_slice(&v);
    }

    let attrs: Vec<Option<u32>> = items.iter().map(|i| i.attributes).collect();
    if attrs.iter().any(Option::is_some) {
        let mut v = Vec::new();
        write_defined(&mut v, &attrs.iter().map(Option::is_some).collect::<Vec<_>>());
        v.push(0);
        for a in attrs.iter().flatten() {
            v.extend_from_slice(&a.to_le_bytes());
        }
        out.push(pid::WIN_ATTRIBUTES);
        write_number(out, v.len() as u64);
        out.extend_from_slice(&v);
    }
    out.push(pid::END);
    Ok(())
}

/// PackInfo + UnpackInfo for folders with one packed stream each.
fn write_pack_and_unpack(out: &mut Vec<u8>, pack_pos: u64, folders: &[&FolderOut], folder_crcs: Option<&[u32]>) {
    out.push(pid::PACK_INFO);
    write_number(out, pack_pos);
    write_number(out, folders.len() as u64);
    out.push(pid::SIZE);
    for f in folders {
        write_number(out, f.packed.len() as u64);
    }
    out.push(pid::END);

    out.push(pid::UNPACK_INFO);
    out.push(pid::FOLDER);
    write_number(out, folders.len() as u64);
    out.push(0); // External
    for f in folders {
        write_folder(out, &f.coders);
    }
    out.push(pid::CODERS_UNPACK_SIZE);
    for f in folders {
        for &s in &f.unpack_sizes {
            write_number(out, s);
        }
    }
    if let Some(c) = folder_crcs {
        out.push(pid::CRC);
        write_digests(out, c);
    }
    out.push(pid::END);
}

fn build_header(items: &[SevenZItem<'_>], blocks: &[Vec<usize>], folders: &[FolderOut]) -> Result<Vec<u8>> {
    let mut h = Vec::new();
    h.push(pid::HEADER);
    if !folders.is_empty() {
        h.push(pid::MAIN_STREAMS_INFO);
        let refs: Vec<&FolderOut> = folders.iter().collect();
        write_pack_and_unpack(&mut h, 0, &refs, None);

        h.push(pid::SUBSTREAMS_INFO);
        if blocks.iter().any(|b| b.len() != 1) {
            h.push(pid::NUM_UNPACK_STREAM);
            for b in blocks {
                write_number(&mut h, b.len() as u64);
            }
        }
        if blocks.iter().any(|b| b.len() > 1) {
            h.push(pid::SIZE);
            for b in blocks {
                for &i in &b[..b.len() - 1] {
                    write_number(&mut h, items[i].data.len() as u64);
                }
            }
        }
        h.push(pid::CRC);
        let crcs: Vec<u32> = blocks.iter().flatten().map(|&i| crc32(items[i].data)).collect();
        write_digests(&mut h, &crcs);
        h.push(pid::END);
        h.push(pid::END);
    }
    if !items.is_empty() {
        write_files_info(&mut h, items)?;
    }
    h.push(pid::END);
    Ok(h)
}

fn validate_items(items: &[SevenZItem<'_>], limits: &SevenZWriteLimits) -> Result<()> {
    if items.len() > limits.max_entries {
        return Err(SevenZWriteError::LimitExceeded);
    }
    let mut total = 0u64;
    for it in items {
        if it.name.is_empty() || it.name.contains('\0') {
            return Err(SevenZWriteError::InvalidName);
        }
        if it.name.encode_utf16().count() > limits.max_name_units {
            return Err(SevenZWriteError::LimitExceeded);
        }
        if it.is_dir && !it.data.is_empty() {
            return Err(SevenZWriteError::InvalidEntry);
        }
        total = total.checked_add(it.data.len() as u64).ok_or(SevenZWriteError::LimitExceeded)?;
        if total > limits.max_input_bytes {
            return Err(SevenZWriteError::LimitExceeded);
        }
    }
    Ok(())
}

/// Build a complete 7z archive in memory.
pub fn write_7z(items: &[SevenZItem<'_>], opts: &SevenZWriteOptions, limits: SevenZWriteLimits) -> Result<Vec<u8>> {
    write_7z_with(items, opts, limits, None)
}

/// [`write_7z`] with an optional [`PackCoder`] applied to every packed
/// stream (and to the header when [`PackCoder::applies_to_header`]).
pub fn write_7z_with(
    items: &[SevenZItem<'_>],
    opts: &SevenZWriteOptions,
    limits: SevenZWriteLimits,
    pack: Option<&dyn PackCoder>,
) -> Result<Vec<u8>> {
    opts.validate()?;
    validate_items(items, &limits)?;

    let mut out = Vec::new();
    reserve(&mut out, 32)?;
    out.resize(32, 0);
    if items.is_empty() {
        finish_signature(&mut out, 0, 0, 0);
        return Ok(out);
    }

    let blocks = plan_blocks(items, opts);
    let folders = encode_all(items, &blocks, opts, pack)?;
    for f in &folders {
        let new_len = (out.len() as u64).checked_add(f.packed.len() as u64).ok_or(SevenZWriteError::LimitExceeded)?;
        if new_len > limits.max_output_bytes {
            return Err(SevenZWriteError::LimitExceeded);
        }
        reserve(&mut out, f.packed.len())?;
        out.extend_from_slice(&f.packed);
    }

    let raw = build_header(items, &blocks, &folders)?;
    drop(folders);
    let header_pack = pack.filter(|p| p.applies_to_header());
    let header = if opts.compress_header || header_pack.is_some() {
        encode_header(&raw, (out.len() - 32) as u64, header_pack)?
    } else {
        None
    };
    let next: Vec<u8> = match header {
        Some((packed, enc)) if header_pack.is_some() || packed.len() + enc.len() < raw.len() => {
            reserve(&mut out, packed.len())?;
            out.extend_from_slice(&packed);
            enc
        }
        _ => raw,
    };
    let next_offset = (out.len() - 32) as u64;
    let total = (out.len() as u64).checked_add(next.len() as u64).ok_or(SevenZWriteError::LimitExceeded)?;
    if total > limits.max_output_bytes {
        return Err(SevenZWriteError::LimitExceeded);
    }
    reserve(&mut out, next.len())?;
    out.extend_from_slice(&next);
    finish_signature(&mut out, next_offset, next.len() as u64, crc32(&next));
    Ok(out)
}

/// LZMA-compress `raw` and build the `kEncodedHeader` record pointing at it.
/// `pack_pos` is where the packed header will start (relative to byte 32).
fn encode_header(raw: &[u8], pack_pos: u64, pack: Option<&dyn PackCoder>) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if raw.len() > MAX_INPUT {
        // An encrypted header must never fall back to plain text.
        return if pack.is_some() { Err(SevenZWriteError::LimitExceeded) } else { Ok(None) };
    }
    let mut o = LzmaEncoderOptions::preset(5).map_err(|_| SevenZWriteError::InvalidOptions)?;
    o.dictionary_size = 1 << 20;
    let (coder, packed) = lzma_coder(raw, &o)?;
    let folder = apply_pack(FolderOut { coders: vec![coder], unpack_sizes: vec![raw.len() as u64], packed }, pack)?;
    let mut enc = vec![pid::ENCODED_HEADER];
    write_pack_and_unpack(&mut enc, pack_pos, &[&folder], Some(&[crc32(raw)]));
    enc.push(pid::END);
    Ok(Some((folder.packed, enc)))
}

fn finish_signature(out: &mut [u8], next_offset: u64, next_size: u64, next_crc: u32) {
    out[..6].copy_from_slice(&SIGNATURE);
    out[6] = 0;
    out[7] = 4;
    out[12..20].copy_from_slice(&next_offset.to_le_bytes());
    out[20..28].copy_from_slice(&next_size.to_le_bytes());
    out[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let c = crc32(&out[12..32]);
    out[8..12].copy_from_slice(&c.to_le_bytes());
}
