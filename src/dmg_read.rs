// SPDX-License-Identifier: MIT OR Apache-2.0
//! Apple UDIF disk image (`.dmg`) reading.
//!
//! Spec source: the publicly documented UDIF layout (Apple's
//! `UDIFResourceFile` "koly" trailer and `BLKXTable` "mish" block maps as
//! described in Jonathan Levin's "Demystifying the DMG File Format" and
//! the libdmg-hfsplus/dmg2img notes): a 512-byte big-endian `koly` trailer
//! at the end of the file points to the data fork and to an XML property
//! list whose `resource-fork`/`blkx` array holds one base64 `mish` table
//! per partition. Each table lists chunks (40 bytes each) that map runs of
//! 512-byte sectors to compressed data in the data fork: zero fill
//! (`0x00000000`, `0x00000002`), raw (`0x00000001`), ADC (`0x80000004`),
//! zlib (`0x80000005`), bzip2 (`0x80000006`), LZFSE (`0x80000007`), and
//! LZMA/xz (`0x80000008`); comments (`0x7ffffffe`) and the terminator
//! (`0xffffffff`) carry no data.
//!
//! Codecs are reused: `zlib_wrapper`/`inflate`, `bzip2_decode`,
//! `xz_decode`, `lzma_decode` (`.lzma` fallback), `lzfse` and `adc`.
//! The plist is parsed with `xml_mini`. Base64 is decoded locally; this is
//! an adapter seam for the forge `base64_codec` module, which is not yet
//! integrated. Partition-map parsing for raw whole-disk images belongs to
//! the forge `mbr_gpt` module (also not yet integrated): UDIF already
//! lists partitions individually, so it is not needed for hdiutil output.
//!
//! [`DmgReader`] presents the image to the CLI: when a partition holds an
//! HFS+/HFSX volume (see `hfs_read`), its files are listed; other
//! partitions (or every partition if none is HFS+) appear as raw
//! `N.<name>.img` entries. Output sizes are capped by the reader limits and
//! malformed input returns an error, never panics.

use crate::adc::decode_adc;
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::bzip2_decode::decode_bzip2;
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::hfs_read::{is_hfs_plus, HfsError, HfsKind, HfsLimits, HfsVolume};
use crate::lzfse::decode_lzfse;
use crate::xml_mini::{parse_xml, XmlDoc, XmlLimits};
use crate::xz_decode::decode_xz;
use crate::zlib_wrapper::decode_zlib;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmgError {
    Truncated,
    /// No `koly` trailer.
    NotDmg,
    /// Malformed trailer, plist, block table or chunk.
    Invalid,
    /// Unknown chunk type or unsupported layout.
    Unsupported,
    /// A chunk failed to decompress or produced the wrong size.
    Corrupt,
    LimitExceeded,
    Allocation,
}

type R<T> = Result<T, DmgError>;

pub const SECTOR: u64 = 512;
const KOLY_SIZE: usize = 512;
const MAX_DICT: u64 = 1 << 30;

pub mod chunk_type {
    pub const ZERO: u32 = 0x0000_0000;
    pub const RAW: u32 = 0x0000_0001;
    pub const IGNORE: u32 = 0x0000_0002;
    pub const ADC: u32 = 0x8000_0004;
    pub const ZLIB: u32 = 0x8000_0005;
    pub const BZIP2: u32 = 0x8000_0006;
    pub const LZFSE: u32 = 0x8000_0007;
    pub const LZMA: u32 = 0x8000_0008;
    pub const COMMENT: u32 = 0x7fff_fffe;
    pub const TERMINATOR: u32 = 0xffff_ffff;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u32,
    /// First sector, relative to the partition.
    pub sector: u64,
    pub sector_count: u64,
    /// Absolute offset of the compressed data in the file.
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmgPartition {
    pub name: String,
    pub first_sector: u64,
    pub sector_count: u64,
    pub chunks: Vec<Chunk>,
}

impl DmgPartition {
    pub fn size(&self) -> u64 {
        self.sector_count.saturating_mul(SECTOR)
    }
}

/// A parsed UDIF image.
pub struct DmgImage<'a> {
    data: &'a [u8],
    pub partitions: Vec<DmgPartition>,
}

fn be32(b: &[u8], at: usize) -> R<u32> {
    let s = b.get(at..at + 4).ok_or(DmgError::Truncated)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> R<u64> {
    Ok((u64::from(be32(b, at)?) << 32) | u64::from(be32(b, at + 4)?))
}

/// True when `bytes` ends with a UDIF `koly` trailer.
pub fn is_dmg(bytes: &[u8]) -> bool {
    bytes.len() >= KOLY_SIZE && &bytes[bytes.len() - KOLY_SIZE..bytes.len() - KOLY_SIZE + 4] == b"koly"
}

/// Standard base64 (RFC 4648) with whitespace ignored. Adapter seam for
/// the forge `base64_codec` module.
fn base64_decode(s: &str, max: usize) -> R<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut n = 0u32;
    let mut pad = false;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad = true;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(DmgError::Invalid),
        };
        if pad {
            return Err(DmgError::Invalid);
        }
        acc = (acc << 6) | u32::from(v);
        n += 6;
        if n >= 8 {
            n -= 8;
            if out.len() >= max {
                return Err(DmgError::LimitExceeded);
            }
            out.try_reserve(1).map_err(|_| DmgError::Allocation)?;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    Ok(out)
}

/// Value node following `<key>name</key>` in a plist `<dict>` node.
fn dict_get(doc: &XmlDoc, dict: usize, name: &str) -> Option<usize> {
    let ch = &doc.node(dict).children;
    let mut i = 0;
    while i + 1 < ch.len() {
        let k = doc.node(ch[i]);
        if k.name == "key" && k.text.trim() == name {
            return Some(ch[i + 1]);
        }
        i += 1;
    }
    None
}

fn parse_mish(m: &[u8], data_fork: u64, file_len: u64, max_entries: usize) -> R<(u64, u64, Vec<Chunk>)> {
    if m.get(..4) != Some(b"mish") {
        return Err(DmgError::Invalid);
    }
    let first = be64(m, 8)?;
    let count = be64(m, 16)?;
    let data_off = be64(m, 24)?;
    let n = be32(m, 200)? as usize;
    if n > max_entries || 204 + n * 40 > m.len() {
        return Err(if n > max_entries { DmgError::LimitExceeded } else { DmgError::Truncated });
    }
    let base = data_fork.checked_add(data_off).ok_or(DmgError::Invalid)?;
    let mut chunks = Vec::new();
    chunks.try_reserve_exact(n).map_err(|_| DmgError::Allocation)?;
    for i in 0..n {
        let c = &m[204 + i * 40..204 + (i + 1) * 40];
        let kind = be32(c, 0)?;
        let ch = Chunk {
            kind,
            sector: be64(c, 8)?,
            sector_count: be64(c, 16)?,
            offset: base.checked_add(be64(c, 24)?).ok_or(DmgError::Invalid)?,
            length: be64(c, 32)?,
        };
        if matches!(kind, chunk_type::COMMENT | chunk_type::TERMINATOR) {
            continue;
        }
        let end_sector = ch.sector.checked_add(ch.sector_count).ok_or(DmgError::Invalid)?;
        if end_sector > count {
            return Err(DmgError::Invalid);
        }
        if !matches!(kind, chunk_type::ZERO | chunk_type::IGNORE)
            && ch.offset.checked_add(ch.length).is_none_or(|e| e > file_len)
        {
            return Err(DmgError::Truncated);
        }
        chunks.push(ch);
    }
    Ok((first, count, chunks))
}

impl<'a> DmgImage<'a> {
    pub fn open(bytes: &'a [u8], max_entries: usize) -> R<Self> {
        if !is_dmg(bytes) {
            return Err(DmgError::NotDmg);
        }
        let k = &bytes[bytes.len() - KOLY_SIZE..];
        let data_fork = be64(k, 24)?;
        let data_len = be64(k, 32)?;
        let xml_off = be64(k, 216)?;
        let xml_len = be64(k, 224)?;
        let file_len = bytes.len() as u64;
        if data_fork.checked_add(data_len).is_none_or(|e| e > file_len) {
            return Err(DmgError::Truncated);
        }
        if xml_len == 0 {
            // Very old images keep the block tables in a real resource fork.
            return Err(DmgError::Unsupported);
        }
        let xml_end = xml_off.checked_add(xml_len).ok_or(DmgError::Invalid)?;
        if xml_end > file_len {
            return Err(DmgError::Truncated);
        }
        let xml = &bytes[xml_off as usize..xml_end as usize];
        let doc = parse_xml(xml, &XmlLimits { max_nodes: 1 << 20, max_depth: 64, max_input: 64 << 20 })
            .map_err(|_| DmgError::Invalid)?;
        let root_dict = doc.child(0, "dict").ok_or(DmgError::Invalid)?;
        let rf = dict_get(&doc, root_dict, "resource-fork").ok_or(DmgError::Invalid)?;
        let blkx = dict_get(&doc, rf, "blkx").ok_or(DmgError::Invalid)?;
        let mut partitions = Vec::new();
        for &d in &doc.node(blkx).children {
            if doc.node(d).name != "dict" {
                continue;
            }
            let name = dict_get(&doc, d, "Name")
                .or_else(|| dict_get(&doc, d, "CFName"))
                .map(|n| doc.node(n).text.trim().to_string())
                .unwrap_or_default();
            let data = dict_get(&doc, d, "Data").ok_or(DmgError::Invalid)?;
            let mish = base64_decode(&doc.node(data).text, 64 << 20)?;
            let (first, count, chunks) = parse_mish(&mish, data_fork, file_len, max_entries)?;
            if partitions.len() >= max_entries {
                return Err(DmgError::LimitExceeded);
            }
            partitions.push(DmgPartition { name, first_sector: first, sector_count: count, chunks });
        }
        if partitions.is_empty() {
            return Err(DmgError::Invalid);
        }
        Ok(DmgImage { data: bytes, partitions })
    }

    /// Decode partition `index` completely.
    pub fn read_partition(&self, index: usize, max_output: u64) -> R<Vec<u8>> {
        let p = self.partitions.get(index).ok_or(DmgError::Invalid)?;
        let size = p.sector_count.checked_mul(SECTOR).ok_or(DmgError::LimitExceeded)?;
        if size > max_output {
            return Err(DmgError::LimitExceeded);
        }
        let size = usize::try_from(size).map_err(|_| DmgError::LimitExceeded)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| DmgError::Allocation)?;
        out.resize(size, 0);
        for c in &p.chunks {
            let start = (c.sector * SECTOR) as usize;
            let len = (c.sector_count * SECTOR) as usize;
            if matches!(c.kind, chunk_type::ZERO | chunk_type::IGNORE) {
                continue;
            }
            let src = &self.data[c.offset as usize..(c.offset + c.length) as usize];
            let dec = match c.kind {
                chunk_type::RAW => {
                    if src.len() < len {
                        return Err(DmgError::Corrupt);
                    }
                    out[start..start + len].copy_from_slice(&src[..len]);
                    continue;
                }
                chunk_type::ADC => decode_adc(src, len).map_err(|_| DmgError::Corrupt)?,
                chunk_type::ZLIB => decode_zlib(src, len, len / 3 + 64).map_err(|_| DmgError::Corrupt)?,
                chunk_type::BZIP2 => decode_bzip2(src, len).map_err(|_| DmgError::Corrupt)?,
                chunk_type::LZFSE => decode_lzfse(src, len).map_err(|_| DmgError::Corrupt)?,
                chunk_type::LZMA => match decode_xz(src, MAX_DICT, len) {
                    Ok(v) => v,
                    Err(_) => crate::lzma_decode::decode_lzma_alone(src, MAX_DICT, len).map_err(|_| DmgError::Corrupt)?,
                },
                _ => return Err(DmgError::Unsupported),
            };
            if dec.len() != len {
                return Err(DmgError::Corrupt);
            }
            out[start..start + len].copy_from_slice(&dec);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ArchiveReader
// ---------------------------------------------------------------------------

impl From<DmgError> for ReaderError {
    fn from(e: DmgError) -> Self {
        match e {
            DmgError::Truncated => ReaderError::Truncated,
            DmgError::NotDmg | DmgError::Invalid | DmgError::Corrupt => ReaderError::Invalid,
            DmgError::Unsupported => ReaderError::Unsupported,
            DmgError::LimitExceeded => ReaderError::LimitExceeded,
            DmgError::Allocation => ReaderError::Allocation,
        }
    }
}

impl From<HfsError> for ReaderError {
    fn from(e: HfsError) -> Self {
        match e {
            HfsError::Truncated => ReaderError::Truncated,
            HfsError::NotHfs | HfsError::Invalid => ReaderError::Invalid,
            HfsError::Unsupported => ReaderError::Unsupported,
            HfsError::LimitExceeded => ReaderError::LimitExceeded,
            HfsError::Allocation => ReaderError::Allocation,
        }
    }
}

enum Source {
    /// Entry `i` of HFS volume `v`.
    Hfs(usize, usize),
    /// Raw partition `p`.
    Partition(usize),
}

/// [`ArchiveReader`] over a DMG: HFS+ volume contents, else raw partitions.
pub struct DmgReader<'a> {
    image: DmgImage<'a>,
    /// Decoded HFS+ partitions.
    volumes: Vec<HfsVolume<'static>>,
    entries: Vec<PlannedEntry>,
    sources: Vec<Source>,
    max_entry_size: u64,
}

fn sanitize(name: &str) -> String {
    let s: String = name.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    if s.trim().is_empty() { "partition".to_string() } else { s.trim().to_string() }
}

impl<'a> DmgReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let image = DmgImage::open(bytes, limits.max_entries)?;
        let mut volumes = Vec::new();
        let mut used = 0u64;
        for (i, p) in image.partitions.iter().enumerate() {
            if p.size() < 1536 {
                continue;
            }
            used = used.saturating_add(p.size());
            if used > limits.max_total_size {
                return Err(ReaderError::LimitExceeded);
            }
            let data = image.read_partition(i, limits.max_total_size)?;
            if !is_hfs_plus(&data) {
                continue;
            }
            let hl = HfsLimits { max_entries: limits.max_entries, max_nodes: 1 << 22, max_fork_size: limits.max_total_size };
            volumes.push((i, HfsVolume::open_owned(data, hl)?));
        }
        let mut entries = Vec::new();
        let mut sources = Vec::new();
        let multi = volumes.len() > 1;
        for (vi, (pi, v)) in volumes.iter().enumerate() {
            let prefix = if multi { format!("{}.{}/", pi, sanitize(&image.partitions[*pi].name)) } else { String::new() };
            for (ei, e) in v.entries.iter().enumerate() {
                if entries.len() >= limits.max_entries {
                    return Err(ReaderError::LimitExceeded);
                }
                let mut path = prefix.clone().into_bytes();
                path.extend_from_slice(&e.path);
                let kind = match e.kind {
                    HfsKind::Dir => EntryKind::Dir,
                    HfsKind::File => EntryKind::File,
                    HfsKind::Symlink => EntryKind::Symlink { target: v.read(ei, 4096)? },
                };
                let size = if kind == EntryKind::File { e.size } else { 0 };
                entries.push(PlannedEntry { path, kind, size, mode: e.mode.map(|m| m & 0o7777), mtime: e.mtime });
                sources.push(Source::Hfs(vi, ei));
            }
        }
        if volumes.is_empty() {
            for (i, p) in image.partitions.iter().enumerate() {
                entries.push(PlannedEntry {
                    path: format!("{}.{}.img", i, sanitize(&p.name)).into_bytes(),
                    kind: EntryKind::File,
                    size: p.size(),
                    mode: None,
                    mtime: None,
                });
                sources.push(Source::Partition(i));
            }
        }
        let volumes = volumes.into_iter().map(|(_, v)| v).collect();
        Ok(DmgReader { image, volumes, entries, sources, max_entry_size: limits.max_entry_size })
    }
}

impl ArchiveReader for DmgReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Dmg
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let e = self.entries.get(index).ok_or(ReaderError::OutOfRange)?;
        if e.size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        match (&e.kind, &self.sources[index]) {
            (EntryKind::File, Source::Hfs(v, i)) => Ok(self.volumes[*v].read(*i, self.max_entry_size)?),
            (EntryKind::File, Source::Partition(p)) => Ok(self.image.read_partition(*p, self.max_entry_size)?),
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(base64_decode("aGVs\nbG8=", 100).unwrap(), b"hello");
        assert_eq!(base64_decode("", 100).unwrap(), b"");
        assert!(base64_decode("a=b", 100).is_err());
        assert!(base64_decode("a*", 100).is_err());
        assert_eq!(base64_decode("aGVsbG8=", 2), Err(DmgError::LimitExceeded));
    }

    #[test]
    fn not_dmg() {
        assert!(!is_dmg(b"koly"));
        assert_eq!(DmgImage::open(&[0u8; 600], 10).err(), Some(DmgError::NotDmg));
        let mut b = vec![0u8; 600];
        b[88..92].copy_from_slice(b"koly");
        assert_eq!(DmgImage::open(&b, 10).err(), Some(DmgError::Unsupported));
    }
}
