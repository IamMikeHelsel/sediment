// SPDX-License-Identifier: MIT OR Apache-2.0
//! HFS+ / HFSX volume reading: catalog B-tree walk and data-fork reads.
//!
//! Spec source: Apple Technical Note TN1150 "HFS Plus Volume Format"
//! (volume header at byte 1024, `HFSPlusForkData` with eight inline
//! extents, B-tree node descriptors and header record, catalog keys and
//! the folder/file/thread record layouts, the extents-overflow file keyed
//! by fork type, file ID and start block, `HFSPlusBSDInfo` permissions,
//! symbolic links as `slnk`/`rhap` files, and file hard links as
//! `hlnk`/`hfs+` files pointing at `iNode<N>` in the metadata directory).
//! Dates are seconds since 1904-01-01 UTC.
//!
//! Only leaf nodes are visited, following the `fLink` chain from the
//! header's first leaf, so index nodes are never trusted for layout.
//! Names are UTF-16 (decomposed, as stored) converted to UTF-8; a `/`
//! inside an HFS name becomes `:` as on macOS. The private metadata
//! directories and the journal files are not listed. Files whose data
//! lives in a `com.apple.decmpfs` attribute (transparent compression)
//! are listed but reading them returns [`HfsError::Unsupported`].
//!
//! All structures are bounds-checked; node counts, entries and output
//! sizes are capped by [`HfsLimits`]; malformed input returns an error.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfsError {
    Truncated,
    /// Not an HFS+/HFSX volume (bad signature).
    NotHfs,
    /// Malformed volume header, B-tree or record.
    Invalid,
    /// A feature this reader does not provide.
    Unsupported,
    LimitExceeded,
    Allocation,
}

type R<T> = Result<T, HfsError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HfsLimits {
    pub max_entries: usize,
    pub max_nodes: usize,
    /// Largest fork (catalog or file) that will be materialized.
    pub max_fork_size: u64,
}

impl Default for HfsLimits {
    fn default() -> Self {
        HfsLimits { max_entries: 1 << 20, max_nodes: 1 << 22, max_fork_size: 1 << 32 }
    }
}

/// Seconds between 1904-01-01 and 1970-01-01.
const HFS_EPOCH_OFFSET: i64 = 2_082_844_800;
const ROOT_PARENT_ID: u32 = 1;
const ROOT_FOLDER_ID: u32 = 2;
const CATALOG_FILE_ID: u32 = 4;
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const UF_COMPRESSED: u8 = 0x20;
const MAX_LINK_TARGET: u64 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extent {
    pub start_block: u32,
    pub block_count: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForkData {
    pub logical_size: u64,
    pub total_blocks: u32,
    pub extents: [Extent; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HfsKind {
    Dir,
    File,
    Symlink,
}

/// One listed catalog object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsEntry {
    /// UTF-8 path relative to the volume root, `/`-separated.
    pub path: Vec<u8>,
    pub kind: HfsKind,
    pub size: u64,
    /// Unix mode bits (permissions and type), when set.
    pub mode: Option<u32>,
    /// Content modification time, Unix seconds.
    pub mtime: Option<i64>,
    pub file_id: u32,
    pub fork: ForkData,
    pub compressed: bool,
}

/// A parsed HFS+ volume held in memory (`data` starts at the volume).
pub struct HfsVolume<'a> {
    data: Cow<'a, [u8]>,
    block_size: u32,
    extents_fork: ForkData,
    pub entries: Vec<HfsEntry>,
    pub volume_name: String,
    limits: HfsLimits,
}

fn be16(b: &[u8], at: usize) -> R<u16> {
    let s = b.get(at..at + 2).ok_or(HfsError::Truncated)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> R<u32> {
    let s = b.get(at..at + 4).ok_or(HfsError::Truncated)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> R<u64> {
    Ok((u64::from(be32(b, at)?) << 32) | u64::from(be32(b, at + 4)?))
}

fn parse_fork(b: &[u8], at: usize) -> R<ForkData> {
    let mut f = ForkData { logical_size: be64(b, at)?, total_blocks: be32(b, at + 12)?, ..Default::default() };
    for (i, e) in f.extents.iter_mut().enumerate() {
        e.start_block = be32(b, at + 16 + 8 * i)?;
        e.block_count = be32(b, at + 20 + 8 * i)?;
    }
    Ok(f)
}

/// True when `data` holds an HFS+ (`H+`) or HFSX (`HX`) volume header.
pub fn is_hfs_plus(data: &[u8]) -> bool {
    matches!(data.get(1024..1026), Some(b"H+") | Some(b"HX"))
}

fn utf16_name(units: &[u16]) -> String {
    let s: String = char::decode_utf16(units.iter().copied()).map(|r| r.unwrap_or('\u{FFFD}')).collect();
    s.replace('/', ":")
}

/// Catalog leaf record, before path assembly.
struct Raw {
    parent: u32,
    name: String,
    rec: Rec,
}

enum Rec {
    Folder { id: u32, mtime: u32, mode: u16 },
    File { id: u32, mtime: u32, mode: u16, owner_flags: u8, special: u32, ftype: [u8; 4], creator: [u8; 4], fork: ForkData },
}

impl<'a> HfsVolume<'a> {
    /// Parse the volume header and the whole catalog.
    pub fn open(data: &'a [u8], limits: HfsLimits) -> R<Self> {
        Self::open_cow(Cow::Borrowed(data), limits)
    }

    /// Like [`HfsVolume::open`], taking ownership of the volume bytes.
    pub fn open_owned(data: Vec<u8>, limits: HfsLimits) -> R<HfsVolume<'static>> {
        HfsVolume::open_cow(Cow::Owned(data), limits)
    }

    fn open_cow(data: Cow<'a, [u8]>, limits: HfsLimits) -> R<Self> {
        let vh = data.get(1024..1536).ok_or(HfsError::Truncated)?;
        if !matches!(&vh[..2], b"H+" | b"HX") {
            return Err(HfsError::NotHfs);
        }
        let block_size = be32(vh, 40)?;
        if block_size < 512 || !block_size.is_power_of_two() || block_size > (1 << 20) {
            return Err(HfsError::Invalid);
        }
        let extents_fork = parse_fork(vh, 192)?;
        let catalog_fork = parse_fork(vh, 272)?;
        let mut vol = HfsVolume { data, block_size, extents_fork, entries: Vec::new(), volume_name: String::new(), limits };
        let catalog = vol.read_fork(&catalog_fork, CATALOG_FILE_ID, 0, limits.max_fork_size)?;
        let raws = vol.walk_catalog(&catalog)?;
        vol.build(raws)?;
        Ok(vol)
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// All extents of a fork: the eight inline ones, then overflow records.
    fn fork_extents(&self, fork: &ForkData, file_id: u32, fork_type: u8) -> R<Vec<Extent>> {
        let mut ext = Vec::new();
        let mut blocks = 0u64;
        for e in fork.extents.iter() {
            if e.block_count == 0 {
                break;
            }
            ext.push(*e);
            blocks += u64::from(e.block_count);
        }
        if blocks < u64::from(fork.total_blocks) {
            if file_id == 3 {
                return Err(HfsError::Invalid);
            }
            self.overflow_extents(file_id, fork_type, &mut ext, &mut blocks, u64::from(fork.total_blocks))?;
        }
        Ok(ext)
    }

    fn overflow_extents(&self, file_id: u32, fork_type: u8, ext: &mut Vec<Extent>, blocks: &mut u64, total: u64) -> R<()> {
        let tree = self.read_fork(&self.extents_fork, 3, 0, self.limits.max_fork_size)?;
        let mut found: Vec<(u32, [Extent; 8])> = Vec::new();
        self.for_each_leaf_record(&tree, |key, rec| {
            // HFSPlusExtentKey: keyLength(2) forkType(1) pad(1) fileID(4) startBlock(4)
            if key.len() < 12 {
                return Ok(());
            }
            if key[2] != fork_type || u32::from_be_bytes([key[4], key[5], key[6], key[7]]) != file_id {
                return Ok(());
            }
            let start = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
            let mut e = [Extent::default(); 8];
            for (i, x) in e.iter_mut().enumerate() {
                x.start_block = be32(rec, 8 * i)?;
                x.block_count = be32(rec, 8 * i + 4)?;
            }
            found.push((start, e));
            Ok(())
        })?;
        found.sort_by_key(|f| f.0);
        for (start, recs) in found {
            if u64::from(start) != *blocks {
                return Err(HfsError::Invalid);
            }
            for e in recs {
                if e.block_count == 0 {
                    break;
                }
                ext.push(e);
                *blocks += u64::from(e.block_count);
            }
        }
        if *blocks < total {
            return Err(HfsError::Invalid);
        }
        Ok(())
    }

    /// Materialize a fork (`fork_type` 0 = data).
    fn read_fork(&self, fork: &ForkData, file_id: u32, fork_type: u8, max: u64) -> R<Vec<u8>> {
        if fork.logical_size > max {
            return Err(HfsError::LimitExceeded);
        }
        let size = usize::try_from(fork.logical_size).map_err(|_| HfsError::LimitExceeded)?;
        let bs = u64::from(self.block_size);
        if fork.logical_size > u64::from(fork.total_blocks) * bs {
            return Err(HfsError::Invalid);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| HfsError::Allocation)?;
        if size == 0 {
            return Ok(out);
        }
        for e in self.fork_extents(fork, file_id, fork_type)? {
            let off = u64::from(e.start_block) * bs;
            let len = (u64::from(e.block_count) * bs).min((size - out.len()) as u64);
            let end = off.checked_add(len).ok_or(HfsError::Invalid)?;
            if end > self.data.len() as u64 {
                return Err(HfsError::Truncated);
            }
            out.extend_from_slice(&self.data[off as usize..end as usize]);
            if out.len() == size {
                break;
            }
        }
        if out.len() != size {
            return Err(HfsError::Invalid);
        }
        Ok(out)
    }

    /// Call `f(key, record_data)` for each record of every leaf node.
    fn for_each_leaf_record(&self, tree: &[u8], mut f: impl FnMut(&[u8], &[u8]) -> R<()>) -> R<()> {
        // Header node: descriptor (14) then header record.
        let hdr = tree.get(14..14 + 106).ok_or(HfsError::Truncated)?;
        let first_leaf = be32(hdr, 10)?;
        let node_size = usize::from(be16(hdr, 18)?);
        if node_size < 512 || !node_size.is_power_of_two() {
            return Err(HfsError::Invalid);
        }
        let mut node = first_leaf;
        let mut seen = HashSet::new();
        while node != 0 {
            if !seen.insert(node) || seen.len() > self.limits.max_nodes {
                return Err(HfsError::Invalid);
            }
            let start = (node as usize).checked_mul(node_size).ok_or(HfsError::Invalid)?;
            let nd = tree.get(start..start + node_size).ok_or(HfsError::Truncated)?;
            let flink = be32(nd, 0)?;
            let kind = nd[8] as i8;
            if kind != -1 {
                return Err(HfsError::Invalid);
            }
            let nrec = usize::from(be16(nd, 10)?);
            if nrec * 2 + 14 > node_size {
                return Err(HfsError::Invalid);
            }
            for i in 0..nrec {
                let off = usize::from(be16(nd, node_size - 2 * (i + 1))?);
                let next = usize::from(be16(nd, node_size - 2 * (i + 2))?);
                if off < 14 || next > node_size - 2 * (nrec + 1) || off >= next {
                    return Err(HfsError::Invalid);
                }
                let rec = &nd[off..next];
                let klen = usize::from(be16(rec, 0)?);
                let key = rec.get(..2 + klen).ok_or(HfsError::Invalid)?;
                let data = &rec[2 + klen..];
                f(key, data)?;
            }
            node = flink;
        }
        Ok(())
    }

    fn walk_catalog(&self, cat: &[u8]) -> R<Vec<Raw>> {
        let mut raws = Vec::new();
        let max = self.limits.max_entries;
        self.for_each_leaf_record(cat, |key, d| {
            // HFSPlusCatalogKey: keyLength(2) parentID(4) nodeName(len(2) + UTF-16)
            if key.len() < 8 {
                return Err(HfsError::Invalid);
            }
            let parent = be32(key, 2)?;
            let n = usize::from(be16(key, 6)?);
            let nb = key.get(8..8 + 2 * n).ok_or(HfsError::Invalid)?;
            let rtype = be16(d, 0)?;
            let units: Vec<u16> = nb.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            let rec = match rtype {
                1 => Rec::Folder { id: be32(d, 8)?, mtime: be32(d, 16)?, mode: be16(d, 42)? },
                2 => {
                    let mut ftype = [0u8; 4];
                    let mut creator = [0u8; 4];
                    ftype.copy_from_slice(d.get(48..52).ok_or(HfsError::Truncated)?);
                    creator.copy_from_slice(d.get(52..56).ok_or(HfsError::Truncated)?);
                    Rec::File {
                        id: be32(d, 8)?,
                        mtime: be32(d, 16)?,
                        mode: be16(d, 42)?,
                        owner_flags: *d.get(41).ok_or(HfsError::Truncated)?,
                        special: be32(d, 44)?,
                        ftype,
                        creator,
                        fork: parse_fork(d, 88)?,
                    }
                }
                3 | 4 => return Ok(()),
                _ => return Err(HfsError::Invalid),
            };
            if raws.len() >= max {
                return Err(HfsError::LimitExceeded);
            }
            raws.try_reserve(1).map_err(|_| HfsError::Allocation)?;
            raws.push(Raw { parent, name: utf16_name(&units), rec });
            Ok(())
        })?;
        Ok(raws)
    }

    fn build(&mut self, raws: Vec<Raw>) -> R<()> {
        // folder id -> (parent, name)
        let mut folders: HashMap<u32, (u32, String)> = HashMap::new();
        for r in &raws {
            if let Rec::Folder { id, .. } = r.rec {
                folders.insert(id, (r.parent, r.name.clone()));
            }
        }
        if let Some((_, n)) = folders.get(&ROOT_FOLDER_ID) {
            self.volume_name = n.clone();
        }
        // Private metadata directories (hard-link targets) and their ids.
        let mut hidden: HashSet<u32> = HashSet::new();
        let mut inode_dir = None;
        for (&id, (parent, name)) in &folders {
            if *parent == ROOT_FOLDER_ID && (name.starts_with('\0') || name == ".HFS+ Private Directory Data\r") {
                hidden.insert(id);
                if name.starts_with('\0') {
                    inode_dir = Some(id);
                }
            }
        }
        let mut inodes: HashMap<u32, (ForkData, u32, bool)> = HashMap::new();
        if let Some(dir) = inode_dir {
            for r in &raws {
                if let (true, Rec::File { id, fork, owner_flags, .. }) = (r.parent == dir, &r.rec)
                    && let Some(n) = r.name.strip_prefix("iNode").and_then(|n| n.parse::<u32>().ok())
                {
                    inodes.insert(n, (*fork, *id, owner_flags & UF_COMPRESSED != 0));
                }
            }
        }
        let mut path_cache: HashMap<u32, Option<String>> = HashMap::new();
        let mut entries = Vec::new();
        for r in &raws {
            // The root folder's own record (parent 1) is the volume name.
            if r.parent == ROOT_PARENT_ID {
                continue;
            }
            let Some(parent_path) = folder_path(r.parent, &folders, &hidden, &mut path_cache)? else {
                continue;
            };
            if r.parent == ROOT_FOLDER_ID && matches!(r.name.as_str(), ".journal" | ".journal_info_block") {
                continue;
            }
            let path = if parent_path.is_empty() { r.name.clone() } else { format!("{parent_path}/{}", r.name) };
            let e = match &r.rec {
                Rec::Folder { id, mtime, mode } => {
                    if *id == ROOT_FOLDER_ID || hidden.contains(id) {
                        continue;
                    }
                    HfsEntry {
                        path: path.into_bytes(),
                        kind: HfsKind::Dir,
                        size: 0,
                        mode: (*mode != 0).then_some(u32::from(*mode)),
                        mtime: hfs_time(*mtime),
                        file_id: *id,
                        fork: ForkData::default(),
                        compressed: false,
                    }
                }
                Rec::File { id, mtime, mode, owner_flags, special, ftype, creator, fork } => {
                    let mut fork = *fork;
                    let mut file_id = *id;
                    let mut compressed = owner_flags & UF_COMPRESSED != 0;
                    let is_link = (u32::from(*mode) & S_IFMT == S_IFLNK) || (ftype == b"slnk" && creator == b"rhap");
                    if ftype == b"hlnk" && creator == b"hfs+" {
                        let (f, i, c) = *inodes.get(special).ok_or(HfsError::Invalid)?;
                        fork = f;
                        file_id = i;
                        compressed = c;
                    }
                    HfsEntry {
                        path: path.into_bytes(),
                        kind: if is_link { HfsKind::Symlink } else { HfsKind::File },
                        size: if compressed { 0 } else { fork.logical_size },
                        mode: (*mode != 0).then_some(u32::from(*mode)),
                        mtime: hfs_time(*mtime),
                        file_id,
                        fork,
                        compressed,
                    }
                }
            };
            entries.try_reserve(1).map_err(|_| HfsError::Allocation)?;
            entries.push(e);
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        self.entries = entries;
        Ok(())
    }

    /// Contents of entry `index` (data fork; link target for symlinks).
    pub fn read(&self, index: usize, max_output: u64) -> R<Vec<u8>> {
        let e = self.entries.get(index).ok_or(HfsError::Invalid)?;
        match e.kind {
            HfsKind::Dir => Ok(Vec::new()),
            _ if e.compressed => Err(HfsError::Unsupported),
            HfsKind::Symlink => self.read_fork(&e.fork, e.file_id, 0, max_output.min(MAX_LINK_TARGET)),
            HfsKind::File => self.read_fork(&e.fork, e.file_id, 0, max_output),
        }
    }
}

fn hfs_time(t: u32) -> Option<i64> {
    (t != 0).then(|| i64::from(t) - HFS_EPOCH_OFFSET)
}

/// Path of folder `id` relative to the root ("" for the root); `None` if
/// it lies in a hidden directory. Cycles and orphans are errors.
fn folder_path(
    id: u32,
    folders: &HashMap<u32, (u32, String)>,
    hidden: &HashSet<u32>,
    cache: &mut HashMap<u32, Option<String>>,
) -> R<Option<String>> {
    let mut chain = Vec::new();
    let mut cur = id;
    let base: Option<String> = loop {
        if cur == ROOT_FOLDER_ID {
            break Some(String::new());
        }
        if hidden.contains(&cur) {
            break None;
        }
        if let Some(p) = cache.get(&cur) {
            break p.clone();
        }
        if chain.len() > 4096 || chain.contains(&cur) {
            return Err(HfsError::Invalid);
        }
        chain.push(cur);
        cur = folders.get(&cur).ok_or(HfsError::Invalid)?.0;
    };
    let mut path = base;
    for &f in chain.iter().rev() {
        path = path.map(|p| {
            let n = &folders[&f].1;
            if p.is_empty() { n.clone() } else { format!("{p}/{n}") }
        });
        cache.insert(f, path.clone());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_hfs() {
        assert_eq!(HfsVolume::open(&[0u8; 100], HfsLimits::default()).err(), Some(HfsError::Truncated));
        assert_eq!(HfsVolume::open(&[0u8; 2048], HfsLimits::default()).err(), Some(HfsError::NotHfs));
        let mut v = vec![0u8; 2048];
        v[1024..1026].copy_from_slice(b"H+");
        assert_eq!(HfsVolume::open(&v, HfsLimits::default()).err(), Some(HfsError::Invalid));
    }

    #[test]
    fn names() {
        assert_eq!(utf16_name(&[0x61, 0x2f, 0x62]), "a:b");
        assert_eq!(hfs_time(0), None);
        assert_eq!(hfs_time(2_082_844_800), Some(0));
    }
}
