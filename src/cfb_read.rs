// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compound File Binary (OLE2 / structured storage) reader: the container
//! of MSI, MSP, MSM, legacy DOC/XLS/PPT and similar files.
//!
//! Spec source: [MS-CFB] Compound File Binary File Format: the 512-byte
//! header, version 3 (512-byte sectors) and version 4 (4096-byte sectors),
//! the DIFAT (109 header entries + chained DIFAT sectors), FAT, mini FAT,
//! the 128-byte directory entries forming a red-black tree per storage, the
//! mini stream (held in the root entry's chain) for streams smaller than the
//! mini stream cutoff, and FILETIME timestamps.
//!
//! MSI stream names: Windows Installer packs table and stream names into
//! UTF-16 code points U+3800..U+4840 (two 6-bit characters from
//! `0-9A-Za-z._` per code point, U+4800.. for a single trailing character,
//! U+4840 as a table-name prefix shown as `!`). This publicly described
//! scheme is decoded when [`MsiNames::Auto`] detects an MSI-style file.
//!
//! Entry paths join storage names with `/`. Characters below U+0020 are shown
//! as `[N]` (e.g. `[5]SummaryInformation`), and `/` or `\` inside a name
//! become `_`, so every path is one safe relative path per entry.
//!
//! Every chain walk is bounded by the sector count (loops are detected),
//! every table is bounded by the file size, and stream reads are bounded by
//! [`CfbLimits::max_stream_size`].

use crate::extract_plan::{EntryKind, PlannedEntry};

const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MAXREGSECT: u32 = 0xFFFF_FFFA;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
const NOSTREAM: u32 = 0xFFFF_FFFF;
const DIR_ENTRY: usize = 128;
const MINI_SECTOR: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfbError {
    /// File ends inside the header or a required sector.
    Truncated,
    /// Missing D0 CF 11 E0 A1 B1 1A E1 signature.
    InvalidSignature,
    /// Unsupported version / byte order / sector shift, or inconsistent counts.
    InvalidHeader,
    /// A chain references a sector outside the file or a special value.
    InvalidSector,
    /// A sector chain loops or is shorter than the stream it holds.
    InvalidChain,
    /// Malformed directory (bad root, bad tree links, cycles, bad names).
    InvalidDirectory,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Index out of range.
    OutOfRange,
    /// The entry is a storage, not a stream.
    NotAStream,
}

/// How to present MSI-encoded stream names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsiNames {
    /// Decode when the root CLSID is an MSI/MSP/MST class or some name starts
    /// with the U+4840 table prefix.
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfbLimits {
    pub max_entries: usize,
    /// Largest stream `read` will materialize.
    pub max_stream_size: u64,
    pub msi_names: MsiNames,
}

impl Default for CfbLimits {
    fn default() -> Self {
        CfbLimits { max_entries: 100_000, max_stream_size: 1 << 30, msi_names: MsiNames::Auto }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfbEntryKind {
    Storage,
    Stream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfbEntry {
    /// Display path (see module docs).
    pub path: String,
    /// The raw UTF-16 name of this entry.
    pub name_utf16: Vec<u16>,
    pub kind: CfbEntryKind,
    pub size: u64,
    pub clsid: [u8; 16],
    pub state_bits: u32,
    /// FILETIME values (100 ns since 1601-01-01), 0 when not set.
    pub ctime: u64,
    pub mtime: u64,
    /// Directory entry index.
    pub dir_id: u32,
    start_sector: u32,
}

impl CfbEntry {
    /// Modification time as Unix seconds, when set.
    pub fn mtime_unix(&self) -> Option<i64> {
        filetime_to_unix(self.mtime)
    }
}

/// FILETIME (100 ns ticks since 1601) to Unix seconds; 0 means "not set".
pub fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    Some((ft / 10_000_000) as i64 - 11_644_473_600)
}

#[derive(Debug, Clone)]
struct RawDir {
    name: Vec<u16>,
    typ: u8,
    left: u32,
    right: u32,
    child: u32,
    clsid: [u8; 16],
    state_bits: u32,
    ctime: u64,
    mtime: u64,
    start: u32,
    size: u64,
}

#[derive(Debug, Clone)]
pub struct CfbArchive<'a> {
    bytes: &'a [u8],
    limits: CfbLimits,
    pub major_version: u16,
    pub sector_size: usize,
    pub mini_cutoff: u64,
    /// CLSID of the root storage.
    pub root_clsid: [u8; 16],
    fat: Vec<u32>,
    minifat: Vec<u32>,
    /// Sectors of the mini stream (the root entry's chain).
    mini_chain: Vec<u32>,
    mini_size: u64,
    entries: Vec<CfbEntry>,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from(le32(b, at)) | (u64::from(le32(b, at + 4)) << 32)
}

const MSI_TABLE: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
const MSI_CLSIDS: [[u8; 4]; 3] = [[0x84, 0x10, 0x0C, 0x00], [0x86, 0x10, 0x0C, 0x00], [0x82, 0x10, 0x0C, 0x00]];

/// Decode an MSI-packed name; code points outside U+3800..=U+4840 pass
/// through unchanged.
pub fn decode_msi_name(name: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(name.len() * 2);
    for &c in name {
        match c {
            0x4840 => out.push(u16::from(b'!')),
            0x4800..=0x483F => out.push(u16::from(MSI_TABLE[(c - 0x4800) as usize])),
            0x3800..=0x47FF => {
                let v = c - 0x3800;
                out.push(u16::from(MSI_TABLE[(v & 0x3F) as usize]));
                out.push(u16::from(MSI_TABLE[((v >> 6) & 0x3F) as usize]));
            }
            _ => out.push(c),
        }
    }
    out
}

fn display_name(name: &[u16]) -> String {
    let mut s = String::new();
    for ch in char::decode_utf16(name.iter().copied()) {
        let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        match ch {
            '\0'..='\u{1f}' => {
                s.push('[');
                s.push_str(&(ch as u32).to_string());
                s.push(']');
            }
            '/' | '\\' => s.push('_'),
            _ => s.push(ch),
        }
    }
    s
}

impl<'a> CfbArchive<'a> {
    pub fn parse(bytes: &'a [u8], limits: CfbLimits) -> Result<Self, CfbError> {
        if bytes.len() < 512 {
            return Err(if bytes.len() >= 8 && bytes[..8] != SIGNATURE {
                CfbError::InvalidSignature
            } else {
                CfbError::Truncated
            });
        }
        if bytes[..8] != SIGNATURE {
            return Err(CfbError::InvalidSignature);
        }
        let major = le16(bytes, 0x1A);
        let byte_order = le16(bytes, 0x1C);
        let shift = le16(bytes, 0x1E);
        let mini_shift = le16(bytes, 0x20);
        let expected_shift = match major {
            3 => 9,
            4 => 12,
            _ => return Err(CfbError::InvalidHeader),
        };
        if byte_order != 0xFFFE || shift != expected_shift || mini_shift != 6 {
            return Err(CfbError::InvalidHeader);
        }
        let ss = 1usize << shift;
        let num_fat = le32(bytes, 0x2C) as usize;
        let first_dir = le32(bytes, 0x30);
        let mini_cutoff = u64::from(le32(bytes, 0x38));
        let first_minifat = le32(bytes, 0x3C);
        let num_minifat = le32(bytes, 0x40) as usize;
        let first_difat = le32(bytes, 0x44);
        let num_difat = le32(bytes, 0x48) as usize;
        // Sectors that start inside the file (the last may be partial).
        let num_sectors = bytes.len().saturating_sub(ss).div_ceil(ss);
        if num_fat > num_sectors || num_difat > num_sectors || num_minifat > num_sectors {
            return Err(CfbError::InvalidHeader);
        }
        let mut arc = CfbArchive {
            bytes,
            limits,
            major_version: major,
            sector_size: ss,
            mini_cutoff,
            root_clsid: [0; 16],
            fat: Vec::new(),
            minifat: Vec::new(),
            mini_chain: Vec::new(),
            mini_size: 0,
            entries: Vec::new(),
        };
        // DIFAT: header entries, then the DIFAT sector chain.
        let mut fat_sectors: Vec<u32> = Vec::new();
        fat_sectors.try_reserve(num_fat).map_err(|_| CfbError::Allocation)?;
        for k in 0..109 {
            if fat_sectors.len() == num_fat {
                break;
            }
            fat_sectors.push(le32(bytes, 0x4C + 4 * k));
        }
        let mut dif = first_difat;
        let mut seen = 0usize;
        let per = ss / 4 - 1;
        while fat_sectors.len() < num_fat {
            if dif > MAXREGSECT || seen >= num_difat.max(1) || seen > num_sectors {
                return Err(CfbError::InvalidChain);
            }
            let sec = arc.sector(dif)?;
            for k in 0..per {
                if fat_sectors.len() == num_fat {
                    break;
                }
                fat_sectors.push(le32(sec, 4 * k));
            }
            dif = le32(sec, 4 * per);
            seen += 1;
        }
        // FAT
        let mut fat = Vec::new();
        fat.try_reserve(num_fat * (ss / 4)).map_err(|_| CfbError::Allocation)?;
        for &fs in &fat_sectors {
            let sec = arc.sector(fs)?;
            fat.extend(sec.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])));
        }
        arc.fat = fat;
        // Mini FAT
        if num_minifat > 0 {
            let chain = arc.chain(first_minifat, &arc.fat, num_sectors)?;
            if chain.len() < num_minifat {
                return Err(CfbError::InvalidChain);
            }
            let mut mf = Vec::new();
            mf.try_reserve(num_minifat * (ss / 4)).map_err(|_| CfbError::Allocation)?;
            for &s in &chain[..num_minifat] {
                let sec = arc.sector(s)?;
                mf.extend(sec.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])));
            }
            arc.minifat = mf;
        }
        // Directory
        let dir_chain = arc.chain(first_dir, &arc.fat, num_sectors)?;
        let per_sector = ss / DIR_ENTRY;
        let max_dirs = dir_chain.len().saturating_mul(per_sector);
        let mut raw: Vec<RawDir> = Vec::new();
        raw.try_reserve(max_dirs.min(limits.max_entries.saturating_add(1)))
            .map_err(|_| CfbError::Allocation)?;
        'outer: for &s in &dir_chain {
            let sec = arc.sector(s)?;
            for k in 0..per_sector {
                let e = &sec[k * DIR_ENTRY..(k + 1) * DIR_ENTRY];
                if raw.len() > limits.max_entries {
                    break 'outer;
                }
                let name_len = le16(e, 64) as usize;
                let typ = e[66];
                let name = if typ == 0 || name_len == 0 {
                    Vec::new()
                } else {
                    if name_len > 64 || name_len % 2 != 0 {
                        return Err(CfbError::InvalidDirectory);
                    }
                    let units = name_len / 2 - 1;
                    (0..units).map(|i| le16(e, 2 * i)).collect()
                };
                let mut size = le64(e, 120);
                if major == 3 {
                    size &= 0xFFFF_FFFF;
                }
                let mut clsid = [0u8; 16];
                clsid.copy_from_slice(&e[80..96]);
                raw.push(RawDir {
                    name,
                    typ,
                    left: le32(e, 68),
                    right: le32(e, 72),
                    child: le32(e, 76),
                    clsid,
                    state_bits: le32(e, 96),
                    ctime: le64(e, 100),
                    mtime: le64(e, 108),
                    start: le32(e, 116),
                    size,
                });
            }
        }
        let root = raw.first().ok_or(CfbError::InvalidDirectory)?;
        if root.typ != 5 {
            return Err(CfbError::InvalidDirectory);
        }
        arc.root_clsid = root.clsid;
        arc.mini_size = root.size;
        if root.size > 0 {
            let need = usize::try_from(root.size.div_ceil(ss as u64)).map_err(|_| CfbError::InvalidHeader)?;
            if need > num_sectors {
                return Err(CfbError::InvalidChain);
            }
            let chain = arc.chain(root.start, &arc.fat, num_sectors)?;
            if chain.len() < need {
                return Err(CfbError::InvalidChain);
            }
            arc.mini_chain = chain;
        }
        let decode_msi = match limits.msi_names {
            MsiNames::Always => true,
            MsiNames::Never => false,
            MsiNames::Auto => {
                MSI_CLSIDS.iter().any(|c| root.clsid[..4] == *c && root.clsid[4..] == [0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
                    || raw.iter().any(|d| (d.typ == 1 || d.typ == 2) && d.name.first() == Some(&0x4840))
            }
        };
        arc.entries = walk(&raw, decode_msi, limits.max_entries)?;
        Ok(arc)
    }

    /// Bytes of sector `id` (the final sector of the file may be short).
    fn sector(&self, id: u32) -> Result<&'a [u8], CfbError> {
        if id > MAXREGSECT {
            return Err(CfbError::InvalidSector);
        }
        let start = (id as usize + 1).checked_mul(self.sector_size).ok_or(CfbError::InvalidSector)?;
        if start >= self.bytes.len() {
            return Err(CfbError::InvalidSector);
        }
        let end = (start + self.sector_size).min(self.bytes.len());
        if end - start < self.sector_size {
            return Err(CfbError::Truncated);
        }
        Ok(&self.bytes[start..end])
    }

    /// Follow a chain through `table` (FAT or mini FAT), at most `max` links.
    fn chain(&self, start: u32, table: &[u32], max: usize) -> Result<Vec<u32>, CfbError> {
        let mut out = Vec::new();
        let mut cur = start;
        while cur != ENDOFCHAIN {
            if cur > MAXREGSECT || cur as usize >= table.len() {
                return Err(CfbError::InvalidSector);
            }
            if out.len() >= max.min(table.len()) {
                return Err(CfbError::InvalidChain);
            }
            out.try_reserve(1).map_err(|_| CfbError::Allocation)?;
            out.push(cur);
            cur = table[cur as usize];
            if cur == FREESECT {
                return Err(CfbError::InvalidChain);
            }
        }
        Ok(out)
    }

    pub fn entries(&self) -> &[CfbEntry] {
        &self.entries
    }

    /// Contents of stream entry `index`.
    pub fn read(&self, index: usize) -> Result<Vec<u8>, CfbError> {
        let e = self.entries.get(index).ok_or(CfbError::OutOfRange)?;
        if e.kind != CfbEntryKind::Stream {
            return Err(CfbError::NotAStream);
        }
        if e.size > self.limits.max_stream_size {
            return Err(CfbError::LimitExceeded);
        }
        let size = usize::try_from(e.size).map_err(|_| CfbError::LimitExceeded)?;
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if e.size < self.mini_cutoff {
            let need = size.div_ceil(MINI_SECTOR);
            if (need as u64).saturating_mul(MINI_SECTOR as u64) > self.mini_size.next_multiple_of(MINI_SECTOR as u64) {
                return Err(CfbError::InvalidChain);
            }
            let chain = chain_n(e.start_sector, &self.minifat, need)?;
            out.try_reserve(size).map_err(|_| CfbError::Allocation)?;
            for &m in &chain[..need] {
                let off = m as usize * MINI_SECTOR;
                let sec_idx = off / self.sector_size;
                let in_sec = off % self.sector_size;
                let s = *self.mini_chain.get(sec_idx).ok_or(CfbError::InvalidSector)?;
                let sec = self.sector(s)?;
                let n = (size - out.len()).min(MINI_SECTOR);
                out.extend_from_slice(&sec[in_sec..in_sec + n]);
            }
        } else {
            let need = size.div_ceil(self.sector_size);
            if need > self.fat.len() {
                return Err(CfbError::InvalidChain);
            }
            let chain = chain_n(e.start_sector, &self.fat, need)?;
            out.try_reserve(size).map_err(|_| CfbError::Allocation)?;
            for &c in &chain[..need] {
                let sec = self.sector(c)?;
                let n = (size - out.len()).min(self.sector_size);
                out.extend_from_slice(&sec[..n]);
            }
        }
        Ok(out)
    }

    /// Index of the entry with display path `path`.
    pub fn find(&self, path: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.path == path)
    }

    /// Format-neutral entries (storages as directories, streams as files).
    pub fn planned_entries(&self) -> Vec<PlannedEntry> {
        self.entries
            .iter()
            .map(|e| PlannedEntry {
                path: e.path.as_bytes().to_vec(),
                kind: if e.kind == CfbEntryKind::Storage { EntryKind::Dir } else { EntryKind::File },
                size: if e.kind == CfbEntryKind::Stream { e.size } else { 0 },
                mode: None,
                mtime: e.mtime_unix(),
            })
            .collect()
    }
}

/// The first `n` links of a chain; a repeated sector, a free sector or an
/// early end of chain is an error. Work and memory are O(n).
fn chain_n(start: u32, table: &[u32], n: usize) -> Result<Vec<u32>, CfbError> {
    let mut out = Vec::new();
    out.try_reserve(n).map_err(|_| CfbError::Allocation)?;
    let mut seen = std::collections::HashSet::new();
    seen.try_reserve(n).map_err(|_| CfbError::Allocation)?;
    let mut cur = start;
    for _ in 0..n {
        if cur > MAXREGSECT || cur as usize >= table.len() {
            return Err(if cur == ENDOFCHAIN || cur == FREESECT { CfbError::InvalidChain } else { CfbError::InvalidSector });
        }
        if !seen.insert(cur) {
            return Err(CfbError::InvalidChain);
        }
        out.push(cur);
        cur = table[cur as usize];
    }
    Ok(out)
}

/// Depth-first walk of the storage tree; siblings in tree (sorted) order.
fn walk(raw: &[RawDir], decode_msi: bool, max_entries: usize) -> Result<Vec<CfbEntry>, CfbError> {
    let mut visited = vec![false; raw.len()];
    visited[0] = true;
    let mut out: Vec<CfbEntry> = Vec::new();
    // stack of (storage child-tree root, parent path); processed in order by
    // expanding each sibling tree in-order before descending.
    let mut work: Vec<(u32, String)> = vec![(raw[0].child, String::new())];
    while let Some((tree_root, parent)) = work.pop() {
        // in-order traversal of the sibling tree
        let mut siblings: Vec<u32> = Vec::new();
        let mut stack: Vec<u32> = Vec::new();
        let mut cur = tree_root;
        loop {
            while cur != NOSTREAM {
                let d = raw.get(cur as usize).ok_or(CfbError::InvalidDirectory)?;
                if visited[cur as usize] || !(d.typ == 1 || d.typ == 2) {
                    return Err(CfbError::InvalidDirectory);
                }
                visited[cur as usize] = true;
                stack.push(cur);
                cur = d.left;
            }
            let Some(n) = stack.pop() else { break };
            siblings.push(n);
            cur = raw[n as usize].right;
        }
        let mut subdirs: Vec<(u32, String)> = Vec::new();
        for id in siblings {
            if out.len() >= max_entries {
                return Err(CfbError::LimitExceeded);
            }
            let d = &raw[id as usize];
            let shown = if decode_msi { decode_msi_name(&d.name) } else { d.name.clone() };
            let name = display_name(&shown);
            let path = if parent.is_empty() { name } else { format!("{parent}/{name}") };
            let kind = if d.typ == 1 { CfbEntryKind::Storage } else { CfbEntryKind::Stream };
            if kind == CfbEntryKind::Storage {
                subdirs.push((d.child, path.clone()));
            }
            out.push(CfbEntry {
                path,
                name_utf16: d.name.clone(),
                kind,
                size: if kind == CfbEntryKind::Stream { d.size } else { 0 },
                clsid: d.clsid,
                state_bits: d.state_bits,
                ctime: d.ctime,
                mtime: d.mtime,
                dir_id: id,
                start_sector: d.start,
            });
        }
        // push in reverse so the first storage is expanded first
        for s in subdirs.into_iter().rev() {
            work.push(s);
        }
    }
    Ok(out)
}
