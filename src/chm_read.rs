// SPDX-License-Identifier: MIT OR Apache-2.0
//! Microsoft Compiled HTML Help (.chm, ITSF/ITSS) reader: listing and
//! extraction, in memory.
//!
//! Spec source: the publicly documented ITSF layout (the "unofficial CHM
//! specification" describing the ITSF header, header section 0, the ITSP
//! directory header, PMGL listing chunks and PMGI index chunks with ENCINT
//! fields), and the MSCompressed section layout: LZXC ControlData (version 2
//! counts the reset interval and window size in 32 KiB units), the LZX
//! transform's ResetTable (one 64-bit compressed offset per 32 KiB frame),
//! and the Content stream, decoded with [`crate::lzx`].
//!
//! Directory entries are read by following the PMGL chunk chain from the
//! first listing chunk (PMGI index chunks are not needed for a full listing).
//! Content section 0 is stored; section 1 is LZX ("MSCompressed"). Reading a
//! section-1 file decodes from the reset point at or before its first frame.
//!
//! Every count, offset and length is bounds-checked against the file and
//! [`ChmLimits`]; malformed input returns an error.

use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::lzx::{FRAME_SIZE, LzxError, lzx_decompress};

const CONTENT: &[u8] = b"::DataSpace/Storage/MSCompressed/Content";
const CONTROL: &[u8] = b"::DataSpace/Storage/MSCompressed/ControlData";
const RESET_TABLE: &[u8] =
    b"::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChmError {
    Truncated,
    /// Missing `ITSF` / `ITSP` signature.
    InvalidSignature,
    /// Inconsistent ITSF / ITSP header fields.
    InvalidHeader,
    /// Malformed directory chunk or chunk chain.
    InvalidDirectory,
    /// Malformed directory entry (ENCINT overflow, bad name, range outside
    /// its section).
    InvalidEntry,
    /// Content section other than 0 (stored) and 1 (LZX), or section 1 data
    /// requested from a file without one.
    UnsupportedSection,
    /// Malformed LZXC ControlData.
    InvalidControlData,
    /// Malformed or inconsistent LZX ResetTable.
    InvalidResetTable,
    /// The LZX data is corrupt.
    DataError,
    LimitExceeded,
    Allocation,
    OutOfRange,
}

impl From<LzxError> for ChmError {
    fn from(e: LzxError) -> Self {
        match e {
            LzxError::LimitExceeded => ChmError::LimitExceeded,
            LzxError::Allocation => ChmError::Allocation,
            LzxError::InvalidWindow => ChmError::InvalidControlData,
            _ => ChmError::DataError,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChmLimits {
    pub max_entries: usize,
    pub max_name_len: usize,
    /// Largest number of decompressed bytes one read may produce (the reset
    /// interval containing an entry plus the entry itself).
    pub max_output: u64,
}

impl Default for ChmLimits {
    fn default() -> Self {
        ChmLimits { max_entries: 1_000_000, max_name_len: 4096, max_output: 1 << 30 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChmEntry {
    /// Name as stored (UTF-8, usually starting with `/` or `::`).
    pub name: Vec<u8>,
    /// Name with the leading `/` removed, decoded lossily as UTF-8.
    pub path: String,
    pub section: u64,
    pub offset: u64,
    pub length: u64,
}

impl ChmEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with(b"/")
    }

    /// Internal bookkeeping entries: `::DataSpace/...`, `/#...`, `/$...`.
    pub fn is_system(&self) -> bool {
        self.name.starts_with(b"::") || self.name.starts_with(b"/#") || self.name.starts_with(b"/$")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzxSection {
    /// Absolute byte range of the compressed Content stream.
    pub content: std::ops::Range<usize>,
    pub window_bits: u8,
    pub reset_interval_frames: u32,
    pub uncompressed_len: u64,
    /// Compressed offset (relative to `content`) of each 32 KiB frame.
    pub frame_offsets: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct ChmArchive<'a> {
    bytes: &'a [u8],
    limits: ChmLimits,
    pub version: u32,
    pub language: u32,
    /// Absolute offset of content section 0.
    pub content_offset: u64,
    entries: Vec<ChmEntry>,
    /// Section 1 setup; `None` when the file has no usable LZX section.
    pub lzx: Option<LzxSection>,
}

fn le32(b: &[u8], at: usize) -> Result<u32, ChmError> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(ChmError::Truncated)
}

fn le64(b: &[u8], at: usize) -> Result<u64, ChmError> {
    Ok(u64::from(le32(b, at)?) | (u64::from(le32(b, at + 4)?) << 32))
}

/// Big-endian base-128 integer with continuation bits.
fn encint(b: &[u8], at: &mut usize) -> Result<u64, ChmError> {
    let mut v: u64 = 0;
    for _ in 0..10 {
        let c = *b.get(*at).ok_or(ChmError::InvalidEntry)?;
        *at += 1;
        if v >> 57 != 0 {
            return Err(ChmError::InvalidEntry);
        }
        v = (v << 7) | u64::from(c & 0x7F);
        if c & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ChmError::InvalidEntry)
}

impl<'a> ChmArchive<'a> {
    pub fn parse(bytes: &'a [u8], limits: ChmLimits) -> Result<Self, ChmError> {
        if bytes.len() < 4 || &bytes[..4] != b"ITSF" {
            return Err(if bytes.len() < 4 { ChmError::Truncated } else { ChmError::InvalidSignature });
        }
        let version = le32(bytes, 4)?;
        let header_len = le32(bytes, 8)? as usize;
        let language = le32(bytes, 0x14)?;
        if !(2..=3).contains(&version) || header_len < 0x58 || header_len > bytes.len() {
            return Err(ChmError::InvalidHeader);
        }
        let dir_off = le64(bytes, 0x48)?;
        let dir_len = le64(bytes, 0x50)?;
        let dir_end = dir_off.checked_add(dir_len).ok_or(ChmError::InvalidHeader)?;
        if dir_end > bytes.len() as u64 {
            return Err(ChmError::Truncated);
        }
        let content_offset = if version >= 3 && header_len >= 0x60 { le64(bytes, 0x58)? } else { dir_end };
        if content_offset > bytes.len() as u64 {
            return Err(ChmError::Truncated);
        }
        let dir = &bytes[dir_off as usize..dir_end as usize];
        if dir.len() < 0x30 || &dir[..4] != b"ITSP" {
            return Err(if dir.len() < 4 { ChmError::Truncated } else { ChmError::InvalidSignature });
        }
        let itsp_len = le32(dir, 8)? as usize;
        let chunk_size = le32(dir, 0x10)? as usize;
        let first_pmgl = le32(dir, 0x20)?;
        let num_chunks = le32(dir, 0x2C)? as usize;
        if itsp_len < 0x30 || itsp_len > dir.len() || !(0x20..=1 << 20).contains(&chunk_size) {
            return Err(ChmError::InvalidHeader);
        }
        let chunks = &dir[itsp_len..];
        let avail = chunks.len() / chunk_size;
        if num_chunks > avail {
            return Err(ChmError::Truncated);
        }
        let mut entries: Vec<ChmEntry> = Vec::new();
        let mut cur = first_pmgl;
        let mut visited = 0usize;
        while cur != u32::MAX {
            let ci = cur as usize;
            if ci >= num_chunks || visited >= num_chunks {
                return Err(ChmError::InvalidDirectory);
            }
            visited += 1;
            let ch = &chunks[ci * chunk_size..(ci + 1) * chunk_size];
            if &ch[..4] != b"PMGL" {
                return Err(ChmError::InvalidDirectory);
            }
            let free = le32(ch, 4)? as usize;
            let next = le32(ch, 0x10)?;
            if free > chunk_size - 0x14 {
                return Err(ChmError::InvalidDirectory);
            }
            let end = chunk_size - free;
            let mut at = 0x14;
            while at < end {
                if entries.len() >= limits.max_entries {
                    return Err(ChmError::LimitExceeded);
                }
                let area = &ch[..end];
                let nlen = encint(area, &mut at)?;
                if nlen == 0 || nlen > limits.max_name_len as u64 {
                    return Err(ChmError::InvalidEntry);
                }
                let nend = at + nlen as usize;
                let name = area.get(at..nend).ok_or(ChmError::InvalidEntry)?.to_vec();
                at = nend;
                let section = encint(area, &mut at)?;
                let offset = encint(area, &mut at)?;
                let length = encint(area, &mut at)?;
                let shown = name.strip_prefix(b"/").unwrap_or(&name);
                let path = String::from_utf8_lossy(shown).into_owned();
                entries.try_reserve(1).map_err(|_| ChmError::Allocation)?;
                entries.push(ChmEntry { name, path, section, offset, length });
            }
            cur = next;
        }
        let mut arc = ChmArchive { bytes, limits, version, language, content_offset, entries, lzx: None };
        arc.lzx = arc.setup_lzx().ok();
        Ok(arc)
    }

    pub fn entries(&self) -> &[ChmEntry] {
        &self.entries
    }

    /// Index of the entry whose stored name is `name`.
    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.name == name)
    }

    fn section0(&self, offset: u64, length: u64) -> Result<&'a [u8], ChmError> {
        let start = self.content_offset.checked_add(offset).ok_or(ChmError::InvalidEntry)?;
        let end = start.checked_add(length).ok_or(ChmError::InvalidEntry)?;
        if end > self.bytes.len() as u64 {
            return Err(ChmError::InvalidEntry);
        }
        Ok(&self.bytes[start as usize..end as usize])
    }

    fn system_file(&self, name: &[u8]) -> Result<&'a [u8], ChmError> {
        let e = self.find(name).map(|i| &self.entries[i]).ok_or(ChmError::UnsupportedSection)?;
        if e.section != 0 {
            return Err(ChmError::UnsupportedSection);
        }
        self.section0(e.offset, e.length)
    }

    /// Read ControlData, ResetTable and locate Content.
    pub fn setup_lzx(&self) -> Result<LzxSection, ChmError> {
        let ctl = self.system_file(CONTROL)?;
        if ctl.len() < 24 || &ctl[4..8] != b"LZXC" {
            return Err(ChmError::InvalidControlData);
        }
        let cversion = le32(ctl, 8)?;
        let mut reset = u64::from(le32(ctl, 12)?);
        let mut window = u64::from(le32(ctl, 16)?);
        match cversion {
            1 => {}
            2 => {
                reset *= FRAME_SIZE as u64;
                window *= FRAME_SIZE as u64;
            }
            _ => return Err(ChmError::InvalidControlData),
        }
        let window_bits = match window {
            0x8000 => 15,
            0x10000 => 16,
            0x20000 => 17,
            0x40000 => 18,
            0x80000 => 19,
            0x100000 => 20,
            0x200000 => 21,
            _ => return Err(ChmError::InvalidControlData),
        };
        if reset == 0 || reset % FRAME_SIZE as u64 != 0 {
            return Err(ChmError::InvalidControlData);
        }
        let reset_interval_frames = u32::try_from(reset / FRAME_SIZE as u64).map_err(|_| ChmError::InvalidControlData)?;
        let rt = self.system_file(RESET_TABLE)?;
        let n = le32(rt, 4)? as usize;
        let entry_size = le32(rt, 8)?;
        let table_off = le32(rt, 12)? as usize;
        let uncompressed_len = le64(rt, 16)?;
        let block = le64(rt, 32)?;
        if entry_size != 8 || block != FRAME_SIZE as u64 || table_off < 40 {
            return Err(ChmError::InvalidResetTable);
        }
        let table_end = n.checked_mul(8).and_then(|x| x.checked_add(table_off)).ok_or(ChmError::InvalidResetTable)?;
        if table_end > rt.len() {
            return Err(ChmError::InvalidResetTable);
        }
        let frames = uncompressed_len.div_ceil(FRAME_SIZE as u64);
        if (n as u64) < frames {
            return Err(ChmError::InvalidResetTable);
        }
        let content = self.system_file(CONTENT)?;
        let base = content.as_ptr() as usize - self.bytes.as_ptr() as usize;
        let mut frame_offsets = Vec::new();
        frame_offsets.try_reserve(n).map_err(|_| ChmError::Allocation)?;
        for k in 0..n {
            let o = le64(rt, table_off + 8 * k)?;
            if o > content.len() as u64 {
                return Err(ChmError::InvalidResetTable);
            }
            frame_offsets.push(o);
        }
        Ok(LzxSection {
            content: base..base + content.len(),
            window_bits,
            reset_interval_frames,
            uncompressed_len,
            frame_offsets,
        })
    }

    /// Decode section-1 bytes `[start, end)`.
    fn section1(&self, start: u64, end: u64) -> Result<Vec<u8>, ChmError> {
        let lzx = self.lzx.as_ref().ok_or(ChmError::UnsupportedSection)?;
        if end > lzx.uncompressed_len || start > end {
            return Err(ChmError::InvalidEntry);
        }
        if start == end {
            return Ok(Vec::new());
        }
        let frame = start / FRAME_SIZE as u64;
        let reset_frame = frame - frame % u64::from(lzx.reset_interval_frames);
        let out_start = reset_frame * FRAME_SIZE as u64;
        let out_end = end.next_multiple_of(FRAME_SIZE as u64).min(lzx.uncompressed_len);
        let n = out_end - out_start;
        if n > self.limits.max_output {
            return Err(ChmError::LimitExceeded);
        }
        let in_off = *lzx.frame_offsets.get(reset_frame as usize).ok_or(ChmError::InvalidResetTable)? as usize;
        let input = &self.bytes[lzx.content.start + in_off..lzx.content.end];
        let data = lzx_decompress(input, lzx.window_bits, n as usize, lzx.reset_interval_frames)?;
        let a = (start - out_start) as usize;
        let b = (end - out_start) as usize;
        Ok(data[a..b].to_vec())
    }

    /// Contents of entry `index` (empty for directories).
    pub fn read(&self, index: usize) -> Result<Vec<u8>, ChmError> {
        let e = self.entries.get(index).ok_or(ChmError::OutOfRange)?;
        if e.length > self.limits.max_output {
            return Err(ChmError::LimitExceeded);
        }
        match e.section {
            0 => {
                let s = self.section0(e.offset, e.length)?;
                let mut v = Vec::new();
                v.try_reserve(s.len()).map_err(|_| ChmError::Allocation)?;
                v.extend_from_slice(s);
                Ok(v)
            }
            1 => {
                let end = e.offset.checked_add(e.length).ok_or(ChmError::InvalidEntry)?;
                self.section1(e.offset, end)
            }
            _ => Err(ChmError::UnsupportedSection),
        }
    }

    /// Read every entry, decoding the LZX section at most once (when it fits
    /// `max_output`; otherwise entries are decoded one by one).
    pub fn read_all(&self) -> Vec<Result<Vec<u8>, ChmError>> {
        let whole = match &self.lzx {
            Some(l)
                if l.uncompressed_len <= self.limits.max_output
                    && self.entries.iter().any(|e| e.section == 1 && e.length > 0) =>
            {
                Some(self.section1(0, l.uncompressed_len))
            }
            _ => None,
        };
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| match (&whole, e.section) {
                (Some(Ok(d)), 1) => {
                    let end = e.offset.checked_add(e.length).ok_or(ChmError::InvalidEntry)?;
                    if end > d.len() as u64 {
                        return Err(ChmError::InvalidEntry);
                    }
                    Ok(d[e.offset as usize..end as usize].to_vec())
                }
                (Some(Err(err)), 1) => Err(*err),
                _ => self.read(i),
            })
            .collect()
    }

    /// Format-neutral entries: names ending in `/` are directories.
    pub fn planned_entries(&self) -> Vec<PlannedEntry> {
        self.entries
            .iter()
            .map(|e| PlannedEntry {
                path: e.path.as_bytes().to_vec(),
                kind: if e.is_dir() { EntryKind::Dir } else { EntryKind::File },
                size: if e.is_dir() { 0 } else { e.length },
                mode: None,
                mtime: None,
            })
            .collect()
    }
}
