// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO-9660 directory walk with Rock Ridge (RRIP) names and attributes.
//!
//! Spec sources: ECMA-119 4th edition (directory records, 9.1; volume
//! descriptors, 8), IEEE P1281 System Use Sharing Protocol 1.12 (SP, CE, PD,
//! ST, ER entries) and IEEE P1282 Rock Ridge Interchange Protocol 1.12 (PX,
//! NM, SL, CL, PL, RE, TF entries).
//!
//! This module covers what the plain ISO-9660 directory reader
//! (`iso9660_dir`, owned by the forge queue) does not: System Use areas,
//! Rock Ridge alternate names, POSIX modes, symbolic link targets, deep
//! directory relocation (CL/RE), Rock Ridge and record timestamps,
//! multi-extent files (ECMA-119 6.5.1) and extended attribute records in
//! front of file data. Without Rock Ridge (no SP entry in the root `.`
//! record) the walk falls back to the primary ISO names, so it is usable on
//! any ISO-9660 image. Joliet names are left to `iso9660_dir`.
//!
//! Adapter seam: [`list_entries`] takes the root directory as an
//! [`IsoDirRef`]; callers holding an `iso9660_dir::IsoVolume` pass
//! `IsoDirRef { extent: vol.root.extent, size: vol.root.size }`.
//! [`primary_root`] is a minimal stand-in that reads it from the first
//! Primary Volume Descriptor.
//!
//! Every read is bounds-checked and every walk is bounded by [`RrLimits`];
//! malformed input returns an error, never a panic.

use std::collections::HashSet;

const SECTOR: u64 = 2048;
const MAX_DESCRIPTORS: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrError {
    /// A structure lies (partly) outside the image.
    Truncated,
    /// No Primary Volume Descriptor (only from [`primary_root`]).
    NoPrimaryDescriptor,
    /// Malformed volume descriptor or directory record.
    BadRecord,
    /// Malformed System Use entry.
    BadSusp,
    /// A name is not a usable path component.
    BadName,
    /// A directory is reachable from itself.
    LoopDetected,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Interleaved file data (file unit size / gap) is not supported.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrLimits {
    pub max_depth: usize,
    pub max_entries: usize,
    /// Continuation areas followed per directory record.
    pub max_ce_hops: usize,
    /// Extents of one multi-extent file.
    pub max_extents: usize,
}

impl Default for RrLimits {
    fn default() -> Self {
        RrLimits { max_depth: 64, max_entries: 1_000_000, max_ce_hops: 32, max_extents: 4096 }
    }
}

/// A directory's location: first logical block (2048 bytes) and byte size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoDirRef {
    pub extent: u32,
    pub size: u32,
}

/// One contiguous piece of file data: first block and length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoSpan {
    pub block: u32,
    pub len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RrKind {
    File,
    Dir,
    Symlink { target: String },
    /// Device, FIFO or socket (metadata only).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrEntry {
    /// Components joined with `/`, no leading `/`.
    pub path: String,
    pub kind: RrKind,
    /// Total data size (sum of all extents; 0 for directories and links).
    pub size: u64,
    /// POSIX mode from the PX entry, when present.
    pub mode: Option<u32>,
    /// Modification time (TF modify stamp, else the record date), Unix seconds UTC.
    pub mtime: Option<i64>,
    /// Data extents in order (more than one for multi-extent files).
    pub extents: Vec<IsoSpan>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RrInfo {
    /// Concatenated NM name, if any NM entry was present.
    pub name: Option<String>,
    /// NM flagged CURRENT or PARENT.
    pub name_special: bool,
    pub mode: Option<u32>,
    pub symlink: Option<String>,
    /// CL: block of the relocated directory this record stands for.
    pub child_link: Option<u32>,
    /// RE: this directory was relocated and is listed through its CL.
    pub relocated: bool,
    pub mtime: Option<i64>,
    /// SP entry (only meaningful in the root `.` record): bytes to skip.
    pub sp_skip: Option<u8>,
}

// ----------------------------------------------------------------- helpers

fn le32(b: &[u8], at: usize) -> Result<u32, RrError> {
    let s = b.get(at..at + 4).ok_or(RrError::BadRecord)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn image_range(image: &[u8], block: u32, offset: u64, len: u64) -> Result<&[u8], RrError> {
    let start = (block as u64).checked_mul(SECTOR).and_then(|s| s.checked_add(offset)).ok_or(RrError::Truncated)?;
    let end = start.checked_add(len).ok_or(RrError::Truncated)?;
    if end > image.len() as u64 {
        return Err(RrError::Truncated);
    }
    Ok(&image[start as usize..end as usize])
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, off_quarters: i8) -> Option<i64> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let local = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s;
    let off = if (-48..=52).contains(&off_quarters) { off_quarters as i64 * 900 } else { 0 };
    Some(local - off)
}

/// ECMA-119 9.1.5 seven-byte recording date.
fn short_date(b: &[u8]) -> Option<i64> {
    let b = b.get(..7)?;
    if b.iter().all(|&x| x == 0) {
        return None;
    }
    civil_to_unix(1900 + b[0] as i64, b[1] as i64, b[2] as i64, b[3] as i64, b[4] as i64, b[5] as i64, b[6] as i8)
}

/// ECMA-119 8.4.26.1 seventeen-byte date ("YYYYMMDDHHMMSScc" + offset).
fn long_date(b: &[u8]) -> Option<i64> {
    let b = b.get(..17)?;
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = std::str::from_utf8(&b[r]).ok()?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let y = num(0..4)?;
    if y == 0 {
        return None;
    }
    civil_to_unix(y, num(4..6)?, num(6..8)?, num(8..10)?, num(10..12)?, num(12..14)?, b[16] as i8)
}

fn valid_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Primary ISO name: drop the `;version`, and the lone trailing `.` of
/// files without an extension.
fn iso_name(raw: &[u8], is_dir: bool) -> Result<String, RrError> {
    let mut s = String::from_utf8_lossy(raw).into_owned();
    if let Some(i) = s.find(';') {
        s.truncate(i);
    }
    if !is_dir && s.ends_with('.') {
        s.pop();
    }
    if !valid_component(&s) {
        return Err(RrError::BadName);
    }
    Ok(s)
}

// ---------------------------------------------------------- volume seam

/// Root directory of the first Primary Volume Descriptor (ECMA-119 8.4).
/// Stand-in for `iso9660_dir::parse_volume(..).root`.
pub fn primary_root(image: &[u8]) -> Result<IsoDirRef, RrError> {
    for n in 16..16 + MAX_DESCRIPTORS {
        let d = image_range(image, n as u32, 0, SECTOR)?;
        if &d[1..6] != b"CD001" {
            return Err(RrError::NoPrimaryDescriptor);
        }
        match d[0] {
            255 => break,
            1 => {
                if u16::from_le_bytes([d[128], d[129]]) != 2048 {
                    return Err(RrError::Unsupported);
                }
                return Ok(IsoDirRef { extent: le32(d, 158)?, size: le32(d, 166)? });
            }
            _ => {}
        }
    }
    Err(RrError::NoPrimaryDescriptor)
}

// ------------------------------------------------------------------ SUSP

/// System Use area of a directory record (after the name and its padding
/// byte), minus `skip` bytes announced by the SP entry.
fn system_use(record: &[u8], skip: usize) -> &[u8] {
    let name_len = record.get(32).copied().unwrap_or(0) as usize;
    let start = 33 + name_len + usize::from(name_len.is_multiple_of(2)) + skip;
    record.get(start..).unwrap_or(&[])
}

/// Parse the SUSP / RRIP entries of one directory record, following CE
/// continuation areas. `skip` is the SP LEN_SKP value (0 for the root `.`).
pub fn parse_system_use(image: &[u8], record: &[u8], skip: usize, limits: &RrLimits) -> Result<RrInfo, RrError> {
    let mut info = RrInfo::default();
    let mut name: Vec<u8> = Vec::new();
    let mut name_seen = false;
    let mut link: Vec<String> = Vec::new();
    let mut link_cur: Option<String> = None;
    let mut link_abs = false;
    let mut link_seen = false;
    let mut area = system_use(record, skip);
    let mut hops = 0usize;
    loop {
        let mut next: Option<(u32, u32, u32)> = None;
        let mut pos = 0usize;
        while pos + 4 <= area.len() {
            let sig = [area[pos], area[pos + 1]];
            if sig == [0, 0] {
                break; // zero padding at the end of the area
            }
            let len = area[pos + 2] as usize;
            if len < 4 || pos + len > area.len() {
                return Err(RrError::BadSusp);
            }
            let e = &area[pos..pos + len];
            pos += len;
            match &sig {
                b"ST" => break,
                b"CE" => {
                    if len < 28 {
                        return Err(RrError::BadSusp);
                    }
                    next = Some((le32(e, 4)?, le32(e, 12)?, le32(e, 20)?));
                }
                b"SP" => {
                    if len < 7 || e[4] != 0xBE || e[5] != 0xEF {
                        return Err(RrError::BadSusp);
                    }
                    info.sp_skip = Some(e[6]);
                }
                b"NM" => {
                    let flags = *e.get(4).ok_or(RrError::BadSusp)?;
                    name_seen = true;
                    if flags & 0x06 != 0 {
                        info.name_special = true;
                    }
                    name.extend_from_slice(e.get(5..).unwrap_or(&[]));
                    if name.len() > 4096 {
                        return Err(RrError::LimitExceeded);
                    }
                }
                b"PX" => info.mode = Some(le32(e, 4).map_err(|_| RrError::BadSusp)?),
                b"SL" => {
                    link_seen = true;
                    let mut p = 5usize;
                    while p + 2 <= e.len() {
                        let (cf, cl) = (e[p], e[p + 1] as usize);
                        let content = e.get(p + 2..p + 2 + cl).ok_or(RrError::BadSusp)?;
                        p += 2 + cl;
                        let cur = link_cur.get_or_insert_with(String::new);
                        if cf & 0x02 != 0 {
                            cur.push('.');
                        } else if cf & 0x04 != 0 {
                            cur.push_str("..");
                        } else if cf & 0x08 != 0 {
                            link_abs = true;
                            link.clear();
                            link_cur = None;
                            continue;
                        } else if cf & 0x30 != 0 {
                            return Err(RrError::Unsupported);
                        } else {
                            cur.push_str(&String::from_utf8_lossy(content));
                        }
                        if cf & 0x01 == 0 {
                            link.push(link_cur.take().unwrap_or_default());
                        }
                        if link.len() > 4096 {
                            return Err(RrError::LimitExceeded);
                        }
                    }
                    if p != e.len() {
                        return Err(RrError::BadSusp);
                    }
                }
                b"CL" => info.child_link = Some(le32(e, 4).map_err(|_| RrError::BadSusp)?),
                b"RE" => info.relocated = true,
                b"TF" => {
                    let flags = *e.get(4).ok_or(RrError::BadSusp)?;
                    let size = if flags & 0x80 != 0 { 17 } else { 7 };
                    if flags & 0x02 != 0 {
                        let idx = usize::from(flags & 0x01 != 0);
                        let at = 5 + idx * size;
                        let stamp = e.get(at..at + size).ok_or(RrError::BadSusp)?;
                        info.mtime = if size == 17 { long_date(stamp) } else { short_date(stamp) };
                    }
                }
                // PD padding, PL, ER, ES, RR (RRIP 1.09 flags), PN, SF, ZF, ...
                _ => {}
            }
        }
        let Some((block, offset, length)) = next else { break };
        hops += 1;
        if hops > limits.max_ce_hops {
            return Err(RrError::LimitExceeded);
        }
        area = image_range(image, block, offset as u64, length as u64)?;
    }
    if name_seen {
        info.name = Some(String::from_utf8_lossy(&name).into_owned());
    }
    if link_seen {
        if let Some(rest) = link_cur.take() {
            link.push(rest);
        }
        let joined = link.join("/");
        info.symlink = Some(if link_abs { format!("/{joined}") } else { joined });
    }
    Ok(info)
}

/// `Some(len_skp)` when the root directory's `.` record carries a SUSP SP
/// entry (Rock Ridge / SUSP in use), else `None`.
pub fn detect_susp(image: &[u8], root: IsoDirRef) -> Result<Option<u8>, RrError> {
    let data = image_range(image, root.extent, 0, root.size as u64)?;
    let len = *data.first().ok_or(RrError::BadRecord)? as usize;
    if len < 34 {
        return Err(RrError::BadRecord);
    }
    let rec = data.get(..len).ok_or(RrError::BadRecord)?;
    let area = system_use(rec, 0);
    if area.len() >= 7 && &area[..2] == b"SP" && area[4] == 0xBE && area[5] == 0xEF {
        return Ok(Some(area[6]));
    }
    Ok(None)
}

// ------------------------------------------------------------------ walk

/// Iterate the directory records of a directory extent (ECMA-119 6.8.1:
/// records do not cross sector boundaries; a zero length byte pads to the
/// next sector).
fn records(data: &[u8]) -> impl Iterator<Item = Result<&[u8], RrError>> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        while pos < data.len() {
            let len = data[pos] as usize;
            if len == 0 {
                pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
                continue;
            }
            if len < 34 || pos + len > data.len() {
                pos = data.len();
                return Some(Err(RrError::BadRecord));
            }
            let r = &data[pos..pos + len];
            pos += len;
            return Some(Ok(r));
        }
        None
    })
}

struct Walk<'a> {
    image: &'a [u8],
    limits: &'a RrLimits,
    skip: Option<usize>,
    seen: HashSet<u32>,
    out: Vec<RrEntry>,
}

struct Pending {
    name: Vec<u8>,
    extents: Vec<IsoSpan>,
}

impl Walk<'_> {
    fn dir(&mut self, dir: IsoDirRef, prefix: &str, depth: usize) -> Result<(), RrError> {
        let image = self.image;
        let data = image_range(image, dir.extent, 0, dir.size as u64)?;
        let mut pending: Option<Pending> = None;
        for rec in records(data) {
            let rec = rec?;
            let name_len = rec[32] as usize;
            let raw_name = rec.get(33..33 + name_len).ok_or(RrError::BadRecord)?;
            if name_len == 1 && (raw_name[0] == 0 || raw_name[0] == 1) {
                continue; // "." and ".."
            }
            if name_len == 0 {
                return Err(RrError::BadRecord);
            }
            let flags = rec[25];
            let is_dir = flags & 0x02 != 0;
            let xa = rec[1] as u32;
            let span = IsoSpan { block: le32(rec, 2)?.checked_add(xa).ok_or(RrError::BadRecord)?, len: le32(rec, 10)? };
            if !is_dir && (rec[26] != 0 || rec[27] != 0) {
                return Err(RrError::Unsupported);
            }
            // Multi-extent (ECMA-119 6.5.1): consecutive records, same name.
            let mut extents = vec![span];
            if let Some(p) = pending.take() {
                if p.name != raw_name || is_dir {
                    return Err(RrError::BadRecord);
                }
                extents = p.extents;
                if extents.len() >= self.limits.max_extents {
                    return Err(RrError::LimitExceeded);
                }
                extents.push(span);
            }
            if flags & 0x80 != 0 {
                if is_dir {
                    return Err(RrError::BadRecord);
                }
                pending = Some(Pending { name: raw_name.to_vec(), extents });
                continue;
            }
            let info = match self.skip {
                Some(skip) => parse_system_use(image, rec, skip, self.limits)?,
                None => RrInfo::default(),
            };
            if info.relocated {
                continue; // listed where its CL placeholder is
            }
            let name = match &info.name {
                Some(n) => {
                    if info.name_special || !valid_component(n) {
                        return Err(RrError::BadName);
                    }
                    n.clone()
                }
                None => iso_name(raw_name, is_dir)?,
            };
            if depth + 1 > self.limits.max_depth || self.out.len() >= self.limits.max_entries {
                return Err(RrError::LimitExceeded);
            }
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let mut child_dir = None;
            let kind = if let Some(cl) = info.child_link {
                // The relocated directory's own "." record gives its size.
                let first = image_range(image, cl, 0, SECTOR)?;
                let dot_len = first[0] as usize;
                if dot_len < 34 || first[32] != 1 || first[33] != 0 {
                    return Err(RrError::BadRecord);
                }
                child_dir = Some(IsoDirRef { extent: cl, size: le32(first, 10)? });
                RrKind::Dir
            } else if is_dir {
                child_dir = Some(IsoDirRef { extent: le32(rec, 2)?, size: span.len });
                RrKind::Dir
            } else if let Some(target) = info.symlink.clone() {
                RrKind::Symlink { target }
            } else {
                match info.mode.map(|m| m & 0o170000) {
                    None | Some(0) | Some(0o100000) => RrKind::File,
                    Some(0o120000) => return Err(RrError::BadSusp),
                    Some(0o040000) => return Err(RrError::BadRecord),
                    Some(_) => RrKind::Other,
                }
            };
            let size = match kind {
                RrKind::File | RrKind::Other => extents.iter().map(|e| e.len as u64).sum(),
                _ => 0,
            };
            self.out.try_reserve(1).map_err(|_| RrError::Allocation)?;
            let kind_ref = &kind;
            let extents = if matches!(kind_ref, RrKind::File | RrKind::Other) { extents } else { Vec::new() };
            self.out.push(RrEntry {
                path: path.clone(),
                kind,
                size,
                mode: info.mode,
                mtime: info.mtime.or_else(|| short_date(&rec[18..25])),
                extents,
            });
            if let Some(d) = child_dir {
                if !self.seen.insert(d.extent) {
                    return Err(RrError::LoopDetected);
                }
                self.dir(d, &path, depth + 1)?;
            }
        }
        if pending.is_some() {
            return Err(RrError::BadRecord);
        }
        Ok(())
    }
}

/// Pre-order listing of the tree rooted at `root`, using Rock Ridge names
/// and attributes when the root `.` record carries an SP entry, else the
/// primary ISO names. Relocated directories appear at their original place.
pub fn list_entries(image: &[u8], root: IsoDirRef, limits: &RrLimits) -> Result<Vec<RrEntry>, RrError> {
    let skip = detect_susp(image, root)?.map(usize::from);
    let mut walk = Walk { image, limits, skip, seen: HashSet::new(), out: Vec::new() };
    walk.seen.insert(root.extent);
    walk.dir(root, "", 0)?;
    Ok(walk.out)
}

/// True when the tree rooted at `root` uses Rock Ridge (SP entry present).
pub fn has_rock_ridge(image: &[u8], root: IsoDirRef) -> bool {
    matches!(detect_susp(image, root), Ok(Some(_)))
}

/// Concatenated data of a listed file (all extents).
pub fn read_file(image: &[u8], entry: &RrEntry, max_size: u64) -> Result<Vec<u8>, RrError> {
    read_spans(image, &entry.extents, max_size)
}

/// Concatenated data of `spans`, refusing totals above `max_size`.
pub fn read_spans(image: &[u8], spans: &[IsoSpan], max_size: u64) -> Result<Vec<u8>, RrError> {
    let total: u64 = spans.iter().map(|e| e.len as u64).sum();
    if total > max_size {
        return Err(RrError::LimitExceeded);
    }
    let want = usize::try_from(total).map_err(|_| RrError::LimitExceeded)?;
    let mut out = Vec::new();
    out.try_reserve_exact(want).map_err(|_| RrError::Allocation)?;
    for e in spans {
        out.extend_from_slice(image_range(image, e.block, 0, e.len as u64)?);
    }
    Ok(out)
}
