// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only disc / disk image front end: format detection and a uniform
//! entry listing over UDF ([`crate::udf_read`]), ISO-9660 with Rock Ridge
//! ([`crate::iso_rockridge`]) and partition tables (partitions listed as
//! `N.img` entries).
//!
//! Spec sources: ECMA-119 8 (volume descriptor set at sector 16, `CD001`),
//! ECMA-167 2/8.3 (volume recognition sequence), the IBM PC MBR layout
//! (boot signature `55 AA` at 510, four 16-byte entries at 446) and the
//! UEFI 2.x specification chapter 5 (GPT header `EFI PART` at LBA 1, a
//! protective MBR entry of type `0xEE`).
//!
//! Adapter seams (forge-owned modules not yet integrated when this was
//! written):
//! - Partition tables are parsed by `mbr_gpt`. Its results are turned into
//!   entries by [`partition_entries`] through the neutral
//!   [`PartitionSpan`]; [`list_disc`] returns `Unsupported` for `Mbr`/`Gpt`
//!   until the coordinator adds that arm.
//! - Joliet names come from `iso9660_dir`; this front end lists ISO images
//!   through Rock Ridge or primary names.

use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::iso_rockridge::{self, IsoSpan, RrError, RrKind, RrLimits};
use crate::udf_read::{self, UdfAddr, UdfError, UdfKind, UdfLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscError {
    /// No known disc / disk image signature.
    NotADisc,
    /// Recognised, but this structure is not read (yet).
    Unsupported,
    /// A structure or entry lies outside the image.
    Truncated,
    /// Structurally invalid metadata.
    Invalid,
    /// A directory is reachable from itself.
    LoopDetected,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// An entry index is out of range.
    OutOfRange,
}

impl From<UdfError> for DiscError {
    fn from(e: UdfError) -> Self {
        match e {
            UdfError::Truncated => DiscError::Truncated,
            UdfError::Unsupported => DiscError::Unsupported,
            UdfError::LoopDetected => DiscError::LoopDetected,
            UdfError::LimitExceeded => DiscError::LimitExceeded,
            UdfError::Allocation => DiscError::Allocation,
            UdfError::NoAnchor
            | UdfError::BadTag
            | UdfError::BadChecksum
            | UdfError::BadCrc
            | UdfError::BadDescriptor
            | UdfError::NoPartition
            | UdfError::NoFileSet
            | UdfError::BadAddress
            | UdfError::BadAllocation
            | UdfError::BadName => DiscError::Invalid,
        }
    }
}

impl From<RrError> for DiscError {
    fn from(e: RrError) -> Self {
        match e {
            RrError::Truncated => DiscError::Truncated,
            RrError::Unsupported => DiscError::Unsupported,
            RrError::LoopDetected => DiscError::LoopDetected,
            RrError::LimitExceeded => DiscError::LimitExceeded,
            RrError::Allocation => DiscError::Allocation,
            RrError::NoPrimaryDescriptor | RrError::BadRecord | RrError::BadSusp | RrError::BadName => {
                DiscError::Invalid
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscKind {
    /// ISO-9660 only.
    Iso,
    /// UDF only.
    Udf,
    /// ISO-9660 and UDF structures on the same image (UDF bridge).
    IsoUdf,
    /// GUID partition table (protective MBR + `EFI PART` header).
    Gpt,
    /// Classic MBR partition table.
    Mbr,
}

/// Identify a disc / disk image by its signatures. File systems win over a
/// partition table, so hybrid ISO images (with an MBR in the system area)
/// are reported as ISO.
pub fn detect_disc(image: &[u8]) -> Option<DiscKind> {
    let iso = image.get(32769..32774) == Some(b"CD001");
    let udf = udf_read::has_udf_signature(image);
    match (iso, udf) {
        (true, true) => return Some(DiscKind::IsoUdf),
        (true, false) => return Some(DiscKind::Iso),
        (false, true) => return Some(DiscKind::Udf),
        _ => {}
    }
    if !mbr_plausible(image) {
        return None;
    }
    let protective = (0..4).any(|i| image[446 + i * 16 + 4] == 0xEE);
    let header = [512usize, 4096].iter().any(|&s| image.get(s..s + 8) == Some(b"EFI PART"));
    if protective && header { Some(DiscKind::Gpt) } else { Some(DiscKind::Mbr) }
}

/// Boot signature present, every entry's status byte is 0x00 or 0x80, and
/// at least one entry is in use with a non-zero size.
fn mbr_plausible(image: &[u8]) -> bool {
    let Some(s) = image.get(..512) else { return false };
    if s[510] != 0x55 || s[511] != 0xAA {
        return false;
    }
    let entries = || (0..4).map(|i| &s[446 + i * 16..462 + i * 16]);
    entries().all(|e| e[0] == 0 || e[0] == 0x80)
        && entries().any(|e| e[4] != 0 && u32::from_le_bytes([e[12], e[13], e[14], e[15]]) != 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscEntryKind {
    File,
    Dir,
    Symlink { target: String },
    Other,
}

/// Where an entry's data lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscSource {
    Udf(UdfAddr),
    Iso(Vec<IsoSpan>),
    /// Byte range of a partition inside the image.
    Range { offset: u64, len: u64 },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscEntry {
    pub path: String,
    pub kind: DiscEntryKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime: Option<i64>,
    pub source: DiscSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscLimits {
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_entry_size: u64,
}

impl Default for DiscLimits {
    fn default() -> Self {
        DiscLimits { max_depth: 64, max_entries: 1_000_000, max_entry_size: 1 << 30 }
    }
}

/// A listed image: the format actually used and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscListing {
    pub kind: DiscKind,
    pub udf: Option<udf_read::UdfVolume>,
    pub entries: Vec<DiscEntry>,
}

fn udf_limits(l: &DiscLimits) -> UdfLimits {
    UdfLimits { max_depth: l.max_depth, max_entries: l.max_entries, max_file_size: l.max_entry_size, ..UdfLimits::default() }
}

fn rr_limits(l: &DiscLimits) -> RrLimits {
    RrLimits { max_depth: l.max_depth, max_entries: l.max_entries, ..RrLimits::default() }
}

fn list_udf(image: &[u8], limits: &DiscLimits, kind: DiscKind) -> Result<DiscListing, DiscError> {
    let vol = udf_read::open_volume(image)?;
    let entries = udf_read::list_entries(image, &vol, &udf_limits(limits))?
        .into_iter()
        .map(|e| DiscEntry {
            path: e.path,
            kind: match e.kind {
                UdfKind::File => DiscEntryKind::File,
                UdfKind::Dir => DiscEntryKind::Dir,
                UdfKind::Symlink { target } => DiscEntryKind::Symlink { target },
                UdfKind::Other => DiscEntryKind::Other,
            },
            size: e.size,
            mode: Some(e.mode),
            mtime: e.mtime,
            source: DiscSource::Udf(e.icb),
        })
        .collect();
    Ok(DiscListing { kind, udf: Some(vol), entries })
}

fn list_iso(image: &[u8], limits: &DiscLimits, kind: DiscKind) -> Result<DiscListing, DiscError> {
    let root = iso_rockridge::primary_root(image)?;
    let entries = iso_rockridge::list_entries(image, root, &rr_limits(limits))?
        .into_iter()
        .map(|e| {
            let source = match e.kind {
                RrKind::File => DiscSource::Iso(e.extents),
                _ => DiscSource::None,
            };
            DiscEntry {
                path: e.path,
                kind: match e.kind {
                    RrKind::File => DiscEntryKind::File,
                    RrKind::Dir => DiscEntryKind::Dir,
                    RrKind::Symlink { target } => DiscEntryKind::Symlink { target },
                    RrKind::Other => DiscEntryKind::Other,
                },
                size: e.size,
                mode: e.mode,
                mtime: e.mtime,
                source,
            }
        })
        .collect();
    Ok(DiscListing { kind, udf: None, entries })
}

/// Detect and list `image`. A UDF bridge disc is read through UDF, falling
/// back to ISO-9660 when the UDF side uses unsupported structures.
pub fn list_disc(image: &[u8], limits: &DiscLimits) -> Result<DiscListing, DiscError> {
    match detect_disc(image).ok_or(DiscError::NotADisc)? {
        DiscKind::Udf => list_udf(image, limits, DiscKind::Udf),
        DiscKind::Iso => list_iso(image, limits, DiscKind::Iso),
        DiscKind::IsoUdf => match list_udf(image, limits, DiscKind::IsoUdf) {
            Err(DiscError::Unsupported) => list_iso(image, limits, DiscKind::IsoUdf),
            r => r,
        },
        // Seam: parse with mbr_gpt, then call partition_entries.
        DiscKind::Mbr | DiscKind::Gpt => Err(DiscError::Unsupported),
    }
}

/// Contents of `listing.entries[index]` (empty for directories, links and
/// other non-file entries).
pub fn read_entry(image: &[u8], listing: &DiscListing, index: usize, limits: &DiscLimits) -> Result<Vec<u8>, DiscError> {
    let e = listing.entries.get(index).ok_or(DiscError::OutOfRange)?;
    if e.kind != DiscEntryKind::File {
        return Ok(Vec::new());
    }
    if e.size > limits.max_entry_size {
        return Err(DiscError::LimitExceeded);
    }
    match &e.source {
        DiscSource::Udf(icb) => {
            let vol = listing.udf.as_ref().ok_or(DiscError::Invalid)?;
            Ok(udf_read::read_file(image, vol, *icb, &udf_limits(limits))?)
        }
        DiscSource::Iso(spans) => Ok(iso_rockridge::read_spans(image, spans, limits.max_entry_size)?),
        DiscSource::Range { offset, len } => {
            let end = offset.checked_add(*len).ok_or(DiscError::Truncated)?;
            if end > image.len() as u64 {
                return Err(DiscError::Truncated);
            }
            let mut out = Vec::new();
            out.try_reserve_exact(*len as usize).map_err(|_| DiscError::Allocation)?;
            out.extend_from_slice(&image[*offset as usize..end as usize]);
            Ok(out)
        }
        DiscSource::None => Ok(Vec::new()),
    }
}

/// Partition description independent of the table format (adapter seam
/// for `mbr_gpt::MbrPartition` / `mbr_gpt::GptPartition`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionSpan {
    /// Partition number as shown to users (MBR 1-4 primary, 5+ logical;
    /// GPT 1-based slot).
    pub number: u32,
    pub first_lba: u64,
    pub sector_count: u64,
    /// GPT partition name, if any.
    pub label: Option<String>,
}

/// Turn partitions into file entries named `N.img` (or `N.<label>.img`
/// with path separators and control characters replaced by `_`). Every
/// partition must lie inside the image (`Truncated`) and must not overlap
/// another (`Invalid`).
pub fn partition_entries(
    spans: &[PartitionSpan],
    sector_size: u64,
    image_len: u64,
    limits: &DiscLimits,
) -> Result<Vec<DiscEntry>, DiscError> {
    if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
        return Err(DiscError::Invalid);
    }
    if spans.len() > limits.max_entries {
        return Err(DiscError::LimitExceeded);
    }
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut out = Vec::new();
    for p in spans {
        let offset = p.first_lba.checked_mul(sector_size).ok_or(DiscError::Truncated)?;
        let len = p.sector_count.checked_mul(sector_size).ok_or(DiscError::Truncated)?;
        let end = offset.checked_add(len).ok_or(DiscError::Truncated)?;
        if end > image_len {
            return Err(DiscError::Truncated);
        }
        if len > 0 && ranges.iter().any(|&(s, e)| offset < e && s < end) {
            return Err(DiscError::Invalid);
        }
        ranges.push((offset, end));
        let path = match p.label.as_deref().map(sanitize_label) {
            Some(l) if !l.is_empty() => format!("{}.{l}.img", p.number),
            _ => format!("{}.img", p.number),
        };
        out.push(DiscEntry {
            path,
            kind: DiscEntryKind::File,
            size: len,
            mode: None,
            mtime: None,
            source: DiscSource::Range { offset, len },
        });
    }
    Ok(out)
}

fn sanitize_label(l: &str) -> String {
    let s: String = l.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    let s = s.trim().to_string();
    if s == "." || s == ".." { "_".repeat(s.len()) } else { s }
}

/// Map listed entries to the format-neutral extraction plan input, paired
/// with their index in `listing.entries` (for [`read_entry`]). Devices,
/// FIFOs and sockets (`Other`) carry no data and are left out.
pub fn planned_entries(listing: &DiscListing) -> Vec<(usize, PlannedEntry)> {
    listing
        .entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let kind = match &e.kind {
                DiscEntryKind::Dir => EntryKind::Dir,
                DiscEntryKind::Symlink { target } => EntryKind::Symlink { target: target.as_bytes().to_vec() },
                DiscEntryKind::File => EntryKind::File,
                DiscEntryKind::Other => return None,
            };
            let size = if kind == EntryKind::File { e.size } else { 0 };
            Some((i, PlannedEntry { path: e.path.as_bytes().to_vec(), kind, size, mode: e.mode, mtime: e.mtime }))
        })
        .collect()
}
