// SPDX-License-Identifier: MIT OR Apache-2.0
//! Data for `sediment l -slt` (7-Zip "technical listing").
//!
//! Generic members are described from the format-neutral
//! [`ArchiveReader`] view (path, size, mtime, attributes from the Unix mode,
//! CRC). 7z archives are additionally re-read with
//! [`crate::sevenz_read::SevenZArchive`] so their blocks match `7zz l -slt`
//! field for field: full FILETIME precision, Created/Accessed, Windows
//! attributes, per-block Packed Size, coder Method names and Block index,
//! plus the archive-level Headers Size / Method / Solid / Blocks lines.
//!
//! Spec sources: the 7z format description (`7zFormat.txt`, method IDs
//! from the public `Methods.txt` list), Microsoft FILETIME and
//! FILE_ATTRIBUTE_* definitions, and observed `7zz l -slt` output (field
//! order, method name spelling such as `LZMA2:12`, packed size reported on
//! the first file of each block). No 7-Zip source was used.

use crate::archive_open::SevenZCodecs;
use crate::archive_name::escape_name;
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::cli_seam::slt_format::SltEntry;
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::sevenz_header::{Coder, SevenZLimits};
use crate::sevenz_read::SevenZArchive;

/// Seconds since 1970 to FILETIME (100 ns ticks since 1601), if representable.
pub fn unix_to_filetime(secs: i64) -> Option<u64> {
    let since_1601 = secs.checked_add(11_644_473_600)?;
    u64::try_from(since_1601).ok()?.checked_mul(10_000_000)
}

/// Path text: UTF-8 as is, escaped (see `archive_name`) when not printable
/// UTF-8; a trailing `/` (directory marker) is dropped.
pub fn slt_path(name: &[u8]) -> String {
    let end = name.iter().rposition(|&b| b != b'/').map_or(name.len().min(1), |i| i + 1);
    let name = &name[..end];
    match std::str::from_utf8(name) {
        Ok(s) if !s.chars().any(char::is_control) => s.to_owned(),
        _ => escape_name(name).unwrap_or_else(|_| String::from("?")),
    }
}

/// Windows attributes (+ Unix extension when the mode is known).
pub fn entry_attributes(e: &PlannedEntry, format: ArchiveFormat) -> Option<u32> {
    let (dos, type_bits) = match e.kind {
        EntryKind::Dir => (0x10u32, 0o040000u32),
        EntryKind::Symlink { .. } => (0, 0o120000),
        _ if matches!(format, ArchiveFormat::Zip | ArchiveFormat::SevenZ) => (0x20, 0o100000),
        _ => (0, 0o100000),
    };
    match e.mode {
        Some(m) => Some(dos | 0x8000 | ((type_bits | (m & 0o7777)) << 16)),
        None if dos != 0 => Some(dos),
        None => None,
    }
}

/// Size shown for a member (link target length for symlinks).
pub fn listed_size(e: &PlannedEntry) -> u64 {
    match &e.kind {
        EntryKind::Symlink { target } => target.len() as u64,
        EntryKind::Dir => 0,
        _ => e.size,
    }
}

/// Generic `-slt` fields for member `i` of `reader`.
pub fn generic_entry(reader: &dyn ArchiveReader, i: usize) -> SltEntry {
    let format = reader.format();
    let e = &reader.entries()[i];
    let is_dir = matches!(e.kind, EntryKind::Dir);
    SltEntry {
        path: slt_path(&e.path),
        folder: match format {
            ArchiveFormat::Zip | ArchiveFormat::Tar => Some(is_dir),
            _ => None,
        },
        size: listed_size(e),
        packed_size: None,
        modified: e.mtime.and_then(unix_to_filetime),
        created: None,
        accessed: None,
        attributes: entry_attributes(e, format),
        crc: if is_dir { None } else { reader.crc32(i) },
        encrypted: false,
        method: match format {
            ArchiveFormat::Gzip => "Deflate".into(),
            ArchiveFormat::Bzip2 => "BZip2".into(),
            _ => String::new(),
        },
        block: None,
    }
}

/// Dictionary size as 7-Zip prints it: `n` for 2^n, else `Nm` / `Nk` / bytes.
pub fn dictionary_name(d: u64) -> String {
    if d.is_power_of_two() {
        d.trailing_zeros().to_string()
    } else if d.is_multiple_of(1 << 20) {
        format!("{}m", d >> 20)
    } else if d.is_multiple_of(1 << 10) {
        format!("{}k", d >> 10)
    } else {
        d.to_string()
    }
}

fn lzma2_dictionary(b: u8) -> Option<u64> {
    match b {
        0..=39 => Some((2 | u64::from(b & 1)) << (b / 2 + 11)),
        40 => Some(u64::from(u32::MAX)),
        _ => None,
    }
}

/// Display name of one 7z coder.
pub fn coder_name(c: &Coder) -> String {
    let id = c.method_id.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let p = &c.properties;
    match (c.method_id.len(), id) {
        (1, 0x00) => "Copy".into(),
        (3, 0x03_01_01) => match p.get(1..5) {
            Some(d) => format!("LZMA:{}", dictionary_name(u64::from(u32::from_le_bytes([d[0], d[1], d[2], d[3]])))),
            None => "LZMA".into(),
        },
        (1, 0x21) => match p.first().and_then(|&b| lzma2_dictionary(b)) {
            Some(d) => format!("LZMA2:{}", dictionary_name(d)),
            None => "LZMA2".into(),
        },
        (1, 0x03) => match p.first() {
            Some(&b) => format!("Delta:{}", u32::from(b) + 1),
            None => "Delta".into(),
        },
        (4, 0x03_03_01_03) => "BCJ".into(),
        (4, 0x03_03_02_05) => "PPC".into(),
        (4, 0x03_03_04_01) => "IA64".into(),
        (4, 0x03_03_05_01) => "ARM".into(),
        (4, 0x03_03_07_01) => "ARMT".into(),
        (4, 0x03_03_08_05) => "SPARC".into(),
        (1, 0x0a) => "ARM64".into(),
        (1, 0x0b) => "RISCV".into(),
        (3, 0x02_03_02) => "Swap2".into(),
        (3, 0x02_03_04) => "Swap4".into(),
        (3, 0x03_04_01) => "PPMD".into(),
        (3, 0x04_01_08) => "Deflate".into(),
        (3, 0x04_01_09) => "Deflate64".into(),
        (3, 0x04_02_02) => "BZip2".into(),
        (4, 0x06_f1_07_01) => "7zAES".into(),
        _ => c.method_id.iter().map(|b| format!("{b:02X}")).collect(),
    }
}

fn is_aes(c: &Coder) -> bool {
    c.method_id == [0x06, 0xf1, 0x07, 0x01]
}

/// Archive-level `(key, value)` lines and the per-item blocks of a 7z.
pub type SevenZDetails = (Vec<(String, String)>, Vec<SltEntry>);

/// 7z listing details: archive-level `(key, value)` lines and one
/// [`SltEntry`] per non-anti item, in the order `SevenZReader` lists them.
pub fn sevenz_details(bytes: &[u8], limits: ReaderLimits) -> Result<SevenZDetails, ReaderError> {
    let codecs = SevenZCodecs::new(limits.max_total_size);
    let sl = SevenZLimits { max_files: limits.max_entries, max_unpack_bytes: limits.max_total_size, ..SevenZLimits::default() };
    let archive = SevenZArchive::open(bytes, &codecs, sl)?;
    let streams = &archive.header().main_streams;
    let folders = &streams.folders;
    // Packed size of each folder: its run of pack streams, in folder order.
    let mut folder_packed = Vec::new();
    folder_packed.try_reserve_exact(folders.len()).map_err(|_| ReaderError::Allocation)?;
    let mut next = 0usize;
    for f in folders {
        let n = f.packed_streams.len();
        let sizes = streams.pack_info.sizes.get(next..next.saturating_add(n)).ok_or(ReaderError::Invalid)?;
        folder_packed.push(sizes.iter().try_fold(0u64, |a, &s| a.checked_add(s)).ok_or(ReaderError::Invalid)?);
        next += n;
    }
    // 7-Zip names a block's coders in reverse storage order ("LZMA2:13 BCJ").
    let methods: Vec<String> = folders.iter().map(|f| f.coders.iter().rev().map(coder_name).collect::<Vec<_>>().join(" ")).collect();
    let mut entries = Vec::new();
    for e in archive.entries().iter().filter(|e| !e.is_anti) {
        let folder = e.folder_index.filter(|_| e.has_stream);
        let first_in_folder = e.index_in_folder == Some(0);
        entries.try_reserve(1).map_err(|_| ReaderError::Allocation)?;
        entries.push(SltEntry {
            path: slt_path(e.name.as_bytes()),
            folder: None,
            size: e.size,
            packed_size: match folder {
                None => Some(0),
                Some(k) if first_in_folder => folder_packed.get(k).copied(),
                Some(_) => None,
            },
            modified: e.mtime,
            created: e.ctime,
            accessed: e.atime,
            attributes: e.attributes,
            crc: e.crc.filter(|_| e.has_stream),
            encrypted: folder.and_then(|k| folders.get(k)).is_some_and(|f| f.coders.iter().any(is_aes)),
            method: folder.and_then(|k| methods.get(k)).cloned().unwrap_or_default(),
            block: folder.map(|k| k as u64),
        });
    }
    let packed_total = streams.pack_info.sizes.iter().fold(0u64, |a, &s| a.saturating_add(s));
    let mut header = vec![("Headers Size".to_string(), (bytes.len() as u64).saturating_sub(packed_total).to_string())];
    let mut names: Vec<&str> = Vec::new();
    for m in &methods {
        for part in m.split(' ') {
            if !part.is_empty() && !names.contains(&part) {
                names.push(part);
            }
        }
    }
    if !names.is_empty() {
        header.push(("Method".into(), names.join(" ")));
    }
    let solid = streams.substreams.num_unpack_streams.iter().any(|&n| n > 1);
    header.push(("Solid".into(), if solid { "+" } else { "-" }.into()));
    header.push(("Blocks".into(), folders.len().to_string()));
    Ok((header, entries))
}

/// The archive block printed before the entries (without `-ba`).
pub fn archive_header(display: &str, type_name: &str, physical: u64, extra: &[(String, String)]) -> String {
    let mut s = format!("Listing archive: {display}\n\n--\nPath = {display}\nType = {type_name}\nPhysical Size = {physical}\n");
    for (k, v) in extra {
        s.push_str(&format!("{k} = {v}\n"));
    }
    s.push_str("\n----------\n");
    s
}

// ---------------------------------------------------------------------------
// Default `l` table (7-Zip "Date Time Attr Size Compressed Name" layout)
// ---------------------------------------------------------------------------

/// One row of the default `l` table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TableRow {
    /// FILETIME (100 ns ticks since 1601-01-01 UTC), if known.
    pub modified: Option<u64>,
    /// Windows attribute bits (only `R H S D A` are shown).
    pub attributes: u32,
    pub size: u64,
    /// Bytes the member occupies in the archive, when the format says.
    pub packed: Option<u64>,
    /// Display name: UTF-8 as is, directory slash dropped (see [`slt_path`]).
    pub name: String,
    pub is_dir: bool,
}

/// Column header line of the table.
pub const TABLE_HEADER: &str = "   Date      Time    Attr         Size   Compressed  Name\n";
/// Separator line printed above and below the rows.
pub const TABLE_RULE: &str = "------------------- ----- ------------ ------------  ------------------------\n";

fn table_date(ft: Option<u64>) -> String {
    match ft {
        Some(ft) => {
            let s = crate::cli_seam::slt_format::format_filetime(ft);
            s.get(..19).unwrap_or(&s).to_owned()
        }
        None => String::new(),
    }
}

/// The five-character attribute column: `D R H S A`, `.` when clear.
pub fn table_attributes(attrib: u32) -> String {
    [(0x10u32, 'D'), (0x01, 'R'), (0x02, 'H'), (0x04, 'S'), (0x20, 'A')]
        .iter()
        .map(|&(bit, c)| if attrib & bit != 0 { c } else { '.' })
        .collect()
}

/// One formatted table row (with newline).
pub fn format_table_row(r: &TableRow) -> String {
    let packed = r.packed.map(|p| p.to_string()).unwrap_or_default();
    format!("{:19} {} {:>12} {:>12}  {}\n", table_date(r.modified), table_attributes(r.attributes), r.size, packed, r.name)
}

/// Totals line: newest date, summed sizes, `N files[, M folders]`.
pub fn format_table_totals(rows: &[TableRow]) -> String {
    let newest = rows.iter().filter_map(|r| r.modified).max();
    let size = rows.iter().fold(0u64, |a, r| a.saturating_add(r.size));
    let packed = if !rows.is_empty() && rows.iter().all(|r| r.packed.is_none()) {
        String::new()
    } else {
        rows.iter().filter_map(|r| r.packed).fold(0u64, |a, p| a.saturating_add(p)).to_string()
    };
    let folders = rows.iter().filter(|r| r.is_dir).count();
    let files = rows.len() - folders;
    let mut count = format!("{files} files");
    if folders > 0 {
        count.push_str(&format!(", {folders} folders"));
    }
    format!("{:19}       {:>12} {:>12}  {count}\n", table_date(newest), size, packed)
}

/// Header, rule, rows, rule and totals (no archive block).
pub fn format_table(rows: &[TableRow]) -> String {
    let mut s = String::from(TABLE_HEADER);
    s.push_str(TABLE_RULE);
    for r in rows {
        s.push_str(&format_table_row(r));
    }
    s.push_str(TABLE_RULE);
    s.push_str(&format_table_totals(rows));
    s
}

/// Per-member `(DOS attribute byte, compressed size)` from the zip central
/// directory, in the order `ZipReader` lists members.
fn zip_table_details(bytes: &[u8], limits: ReaderLimits) -> Option<Vec<(u32, u64)>> {
    use crate::zip_reader2::{Reader2Limits, ZipArchive2};
    let l2 = Reader2Limits {
        max_entries: limits.max_entries,
        max_entry_size: limits.max_total_size,
        max_total_size: limits.max_total_size,
        max_deflate_blocks: 1 << 20,
    };
    let zip = ZipArchive2::open(bytes, l2).ok()?;
    let mut out = Vec::new();
    out.try_reserve_exact(zip.len()).ok()?;
    out.extend(zip.entries().iter().map(|e| (e.external_attributes & 0x37, e.compressed_size)));
    Some(out)
}

/// Rows of the default `l` table for members `chosen` of `reader`; `bytes`
/// is the whole archive (re-read for zip/7z specific columns).
pub fn table_rows(reader: &dyn ArchiveReader, chosen: &[usize], bytes: &[u8], limits: ReaderLimits) -> Vec<TableRow> {
    let format = reader.format();
    let entries = reader.entries();
    let sevenz = match format {
        ArchiveFormat::SevenZ => sevenz_details(bytes, limits).ok().map(|(_, e)| e).filter(|e| e.len() == entries.len()),
        _ => None,
    };
    let zip = match format {
        ArchiveFormat::Zip => zip_table_details(bytes, limits).filter(|z| z.len() == entries.len()),
        _ => None,
    };
    let mut rows = Vec::new();
    for &i in chosen {
        let Some(e) = entries.get(i) else { continue };
        let is_dir = matches!(e.kind, EntryKind::Dir);
        let mut row = TableRow {
            modified: e.mtime.and_then(unix_to_filetime),
            attributes: entry_attributes(e, format).unwrap_or(0) & 0x37,
            size: listed_size(e),
            packed: None,
            name: slt_path(&e.path),
            is_dir,
        };
        match format {
            ArchiveFormat::SevenZ => {
                if let Some(d) = sevenz.as_ref().and_then(|s| s.get(i)) {
                    row.modified = d.modified;
                    row.attributes = d.attributes.unwrap_or(0) & 0x37;
                    // Empty files (no stream) show a blank Compressed cell, as 7-Zip does.
                    row.packed = d.packed_size.filter(|&p| is_dir || p != 0 || d.size != 0);
                    row.size = d.size;
                    row.name = d.path.clone();
                }
            }
            ArchiveFormat::Zip => {
                if let Some(&(attr, packed)) = zip.as_ref().and_then(|z| z.get(i)) {
                    row.attributes = attr;
                    row.packed = Some(packed);
                } else {
                    row.attributes &= 0x10;
                }
            }
            ArchiveFormat::Tar => {
                row.attributes &= 0x10;
                row.packed = Some(match e.kind {
                    EntryKind::File => e.size.div_ceil(512).saturating_mul(512),
                    _ => 0,
                });
            }
            _ => {}
        }
        if is_dir {
            row.attributes |= 0x10;
        }
        rows.push(row);
    }
    rows
}
