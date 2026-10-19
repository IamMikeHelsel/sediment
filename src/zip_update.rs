// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rewrite a ZIP archive according to an [`EditPlan`].
//!
//! Spec source: PKWARE APPNOTE.TXT 6.3.x: 4.3.6 overall layout, 4.3.7 local
//! file header, 4.3.9 data descriptor, 4.3.12 central directory header,
//! 4.3.14-4.3.16 ZIP64 end of central directory record / locator and the
//! classic end record, 4.4.4 general purpose flag bit 11 (UTF-8 names),
//! 4.5.3 ZIP64 extended information extra field (field order: original
//! size, compressed size, local header offset, disk number, each present
//! only when the header field is saturated); Info-ZIP `extrafld.txt` for the
//! Unicode Path extra field (0x7075), which is bound to the old name by a
//! CRC and therefore dropped on rename.
//!
//! Untouched entries are copied byte for byte: the local header, the
//! compressed (possibly encrypted) data and any data descriptor, plus the
//! central directory record with only its local-header offset patched (in
//! the ZIP64 extra field when the record stores it there). Renamed entries
//! keep their data and every header field except the name, the UTF-8 flag
//! and the Unicode Path extra field. New and replacement entries are built
//! with [`crate::zip_create::create_zip`] and spliced in the same way. A
//! leading self-extractor stub is preserved; stored offsets in the output
//! are absolute. A ZIP64 end record is written when the entry count or the
//! central directory position needs it. The archive comment is kept; a
//! central-directory digital signature record is dropped (it would no
//! longer match).

use crate::archive_update::{EditPlan, EntryAction, ExistingEntry, UpdateError, UpdateLimits, normalize_name};
use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::zip64::locate_central_directory;
use crate::zip_create::{ZipCreateError, ZipCreateLimits, ZipCreateOptions, create_zip};
use crate::zip_dos_time::decode_dos;
use crate::zip_reader2::{Entry2, FLAG_MASKED_HEADER, FLAG_UTF8, Reader2Limits, ZipArchive2};

const CENTRAL_SIG: u32 = 0x0201_4b50;
const DIGITAL_SIG: u32 = 0x0505_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const LOCAL_FIXED: usize = 30;
const CENTRAL_FIXED: usize = 46;
const ZIP64_EXTRA: u16 = 0x0001;
const UNICODE_PATH_EXTRA: u16 = 0x7075;

/// Options for new and replacement entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipUpdateOptions {
    /// 0 stores; 1..=9 DEFLATE level.
    pub level: u8,
}

impl Default for ZipUpdateOptions {
    fn default() -> Self {
        Self { level: 5 }
    }
}

/// Result of [`apply_zip`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipUpdated {
    pub bytes: Vec<u8>,
    /// Names of new/replacement entries that were not written (symlinks,
    /// which `zip_create` does not store). A skipped replacement keeps the
    /// old entry.
    pub skipped: Vec<Vec<u8>>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, UpdateError> {
    let s = b.get(at..at.checked_add(2).ok_or(UpdateError::InvalidArchive)?).ok_or(UpdateError::InvalidArchive)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, UpdateError> {
    let s = b.get(at..at.checked_add(4).ok_or(UpdateError::InvalidArchive)?).ok_or(UpdateError::InvalidArchive)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn reader_limits(limits: &UpdateLimits) -> Reader2Limits {
    Reader2Limits { max_entries: limits.max_entries, ..Reader2Limits::default() }
}

/// A parsed archive plus the raw bytes of each central record.
struct Parsed<'a> {
    archive: ZipArchive2<'a>,
    central: Vec<&'a [u8]>,
    /// Bytes before the first local header (self-extractor stub).
    stub: &'a [u8],
}

fn parse<'a>(bytes: &'a [u8], limits: &UpdateLimits) -> Result<Parsed<'a>, UpdateError> {
    let archive = ZipArchive2::open(bytes, reader_limits(limits)).map_err(|e| match e {
        crate::zip_reader2::Reader2Error::LimitExceeded => UpdateError::LimitExceeded,
        crate::zip_reader2::Reader2Error::Allocation => UpdateError::Allocation,
        crate::zip_reader2::Reader2Error::Unsupported => UpdateError::Unsupported,
        _ => UpdateError::InvalidArchive,
    })?;
    let loc = locate_central_directory(bytes).map_err(|_| UpdateError::InvalidArchive)?;
    let cd = bytes
        .get(loc.cd_start..loc.cd_start.checked_add(loc.cd_size).ok_or(UpdateError::InvalidArchive)?)
        .ok_or(UpdateError::InvalidArchive)?;
    let mut central = Vec::new();
    central.try_reserve_exact(archive.len()).map_err(|_| UpdateError::Allocation)?;
    let mut at = 0usize;
    while at < cd.len() {
        let sig = u32_at(cd, at)?;
        if sig == DIGITAL_SIG {
            break;
        }
        if sig != CENTRAL_SIG {
            return Err(UpdateError::InvalidArchive);
        }
        let n = u16_at(cd, at + 28)? as usize;
        let m = u16_at(cd, at + 30)? as usize;
        let k = u16_at(cd, at + 32)? as usize;
        let end = at + CENTRAL_FIXED + n + m + k;
        let rec = cd.get(at..end).ok_or(UpdateError::InvalidArchive)?;
        if central.len() >= archive.len() {
            return Err(UpdateError::InvalidArchive);
        }
        // Cross-check with the reader's view of the same record.
        if &rec[CENTRAL_FIXED..CENTRAL_FIXED + n] != archive.entries()[central.len()].raw_name {
            return Err(UpdateError::InvalidArchive);
        }
        central.push(rec);
        at = end;
    }
    if central.len() != archive.len() {
        return Err(UpdateError::InvalidArchive);
    }
    let first = archive.entries().iter().map(|e| e.header_start).min().unwrap_or(loc.prefix.min(loc.cd_start));
    let stub = &bytes[..first.min(loc.cd_start)];
    Ok(Parsed { archive, central, stub })
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

/// Modification time of an entry and its resolution: the Info-ZIP extended
/// timestamp (1 s) when present, else NTFS times, else the MS-DOS time read
/// as UTC (2 s; Sediment writes DOS times in UTC).
fn entry_mtime(e: &Entry2<'_>) -> (Option<i64>, u32) {
    if let Some(t) = e.extended_timestamp.and_then(|t| t.mtime) {
        return (Some(i64::from(t)), 1);
    }
    if let Some(n) = e.ntfs_times {
        let secs = (n.mtime / 10_000_000) as i64 - 11_644_473_600;
        return (Some(secs), 1);
    }
    match decode_dos(e.dos_date, e.dos_time) {
        Ok(d) => {
            let days = days_from_civil(i64::from(d.year), i64::from(d.month), i64::from(d.day));
            let secs = days * 86400 + i64::from(d.hour) * 3600 + i64::from(d.minute) * 60 + i64::from(d.second);
            (Some(secs), 2)
        }
        Err(_) => (None, 2),
    }
}

fn existing_of(e: &Entry2<'_>) -> ExistingEntry {
    let (mtime, res) = entry_mtime(e);
    ExistingEntry { name: normalize_name(e.name()).to_vec(), is_dir: e.is_dir(), mtime, time_resolution: res }
}

/// List the entries of a ZIP archive for planning (empty input = no archive).
pub fn zip_entries(bytes: &[u8], limits: &UpdateLimits) -> Result<Vec<ExistingEntry>, UpdateError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let p = parse(bytes, limits)?;
    let mut v = Vec::new();
    v.try_reserve_exact(p.archive.len()).map_err(|_| UpdateError::Allocation)?;
    v.extend(p.archive.entries().iter().map(existing_of));
    Ok(v)
}

/// Remove every extra record with `id` from an extra block. A trailing
/// fragment too short for a record header is kept as is; a record that
/// overruns the block is an error.
fn strip_extra(block: &[u8], id: u16) -> Result<Vec<u8>, UpdateError> {
    let mut out = Vec::new();
    out.try_reserve_exact(block.len()).map_err(|_| UpdateError::Allocation)?;
    let mut pos = 0usize;
    while block.len() - pos >= 4 {
        let rid = u16::from_le_bytes([block[pos], block[pos + 1]]);
        let len = u16::from_le_bytes([block[pos + 2], block[pos + 3]]) as usize;
        let end = pos + 4 + len;
        if end > block.len() {
            return Err(UpdateError::InvalidArchive);
        }
        if rid != id {
            out.extend_from_slice(&block[pos..end]);
        }
        pos = end;
    }
    out.extend_from_slice(&block[pos..]);
    Ok(out)
}

fn utf8_flag(flags: u16, name: &[u8]) -> u16 {
    if name.is_ascii() {
        flags
    } else if std::str::from_utf8(name).is_ok() {
        flags | FLAG_UTF8
    } else {
        flags & !FLAG_UTF8
    }
}

/// Patch the local header offset of a central record (in the ZIP64 extra
/// field when the fixed field is saturated).
fn patch_offset(rec: &mut [u8], offset: u64) -> Result<(), UpdateError> {
    let field = u32_at(rec, 42)?;
    if field != u32::MAX {
        let v = u32::try_from(offset).ok().filter(|&v| v != u32::MAX).ok_or(UpdateError::LimitExceeded)?;
        rec[42..46].copy_from_slice(&v.to_le_bytes());
        return Ok(());
    }
    let n = u16_at(rec, 28)? as usize;
    let m = u16_at(rec, 30)? as usize;
    let usize_sat = u32_at(rec, 24)? == u32::MAX;
    let csize_sat = u32_at(rec, 20)? == u32::MAX;
    let start = CENTRAL_FIXED + n;
    let mut pos = start;
    let end = start + m;
    while end - pos >= 4 {
        let id = u16_at(rec, pos)?;
        let len = u16_at(rec, pos + 2)? as usize;
        if id == ZIP64_EXTRA {
            let at = pos + 4 + 8 * (usize::from(usize_sat) + usize::from(csize_sat));
            if at + 8 > pos + 4 + len {
                return Err(UpdateError::InvalidArchive);
            }
            rec[at..at + 8].copy_from_slice(&offset.to_le_bytes());
            return Ok(());
        }
        pos += 4 + len;
    }
    Err(UpdateError::InvalidArchive)
}

struct Writer {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u64,
    max: u64,
}

impl Writer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), UpdateError> {
        if (self.out.len() as u64).saturating_add(bytes.len() as u64) > self.max {
            return Err(UpdateError::LimitExceeded);
        }
        self.out.try_reserve(bytes.len()).map_err(|_| UpdateError::Allocation)?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    /// Copy one entry from `src` (whose central record is `rec`), optionally
    /// renamed to `new_name` (raw name including any trailing `/`).
    fn copy(&mut self, src: &[u8], e: &Entry2<'_>, rec: &[u8], new_name: Option<&[u8]>) -> Result<(), UpdateError> {
        let offset = self.out.len() as u64;
        let end = e.descriptor.map(|d| d.end).unwrap_or(e.data_end);
        let mut crec: Vec<u8>;
        match new_name {
            None => {
                self.push(src.get(e.header_start..end).ok_or(UpdateError::InvalidArchive)?)?;
                crec = Vec::new();
                crec.try_reserve_exact(rec.len()).map_err(|_| UpdateError::Allocation)?;
                crec.extend_from_slice(rec);
            }
            Some(name) => {
                if e.flags & FLAG_MASKED_HEADER != 0 {
                    return Err(UpdateError::Unsupported);
                }
                let name_len = u16::try_from(name.len()).map_err(|_| UpdateError::InvalidName)?;
                // Local header.
                let fixed = src.get(e.header_start..e.header_start + LOCAL_FIXED).ok_or(UpdateError::InvalidArchive)?;
                let lextra = strip_extra(e.local_extra, UNICODE_PATH_EXTRA)?;
                let mut lh = Vec::new();
                lh.try_reserve_exact(LOCAL_FIXED + name.len() + lextra.len()).map_err(|_| UpdateError::Allocation)?;
                lh.extend_from_slice(fixed);
                let lflags = utf8_flag(u16::from_le_bytes([fixed[6], fixed[7]]), name);
                lh[6..8].copy_from_slice(&lflags.to_le_bytes());
                lh[26..28].copy_from_slice(&name_len.to_le_bytes());
                lh[28..30].copy_from_slice(&(lextra.len() as u16).to_le_bytes());
                lh.extend_from_slice(name);
                lh.extend_from_slice(&lextra);
                self.push(&lh)?;
                self.push(src.get(e.data_start..end).ok_or(UpdateError::InvalidArchive)?)?;
                // Central record.
                let n = u16_at(rec, 28)? as usize;
                let m = u16_at(rec, 30)? as usize;
                let cextra = strip_extra(&rec[CENTRAL_FIXED + n..CENTRAL_FIXED + n + m], UNICODE_PATH_EXTRA)?;
                let comment = &rec[CENTRAL_FIXED + n + m..];
                crec = Vec::new();
                crec.try_reserve_exact(CENTRAL_FIXED + name.len() + cextra.len() + comment.len())
                    .map_err(|_| UpdateError::Allocation)?;
                crec.extend_from_slice(&rec[..CENTRAL_FIXED]);
                let cflags = utf8_flag(u16_at(rec, 8)?, name);
                crec[8..10].copy_from_slice(&cflags.to_le_bytes());
                crec[28..30].copy_from_slice(&name_len.to_le_bytes());
                crec[30..32].copy_from_slice(&(cextra.len() as u16).to_le_bytes());
                crec.extend_from_slice(name);
                crec.extend_from_slice(&cextra);
                crec.extend_from_slice(comment);
            }
        }
        patch_offset(&mut crec, offset)?;
        self.central.try_reserve(crec.len()).map_err(|_| UpdateError::Allocation)?;
        self.central.extend_from_slice(&crec);
        self.count += 1;
        Ok(())
    }

    fn finish(mut self, comment: &[u8]) -> Result<Vec<u8>, UpdateError> {
        let cd_offset = self.out.len() as u64;
        let cd_size = self.central.len() as u64;
        let central = core::mem::take(&mut self.central);
        self.push(&central)?;
        let need64 = self.count >= 0xFFFF || cd_offset >= 0xFFFF_FFFF || cd_size >= 0xFFFF_FFFF;
        let mut tail = Vec::new();
        if need64 {
            let rec_off = self.out.len() as u64;
            tail.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
            tail.extend_from_slice(&44u64.to_le_bytes());
            tail.extend_from_slice(&45u16.to_le_bytes());
            tail.extend_from_slice(&45u16.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&self.count.to_le_bytes());
            tail.extend_from_slice(&self.count.to_le_bytes());
            tail.extend_from_slice(&cd_size.to_le_bytes());
            tail.extend_from_slice(&cd_offset.to_le_bytes());
            tail.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
            tail.extend_from_slice(&0u32.to_le_bytes());
            tail.extend_from_slice(&rec_off.to_le_bytes());
            tail.extend_from_slice(&1u32.to_le_bytes());
        }
        let count16 = if need64 { 0xFFFF } else { self.count as u16 };
        let sat32 = |v: u64| if need64 { u32::MAX } else { v as u32 };
        tail.extend_from_slice(&EOCD_SIG.to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
        tail.extend_from_slice(&count16.to_le_bytes());
        tail.extend_from_slice(&count16.to_le_bytes());
        tail.extend_from_slice(&sat32(cd_size).to_le_bytes());
        tail.extend_from_slice(&sat32(cd_offset).to_le_bytes());
        let clen = u16::try_from(comment.len()).map_err(|_| UpdateError::InvalidArchive)?;
        tail.extend_from_slice(&clen.to_le_bytes());
        tail.extend_from_slice(comment);
        self.push(&tail)?;
        Ok(self.out)
    }
}

fn map_create(e: ZipCreateError) -> UpdateError {
    match e {
        ZipCreateError::InvalidName => UpdateError::InvalidName,
        ZipCreateError::LimitExceeded | ZipCreateError::Unsupported => UpdateError::LimitExceeded,
        ZipCreateError::Allocation => UpdateError::Allocation,
        ZipCreateError::InvalidEntry | ZipCreateError::InvalidLevel => UpdateError::EncodeFailed,
    }
}

/// Apply `plan` to the ZIP archive `bytes` (empty = start a new archive).
pub fn apply_zip(
    bytes: &[u8],
    plan: &EditPlan<'_>,
    opts: ZipUpdateOptions,
    limits: &UpdateLimits,
) -> Result<ZipUpdated, UpdateError> {
    let parsed = if bytes.is_empty() { None } else { Some(parse(bytes, limits)?) };
    let n_old = parsed.as_ref().map_or(0, |p| p.archive.len());
    if plan.actions.len() != n_old {
        return Err(UpdateError::InvalidArchive);
    }

    // Build every new member (replacements first, in archive order, then
    // additions) in one fresh archive, then splice its records in.
    let mut fresh_in: Vec<ArchiveEntry<'_>> = Vec::new();
    let mut skipped = Vec::new();
    // For each replacement: index into the fresh archive, or None if skipped.
    let mut repl_slot: Vec<Option<usize>> = Vec::new();
    repl_slot.try_reserve_exact(n_old).map_err(|_| UpdateError::Allocation)?;
    repl_slot.resize(n_old, None);
    for (i, a) in plan.actions.iter().enumerate() {
        if let EntryAction::Replace(e) = a {
            if e.kind == EntryKind::Symlink {
                skipped.push(e.name.to_vec());
            } else {
                repl_slot[i] = Some(fresh_in.len());
                fresh_in.push(*e);
            }
        }
    }
    let mut add_slots = Vec::new();
    for e in &plan.additions {
        if e.kind == EntryKind::Symlink {
            skipped.push(e.name.to_vec());
        } else {
            add_slots.push(fresh_in.len());
            fresh_in.push(*e);
        }
    }
    let total_entries = n_old + fresh_in.len();
    if total_entries > limits.max_entries {
        return Err(UpdateError::LimitExceeded);
    }
    let fresh_bytes = if fresh_in.is_empty() {
        Vec::new()
    } else {
        let zl = ZipCreateLimits {
            max_entries: limits.max_entries.min(0xFFFE),
            max_total_input: limits.max_total_bytes,
            max_archive_bytes: usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX).min((u32::MAX - 1) as usize),
        };
        create_zip(&fresh_in, ZipCreateOptions { level: opts.level }, zl).map_err(map_create)?.bytes
    };
    drop(fresh_in);
    let fresh = if fresh_bytes.is_empty() { None } else { Some(parse(&fresh_bytes, limits)?) };

    let mut w = Writer { out: Vec::new(), central: Vec::new(), count: 0, max: limits.max_output_bytes };
    if let Some(p) = &parsed {
        w.push(p.stub)?;
    }
    let fresh_copy = |w: &mut Writer, slot: usize| -> Result<(), UpdateError> {
        let f = fresh.as_ref().ok_or(UpdateError::EncodeFailed)?;
        let e = f.archive.entries().get(slot).ok_or(UpdateError::EncodeFailed)?;
        w.copy(&fresh_bytes, e, f.central[slot], None)
    };
    if let Some(p) = &parsed {
        for (i, a) in plan.actions.iter().enumerate() {
            let e = &p.archive.entries()[i];
            match a {
                EntryAction::Keep => w.copy(bytes, e, p.central[i], None)?,
                EntryAction::Delete => {}
                EntryAction::Rename(new) => {
                    let mut raw = new.clone();
                    if e.raw_name.ends_with(b"/") {
                        raw.push(b'/');
                    }
                    w.copy(bytes, e, p.central[i], Some(&raw))?;
                }
                EntryAction::Replace(_) => match repl_slot[i] {
                    Some(s) => fresh_copy(&mut w, s)?,
                    None => w.copy(bytes, e, p.central[i], None)?,
                },
            }
        }
    }
    for s in add_slots {
        fresh_copy(&mut w, s)?;
    }
    let comment = parsed.as_ref().map_or(&[][..], |p| p.archive.comment());
    let out = w.finish(comment)?;
    Ok(ZipUpdated { bytes: out, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_extra_keeps_others_and_fragment() {
        let block = [0x75, 0x70, 1, 0, 9, 0x55, 0x54, 0, 0, 7];
        assert_eq!(strip_extra(&block, 0x7075).unwrap(), vec![0x55, 0x54, 0, 0, 7]);
        assert_eq!(strip_extra(&[1, 0, 9, 0], 1), Err(UpdateError::InvalidArchive));
    }

    #[test]
    fn utf8_flag_rules() {
        assert_eq!(utf8_flag(0, b"abc"), 0);
        assert_eq!(utf8_flag(0, "é".as_bytes()), FLAG_UTF8);
        assert_eq!(utf8_flag(FLAG_UTF8, &[0xff]), 0);
    }

    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }
}
