// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rewrite a tar archive (uncompressed bytes) according to an [`EditPlan`].
//!
//! Spec sources: POSIX.1-2008 `pax` utility, "ustar Interchange Format"
//! (header layout, name/prefix split, checksum) and "pax Interchange Format"
//! (`x` per-entry and `g` global extended headers, `path` / `linkpath`
//! records); GNU tar manual "Basic Tar Format" (old-GNU `"ustar  \0"` magic
//! without a prefix field, `L` / `K` long name / long link headers, record
//! padding to 10240 bytes).
//!
//! Each entry owns the byte span from the end of the previous entry to the
//! end of its padded data: its extended headers (`x`, `L`, `K`), its main
//! header block and its data. Kept entries copy that span byte for byte.
//! Global `g` headers inside a span are kept even when the entry is deleted
//! or rewritten, since they apply to every later entry. Renamed entries keep
//! their main header block except the name fields (and checksum): the
//! ustar prefix/name split is used when the new name fits, otherwise a pax
//! `path` record (POSIX and v7 headers) or a GNU `L` header (old-GNU
//! headers) carries it; other records of an existing `x` header are kept.
//! Hard links whose target is renamed get their link name rewritten the
//! same way. Replacements and additions are encoded with
//! [`crate::tar_create::encode_headers`]. The archive ends with two zero
//! blocks, padded to a 10240-byte record.

use std::collections::BTreeMap;

use crate::archive_update::{EditPlan, EntryAction, ExistingEntry, UpdateError, UpdateLimits};
use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::pax_record_write::encode_record;
use crate::tar_create::{TarCreateError, TarHeaderSpec, encode_headers};
use crate::tar_read::{TarEntry, TarEntryKind, TarReadError, TarReadLimits, parse_numeric_field, read_entries};

const BLOCK: usize = 512;
const RECORD: usize = 10240;
const PAX_NAME: &[u8] = b"././@PaxHeader";
const GNU_LONG_NAME: &[u8] = b"././@LongLink";
const ZERO_TIME: &[u8; 12] = b"00000000000\0";

fn map_read(e: TarReadError) -> UpdateError {
    match e {
        TarReadError::LimitExceeded => UpdateError::LimitExceeded,
        TarReadError::Allocation => UpdateError::Allocation,
        TarReadError::UnsupportedType => UpdateError::Unsupported,
        _ => UpdateError::InvalidArchive,
    }
}

fn read_limits(limits: &UpdateLimits) -> TarReadLimits {
    TarReadLimits { max_entries: limits.max_entries, max_total_size: limits.max_total_bytes, ..TarReadLimits::default() }
}

fn pad_up(n: usize) -> Option<usize> {
    n.checked_add(BLOCK - 1).map(|v| v / BLOCK * BLOCK)
}

/// One extended header (with its padded data) preceding a main header.
#[derive(Debug, Clone)]
struct Meta {
    typeflag: u8,
    start: usize,
    /// End of the header's data (unpadded).
    data_end: usize,
}

#[derive(Debug, Clone)]
struct Segment {
    start: usize,
    metas: Vec<Meta>,
    main: usize,
    end: usize,
}

struct Parsed {
    entries: Vec<TarEntry>,
    segments: Vec<Segment>,
}

fn parse(tar: &[u8], limits: &UpdateLimits) -> Result<Parsed, UpdateError> {
    let entries = read_entries(tar, read_limits(limits)).map_err(map_read)?;
    let mut segments = Vec::new();
    segments.try_reserve_exact(entries.len()).map_err(|_| UpdateError::Allocation)?;
    let mut start = 0usize;
    for e in &entries {
        let main = e.data_range.start.checked_sub(BLOCK).ok_or(UpdateError::InvalidArchive)?;
        if main < start || main % BLOCK != 0 {
            return Err(UpdateError::InvalidArchive);
        }
        let end = pad_up(e.data_range.end).ok_or(UpdateError::InvalidArchive)?.min(tar.len());
        let mut metas = Vec::new();
        let mut pos = start;
        while pos < main {
            let block = tar.get(pos..pos + BLOCK).ok_or(UpdateError::InvalidArchive)?;
            let tf = block[156];
            if !matches!(tf, b'x' | b'g' | b'L' | b'K') {
                return Err(UpdateError::InvalidArchive);
            }
            let size = parse_numeric_field(&block[124..136]).map_err(map_read)?;
            let size = usize::try_from(size).map_err(|_| UpdateError::InvalidArchive)?;
            let data_end = (pos + BLOCK).checked_add(size).ok_or(UpdateError::InvalidArchive)?;
            let mend = pad_up(data_end).ok_or(UpdateError::InvalidArchive)?;
            if data_end > main || mend > main {
                return Err(UpdateError::InvalidArchive);
            }
            metas.push(Meta { typeflag: tf, start: pos, data_end });
            pos = mend;
        }
        if pos != main {
            return Err(UpdateError::InvalidArchive);
        }
        segments.push(Segment { start, metas, main, end });
        start = end;
    }
    Ok(Parsed { entries, segments })
}

/// List the entries of an (uncompressed) tar archive for planning.
pub fn tar_entries(tar: &[u8], limits: &UpdateLimits) -> Result<Vec<ExistingEntry>, UpdateError> {
    let entries = read_entries(tar, read_limits(limits)).map_err(map_read)?;
    Ok(entries
        .into_iter()
        .map(|e| ExistingEntry {
            is_dir: e.kind == TarEntryKind::Directory,
            name: e.path,
            mtime: Some(e.mtime),
            time_resolution: 1,
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderStyle {
    Posix,
    Gnu,
    V7,
}

fn style(block: &[u8]) -> HeaderStyle {
    if &block[257..263] == b"ustar\0" {
        HeaderStyle::Posix
    } else if &block[257..265] == b"ustar  \0" {
        HeaderStyle::Gnu
    } else {
        HeaderStyle::V7
    }
}

fn octal(field: &mut [u8], v: u64) -> Result<(), UpdateError> {
    let digits = field.len() - 1;
    if digits < 22 && v >> (3 * digits) != 0 {
        return Err(UpdateError::LimitExceeded);
    }
    let mut x = v;
    for i in (0..digits).rev() {
        field[i] = b'0' + (x & 7) as u8;
        x >>= 3;
    }
    field[digits] = 0;
    Ok(())
}

fn set_checksum(b: &mut [u8]) -> Result<(), UpdateError> {
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    octal(&mut b[148..155], u64::from(sum))?;
    b[155] = b' ';
    Ok(())
}

fn set_field(field: &mut [u8], value: &[u8]) {
    field.fill(0);
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
}

/// ustar (prefix, name) split, or None when the name cannot fit.
fn split_ustar(full: &[u8]) -> Option<(&[u8], &[u8])> {
    if full.len() <= 100 {
        return Some((&[], full));
    }
    if full.len() > 256 {
        return None;
    }
    let search_end = full.len().saturating_sub(1);
    (1..search_end)
        .rev()
        .find(|&i| full[i] == b'/' && i <= 155 && full.len() - i - 1 <= 100)
        .map(|i| (&full[..i], &full[i + 1..]))
}

/// A meta header block (pax `x` or GNU `L`/`K`) for `len` data bytes.
fn meta_block(typeflag: u8, gnu: bool, len: usize, mtime_field: &[u8]) -> Result<[u8; BLOCK], UpdateError> {
    let mut b = [0u8; BLOCK];
    set_field(&mut b[..100], if gnu { GNU_LONG_NAME } else { PAX_NAME });
    octal(&mut b[100..108], if gnu { 0 } else { 0o644 })?;
    octal(&mut b[108..116], 0)?;
    octal(&mut b[116..124], 0)?;
    octal(&mut b[124..136], len as u64)?;
    b[136..148].copy_from_slice(mtime_field);
    b[156] = typeflag;
    if gnu {
        b[257..265].copy_from_slice(b"ustar  \0");
    } else {
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
    }
    set_checksum(&mut b)?;
    Ok(b)
}

fn push_meta(out: &mut Vec<u8>, header: &[u8], data: &[u8]) -> Result<(), UpdateError> {
    let padded = pad_up(data.len()).ok_or(UpdateError::LimitExceeded)?;
    out.try_reserve(BLOCK + padded).map_err(|_| UpdateError::Allocation)?;
    out.extend_from_slice(header);
    out.extend_from_slice(data);
    out.resize(out.len() + (padded - data.len()), 0);
    Ok(())
}

/// Split pax records into (keyword, raw record) pairs.
/// (keyword, raw record) of one pax record.
type PaxRecord<'a> = (&'a [u8], &'a [u8]);

fn pax_records(data: &[u8]) -> Result<Vec<PaxRecord<'_>>, UpdateError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let sp = rest.iter().position(|&b| b == b' ').ok_or(UpdateError::InvalidArchive)?;
        let digits = std::str::from_utf8(&rest[..sp]).map_err(|_| UpdateError::InvalidArchive)?;
        let len: usize = digits.parse().map_err(|_| UpdateError::InvalidArchive)?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(UpdateError::InvalidArchive);
        }
        let kv = &rest[sp + 1..len - 1];
        let eq = kv.iter().position(|&b| b == b'=').ok_or(UpdateError::InvalidArchive)?;
        out.push((&kv[..eq], &rest[..len]));
        rest = &rest[len..];
    }
    Ok(out)
}

fn record(key: &[u8], value: &[u8]) -> Result<Vec<u8>, UpdateError> {
    encode_record(key, value, usize::MAX).map_err(|_| UpdateError::InvalidName)
}

/// Re-emit an entry's headers with a new path and/or link target, followed
/// by its (unchanged) data.
fn rewrite_entry(
    tar: &[u8],
    seg: &Segment,
    new_path: Option<&[u8]>,
    new_link: Option<&[u8]>,
    is_dir: bool,
    out: &mut Vec<u8>,
) -> Result<(), UpdateError> {
    let mut main = [0u8; BLOCK];
    main.copy_from_slice(&tar[seg.main..seg.main + BLOCK]);
    let st = style(&main);
    let mtime_field: [u8; 12] = main[136..148].try_into().map_err(|_| UpdateError::InvalidArchive)?;
    let mut pax: Vec<u8> = Vec::new();
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut kept_gnu: Vec<&Meta> = Vec::new();
    for m in &seg.metas {
        match m.typeflag {
            b'g' => push_meta(out, &tar[m.start..m.start + BLOCK], &tar[m.start + BLOCK..m.data_end])?,
            b'x' => {
                for (key, raw) in pax_records(&tar[m.start + BLOCK..m.data_end])? {
                    let drop = (new_path.is_some() && key == b"path") || (new_link.is_some() && key == b"linkpath");
                    if !drop {
                        pax.extend_from_slice(raw);
                    }
                }
            }
            b'L' if new_path.is_some() => {}
            b'K' if new_link.is_some() => {}
            _ => kept_gnu.push(m),
        }
    }
    if let Some(p) = new_path {
        let mut full = Vec::new();
        full.try_reserve_exact(p.len() + 1).map_err(|_| UpdateError::Allocation)?;
        full.extend_from_slice(p);
        if is_dir {
            full.push(b'/');
        }
        let fits = match st {
            HeaderStyle::Posix => split_ustar(&full),
            _ if full.len() <= 100 => Some((&[][..], &full[..])),
            _ => None,
        };
        match fits {
            Some((prefix, name)) => {
                set_field(&mut main[..100], name);
                if st == HeaderStyle::Posix {
                    set_field(&mut main[345..500], prefix);
                }
            }
            None => {
                set_field(&mut main[..100], &full[..100]);
                if st == HeaderStyle::Posix {
                    main[345..500].fill(0);
                }
                if st == HeaderStyle::Gnu {
                    let mut d = full.clone();
                    d.push(0);
                    long_name = Some(d);
                } else {
                    pax.extend_from_slice(&record(b"path", &full)?);
                }
            }
        }
    }
    if let Some(l) = new_link {
        if l.len() <= 100 {
            set_field(&mut main[157..257], l);
        } else {
            set_field(&mut main[157..257], &l[..100]);
            if st == HeaderStyle::Gnu {
                let mut d = l.to_vec();
                d.push(0);
                long_link = Some(d);
            } else {
                pax.extend_from_slice(&record(b"linkpath", l)?);
            }
        }
    }
    set_checksum(&mut main)?;
    if !pax.is_empty() {
        let h = meta_block(b'x', false, pax.len(), &mtime_field)?;
        push_meta(out, &h, &pax)?;
    }
    for m in kept_gnu {
        push_meta(out, &tar[m.start..m.start + BLOCK], &tar[m.start + BLOCK..m.data_end])?;
    }
    if let Some(d) = long_name {
        let h = meta_block(b'L', true, d.len(), ZERO_TIME)?;
        push_meta(out, &h, &d)?;
    }
    if let Some(d) = long_link {
        let h = meta_block(b'K', true, d.len(), ZERO_TIME)?;
        push_meta(out, &h, &d)?;
    }
    let data = &tar[seg.main + BLOCK..seg.end];
    out.try_reserve(BLOCK + data.len()).map_err(|_| UpdateError::Allocation)?;
    out.extend_from_slice(&main);
    out.extend_from_slice(data);
    let pad = (BLOCK - out.len() % BLOCK) % BLOCK;
    out.resize(out.len() + pad, 0);
    Ok(())
}

fn map_create(e: TarCreateError) -> UpdateError {
    match e {
        TarCreateError::InvalidName => UpdateError::InvalidName,
        TarCreateError::InvalidEntry => UpdateError::EncodeFailed,
        TarCreateError::LimitExceeded => UpdateError::LimitExceeded,
        TarCreateError::Allocation => UpdateError::Allocation,
    }
}

fn encode_new(e: &ArchiveEntry<'_>, out: &mut Vec<u8>) -> Result<(), UpdateError> {
    if e.kind != EntryKind::File && !e.data.is_empty() {
        return Err(UpdateError::EncodeFailed);
    }
    let spec = TarHeaderSpec {
        name: e.name,
        kind: e.kind,
        size: e.data.len() as u64,
        mtime: e.mtime,
        mode: e.mode,
        link_target: e.link_target,
    };
    encode_headers(&spec, out).map_err(map_create)?;
    let padded = pad_up(e.data.len()).ok_or(UpdateError::LimitExceeded)?;
    out.try_reserve(padded).map_err(|_| UpdateError::Allocation)?;
    out.extend_from_slice(e.data);
    out.resize(out.len() + (padded - e.data.len()), 0);
    Ok(())
}

/// Apply `plan` to the uncompressed tar archive `tar` (empty = new archive)
/// and return the new uncompressed archive.
pub fn apply_tar(tar: &[u8], plan: &EditPlan<'_>, limits: &UpdateLimits) -> Result<Vec<u8>, UpdateError> {
    let parsed = if tar.is_empty() { Parsed { entries: Vec::new(), segments: Vec::new() } } else { parse(tar, limits)? };
    if plan.actions.len() != parsed.entries.len() {
        return Err(UpdateError::InvalidArchive);
    }
    if parsed.entries.len().saturating_add(plan.additions.len()) > limits.max_entries {
        return Err(UpdateError::LimitExceeded);
    }
    // Old name -> new name, for hard link targets.
    let mut renamed: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
    for (e, a) in parsed.entries.iter().zip(&plan.actions) {
        if let EntryAction::Rename(n) = a {
            renamed.insert(&e.path, n);
        }
    }
    let max = usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    let check = |out: &Vec<u8>| if out.len() > max { Err(UpdateError::LimitExceeded) } else { Ok(()) };
    for ((e, seg), a) in parsed.entries.iter().zip(&parsed.segments).zip(&plan.actions) {
        let link_fix = if e.kind == TarEntryKind::HardLink {
            e.link_target.as_deref().and_then(|t| renamed.get(t).copied())
        } else {
            None
        };
        let is_dir = e.kind == TarEntryKind::Directory;
        match a {
            EntryAction::Keep if link_fix.is_none() => {
                let span = &tar[seg.start..seg.end];
                out.try_reserve(span.len() + BLOCK).map_err(|_| UpdateError::Allocation)?;
                out.extend_from_slice(span);
                let pad = (BLOCK - out.len() % BLOCK) % BLOCK;
                out.resize(out.len() + pad, 0);
            }
            EntryAction::Keep => rewrite_entry(tar, seg, None, link_fix, is_dir, &mut out)?,
            EntryAction::Rename(n) => rewrite_entry(tar, seg, Some(n), link_fix, is_dir, &mut out)?,
            EntryAction::Delete | EntryAction::Replace(_) => {
                for m in seg.metas.iter().filter(|m| m.typeflag == b'g') {
                    push_meta(&mut out, &tar[m.start..m.start + BLOCK], &tar[m.start + BLOCK..m.data_end])?;
                }
                if let EntryAction::Replace(n) = a {
                    encode_new(n, &mut out)?;
                }
            }
        }
        check(&out)?;
    }
    for n in &plan.additions {
        encode_new(n, &mut out)?;
        check(&out)?;
    }
    let end = (out.len() + 2 * BLOCK).div_ceil(RECORD) * RECORD;
    if end > max {
        return Err(UpdateError::LimitExceeded);
    }
    out.try_reserve(end - out.len()).map_err(|_| UpdateError::Allocation)?;
    out.resize(end, 0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rules() {
        assert_eq!(split_ustar(b"a"), Some((&b""[..], &b"a"[..])));
        let long = [b'a'; 120];
        assert_eq!(split_ustar(&long), None);
        let mut p = vec![b'd'; 50];
        p.push(b'/');
        p.extend_from_slice(&[b'f'; 90]);
        assert_eq!(split_ustar(&p), Some((&p[..50], &p[51..])));
    }

    #[test]
    fn octal_overflow() {
        let mut f = [0u8; 8];
        assert!(octal(&mut f, 0o7777777).is_ok());
        assert_eq!(octal(&mut f, 0o10000000), Err(UpdateError::LimitExceeded));
    }

    #[test]
    fn pax_split() {
        let r = pax_records(b"11 path=ab\n12 uid=1000\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, b"path");
        assert!(pax_records(b"99 path=ab\n").is_err());
    }
}
