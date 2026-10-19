// SPDX-License-Identifier: MIT OR Apache-2.0
//! Build a POSIX ustar archive with pax extended headers where needed.
//!
//! Spec source: POSIX.1-2008 `pax` utility, sections "ustar Interchange Format"
//! and "pax Interchange Format" (extended header records `path`, `linkpath`,
//! `size`, `mtime`); GNU tar manual "Basic Tar Format" for the record padding
//! convention (output padded to a 10240-byte record).
//!
//! Entries are written in the given order (use `fs_collect` for sorted input).
//! uid/gid are 0 and uname/gname are empty so output depends only on names,
//! kinds, data, modes and mtimes: identical input yields identical bytes.
//! A pax `x` header precedes an entry when its name does not fit the ustar
//! name/prefix split, its link target exceeds 100 bytes, its size exceeds
//! 8 GiB - 1, or its mtime is negative or beyond the 11-digit octal range.
//! Records are encoded with `pax_record_write::encode_record`.

use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::pax_record_write::encode_record;
use crate::zip_create::validate_entry_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarCreateError {
    InvalidName,
    /// Directory/symlink with data, or file with a link target.
    InvalidEntry,
    LimitExceeded,
    Allocation,
}

#[derive(Debug, Clone, Copy)]
pub struct TarCreateLimits {
    pub max_entries: usize,
    pub max_total_input: u64,
    pub max_archive_bytes: usize,
}

impl Default for TarCreateLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_total_input: 1 << 30,
            max_archive_bytes: (1usize << 30) + (1 << 26),
        }
    }
}

const BLOCK: usize = 512;
const RECORD: usize = 10240;
const OCTAL11_MAX: u64 = 0o777_7777_7777;
const PAX_NAME: &[u8] = b"././@PaxHeader";

/// Metadata for one header (separate from the data so huge sizes can be tested).
#[derive(Debug, Clone, Copy)]
pub struct TarHeaderSpec<'a> {
    pub name: &'a [u8],
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
    pub link_target: &'a [u8],
}

/// Encode the header block(s) for one entry: an optional pax `x` header with
/// its padded records, followed by the ustar header block.
pub fn encode_headers(spec: &TarHeaderSpec<'_>, out: &mut Vec<u8>) -> Result<(), TarCreateError> {
    if !validate_entry_name(spec.name) {
        return Err(TarCreateError::InvalidName);
    }
    if spec.kind != EntryKind::File && spec.size != 0 {
        return Err(TarCreateError::InvalidEntry);
    }
    if (spec.kind == EntryKind::Symlink) == spec.link_target.is_empty() || spec.link_target.contains(&0) {
        return Err(TarCreateError::InvalidEntry);
    }
    let mut full = Vec::new();
    full.try_reserve_exact(spec.name.len() + 1).map_err(|_| TarCreateError::Allocation)?;
    full.extend_from_slice(spec.name);
    if spec.kind == EntryKind::Directory {
        full.push(b'/');
    }

    let mut pax: Vec<u8> = Vec::new();
    let split = split_ustar_name(&full);
    let (prefix, name): (&[u8], &[u8]) = match split {
        Some(pn) => pn,
        None => {
            add_record(&mut pax, b"path", &full)?;
            (&[], truncate_utf8(&full, 100))
        }
    };
    let link: &[u8] = if spec.link_target.len() > 100 {
        add_record(&mut pax, b"linkpath", spec.link_target)?;
        truncate_utf8(spec.link_target, 100)
    } else {
        spec.link_target
    };
    let size_field = if spec.size > OCTAL11_MAX {
        add_record(&mut pax, b"size", spec.size.to_string().as_bytes())?;
        0
    } else {
        spec.size
    };
    let mtime_field = if spec.mtime < 0 || spec.mtime as u64 > OCTAL11_MAX {
        add_record(&mut pax, b"mtime", spec.mtime.to_string().as_bytes())?;
        spec.mtime.clamp(0, OCTAL11_MAX as i64) as u64
    } else {
        spec.mtime as u64
    };

    if !pax.is_empty() {
        let padded = pax.len().div_ceil(BLOCK) * BLOCK;
        out.try_reserve(BLOCK + padded).map_err(|_| TarCreateError::Allocation)?;
        let h = ustar_block(&[], PAX_NAME, &[], b'x', 0o644, pax.len() as u64, 0);
        out.extend_from_slice(&h);
        out.extend_from_slice(&pax);
        out.resize(out.len() + (padded - pax.len()), 0);
    }
    let typeflag = match spec.kind {
        EntryKind::File => b'0',
        EntryKind::Directory => b'5',
        EntryKind::Symlink => b'2',
    };
    let mode = if spec.kind == EntryKind::Symlink { 0o777 } else { spec.mode & 0o7777 };
    out.try_reserve(BLOCK).map_err(|_| TarCreateError::Allocation)?;
    out.extend_from_slice(&ustar_block(prefix, name, link, typeflag, mode, size_field, mtime_field));
    Ok(())
}

fn add_record(pax: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<(), TarCreateError> {
    let rec = encode_record(key, value, usize::MAX).map_err(|e| match e {
        crate::pax_record_write::PaxWriteError::InvalidKeyword => TarCreateError::InvalidName,
        crate::pax_record_write::PaxWriteError::LimitExceeded => TarCreateError::Allocation,
    })?;
    pax.try_reserve(rec.len()).map_err(|_| TarCreateError::Allocation)?;
    pax.extend_from_slice(&rec);
    Ok(())
}

/// Split into (prefix, name) for ustar, or None when it cannot fit.
fn split_ustar_name(full: &[u8]) -> Option<(&[u8], &[u8])> {
    if full.len() <= 100 {
        return Some((&[], full));
    }
    if full.len() > 256 {
        return None;
    }
    // Split at a '/' so prefix <= 155 and name in 1..=100. Ignore a trailing
    // '/' (directory marker) as split point. Prefer the longest prefix.
    let search_end = full.len().saturating_sub(1);
    for i in (0..search_end).rev() {
        if full[i] == b'/' && i <= 155 && full.len() - i - 1 <= 100 && i > 0 {
            return Some((&full[..i], &full[i + 1..]));
        }
    }
    None
}

fn truncate_utf8(b: &[u8], max: usize) -> &[u8] {
    if b.len() <= max {
        return b;
    }
    let mut end = max;
    // Back off continuation bytes so we never cut a UTF-8 sequence.
    while end > 0 && (b[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    &b[..end]
}

fn octal(field: &mut [u8], v: u64) {
    // Width-1 digits followed by NUL.
    let digits = field.len() - 1;
    let mut x = v;
    for i in (0..digits).rev() {
        field[i] = b'0' + (x & 7) as u8;
        x >>= 3;
    }
    field[digits] = 0;
}

fn ustar_block(prefix: &[u8], name: &[u8], link: &[u8], typeflag: u8, mode: u32, size: u64, mtime: u64) -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..name.len()].copy_from_slice(name);
    octal(&mut b[100..108], mode as u64);
    octal(&mut b[108..116], 0);
    octal(&mut b[116..124], 0);
    octal(&mut b[124..136], size);
    octal(&mut b[136..148], mtime);
    b[156] = typeflag;
    b[157..157 + link.len()].copy_from_slice(link);
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    b[345..345 + prefix.len()].copy_from_slice(prefix);
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| x as u32).sum();
    octal(&mut b[148..155], sum as u64);
    b[155] = b' ';
    b
}

/// Build a complete tar archive (end-of-archive marker and record padding
/// included) from `entries` in order.
pub fn create_tar(entries: &[ArchiveEntry<'_>], limits: TarCreateLimits) -> Result<Vec<u8>, TarCreateError> {
    if entries.len() > limits.max_entries {
        return Err(TarCreateError::LimitExceeded);
    }
    let mut total: u64 = 0;
    let mut estimate: usize = 2 * BLOCK;
    for e in entries {
        total = total.checked_add(e.data.len() as u64).ok_or(TarCreateError::LimitExceeded)?;
        let blocks = e.data.len().div_ceil(BLOCK) * BLOCK;
        estimate = estimate
            .checked_add(BLOCK)
            .and_then(|x| x.checked_add(blocks))
            .ok_or(TarCreateError::LimitExceeded)?;
    }
    if total > limits.max_total_input || estimate > limits.max_archive_bytes {
        return Err(TarCreateError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve(estimate.div_ceil(RECORD) * RECORD).map_err(|_| TarCreateError::Allocation)?;
    for e in entries {
        if e.kind != EntryKind::File && !e.data.is_empty() {
            return Err(TarCreateError::InvalidEntry);
        }
        encode_headers(
            &TarHeaderSpec {
                name: e.name,
                kind: e.kind,
                size: e.data.len() as u64,
                mtime: e.mtime,
                mode: e.mode,
                link_target: e.link_target,
            },
            &mut out,
        )?;
        out.try_reserve(e.data.len() + BLOCK).map_err(|_| TarCreateError::Allocation)?;
        out.extend_from_slice(e.data);
        let pad = (BLOCK - e.data.len() % BLOCK) % BLOCK;
        out.resize(out.len() + pad, 0);
        if out.len() > limits.max_archive_bytes {
            return Err(TarCreateError::LimitExceeded);
        }
    }
    let end = (out.len() + 2 * BLOCK).div_ceil(RECORD) * RECORD;
    if end > limits.max_archive_bytes {
        return Err(TarCreateError::LimitExceeded);
    }
    out.try_reserve(end - out.len()).map_err(|_| TarCreateError::Allocation)?;
    out.resize(end, 0);
    Ok(out)
}
