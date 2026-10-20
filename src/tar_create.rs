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
//!
//! [`create_tar_with_format`] selects the header flavour (7-Zip `-mf=`):
//! * `ustar`: strict POSIX ustar; names/links that do not fit, sizes of
//!   8 GiB or more are errors (no extension headers are ever written).
//! * `gnu`: GNU tar format (GNU tar manual, "GNU tar format"): magic
//!   `"ustar  \0"`, long names/link targets in `././@LongLink` entries of
//!   type `L`/`K`, and base-256 numeric fields for huge sizes and
//!   out-of-range mtimes.
//! * `pax` / `posix`: ustar plus a pax `x` header whenever the name does not
//!   fit, the name or link target is not plain ASCII, the link target exceeds
//!   100 bytes, the size exceeds 8 GiB - 1, the mtime is out of range, or the
//!   mtime has a sub-second part ([`encode_headers_ext`] takes nanoseconds).

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

/// Tar header flavour for [`create_tar_with_format`] (7-Zip `-mf=` names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarFormat {
    Ustar,
    Gnu,
    Pax,
}

impl TarFormat {
    /// Parse `ustar`, `gnu`, `pax` or `posix` (case-insensitive).
    pub fn from_name(name: &str) -> Option<TarFormat> {
        Some(match name.to_ascii_lowercase().as_str() {
            "ustar" => TarFormat::Ustar,
            "gnu" => TarFormat::Gnu,
            "pax" | "posix" => TarFormat::Pax,
            _ => return None,
        })
    }
}

/// Encode the header block(s) for one entry: an optional pax `x` header with
/// its padded records, followed by the ustar header block.
pub fn encode_headers(spec: &TarHeaderSpec<'_>, out: &mut Vec<u8>) -> Result<(), TarCreateError> {
    encode_inner(spec, None, 0, out)
}

/// Like [`encode_headers`] with an explicit format. `mtime_nsec` (0..=999_999_999)
/// is the sub-second part of the mtime; only the pax format can store it.
pub fn encode_headers_ext(
    spec: &TarHeaderSpec<'_>,
    format: TarFormat,
    mtime_nsec: u32,
    out: &mut Vec<u8>,
) -> Result<(), TarCreateError> {
    if mtime_nsec > 999_999_999 {
        return Err(TarCreateError::InvalidEntry);
    }
    match format {
        TarFormat::Gnu => encode_gnu(spec, out),
        f => encode_inner(spec, Some(f), mtime_nsec, out),
    }
}

/// Validate the entry and return its full name (directories get a `/`).
fn full_name(spec: &TarHeaderSpec<'_>) -> Result<Vec<u8>, TarCreateError> {
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
    Ok(full)
}

/// `format`: None = the default (pax only where ustar cannot hold a value),
/// Some(Ustar) = never pax, Some(Pax) = also pax for non-ASCII and ns mtimes.
fn encode_inner(
    spec: &TarHeaderSpec<'_>,
    format: Option<TarFormat>,
    mtime_nsec: u32,
    out: &mut Vec<u8>,
) -> Result<(), TarCreateError> {
    let full = full_name(spec)?;
    let strict = format == Some(TarFormat::Ustar);
    let force_pax = format == Some(TarFormat::Pax);

    let mut pax: Vec<u8> = Vec::new();
    let split = split_ustar_name(&full);
    let (prefix, name): (&[u8], &[u8]) = match split {
        Some(pn) if !(force_pax && !full.is_ascii()) => pn,
        _ if strict => return Err(TarCreateError::InvalidName),
        Some(pn) => {
            add_record(&mut pax, b"path", &full)?;
            pn
        }
        None => {
            add_record(&mut pax, b"path", &full)?;
            (&[], truncate_utf8(&full, 100))
        }
    };
    let link: &[u8] = if spec.link_target.len() > 100 || (force_pax && !spec.link_target.is_ascii()) {
        if strict {
            return Err(TarCreateError::InvalidName);
        }
        add_record(&mut pax, b"linkpath", spec.link_target)?;
        truncate_utf8(spec.link_target, 100)
    } else {
        spec.link_target
    };
    let size_field = if spec.size > OCTAL11_MAX {
        if strict {
            return Err(TarCreateError::LimitExceeded);
        }
        add_record(&mut pax, b"size", spec.size.to_string().as_bytes())?;
        0
    } else {
        spec.size
    };
    let out_of_range = spec.mtime < 0 || spec.mtime as u64 > OCTAL11_MAX;
    if !strict && (out_of_range || (force_pax && mtime_nsec != 0)) {
        let mut v = spec.mtime.to_string();
        if force_pax && mtime_nsec != 0 {
            // POSIX pax: decimal seconds with an optional fraction. Negative
            // times are floor-based seconds plus a positive fraction in
            // `TarHeaderSpec`; express them exactly as a signed decimal.
            let (secs, frac) = if spec.mtime < 0 {
                (spec.mtime + 1, 1_000_000_000 - mtime_nsec)
            } else {
                (spec.mtime, mtime_nsec)
            };
            let sign = if spec.mtime < 0 && secs == 0 { "-" } else { "" };
            let f = format!("{frac:09}");
            v = format!("{sign}{secs}.{}", f.trim_end_matches('0'));
        }
        add_record(&mut pax, b"mtime", v.as_bytes())?;
    }
    let mtime_field = spec.mtime.clamp(0, OCTAL11_MAX as i64) as u64;

    if !pax.is_empty() {
        let padded = pax.len().div_ceil(BLOCK) * BLOCK;
        out.try_reserve(BLOCK + padded).map_err(|_| TarCreateError::Allocation)?;
        let h = ustar_block(&[], PAX_NAME, &[], b'x', 0o644, pax.len() as u64, 0);
        out.extend_from_slice(&h);
        out.extend_from_slice(&pax);
        out.resize(out.len() + (padded - pax.len()), 0);
    }
    let (typeflag, mode) = kind_fields(spec);
    out.try_reserve(BLOCK).map_err(|_| TarCreateError::Allocation)?;
    out.extend_from_slice(&ustar_block(prefix, name, link, typeflag, mode, size_field, mtime_field));
    Ok(())
}

/// GNU format: `././@LongLink` entries for long names, base-256 numbers.
fn encode_gnu(spec: &TarHeaderSpec<'_>, out: &mut Vec<u8>) -> Result<(), TarCreateError> {
    let full = full_name(spec)?;
    let long = |typeflag: u8, value: &[u8], out: &mut Vec<u8>| -> Result<(), TarCreateError> {
        let len = value.len() + 1;
        let padded = len.div_ceil(BLOCK) * BLOCK;
        out.try_reserve(BLOCK + padded).map_err(|_| TarCreateError::Allocation)?;
        let h = header_block(&HeaderFields {
            prefix: &[],
            name: b"././@LongLink",
            link: &[],
            typeflag,
            mode: 0o644,
            size: Num::Value(len as u64),
            mtime: Num::Value(0),
            gnu: true,
        });
        out.extend_from_slice(&h);
        out.extend_from_slice(value);
        out.resize(out.len() + (padded - value.len()), 0);
        Ok(())
    };
    let name: &[u8] = if full.len() > 100 {
        long(b'L', &full, out)?;
        truncate_utf8(&full, 100)
    } else {
        &full
    };
    let link: &[u8] = if spec.link_target.len() > 100 {
        long(b'K', spec.link_target, out)?;
        truncate_utf8(spec.link_target, 100)
    } else {
        spec.link_target
    };
    let size = if spec.size > OCTAL11_MAX { Num::Base256(spec.size as i64) } else { Num::Value(spec.size) };
    let mtime = if spec.mtime < 0 || spec.mtime as u64 > OCTAL11_MAX {
        Num::Base256(spec.mtime)
    } else {
        Num::Value(spec.mtime as u64)
    };
    let (typeflag, mode) = kind_fields(spec);
    out.try_reserve(BLOCK).map_err(|_| TarCreateError::Allocation)?;
    out.extend_from_slice(&header_block(&HeaderFields {
        prefix: &[],
        name,
        link,
        typeflag,
        mode,
        size,
        mtime,
        gnu: true,
    }));
    Ok(())
}

fn kind_fields(spec: &TarHeaderSpec<'_>) -> (u8, u32) {
    let typeflag = match spec.kind {
        EntryKind::File => b'0',
        EntryKind::Directory => b'5',
        EntryKind::Symlink => b'2',
    };
    let mode = if spec.kind == EntryKind::Symlink { 0o777 } else { spec.mode & 0o7777 };
    (typeflag, mode)
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
    header_block(&HeaderFields {
        prefix,
        name,
        link,
        typeflag,
        mode,
        size: Num::Value(size),
        mtime: Num::Value(mtime),
        gnu: false,
    })
}

/// A numeric header field: octal, or GNU base-256 (high bit of the first byte
/// set, big-endian two's complement in the rest of the field).
#[derive(Clone, Copy)]
enum Num {
    Value(u64),
    Base256(i64),
}

struct HeaderFields<'a> {
    prefix: &'a [u8],
    name: &'a [u8],
    link: &'a [u8],
    typeflag: u8,
    mode: u32,
    size: Num,
    mtime: Num,
    gnu: bool,
}

fn put_num(field: &mut [u8], v: Num) {
    match v {
        Num::Value(x) => octal(field, x),
        Num::Base256(x) => {
            let bytes = x.to_be_bytes();
            let fill = if x < 0 { 0xFF } else { 0 };
            let n = field.len();
            field.fill(fill);
            field[n - 8..].copy_from_slice(&bytes);
            field[0] = if x < 0 { 0xFF } else { 0x80 };
        }
    }
}

fn header_block(h: &HeaderFields<'_>) -> [u8; 512] {
    let (prefix, name, link) = (h.prefix, h.name, h.link);
    let mut b = [0u8; 512];
    b[..name.len()].copy_from_slice(name);
    octal(&mut b[100..108], h.mode as u64);
    octal(&mut b[108..116], 0);
    octal(&mut b[116..124], 0);
    put_num(&mut b[124..136], h.size);
    put_num(&mut b[136..148], h.mtime);
    b[156] = h.typeflag;
    b[157..157 + link.len()].copy_from_slice(link);
    if h.gnu {
        b[257..265].copy_from_slice(b"ustar  \0");
    } else {
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
    }
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
    create_tar_inner(entries, None, limits)
}

/// [`create_tar`] with an explicit header format (see [`TarFormat`]).
pub fn create_tar_with_format(
    entries: &[ArchiveEntry<'_>],
    format: TarFormat,
    limits: TarCreateLimits,
) -> Result<Vec<u8>, TarCreateError> {
    create_tar_inner(entries, Some(format), limits)
}

fn create_tar_inner(
    entries: &[ArchiveEntry<'_>],
    format: Option<TarFormat>,
    limits: TarCreateLimits,
) -> Result<Vec<u8>, TarCreateError> {
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
        let spec = TarHeaderSpec {
            name: e.name,
            kind: e.kind,
            size: e.data.len() as u64,
            mtime: e.mtime,
            mode: e.mode,
            link_target: e.link_target,
        };
        match format {
            None => encode_headers(&spec, &mut out)?,
            Some(f) => encode_headers_ext(&spec, f, 0, &mut out)?,
        }
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
