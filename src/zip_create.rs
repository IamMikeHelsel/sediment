// SPDX-License-Identifier: MIT OR Apache-2.0
//! Build a ZIP archive from in-memory entries.
//!
//! Spec source: PKWARE APPNOTE.TXT 6.3.x sections 4.3 (local header, central
//! directory, EOCD), 4.4.2 (version made by), 4.4.4 (general purpose flag,
//! bit 11 = UTF-8), 4.4.6 (MS-DOS time/date); Info-ZIP extra field 0x5455
//! (extended timestamp). No ZIP64: archives needing it are `Unsupported`.
//!
//! Each file is stored or DEFLATE-compressed (`deflate_compress`); stored is
//! chosen whenever DEFLATE does not shrink the data. Sizes and CRCs are written
//! in the local header, so no data descriptors are used. Directories are stored
//! with a trailing `/`. Symlinks are skipped (reported in `skipped`), since ZIP
//! symlink support varies across readers. Output is byte-deterministic.
//! `zip_write::write_stored` is not reused: it fixes time/date and attributes.
//!
//! [`create_zip_with_method`] selects the compression method (7-Zip `-mm=`):
//! Copy (0), Deflate (8), Deflate64 (9, `deflate64_encode`), BZip2 (12, a
//! complete bzip2 stream from `bzip2_encode`), LZMA (14) and XZ (95, a
//! complete .xz stream from `xz_encode`). Per APPNOTE 5.8.8 an LZMA payload
//! starts with a 4-byte header (LZMA SDK major/minor version, little-endian
//! properties size 5) followed by the 5 property bytes (lc/lp/pb byte and the
//! 32-bit dictionary size); the raw LZMA stream always ends with the
//! end-of-stream marker and general-purpose flag bit 1 is set to say so.
//! "Version needed to extract" follows APPNOTE 4.4.3.2 (2.0 deflate, 2.1
//! Deflate64, 4.6 BZip2, 6.3 LZMA/XZ). Entries whose payload would not shrink
//! are stored, like 7-Zip does.

use crate::crc32::crc32;
use crate::deflate_compress::{CompressError, deflate_compress};
use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::zip_dos_time::{DosDateTime, encode_dos};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipCreateError {
    /// Empty name, NUL byte, absolute or `.`/`..` component, or name too long.
    InvalidName,
    /// Directory or symlink entry carries data.
    InvalidEntry,
    /// Would need ZIP64 (>= 65535 entries or >= 4 GiB sizes/offsets).
    Unsupported,
    LimitExceeded,
    Allocation,
    /// Compression level outside 0..=9.
    InvalidLevel,
}

#[derive(Debug, Clone, Copy)]
pub struct ZipCreateLimits {
    pub max_entries: usize,
    pub max_total_input: u64,
    pub max_archive_bytes: usize,
}

impl Default for ZipCreateLimits {
    fn default() -> Self {
        Self {
            max_entries: 65534,
            max_total_input: 1 << 30,
            max_archive_bytes: (u32::MAX - 1) as usize,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipCreateOptions {
    /// 0 = store everything; 1..=9 = DEFLATE level (stored when it doesn't shrink).
    pub level: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipCreated {
    pub bytes: Vec<u8>,
    /// Indices into the input of entries that were not written (symlinks).
    pub skipped: Vec<usize>,
    /// Methods per written entry, in order (0 stored, else the `ZipMethod` id).
    pub methods: Vec<u16>,
}

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const VERSION_NEEDED: u16 = 20;
const FLAG_LZMA_EOS: u16 = 0x0002;

/// Compression method for [`create_zip_with_method`] (7-Zip `-mm=` names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipMethod {
    Copy,
    Deflate,
    Deflate64,
    Bzip2,
    Lzma,
    Xz,
}

impl ZipMethod {
    /// APPNOTE 4.4.5 method id.
    pub fn id(self) -> u16 {
        match self {
            ZipMethod::Copy => 0,
            ZipMethod::Deflate => 8,
            ZipMethod::Deflate64 => 9,
            ZipMethod::Bzip2 => 12,
            ZipMethod::Lzma => 14,
            ZipMethod::Xz => 95,
        }
    }

    /// Parse a 7-Zip method name (case-insensitive): Copy, Store, Deflate,
    /// Deflate64, BZip2, LZMA, XZ.
    pub fn from_name(name: &str) -> Option<ZipMethod> {
        Some(match name.to_ascii_lowercase().as_str() {
            "copy" | "store" => ZipMethod::Copy,
            "deflate" => ZipMethod::Deflate,
            "deflate64" => ZipMethod::Deflate64,
            "bzip2" => ZipMethod::Bzip2,
            "lzma" => ZipMethod::Lzma,
            "xz" => ZipMethod::Xz,
            _ => return None,
        })
    }

    /// APPNOTE 4.4.3.2 "version needed to extract" for this method.
    fn version_needed(self) -> u16 {
        match self {
            ZipMethod::Copy | ZipMethod::Deflate => VERSION_NEEDED,
            ZipMethod::Deflate64 => 21,
            ZipMethod::Bzip2 => 46,
            ZipMethod::Lzma | ZipMethod::Xz => 63,
        }
    }
}

/// Compress one payload with `method` at `level` (1..=9). `Ok(None)` means
/// the result would not be smaller than the input (store it instead).
fn compress_payload(data: &[u8], method: ZipMethod, level: u8) -> Result<Option<Vec<u8>>, ZipCreateError> {
    use crate::compress_wrap::{WrapError, bzip2_compress, xz_compress};
    let cap = data.len() - 1;
    let wrap = |r: Result<Vec<u8>, WrapError>| match r {
        Ok(v) => Ok(Some(v)),
        Err(WrapError::LimitExceeded) => Ok(None),
        Err(WrapError::Allocation) => Err(ZipCreateError::Allocation),
        Err(_) => Err(ZipCreateError::InvalidLevel),
    };
    let out = match method {
        ZipMethod::Copy => return Ok(None),
        ZipMethod::Deflate => match deflate_compress(data, level, cap) {
            Ok(c) => Some(c),
            Err(CompressError::LimitExceeded) => None,
            Err(CompressError::Allocation) => return Err(ZipCreateError::Allocation),
            Err(CompressError::InvalidLevel) => return Err(ZipCreateError::InvalidLevel),
        },
        ZipMethod::Deflate64 => {
            use crate::deflate64_encode::{Deflate64EncodeError, deflate64_compress};
            match deflate64_compress(data, level, cap) {
                Ok(c) => Some(c),
                Err(Deflate64EncodeError::LimitExceeded) => None,
                Err(Deflate64EncodeError::Allocation) => return Err(ZipCreateError::Allocation),
                Err(Deflate64EncodeError::InvalidLevel) => return Err(ZipCreateError::InvalidLevel),
            }
        }
        ZipMethod::Bzip2 => wrap(bzip2_compress(data, level, cap))?,
        ZipMethod::Xz => wrap(xz_compress(data, level, cap))?,
        ZipMethod::Lzma => {
            use crate::lzma_encode::{LzmaEncodeError, LzmaEncoderOptions, effective_dictionary_size, encode_lzma_raw, props_byte};
            let lz = |e: LzmaEncodeError| match e {
                LzmaEncodeError::Allocation => ZipCreateError::Allocation,
                LzmaEncodeError::InputTooLarge => ZipCreateError::Unsupported,
                LzmaEncodeError::InvalidOptions => ZipCreateError::InvalidLevel,
            };
            let opts = LzmaEncoderOptions::preset(level as u32).map_err(lz)?;
            let dict = effective_dictionary_size(opts.dictionary_size, data.len());
            let raw = encode_lzma_raw(data, &opts, true).map_err(lz)?;
            let mut v = Vec::new();
            v.try_reserve_exact(raw.len() + 9).map_err(|_| ZipCreateError::Allocation)?;
            // LZMA SDK version 9.20 (informational), properties size 5.
            v.extend_from_slice(&[9, 20, 5, 0, props_byte(opts.lc, opts.lp, opts.pb)]);
            v.extend_from_slice(&dict.to_le_bytes());
            v.extend_from_slice(&raw);
            Some(v)
        }
    };
    Ok(out.filter(|c| c.len() < data.len()))
}
const VERSION_MADE_BY: u16 = (3 << 8) | 30; // Unix, spec 3.0
const FLAG_UTF8: u16 = 0x0800;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

struct Prepared<'a> {
    name: Vec<u8>,
    flags: u16,
    version_needed: u16,
    method: u16,
    crc: u32,
    csize: u32,
    usize_: u32,
    time: u16,
    date: u16,
    payload: std::borrow::Cow<'a, [u8]>,
    ext_attr: u32,
    ut_mtime: Option<i32>,
    local_offset: u32,
}

/// Validate an archive-relative name: non-empty, no NUL, no leading `/`, no
/// empty, `.` or `..` components.
pub fn validate_entry_name(name: &[u8]) -> bool {
    !name.is_empty()
        && !name.contains(&0)
        && name[0] != b'/'
        && name
            .split(|&c| c == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// Convert Unix seconds to a DOS timestamp in UTC, clamped to 1980..=2107 and
/// rounded down to an even second.
pub fn dos_time_from_unix(secs: i64) -> (u16, u16) {
    const MIN: i64 = 315_532_800; // 1980-01-01T00:00:00Z
    const MAX: i64 = 4_354_819_198; // 2107-12-31T23:59:58Z
    let s = secs.clamp(MIN, MAX);
    let days = s.div_euclid(86400);
    let rem = s.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let v = DosDateTime {
        year: y as u16,
        month: m as u8,
        day: d as u8,
        hour: (rem / 3600) as u8,
        minute: (rem / 60 % 60) as u8,
        second: (rem % 60 / 2 * 2) as u8,
    };
    // Clamped inputs always encode; fall back to the DOS epoch defensively.
    encode_dos(&v).map(|(date, time)| (time, date)).unwrap_or((0, 33))
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn too_big<T: TryFrom<usize>>(v: usize) -> Result<T, ZipCreateError> {
    T::try_from(v).map_err(|_| ZipCreateError::Unsupported)
}

/// Build a ZIP archive.
pub fn create_zip(
    entries: &[ArchiveEntry<'_>],
    options: ZipCreateOptions,
    limits: ZipCreateLimits,
) -> Result<ZipCreated, ZipCreateError> {
    create_zip_with_method(entries, options, ZipMethod::Deflate, limits)
}

/// Build a ZIP archive whose file entries use `method` (stored when level is
/// 0, the entry is empty, or compression does not shrink it).
pub fn create_zip_with_method(
    entries: &[ArchiveEntry<'_>],
    options: ZipCreateOptions,
    method: ZipMethod,
    limits: ZipCreateLimits,
) -> Result<ZipCreated, ZipCreateError> {
    create_zip_with_method_mt(entries, options, method, limits, 1)
}

/// [`create_zip`] (DEFLATE) with each file compressed on up to `threads`
/// workers. The archive is byte-identical for every thread count.
pub fn create_zip_mt(
    entries: &[ArchiveEntry<'_>],
    options: ZipCreateOptions,
    limits: ZipCreateLimits,
    threads: usize,
) -> Result<ZipCreated, ZipCreateError> {
    create_zip_with_method_mt(entries, options, ZipMethod::Deflate, limits, threads)
}

/// [`create_zip_with_method`] with each file's data compressed on up to
/// `threads` workers ([`crate::mt_pool::map_ordered`]). Files are
/// independent, so the archive is byte-identical for every thread count.
pub fn create_zip_with_method_mt(
    entries: &[ArchiveEntry<'_>],
    options: ZipCreateOptions,
    method: ZipMethod,
    limits: ZipCreateLimits,
    threads: usize,
) -> Result<ZipCreated, ZipCreateError> {
    if options.level > 9 {
        return Err(ZipCreateError::InvalidLevel);
    }
    // Validate names and the input limit before spending CPU on DEFLATE.
    let mut planned: u64 = 0;
    for e in entries {
        if !validate_entry_name(e.name) {
            return Err(ZipCreateError::InvalidName);
        }
        if e.kind != EntryKind::Symlink {
            planned = planned.checked_add(e.data.len() as u64).ok_or(ZipCreateError::LimitExceeded)?;
        }
    }
    if planned > limits.max_total_input {
        return Err(ZipCreateError::LimitExceeded);
    }
    // DEFLATE every regular, non-empty file up front (in parallel); `None`
    // means "store" (level 0, empty, or DEFLATE did not shrink the data).
    let compressible = |e: &ArchiveEntry<'_>| options.level != 0 && e.kind == EntryKind::File && !e.data.is_empty();
    let deflated: Vec<(u32, Option<Vec<u8>>)> = crate::mt_pool::map_ordered(entries, threads, ZipCreateError::Allocation, |e| {
        if e.kind == EntryKind::Symlink {
            return Ok((0, None));
        }
        let crc = crc32(e.data);
        if !compressible(e) {
            return Ok((crc, None));
        }
        // Anything not strictly smaller is stored instead.
        Ok((crc, compress_payload(e.data, method, options.level)?))
    })?;
    let mut deflated = deflated.into_iter();
    let mut skipped = Vec::new();
    let mut prepared: Vec<Prepared<'_>> = Vec::new();
    let mut total_input: u64 = 0;
    let written = entries.iter().filter(|e| e.kind != EntryKind::Symlink).count();
    if written > limits.max_entries {
        return Err(ZipCreateError::LimitExceeded);
    }
    if written >= 0xFFFF {
        return Err(ZipCreateError::Unsupported);
    }
    prepared.try_reserve_exact(written).map_err(|_| ZipCreateError::Allocation)?;
    let mut offset: usize = 0;

    for (idx, e) in entries.iter().enumerate() {
        let (crc, pre) = deflated.next().unwrap_or((0, None));
        if !validate_entry_name(e.name) {
            return Err(ZipCreateError::InvalidName);
        }
        match e.kind {
            EntryKind::Symlink => {
                skipped.try_reserve(1).map_err(|_| ZipCreateError::Allocation)?;
                skipped.push(idx);
                continue;
            }
            EntryKind::Directory if !e.data.is_empty() => return Err(ZipCreateError::InvalidEntry),
            _ => {}
        }
        total_input = total_input.checked_add(e.data.len() as u64).ok_or(ZipCreateError::LimitExceeded)?;
        if total_input > limits.max_total_input {
            return Err(ZipCreateError::LimitExceeded);
        }
        let is_dir = e.kind == EntryKind::Directory;
        let mut name = Vec::new();
        name.try_reserve_exact(e.name.len() + 1).map_err(|_| ZipCreateError::Allocation)?;
        name.extend_from_slice(e.name);
        if is_dir {
            name.push(b'/');
        }
        if name.len() > 0xFFFF {
            return Err(ZipCreateError::InvalidName);
        }
        let flags = if !name.is_ascii() && std::str::from_utf8(&name).is_ok() { FLAG_UTF8 } else { 0 };
        let usize_: u32 = too_big(e.data.len())?;
        if usize_ == u32::MAX {
            return Err(ZipCreateError::Unsupported);
        }
        let (method_id, payload): (u16, std::borrow::Cow<'_, [u8]>) = match pre {
            Some(c) => (method.id(), std::borrow::Cow::Owned(c)),
            None => (0, std::borrow::Cow::Borrowed(e.data)),
        };
        let version_needed = if method_id == 0 { VERSION_NEEDED } else { method.version_needed() };
        let flags = if method_id == 14 { flags | FLAG_LZMA_EOS } else { flags };
        let (time, date) = dos_time_from_unix(e.mtime);
        let type_bits = if is_dir { S_IFDIR } else { S_IFREG };
        let ext_attr = ((type_bits | (e.mode & 0o7777)) << 16) | if is_dir { 0x10 } else { 0 };
        let ut_mtime = i32::try_from(e.mtime).ok();
        let local_offset: u32 = too_big(offset)?;
        let extra_len = if ut_mtime.is_some() { 9 } else { 0 };
        offset = offset
            .checked_add(30 + name.len() + extra_len)
            .and_then(|o| o.checked_add(payload.len()))
            .ok_or(ZipCreateError::LimitExceeded)?;
        if offset > limits.max_archive_bytes {
            return Err(ZipCreateError::LimitExceeded);
        }
        prepared.push(Prepared {
            csize: too_big(payload.len())?,
            name,
            flags,
            version_needed,
            method: method_id,
            crc,
            usize_,
            time,
            date,
            payload,
            ext_attr,
            ut_mtime,
            local_offset,
        });
    }

    let central_start = offset;
    let mut central_size: usize = 0;
    for p in &prepared {
        let extra_len = if p.ut_mtime.is_some() { 9 } else { 0 };
        central_size = central_size
            .checked_add(46 + p.name.len() + extra_len)
            .ok_or(ZipCreateError::LimitExceeded)?;
    }
    let total = central_start
        .checked_add(central_size)
        .and_then(|t| t.checked_add(22))
        .ok_or(ZipCreateError::LimitExceeded)?;
    if total > limits.max_archive_bytes {
        return Err(ZipCreateError::LimitExceeded);
    }
    let central_start_u32: u32 = too_big(central_start)?;
    let central_size_u32: u32 = too_big(central_size)?;
    if central_start_u32 == u32::MAX || central_size_u32 == u32::MAX {
        return Err(ZipCreateError::Unsupported);
    }

    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| ZipCreateError::Allocation)?;
    for p in &prepared {
        put32(&mut out, LOCAL_SIG);
        put16(&mut out, p.version_needed);
        put16(&mut out, p.flags);
        put16(&mut out, p.method);
        put16(&mut out, p.time);
        put16(&mut out, p.date);
        put32(&mut out, p.crc);
        put32(&mut out, p.csize);
        put32(&mut out, p.usize_);
        put16(&mut out, p.name.len() as u16);
        put16(&mut out, if p.ut_mtime.is_some() { 9 } else { 0 });
        out.extend_from_slice(&p.name);
        if let Some(t) = p.ut_mtime {
            put_ut(&mut out, t);
        }
        out.extend_from_slice(&p.payload);
    }
    for p in &prepared {
        put32(&mut out, CENTRAL_SIG);
        put16(&mut out, VERSION_MADE_BY);
        put16(&mut out, p.version_needed);
        put16(&mut out, p.flags);
        put16(&mut out, p.method);
        put16(&mut out, p.time);
        put16(&mut out, p.date);
        put32(&mut out, p.crc);
        put32(&mut out, p.csize);
        put32(&mut out, p.usize_);
        put16(&mut out, p.name.len() as u16);
        put16(&mut out, if p.ut_mtime.is_some() { 9 } else { 0 });
        put16(&mut out, 0); // comment
        put16(&mut out, 0); // disk
        put16(&mut out, 0); // internal attrs
        put32(&mut out, p.ext_attr);
        put32(&mut out, p.local_offset);
        out.extend_from_slice(&p.name);
        if let Some(t) = p.ut_mtime {
            put_ut(&mut out, t);
        }
    }
    put32(&mut out, EOCD_SIG);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, prepared.len() as u16);
    put16(&mut out, prepared.len() as u16);
    put32(&mut out, central_size_u32);
    put32(&mut out, central_start_u32);
    put16(&mut out, 0);
    debug_assert_eq!(out.len(), total);
    let methods = prepared.iter().map(|p| p.method).collect();
    Ok(ZipCreated {
        bytes: out,
        skipped,
        methods,
    })
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_ut(out: &mut Vec<u8>, mtime: i32) {
    put16(out, 0x5455);
    put16(out, 5);
    out.push(1); // flags: mtime present
    out.extend_from_slice(&mtime.to_le_bytes());
}
