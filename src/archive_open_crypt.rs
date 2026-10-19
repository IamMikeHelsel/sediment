// SPDX-License-Identifier: MIT OR Apache-2.0
//! Password-aware archive opening: like [`crate::archive_open::open_named`],
//! but ZIP archives with encrypted entries (ZipCrypto, WinZip AES) and 7z
//! archives with 7zAES coders (including encrypted headers, `-mhe=on`) are
//! read with the given password.
//!
//! Because [`ReaderError`] is format-neutral, password problems are reported
//! on the side: [`OpenedArchive::password_problem`] says whether a failed
//! read was caused by a missing or (probably) wrong password, so a command
//! line can print 7-Zip's "Wrong password?" and exit with code 2.
//!
//! 7z has no password check value, so a wrong password surfaces as a
//! decoder failure or CRC mismatch inside a folder that has an AES coder;
//! such failures are classified as "wrong password" (7-Zip does the same).
//! ZIP has a check byte (ZipCrypto) or verifier plus HMAC (AES).
//!
//! Spec sources: see [`crate::zip_crypt`], [`crate::sevenz_aes_coder`] and
//! the 7z / ZIP readers this module builds on.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::{SevenZCodecs, open_named};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::sevenz_aes_coder::{SEVENZ_AES_METHOD_ID, SevenZAesCoderError, SevenZCryptoDecoder};
use crate::sevenz_read::{SevenZArchive, SevenZLimits, SevenZReadError, filetime_to_unix};
use crate::zip_crypt::{ZipCryptError, read_entry};
use crate::zip_dos_time::decode_dos;
use crate::zip_reader2::{Reader2Limits, ZipArchive2};

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;
const MAX_LINK_TARGET: u64 = 4096;

/// Why an encrypted archive could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordProblem {
    /// Encrypted content and no password given.
    Required,
    /// The password is wrong (or the encrypted data is corrupt).
    Wrong,
}

/// Errors from [`open_named_with_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenCryptError {
    Reader(ReaderError),
    /// Needed to open (encrypted 7z header or encrypted symlink target).
    PasswordRequired,
    /// The encrypted header did not decrypt.
    WrongPassword,
}

impl From<ReaderError> for OpenCryptError {
    fn from(e: ReaderError) -> Self {
        Self::Reader(e)
    }
}

/// Shared password state of an opened archive.
#[derive(Debug, Default)]
pub struct CryptStatus {
    encrypted: Cell<bool>,
    problem: Cell<Option<PasswordProblem>>,
}

impl CryptStatus {
    fn note(&self, p: PasswordProblem) {
        if self.problem.get().is_none() {
            self.problem.set(Some(p));
        }
    }
}

/// An opened archive plus its password status.
pub struct OpenedArchive<'a> {
    pub reader: Box<dyn ArchiveReader + 'a>,
    status: Rc<CryptStatus>,
}

impl OpenedArchive<'_> {
    /// True when the archive has encrypted content.
    pub fn is_encrypted(&self) -> bool {
        self.status.encrypted.get()
    }
    /// Set after a read failed because of the password.
    pub fn password_problem(&self) -> Option<PasswordProblem> {
        self.status.problem.get()
    }
}

/// Open `bytes` like [`open_named`], decrypting with `password` when needed.
pub fn open_named_with_password<'a>(
    bytes: &'a [u8],
    archive_name: &[u8],
    limits: ReaderLimits,
    password: Option<&str>,
) -> Result<OpenedArchive<'a>, OpenCryptError> {
    let status = Rc::new(CryptStatus::default());
    match detect_format(bytes) {
        Detected::Zip => {
            let r2 = Reader2Limits {
                max_entries: limits.max_entries,
                max_entry_size: limits.max_entry_size.min(limits.max_total_size),
                max_total_size: limits.max_total_size,
                max_deflate_blocks: 1 << 20,
            };
            if let Ok(z) = ZipArchive2::open(bytes, r2)
                && z.entries().iter().any(|e| e.is_encrypted())
            {
                status.encrypted.set(true);
                let r = EncZipReader::new(z, password, limits, status.clone())?;
                return Ok(OpenedArchive { reader: Box::new(r), status });
            }
        }
        Detected::SevenZip => {
            let r = EncSevenZReader::new(bytes, limits, password, status.clone())?;
            return Ok(OpenedArchive { reader: Box::new(r), status });
        }
        _ => {}
    }
    let reader = open_named(bytes, archive_name, limits)?;
    Ok(OpenedArchive { reader, status })
}

fn copy_vec(d: &[u8]) -> Result<Vec<u8>, ReaderError> {
    let mut v = Vec::new();
    v.try_reserve_exact(d.len()).map_err(|_| ReaderError::Allocation)?;
    v.extend_from_slice(d);
    Ok(v)
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn dos_to_unix(date: u16, time: u16) -> Option<i64> {
    let t = decode_dos(date, time).ok()?;
    let days = days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day));
    Some(days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second))
}

/// ZIP reader for archives with encrypted entries.
pub struct EncZipReader<'a> {
    zip: ZipArchive2<'a>,
    password: Option<Vec<u8>>,
    entries: Vec<PlannedEntry>,
    max_entry_size: u64,
    status: Rc<CryptStatus>,
}

impl Drop for EncZipReader<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.iter_mut().for_each(|b| *b = 0);
            std::hint::black_box(&p);
        }
    }
}

fn zip_err(status: &CryptStatus, encrypted: bool, e: ZipCryptError) -> ReaderError {
    match e {
        ZipCryptError::PasswordRequired => {
            status.note(PasswordProblem::Required);
            ReaderError::Unsupported
        }
        ZipCryptError::BadPassword | ZipCryptError::AuthFailed => {
            status.note(PasswordProblem::Wrong);
            ReaderError::CrcMismatch
        }
        ZipCryptError::CrcMismatch => {
            if encrypted {
                status.note(PasswordProblem::Wrong);
            }
            ReaderError::CrcMismatch
        }
        ZipCryptError::Truncated => ReaderError::Truncated,
        ZipCryptError::Invalid | ZipCryptError::Random => ReaderError::Invalid,
        ZipCryptError::Unsupported => ReaderError::Unsupported,
        ZipCryptError::LimitExceeded => ReaderError::LimitExceeded,
        ZipCryptError::Allocation => ReaderError::Allocation,
    }
}

impl<'a> EncZipReader<'a> {
    fn new(
        zip: ZipArchive2<'a>,
        password: Option<&str>,
        limits: ReaderLimits,
        status: Rc<CryptStatus>,
    ) -> Result<Self, OpenCryptError> {
        let n = zip.entries().len();
        if n > limits.max_entries {
            return Err(ReaderError::LimitExceeded.into());
        }
        let mut r = EncZipReader {
            zip,
            password: password.map(|p| p.as_bytes().to_vec()),
            entries: Vec::new(),
            max_entry_size: limits.max_entry_size,
            status,
        };
        r.entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut total = 0u64;
        for i in 0..n {
            let e = &r.zip.entries()[i];
            let unix_mode = e.unix_mode();
            let fmt = unix_mode.map(|v| v & S_IFMT);
            let dos_dir = e.external_attributes & 0x10 != 0;
            let kind = if fmt == Some(S_IFLNK) {
                if e.uncompressed_size > MAX_LINK_TARGET {
                    return Err(ReaderError::LimitExceeded.into());
                }
                let target = match read_entry(&r.zip, i, r.password.as_deref(), MAX_LINK_TARGET as usize, 64) {
                    Ok(t) => t,
                    Err(x) => {
                        let mapped = zip_err(&r.status, e.is_encrypted(), x);
                        return Err(match r.status.problem.get() {
                            Some(PasswordProblem::Required) => OpenCryptError::PasswordRequired,
                            Some(PasswordProblem::Wrong) => OpenCryptError::WrongPassword,
                            None => OpenCryptError::Reader(mapped),
                        });
                    }
                };
                EntryKind::Symlink { target }
            } else if e.is_dir() || fmt == Some(S_IFDIR) || (dos_dir && e.uncompressed_size == 0) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let size = if matches!(kind, EntryKind::File) { e.uncompressed_size } else { 0 };
            total = total.checked_add(size).ok_or(ReaderError::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded.into());
            }
            let mode = unix_mode.map(|v| v & 0o7777).filter(|&v| v != 0);
            let mtime = e
                .extended_timestamp
                .and_then(|t| t.mtime)
                .map(i64::from)
                .or_else(|| dos_to_unix(e.dos_date, e.dos_time));
            r.entries.push(PlannedEntry { path: e.name().to_vec(), kind, size, mode, mtime });
        }
        Ok(r)
    }
}

impl ArchiveReader for EncZipReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Zip
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let e = self.zip.entries().get(index).ok_or(ReaderError::OutOfRange)?;
        if e.uncompressed_size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        let max = usize::try_from(self.max_entry_size).unwrap_or(usize::MAX);
        let blocks = usize::try_from(e.uncompressed_size).unwrap_or(usize::MAX).saturating_add(16);
        read_entry(&self.zip, index, self.password.as_deref(), max, blocks)
            .map_err(|x| zip_err(&self.status, e.is_encrypted(), x))
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        let e = self.zip.entries().get(index)?;
        match e.encryption {
            crate::zip_reader2::Encryption::Aes(i) if i.vendor_version == 2 => None,
            _ => Some(e.crc32),
        }
    }
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

/// 7z reader with 7zAES support (all other codecs as in
/// [`crate::archive_open::SevenZReader`]). Anti-items are omitted; the last
/// decoded folder is cached.
pub struct EncSevenZReader<'a> {
    archive: SevenZArchive<'a>,
    decoder: SevenZCryptoDecoder<SevenZCodecs>,
    map: Vec<usize>,
    entries: Vec<PlannedEntry>,
    /// Per folder: has a 7zAES coder.
    folder_encrypted: Vec<bool>,
    max_entry_size: u64,
    cache: RefCell<Option<(usize, Vec<Vec<u8>>)>>,
    status: Rc<CryptStatus>,
}

fn aes_problem(decoder: &SevenZCryptoDecoder<SevenZCodecs>) -> PasswordProblem {
    if decoder.last_error() == Some(SevenZAesCoderError::PasswordRequired) || !decoder.has_password() {
        PasswordProblem::Required
    } else {
        PasswordProblem::Wrong
    }
}

impl<'a> EncSevenZReader<'a> {
    fn new(
        bytes: &'a [u8],
        limits: ReaderLimits,
        password: Option<&str>,
        status: Rc<CryptStatus>,
    ) -> Result<Self, OpenCryptError> {
        let codecs = SevenZCodecs { max_output: limits.max_total_size };
        let decoder = SevenZCryptoDecoder::new(codecs, password, limits.max_total_size).map_err(|e| match e {
            SevenZAesCoderError::Allocation => OpenCryptError::Reader(ReaderError::Allocation),
            _ => OpenCryptError::Reader(ReaderError::LimitExceeded),
        })?;
        let sl = SevenZLimits {
            max_files: limits.max_entries,
            max_unpack_bytes: limits.max_total_size,
            ..SevenZLimits::default()
        };
        let archive = match SevenZArchive::open(bytes, &decoder, sl) {
            Ok(a) => a,
            Err(e) => {
                if decoder.aes_used() && !matches!(e, SevenZReadError::LimitExceeded | SevenZReadError::Allocation) {
                    status.encrypted.set(true);
                    let p = aes_problem(&decoder);
                    status.note(p);
                    return Err(match p {
                        PasswordProblem::Required => OpenCryptError::PasswordRequired,
                        PasswordProblem::Wrong => OpenCryptError::WrongPassword,
                    });
                }
                return Err(OpenCryptError::Reader(e.into()));
            }
        };
        let folder_encrypted: Vec<bool> = archive
            .folders()
            .iter()
            .map(|f| f.coders.iter().any(|c| c.method_id == SEVENZ_AES_METHOD_ID))
            .collect();
        if decoder.aes_used() || folder_encrypted.iter().any(|&b| b) {
            status.encrypted.set(true);
        }
        let n = archive.entries().len();
        let mut r = EncSevenZReader {
            archive,
            decoder,
            map: Vec::new(),
            entries: Vec::new(),
            folder_encrypted,
            max_entry_size: limits.max_entry_size,
            cache: RefCell::new(None),
            status,
        };
        r.map.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        r.entries.try_reserve_exact(n).map_err(|_| ReaderError::Allocation)?;
        let mut total = 0u64;
        let mut links = Vec::new();
        for i in 0..n {
            let e = &r.archive.entries()[i];
            if e.is_anti {
                continue;
            }
            let unix = e.unix_mode();
            let fmt = unix.map(|m| m & S_IFMT);
            let kind = if fmt == Some(S_IFLNK) && !e.is_dir {
                if e.size > MAX_LINK_TARGET {
                    return Err(ReaderError::LimitExceeded.into());
                }
                links.push(r.entries.len());
                EntryKind::Symlink { target: Vec::new() }
            } else if e.is_dir || e.has_dir_attribute() || fmt == Some(S_IFDIR) {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let size = if matches!(kind, EntryKind::File) { e.size } else { 0 };
            total = total.checked_add(size).ok_or(ReaderError::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(ReaderError::LimitExceeded.into());
            }
            let mode = unix.map(|m| m & 0o7777).filter(|&m| m != 0);
            let mtime = e.mtime.map(|ft| filetime_to_unix(ft).0);
            r.entries.push(PlannedEntry { path: e.name.as_bytes().to_vec(), kind, size, mode, mtime });
            r.map.push(i);
        }
        for k in links {
            let data = match r.read(k) {
                Ok(d) => d,
                Err(e) => {
                    return Err(match r.status.problem.get() {
                        Some(PasswordProblem::Required) => OpenCryptError::PasswordRequired,
                        Some(PasswordProblem::Wrong) => OpenCryptError::WrongPassword,
                        None => OpenCryptError::Reader(e),
                    });
                }
            };
            if let Some(PlannedEntry { kind: EntryKind::Symlink { target }, .. }) = r.entries.get_mut(k) {
                *target = data;
            }
        }
        Ok(r)
    }
}

impl ArchiveReader for EncSevenZReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::SevenZ
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let &i = self.map.get(index).ok_or(ReaderError::OutOfRange)?;
        let e = &self.archive.entries()[i];
        if e.size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        let (Some(folder), Some(k)) = (e.folder_index, e.index_in_folder) else {
            return Ok(Vec::new());
        };
        let mut cache = self.cache.borrow_mut();
        if cache.as_ref().is_none_or(|(f, _)| *f != folder) {
            *cache = None;
            let parts = match self.archive.extract_folder(folder, &self.decoder) {
                Ok(p) => p,
                Err(err) => {
                    let limit = matches!(err, SevenZReadError::LimitExceeded | SevenZReadError::Allocation);
                    if self.folder_encrypted.get(folder).copied().unwrap_or(false) && !limit {
                        self.status.note(aes_problem(&self.decoder));
                    }
                    return Err(err.into());
                }
            };
            *cache = Some((folder, parts));
        }
        let parts = &cache.as_ref().ok_or(ReaderError::Invalid)?.1;
        copy_vec(parts.get(k).ok_or(ReaderError::Invalid)?)
    }
    fn crc32(&self, index: usize) -> Option<u32> {
        let &i = self.map.get(index)?;
        self.archive.entries()[i].crc
    }
}
