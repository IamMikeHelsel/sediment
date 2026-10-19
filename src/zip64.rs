// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZIP64 end-of-central-directory structures and the ZIP64 extended
//! information extra field, plus a central-directory locator that handles
//! both classic and ZIP64 archives (including > 65535 entries and archives
//! with leading data such as self-extractor stubs).
//!
//! Spec source: PKWARE APPNOTE.TXT 6.3.x sections 4.3.14 (zip64 end of
//! central directory record), 4.3.15 (zip64 end of central directory
//! locator), 4.3.16 (end of central directory record) and 4.5.3 (zip64
//! extended information extra field).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zip64Error {
    /// A structure runs past the end of the input.
    Truncated,
    /// A structure is malformed or inconsistent.
    Invalid,
    /// Well-formed but unsupported (multi-disk archives).
    Unsupported,
    /// A value does not fit the platform or caller limits.
    LimitExceeded,
}

pub const EOCD_SIGNATURE: u32 = 0x0605_4b50;
pub const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
pub const ZIP64_RECORD_SIGNATURE: u32 = 0x0606_4b50;
pub const EOCD_LEN: usize = 22;
pub const ZIP64_LOCATOR_LEN: usize = 20;
/// Fixed part of the zip64 EOCD record (signature + size field + 44 bytes).
pub const ZIP64_RECORD_MIN_LEN: usize = 56;
/// Maximum EOCD comment length plus the EOCD itself: the backward search window.
const EOCD_SEARCH_WINDOW: usize = EOCD_LEN + 0xffff;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Zip64Error> {
    let end = at.checked_add(2).ok_or(Zip64Error::Truncated)?;
    let s = b.get(at..end).ok_or(Zip64Error::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Zip64Error> {
    let end = at.checked_add(4).ok_or(Zip64Error::Truncated)?;
    let s = b.get(at..end).ok_or(Zip64Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Zip64Error> {
    let end = at.checked_add(8).ok_or(Zip64Error::Truncated)?;
    let s = b.get(at..end).ok_or(Zip64Error::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// The classic (16/32-bit) end of central directory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassicEocd<'a> {
    /// Position of the record in the input.
    pub offset: usize,
    pub disk: u16,
    pub cd_disk: u16,
    pub entries_on_disk: u16,
    pub entries_total: u16,
    pub cd_size: u32,
    pub cd_offset: u32,
    pub comment: &'a [u8],
}

/// Parse a classic EOCD at `at`. The comment must end exactly at the end of
/// `bytes`.
pub fn parse_classic_eocd(bytes: &[u8], at: usize) -> Result<ClassicEocd<'_>, Zip64Error> {
    if u32_at(bytes, at)? != EOCD_SIGNATURE {
        return Err(Zip64Error::Invalid);
    }
    let comment_len = u16_at(bytes, at + 20)? as usize;
    let start = at.checked_add(EOCD_LEN).ok_or(Zip64Error::Truncated)?;
    let end = start.checked_add(comment_len).ok_or(Zip64Error::Truncated)?;
    if end > bytes.len() {
        return Err(Zip64Error::Truncated);
    }
    if end != bytes.len() {
        return Err(Zip64Error::Invalid);
    }
    Ok(ClassicEocd {
        offset: at,
        disk: u16_at(bytes, at + 4)?,
        cd_disk: u16_at(bytes, at + 6)?,
        entries_on_disk: u16_at(bytes, at + 8)?,
        entries_total: u16_at(bytes, at + 10)?,
        cd_size: u32_at(bytes, at + 12)?,
        cd_offset: u32_at(bytes, at + 16)?,
        comment: &bytes[start..end],
    })
}

/// Find the classic EOCD by scanning backwards over at most the maximum
/// comment length. The last record whose comment ends exactly at EOF wins.
pub fn find_classic_eocd(bytes: &[u8]) -> Result<ClassicEocd<'_>, Zip64Error> {
    if bytes.len() < EOCD_LEN {
        return Err(Zip64Error::Truncated);
    }
    let last = bytes.len() - EOCD_LEN;
    let first = bytes.len().saturating_sub(EOCD_SEARCH_WINDOW);
    for at in (first..=last).rev() {
        if bytes[at..at + 4] == EOCD_SIGNATURE.to_le_bytes() {
            if let Ok(eocd) = parse_classic_eocd(bytes, at) {
                return Ok(eocd);
            }
        }
    }
    Err(Zip64Error::Invalid)
}

/// ZIP64 end of central directory locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zip64Locator {
    /// Position of the locator in the input.
    pub offset: usize,
    pub record_disk: u32,
    /// Declared offset of the zip64 EOCD record (relative to archive start).
    pub record_offset: u64,
    pub total_disks: u32,
}

/// Parse a ZIP64 EOCD locator at `at`.
pub fn parse_zip64_locator(bytes: &[u8], at: usize) -> Result<Zip64Locator, Zip64Error> {
    if u32_at(bytes, at)? != ZIP64_LOCATOR_SIGNATURE {
        return Err(Zip64Error::Invalid);
    }
    Ok(Zip64Locator {
        offset: at,
        record_disk: u32_at(bytes, at + 4)?,
        record_offset: u64_at(bytes, at + 8)?,
        total_disks: u32_at(bytes, at + 16)?,
    })
}

/// ZIP64 end of central directory record (version 1 layout; the v2 fields
/// used by central-directory encryption are left in `extensible_data`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zip64EndRecord<'a> {
    /// Position of the record in the input.
    pub offset: usize,
    /// "Size of zip64 end of central directory record" (excludes the first 12 bytes).
    pub record_size: u64,
    pub version_made_by: u16,
    pub version_needed: u16,
    pub disk: u32,
    pub cd_disk: u32,
    pub entries_on_disk: u64,
    pub entries_total: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
    pub extensible_data: &'a [u8],
}

impl Zip64EndRecord<'_> {
    /// Total length of the record in bytes.
    pub fn total_len(&self) -> usize {
        // Bounded by the input length at parse time.
        ZIP64_RECORD_MIN_LEN + self.extensible_data.len()
    }
}

/// Parse a ZIP64 EOCD record at `at`.
pub fn parse_zip64_end_record(bytes: &[u8], at: usize) -> Result<Zip64EndRecord<'_>, Zip64Error> {
    if u32_at(bytes, at)? != ZIP64_RECORD_SIGNATURE {
        return Err(Zip64Error::Invalid);
    }
    let record_size = u64_at(bytes, at + 4)?;
    if record_size < 44 {
        return Err(Zip64Error::Invalid);
    }
    let size = usize::try_from(record_size).map_err(|_| Zip64Error::Truncated)?;
    let end = at.checked_add(12).and_then(|v| v.checked_add(size)).ok_or(Zip64Error::Truncated)?;
    if end > bytes.len() {
        return Err(Zip64Error::Truncated);
    }
    Ok(Zip64EndRecord {
        offset: at,
        record_size,
        version_made_by: u16_at(bytes, at + 12)?,
        version_needed: u16_at(bytes, at + 14)?,
        disk: u32_at(bytes, at + 16)?,
        cd_disk: u32_at(bytes, at + 20)?,
        entries_on_disk: u64_at(bytes, at + 24)?,
        entries_total: u64_at(bytes, at + 32)?,
        cd_size: u64_at(bytes, at + 40)?,
        cd_offset: u64_at(bytes, at + 48)?,
        extensible_data: &bytes[at + ZIP64_RECORD_MIN_LEN..end],
    })
}

/// Resolved location of the central directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CentralDirectoryLocation<'a> {
    /// Total number of entries declared.
    pub entries: u64,
    /// Actual start of the central directory in the input.
    pub cd_start: usize,
    /// Size of the central directory in bytes.
    pub cd_size: usize,
    /// Number of bytes preceding the archive (e.g. an SFX stub). Every offset
    /// stored in the archive must be shifted by this amount.
    pub prefix: usize,
    pub eocd: ClassicEocd<'a>,
    pub zip64: Option<(Zip64Locator, Zip64EndRecord<'a>)>,
    pub comment: &'a [u8],
}

fn check_consistent(classic: u64, saturated: u64, zip64: u64) -> Result<(), Zip64Error> {
    if classic != saturated && zip64 < saturated && classic != zip64 {
        return Err(Zip64Error::Invalid);
    }
    Ok(())
}

/// Locate the central directory, using the ZIP64 record when a locator
/// immediately precedes the classic EOCD.
pub fn locate_central_directory(bytes: &[u8]) -> Result<CentralDirectoryLocation<'_>, Zip64Error> {
    let eocd = find_classic_eocd(bytes)?;
    let locator = if eocd.offset >= ZIP64_LOCATOR_LEN
        && u32_at(bytes, eocd.offset - ZIP64_LOCATOR_LEN)? == ZIP64_LOCATOR_SIGNATURE
    {
        Some(parse_zip64_locator(bytes, eocd.offset - ZIP64_LOCATOR_LEN)?)
    } else {
        None
    };

    let (entries, cd_size, cd_offset, cd_end, zip64) = match locator {
        None => {
            if eocd.disk != 0 || eocd.cd_disk != 0 || eocd.entries_on_disk != eocd.entries_total {
                return Err(Zip64Error::Unsupported);
            }
            (eocd.entries_total as u64, eocd.cd_size as u64, eocd.cd_offset as u64, eocd.offset, None)
        }
        Some(loc) => {
            if loc.record_disk != 0 || loc.total_disks > 1 {
                return Err(Zip64Error::Unsupported);
            }
            // The record must sit at its declared offset, or (when the archive
            // has a prefix) directly before the locator with no extensible data.
            let declared = usize::try_from(loc.record_offset).ok();
            let record = match declared.and_then(|d| parse_zip64_end_record(bytes, d).ok()) {
                Some(r) if r.offset.checked_add(r.total_len()) == Some(loc.offset) => r,
                _ => {
                    let at = loc.offset.checked_sub(ZIP64_RECORD_MIN_LEN).ok_or(Zip64Error::Invalid)?;
                    let r = parse_zip64_end_record(bytes, at)?;
                    if r.total_len() != ZIP64_RECORD_MIN_LEN {
                        return Err(Zip64Error::Invalid);
                    }
                    r
                }
            };
            if record.disk != 0 || record.cd_disk != 0 || record.entries_on_disk != record.entries_total {
                return Err(Zip64Error::Unsupported);
            }
            check_consistent(eocd.entries_total as u64, 0xffff, record.entries_total)?;
            check_consistent(eocd.cd_size as u64, 0xffff_ffff, record.cd_size)?;
            check_consistent(eocd.cd_offset as u64, 0xffff_ffff, record.cd_offset)?;
            (record.entries_total, record.cd_size, record.cd_offset, record.offset, Some((loc, record)))
        }
    };

    let cd_size = usize::try_from(cd_size).map_err(|_| Zip64Error::Truncated)?;
    let cd_start = cd_end.checked_sub(cd_size).ok_or(Zip64Error::Invalid)?;
    let prefix = (cd_start as u64).checked_sub(cd_offset).ok_or(Zip64Error::Invalid)?;
    let prefix = usize::try_from(prefix).map_err(|_| Zip64Error::Invalid)?;
    if let Some((loc, record)) = &zip64 {
        // The locator's record offset must agree with the same prefix.
        if loc.record_offset.checked_add(prefix as u64) != Some(record.offset as u64) {
            return Err(Zip64Error::Invalid);
        }
    }
    // An entry count larger than the directory could possibly hold (46 bytes
    // minimum per record) is hostile; reject before callers allocate.
    if entries > (cd_size / 46) as u64 {
        return Err(Zip64Error::Invalid);
    }

    Ok(CentralDirectoryLocation { entries, cd_start, cd_size, prefix, eocd, zip64, comment: eocd.comment })
}

/// Which fields of the ZIP64 extra are present (those whose 16/32-bit header
/// value is saturated, in APPNOTE order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Zip64Needs {
    pub uncompressed_size: bool,
    pub compressed_size: bool,
    pub local_header_offset: bool,
    pub disk_start: bool,
}

impl Zip64Needs {
    /// Needs for a central directory header.
    pub fn central(uncompressed: u32, compressed: u32, local_offset: u32, disk: u16) -> Self {
        Zip64Needs {
            uncompressed_size: uncompressed == 0xffff_ffff,
            compressed_size: compressed == 0xffff_ffff,
            local_header_offset: local_offset == 0xffff_ffff,
            disk_start: disk == 0xffff,
        }
    }

    /// Needs for a local header: APPNOTE 4.5.3 requires both sizes when
    /// either is saturated.
    pub fn local(uncompressed: u32, compressed: u32) -> Self {
        let any = uncompressed == 0xffff_ffff || compressed == 0xffff_ffff;
        Zip64Needs { uncompressed_size: any, compressed_size: any, local_header_offset: false, disk_start: false }
    }

    pub fn any(&self) -> bool {
        self.uncompressed_size || self.compressed_size || self.local_header_offset || self.disk_start
    }
}

/// Values read from a ZIP64 extended information extra field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Zip64Extra {
    pub uncompressed_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub local_header_offset: Option<u64>,
    pub disk_start: Option<u32>,
}

/// Parse a ZIP64 extra payload (without the 4-byte record header), reading
/// only the fields listed in `needs`, in APPNOTE order. Trailing bytes are
/// tolerated (some writers always emit every field).
pub fn parse_zip64_extra(data: &[u8], needs: Zip64Needs) -> Result<Zip64Extra, Zip64Error> {
    let mut pos = 0usize;
    let mut out = Zip64Extra::default();
    if needs.uncompressed_size {
        out.uncompressed_size = Some(u64_at(data, pos)?);
        pos += 8;
    }
    if needs.compressed_size {
        out.compressed_size = Some(u64_at(data, pos)?);
        pos += 8;
    }
    if needs.local_header_offset {
        out.local_header_offset = Some(u64_at(data, pos)?);
        pos += 8;
    }
    if needs.disk_start {
        out.disk_start = Some(u32_at(data, pos)?);
    }
    Ok(out)
}
