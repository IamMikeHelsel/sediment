// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only UDF (Universal Disk Format) reader for images held in memory.
//!
//! Spec sources: ECMA-167 3rd edition ("Volume and File Structure for
//! Write-Once and Rewritable Media", parts 2-4) and the OSTA UDF
//! specification revisions 1.02, 1.50, 2.00 and 2.01. Implemented from the
//! published documents only.
//!
//! Covered:
//! - Volume recognition sequence (`BEA01` / `NSR02` / `NSR03` / `TEA01`) for
//!   detection ([`has_udf_signature`]).
//! - Anchor Volume Descriptor Pointer at sector 256, N-256 or N-1, with the
//!   logical block size probed among 2048, 512, 1024 and 4096 bytes.
//! - Main (falling back to reserve) Volume Descriptor Sequence including
//!   Volume Descriptor Pointer continuations: Primary, Partition and Logical
//!   Volume descriptors (highest sequence number wins), type 1 partition
//!   maps. Type 2 maps (virtual / sparable / metadata partitions) are
//!   recognised and reported as [`UdfError::Unsupported`] when used.
//! - File Set Descriptor, File Entry (tag 261) and Extended File Entry (tag
//!   266, UDF 2.00+), Indirect Entries, short / long / extended allocation
//!   descriptors, Allocation Extent Descriptor chains, data embedded in the
//!   ICB, unrecorded / unallocated (sparse) extents read as zeros.
//! - File Identifier Descriptors with OSTA Compressed Unicode (CS0, 8- and
//!   16-bit) names, symbolic links (ECMA-167 4/14.16 path components),
//!   permissions mapped to Unix modes and modification timestamps.
//!
//! Every descriptor tag is checked (checksum, CRC-CCITT over the CRC length,
//! tag location where it is defined). Walks are bounded by [`UdfLimits`];
//! malformed input returns an error, never a panic.

use std::collections::HashSet;

const SECTOR_PROBE: [usize; 4] = [2048, 512, 1024, 4096];
const MAX_VDS_DESCRIPTORS: usize = 512;
const MAX_VDP_HOPS: usize = 16;
const MAX_INDIRECT_HOPS: usize = 16;
const MAX_PARTITION_MAPS: usize = 64;

const TAG_PVD: u16 = 1;
const TAG_AVDP: u16 = 2;
const TAG_VDP: u16 = 3;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TD: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_AED: u16 = 258;
const TAG_IE: u16 = 259;
const TAG_TE: u16 = 260;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfError {
    /// A structure extends past the end of the image.
    Truncated,
    /// No valid Anchor Volume Descriptor Pointer was found.
    NoAnchor,
    /// A descriptor tag has the wrong identifier, version or location.
    BadTag,
    /// Descriptor tag checksum mismatch.
    BadChecksum,
    /// Descriptor CRC mismatch.
    BadCrc,
    /// A descriptor field is out of range or inconsistent.
    BadDescriptor,
    /// No usable Logical Volume / Partition descriptor, or a partition
    /// reference that names no partition.
    NoPartition,
    /// The File Set Descriptor is missing or invalid.
    NoFileSet,
    /// A valid structure this reader does not interpret.
    Unsupported,
    /// A logical block address lies outside its partition.
    BadAddress,
    /// Allocation descriptors do not cover the information length.
    BadAllocation,
    /// A file identifier is not a usable path component.
    BadName,
    /// A directory is reachable from itself.
    LoopDetected,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdfLimits {
    /// Maximum number of path components of any entry.
    pub max_depth: usize,
    /// Maximum number of entries returned by [`list_entries`].
    pub max_entries: usize,
    /// Maximum size of a single directory's data.
    pub max_dir_bytes: u64,
    /// Maximum number of allocation descriptors per file (including
    /// continuation extents).
    pub max_extents: usize,
    /// Maximum size [`read_file`] materialises.
    pub max_file_size: u64,
}

impl Default for UdfLimits {
    fn default() -> Self {
        UdfLimits {
            max_depth: 64,
            max_entries: 1_000_000,
            max_dir_bytes: 64 << 20,
            max_extents: 1 << 16,
            max_file_size: 1 << 30,
        }
    }
}

/// Address of a logical block: partition reference number (index into the
/// Logical Volume's partition maps) and block number inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdfAddr {
    pub partition: u16,
    pub block: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdfPartitionKind {
    /// Type 1 map: direct mapping onto a Partition Descriptor.
    Physical,
    /// Type 2 map (virtual, sparable, metadata, ...): not supported.
    Type2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdfPartition {
    pub kind: UdfPartitionKind,
    pub number: u16,
    /// First sector of the partition (from the Partition Descriptor).
    pub start: u32,
    /// Length in blocks.
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdfVolume {
    pub block_size: u32,
    /// UDF revision from the Logical Volume domain identifier (e.g. 0x0102,
    /// 0x0201); 0 if not recorded.
    pub revision: u16,
    /// Primary Volume Descriptor volume identifier.
    pub volume_id: String,
    /// Logical Volume Descriptor identifier.
    pub logical_volume_id: String,
    /// File Set Descriptor identifier.
    pub file_set_id: String,
    pub partitions: Vec<UdfPartition>,
    /// ICB of the root directory.
    pub root: UdfAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdfKind {
    File,
    Dir,
    Symlink { target: String },
    /// Devices, FIFOs, sockets and other non-regular types (metadata only).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdfEntry {
    /// Components joined with `/`, no leading `/`.
    pub path: String,
    pub kind: UdfKind,
    /// Information length (0 for directories).
    pub size: u64,
    /// Unix permission bits derived from the UDF permissions field.
    pub mode: u32,
    /// Modification time, seconds since the Unix epoch (UTC).
    pub mtime: Option<i64>,
    /// ICB of the (Extended) File Entry; pass to [`read_file`].
    pub icb: UdfAddr,
}

// ---------------------------------------------------------------- helpers

fn u16le(b: &[u8], at: usize) -> Result<u16, UdfError> {
    let s = b.get(at..at.checked_add(2).ok_or(UdfError::Truncated)?).ok_or(UdfError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], at: usize) -> Result<u32, UdfError> {
    let s = b.get(at..at.checked_add(4).ok_or(UdfError::Truncated)?).ok_or(UdfError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(b: &[u8], at: usize) -> Result<u64, UdfError> {
    let lo = u32le(b, at)? as u64;
    let hi = u32le(b, at + 4)? as u64;
    Ok(lo | (hi << 32))
}

fn slice(b: &[u8], at: usize, len: usize) -> Result<&[u8], UdfError> {
    b.get(at..at.checked_add(len).ok_or(UdfError::Truncated)?).ok_or(UdfError::Truncated)
}

/// CRC-CCITT as used by ECMA-167 7.2.6: polynomial 0x1021, initial value 0,
/// most significant bit first, no final inversion.
pub fn crc_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Verify a descriptor tag (ECMA-167 3/7.2) at the start of `buf`.
/// Returns the tag identifier.
fn check_tag(buf: &[u8], expect: Option<u16>, location: Option<u32>) -> Result<u16, UdfError> {
    let tag = slice(buf, 0, 16)?;
    let sum = tag.iter().enumerate().filter(|&(i, _)| i != 4).fold(0u8, |a, (_, &b)| a.wrapping_add(b));
    if sum != tag[4] {
        return Err(UdfError::BadChecksum);
    }
    let id = u16le(tag, 0)?;
    if let Some(e) = expect
        && id != e
    {
        return Err(UdfError::BadTag);
    }
    let version = u16le(tag, 2)?;
    if version != 2 && version != 3 {
        return Err(UdfError::BadTag);
    }
    let crc_len = u16le(tag, 10)? as usize;
    let body = buf.get(16..16 + crc_len).ok_or(UdfError::BadCrc)?;
    if crc_ccitt(body) != u16le(tag, 8)? {
        return Err(UdfError::BadCrc);
    }
    if let Some(loc) = location
        && u32le(tag, 12)? != loc
    {
        return Err(UdfError::BadTag);
    }
    Ok(id)
}

/// Decode an OSTA CS0 character string (UDF 2.1.1): first byte is the
/// compression ID (8 = one byte per char, 16 = UTF-16BE). An empty input
/// decodes to an empty string.
fn decode_cs0(b: &[u8]) -> Result<String, UdfError> {
    let Some((&comp, rest)) = b.split_first() else {
        return Ok(String::new());
    };
    match comp {
        8 | 254 => Ok(rest.iter().map(|&c| c as char).collect()),
        16 | 255 => {
            if rest.len() % 2 != 0 {
                return Err(UdfError::BadName);
            }
            let units = rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]]));
            Ok(char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect())
        }
        _ => Err(UdfError::BadName),
    }
}

/// Decode a fixed-size dstring field: the last byte holds the used length.
fn decode_dstring(field: &[u8]) -> Result<String, UdfError> {
    let Some((&len, body)) = field.split_last() else {
        return Ok(String::new());
    };
    let used = body.get(..len as usize).ok_or(UdfError::BadDescriptor)?;
    let s = decode_cs0(used).map_err(|_| UdfError::BadDescriptor)?;
    Ok(s.trim_end_matches(['\0', ' ']).to_string())
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

/// ECMA-167 1/7.3 timestamp to Unix seconds (UTC). `None` when invalid.
fn decode_timestamp(t: &[u8]) -> Option<i64> {
    let t = t.get(..12)?;
    let type_tz = u16::from_le_bytes([t[0], t[1]]);
    let year = i16::from_le_bytes([t[2], t[3]]) as i64;
    let (mo, d, h, mi, s) = (t[4] as i64, t[5] as i64, t[6] as i64, t[7] as i64, t[8] as i64);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut secs = days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + s;
    if type_tz >> 12 == 1 {
        let raw = (type_tz & 0x0FFF) as i64;
        let tz = if raw & 0x800 != 0 { raw - 0x1000 } else { raw };
        if tz != -2047 && (-1440..=1440).contains(&tz) {
            secs -= tz * 60;
        }
    }
    Some(secs)
}

fn udf_mode(perms: u32, kind: &UdfKind) -> u32 {
    let bits = (perms & 7) | ((perms >> 5) & 7) << 3 | ((perms >> 10) & 7) << 6;
    let ty = match kind {
        UdfKind::Dir => 0o040000,
        UdfKind::Symlink { .. } => 0o120000,
        _ => 0o100000,
    };
    ty | bits
}

fn valid_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

// ----------------------------------------------------------- detection

/// True when the Volume Recognition Sequence (ECMA-167 2/8.3) starting at
/// byte 32768 contains a `BEA01` ... `NSR02`/`NSR03` structure.
pub fn has_udf_signature(image: &[u8]) -> bool {
    let mut seen_bea = false;
    for i in 0..64usize {
        // Descriptors occupy 2048-byte units regardless of block size.
        let at = 32768 + i * 2048;
        let Some(d) = image.get(at..at + 6) else { return false };
        match &d[1..6] {
            b"BEA01" => seen_bea = true,
            b"NSR02" | b"NSR03" if seen_bea => return true,
            b"TEA01" => return false,
            b"CD001" | b"CDW02" | b"BOOT2" => {}
            _ => return false,
        }
    }
    false
}

// --------------------------------------------------------------- volume

struct Ctx<'a> {
    image: &'a [u8],
    vol: &'a UdfVolume,
}

impl<'a> Ctx<'a> {
    /// `len` bytes starting at logical block `addr` (must stay inside the
    /// partition and the image).
    fn range(&self, addr: UdfAddr, len: u64) -> Result<&'a [u8], UdfError> {
        let part = self.vol.partitions.get(addr.partition as usize).ok_or(UdfError::NoPartition)?;
        if part.kind != UdfPartitionKind::Physical {
            return Err(UdfError::Unsupported);
        }
        let bs = self.vol.block_size as u64;
        let blocks = len.div_ceil(bs).max(1);
        let end_block = (addr.block as u64).checked_add(blocks).ok_or(UdfError::BadAddress)?;
        if end_block > part.length as u64 {
            return Err(UdfError::BadAddress);
        }
        let start = (part.start as u64 + addr.block as u64).checked_mul(bs).ok_or(UdfError::Truncated)?;
        let end = start.checked_add(len).ok_or(UdfError::Truncated)?;
        if end > self.image.len() as u64 {
            return Err(UdfError::Truncated);
        }
        Ok(&self.image[start as usize..end as usize])
    }

    fn block(&self, addr: UdfAddr) -> Result<&'a [u8], UdfError> {
        self.range(addr, self.vol.block_size as u64)
    }
}

fn sector(image: &[u8], bs: usize, n: u64) -> Result<&[u8], UdfError> {
    let start = n.checked_mul(bs as u64).ok_or(UdfError::Truncated)?;
    let end = start.checked_add(bs as u64).ok_or(UdfError::Truncated)?;
    if end > image.len() as u64 {
        return Err(UdfError::Truncated);
    }
    Ok(&image[start as usize..end as usize])
}

fn find_anchor(image: &[u8]) -> Result<(usize, &[u8]), UdfError> {
    for bs in SECTOR_PROBE {
        let n = (image.len() / bs) as u64;
        let mut spots = vec![256u64];
        if n > 257 {
            spots.push(n - 1);
            spots.push(n - 257);
        }
        for s in spots {
            if let Ok(sec) = sector(image, bs, s)
                && check_tag(sec, Some(TAG_AVDP), Some(s as u32)).is_ok()
            {
                return Ok((bs, sec));
            }
        }
    }
    Err(UdfError::NoAnchor)
}

#[derive(Default)]
struct Vds {
    pvd: Option<(u32, String)>,
    lvd: Option<(u32, Vec<u8>)>,
    pds: Vec<(u32, u16, u32, u32)>, // (vdsn, number, start, length)
}

fn read_vds(image: &[u8], bs: usize, extent: (u32, u32)) -> Result<Vds, UdfError> {
    let mut vds = Vds::default();
    let (mut len, mut loc) = extent;
    let mut hops = 0usize;
    let mut total = 0usize;
    'seq: loop {
        let count = (len as usize) / bs;
        for i in 0..count {
            total += 1;
            if total > MAX_VDS_DESCRIPTORS {
                return Err(UdfError::LimitExceeded);
            }
            let s = loc as u64 + i as u64;
            let sec = sector(image, bs, s)?;
            let id = check_tag(sec, None, Some(s as u32))?;
            let vdsn = u32le(sec, 16)?;
            match id {
                TAG_PVD => {
                    if vds.pvd.as_ref().is_none_or(|(n, _)| vdsn >= *n) {
                        vds.pvd = Some((vdsn, decode_dstring(slice(sec, 24, 32)?)?));
                    }
                }
                TAG_PD => {
                    let number = u16le(sec, 22)?;
                    let start = u32le(sec, 188)?;
                    let length = u32le(sec, 192)?;
                    if let Some(p) = vds.pds.iter_mut().find(|p| p.1 == number) {
                        if vdsn >= p.0 {
                            *p = (vdsn, number, start, length);
                        }
                    } else {
                        vds.pds.push((vdsn, number, start, length));
                    }
                }
                TAG_LVD => {
                    if vds.lvd.as_ref().is_none_or(|(n, _)| vdsn >= *n) {
                        vds.lvd = Some((vdsn, sec.to_vec()));
                    }
                }
                TAG_VDP => {
                    hops += 1;
                    if hops > MAX_VDP_HOPS {
                        return Err(UdfError::LimitExceeded);
                    }
                    // Next VDS extent (ECMA-167 3/10.3.3).
                    len = u32le(sec, 20)?;
                    loc = u32le(sec, 24)?;
                    continue 'seq;
                }
                TAG_TD => break 'seq,
                // Implementation Use (4), Unallocated Space (7) and others.
                _ => {}
            }
        }
        break;
    }
    Ok(vds)
}

/// Locate and validate the volume structures and the File Set Descriptor.
pub fn open_volume(image: &[u8]) -> Result<UdfVolume, UdfError> {
    let (bs, anchor) = find_anchor(image)?;
    let main = (u32le(anchor, 16)?, u32le(anchor, 20)?);
    let reserve = (u32le(anchor, 24)?, u32le(anchor, 28)?);
    let vds = match read_vds(image, bs, main) {
        Ok(v) if v.lvd.is_some() && !v.pds.is_empty() => v,
        first => match read_vds(image, bs, reserve) {
            Ok(v) if v.lvd.is_some() && !v.pds.is_empty() => v,
            _ => {
                first?;
                return Err(UdfError::NoPartition);
            }
        },
    };
    let (_, lvd) = vds.lvd.as_ref().ok_or(UdfError::NoPartition)?;
    if u32le(lvd, 212)? as usize != bs {
        return Err(UdfError::Unsupported);
    }
    let logical_volume_id = decode_dstring(slice(lvd, 84, 128)?)?;
    let domain = slice(lvd, 216, 32)?;
    let revision = if &domain[1..20] == b"*OSTA UDF Compliant" { u16le(domain, 24)? } else { 0 };
    let map_len = u32le(lvd, 264)? as usize;
    let map_count = u32le(lvd, 268)? as usize;
    if map_count == 0 || map_count > MAX_PARTITION_MAPS {
        return Err(UdfError::NoPartition);
    }
    let maps = lvd.get(440..440usize.checked_add(map_len).ok_or(UdfError::BadDescriptor)?).ok_or(UdfError::BadDescriptor)?;
    let mut partitions = Vec::new();
    let mut pos = 0usize;
    for _ in 0..map_count {
        let ty = *maps.get(pos).ok_or(UdfError::BadDescriptor)?;
        let len = *maps.get(pos + 1).ok_or(UdfError::BadDescriptor)? as usize;
        let map = maps.get(pos..pos + len).ok_or(UdfError::BadDescriptor)?;
        let (kind, number) = match (ty, len) {
            (1, 6) => (UdfPartitionKind::Physical, u16le(map, 4)?),
            (2, 64) => (UdfPartitionKind::Type2, u16le(map, 38)?),
            _ => return Err(UdfError::BadDescriptor),
        };
        let (start, length) = vds
            .pds
            .iter()
            .find(|p| p.1 == number)
            .map(|p| (p.2, p.3))
            .ok_or(UdfError::NoPartition)?;
        partitions.push(UdfPartition { kind, number, start, length });
        pos += len;
    }
    // Logical Volume Contents Use holds the long_ad of the FSD (UDF 2.2.4.4).
    let fsd_addr = UdfAddr { partition: u16le(lvd, 256)?, block: u32le(lvd, 252)? };
    let mut vol = UdfVolume {
        block_size: bs as u32,
        revision,
        volume_id: vds.pvd.map(|p| p.1).unwrap_or_default(),
        logical_volume_id,
        file_set_id: String::new(),
        partitions,
        root: UdfAddr { partition: 0, block: 0 },
    };
    let ctx = Ctx { image, vol: &vol };
    let fsd = ctx.block(fsd_addr).map_err(|e| if e == UdfError::Unsupported { e } else { UdfError::NoFileSet })?;
    check_tag(fsd, Some(TAG_FSD), Some(fsd_addr.block)).map_err(|_| UdfError::NoFileSet)?;
    let file_set_id = decode_dstring(slice(fsd, 304, 32)?)?;
    // Root Directory ICB long_ad at 400 (ECMA-167 4/14.1).
    if u32le(fsd, 400)? & 0x3FFF_FFFF == 0 {
        return Err(UdfError::NoFileSet);
    }
    let root = UdfAddr { partition: u16le(fsd, 408)?, block: u32le(fsd, 404)? };
    vol.file_set_id = file_set_id;
    vol.root = root;
    Ok(vol)
}

// ---------------------------------------------------------- file entries

struct FileEntry<'a> {
    file_type: u8,
    ad_type: u8,
    info_len: u64,
    perms: u32,
    mtime: Option<i64>,
    ads: &'a [u8],
    addr: UdfAddr,
}

#[derive(Debug, Clone, Copy)]
enum Extent {
    Recorded(UdfAddr, u32),
    Zero(u32),
}

fn read_fe<'a>(ctx: &Ctx<'a>, mut addr: UdfAddr) -> Result<FileEntry<'a>, UdfError> {
    for _ in 0..=MAX_INDIRECT_HOPS {
        let blk = ctx.block(addr)?;
        let id = check_tag(blk, None, Some(addr.block))?;
        let (base, info_at, mtime_at) = match id {
            TAG_FE => (176usize, 56usize, 84usize),
            TAG_EFE => (216, 56, 92),
            TAG_IE => {
                // Indirect Entry (ECMA-167 4/14.7): long_ad at 36.
                let len = u32le(blk, 36)? & 0x3FFF_FFFF;
                if len == 0 {
                    return Err(UdfError::BadDescriptor);
                }
                addr = UdfAddr { partition: u16le(blk, 44)?, block: u32le(blk, 40)? };
                continue;
            }
            TAG_TE => return Err(UdfError::BadDescriptor),
            _ => return Err(UdfError::BadTag),
        };
        let strategy = u16le(blk, 20)?;
        if strategy != 4 && strategy != 4096 {
            return Err(UdfError::Unsupported);
        }
        let file_type = *blk.get(27).ok_or(UdfError::Truncated)?;
        let flags = u16le(blk, 34)?;
        let l_ea = u32le(blk, base - 8)? as usize;
        let l_ad = u32le(blk, base - 4)? as usize;
        let ad_start = base.checked_add(l_ea).ok_or(UdfError::BadDescriptor)?;
        let ads = blk.get(ad_start..ad_start.checked_add(l_ad).ok_or(UdfError::BadDescriptor)?).ok_or(UdfError::BadDescriptor)?;
        return Ok(FileEntry {
            file_type,
            ad_type: (flags & 7) as u8,
            info_len: u64le(blk, info_at)?,
            perms: u32le(blk, 44)?,
            mtime: decode_timestamp(slice(blk, mtime_at, 12)?),
            ads,
            addr,
        });
    }
    Err(UdfError::LimitExceeded)
}

fn collect_extents(ctx: &Ctx<'_>, fe: &FileEntry<'_>, limits: &UdfLimits) -> Result<Vec<Extent>, UdfError> {
    let ad_size = match fe.ad_type {
        0 => 8usize,
        1 => 16,
        2 => 20,
        _ => return Err(UdfError::Unsupported),
    };
    let mut out = Vec::new();
    let mut covered = 0u64;
    let mut area = fe.ads;
    let mut steps = 0usize;
    'chain: loop {
        let mut pos = 0usize;
        while pos + ad_size <= area.len() {
            let ad = &area[pos..pos + ad_size];
            pos += ad_size;
            steps += 1;
            if steps > limits.max_extents {
                return Err(UdfError::LimitExceeded);
            }
            let raw = u32le(ad, 0)?;
            let len = raw & 0x3FFF_FFFF;
            let ty = raw >> 30;
            if len == 0 {
                break 'chain;
            }
            let addr = match fe.ad_type {
                0 => UdfAddr { partition: fe.addr.partition, block: u32le(ad, 4)? },
                1 => UdfAddr { partition: u16le(ad, 8)?, block: u32le(ad, 4)? },
                _ => UdfAddr { partition: u16le(ad, 16)?, block: u32le(ad, 12)? },
            };
            if ty == 3 {
                // Continuation: Allocation Extent Descriptor (ECMA-167 4/14.5).
                let blk = ctx.block(addr)?;
                check_tag(blk, Some(TAG_AED), Some(addr.block))?;
                let l_ad = u32le(blk, 20)? as usize;
                area = blk.get(24..24usize.checked_add(l_ad).ok_or(UdfError::BadDescriptor)?).ok_or(UdfError::BadDescriptor)?;
                continue 'chain;
            }
            if covered >= fe.info_len {
                // Extents past the information length (preallocation) are ignored.
                continue;
            }
            covered += len as u64;
            out.push(if ty == 0 { Extent::Recorded(addr, len) } else { Extent::Zero(len) });
        }
        break;
    }
    if covered < fe.info_len {
        return Err(UdfError::BadAllocation);
    }
    Ok(out)
}

fn read_fe_data(ctx: &Ctx<'_>, fe: &FileEntry<'_>, limits: &UdfLimits, max: u64) -> Result<Vec<u8>, UdfError> {
    if fe.info_len > max {
        return Err(UdfError::LimitExceeded);
    }
    let want = usize::try_from(fe.info_len).map_err(|_| UdfError::LimitExceeded)?;
    if fe.ad_type == 3 {
        return fe.ads.get(..want).map(<[u8]>::to_vec).ok_or(UdfError::BadAllocation);
    }
    let extents = collect_extents(ctx, fe, limits)?;
    let mut out = Vec::new();
    out.try_reserve_exact(want).map_err(|_| UdfError::Allocation)?;
    for e in extents {
        let remaining = (want - out.len()) as u64;
        match e {
            Extent::Recorded(addr, len) => {
                let n = remaining.min(len as u64);
                out.extend_from_slice(ctx.range(addr, n)?);
            }
            Extent::Zero(len) => {
                let n = remaining.min(len as u64) as usize;
                out.resize(out.len() + n, 0);
            }
        }
        if out.len() == want {
            break;
        }
    }
    Ok(out)
}

/// Decode an ECMA-167 4/14.16 symbolic link body into a `/`-separated path.
fn decode_symlink(data: &[u8]) -> Result<String, UdfError> {
    let mut parts: Vec<String> = Vec::new();
    let mut absolute = false;
    let mut pos = 0usize;
    while pos < data.len() {
        let ty = data[pos];
        let l_ci = *data.get(pos + 1).ok_or(UdfError::BadDescriptor)? as usize;
        let ci = data.get(pos + 4..pos + 4 + l_ci).ok_or(UdfError::BadDescriptor)?;
        match ty {
            1 | 2 => {
                parts.clear();
                absolute = true;
            }
            3 => parts.push("..".into()),
            4 => parts.push(".".into()),
            5 => {
                let name = decode_cs0(ci)?;
                if !valid_component(&name) {
                    return Err(UdfError::BadName);
                }
                parts.push(name);
            }
            _ => return Err(UdfError::BadDescriptor),
        }
        pos += 4 + l_ci;
    }
    let joined = parts.join("/");
    Ok(if absolute { format!("/{joined}") } else { joined })
}

// ------------------------------------------------------------ directory

struct Walk<'a, 'b> {
    ctx: &'b Ctx<'a>,
    limits: &'b UdfLimits,
    seen: HashSet<UdfAddr>,
    out: Vec<UdfEntry>,
}

impl Walk<'_, '_> {
    fn dir(&mut self, fe: &FileEntry<'_>, prefix: &str, depth: usize) -> Result<(), UdfError> {
        let data = read_fe_data(self.ctx, fe, self.limits, self.limits.max_dir_bytes)?;
        let mut pos = 0usize;
        while pos < data.len() {
            let fid = &data[pos..];
            check_tag(fid, Some(TAG_FID), None)?;
            let chars = *fid.get(18).ok_or(UdfError::Truncated)?;
            let l_fi = *fid.get(19).ok_or(UdfError::Truncated)? as usize;
            let l_iu = u16le(fid, 36)? as usize;
            let body = 38 + l_iu + l_fi;
            if body > fid.len() {
                return Err(UdfError::BadDescriptor);
            }
            pos += body.next_multiple_of(4).min(fid.len());
            if chars & 0x0C != 0 {
                continue; // deleted (bit 2) or parent (bit 3)
            }
            let name = decode_cs0(&fid[38 + l_iu..body])?;
            if !valid_component(&name) {
                return Err(UdfError::BadName);
            }
            if depth + 1 > self.limits.max_depth {
                return Err(UdfError::LimitExceeded);
            }
            if self.out.len() >= self.limits.max_entries {
                return Err(UdfError::LimitExceeded);
            }
            let icb_len = u32le(fid, 20)? & 0x3FFF_FFFF;
            if icb_len == 0 {
                return Err(UdfError::BadDescriptor);
            }
            let icb = UdfAddr { partition: u16le(fid, 28)?, block: u32le(fid, 24)? };
            let child = read_fe(self.ctx, icb)?;
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let kind = match child.file_type {
                4 => UdfKind::Dir,
                5 | 0 => UdfKind::File,
                12 => {
                    let raw = read_fe_data(self.ctx, &child, self.limits, 1 << 16)?;
                    UdfKind::Symlink { target: decode_symlink(&raw)? }
                }
                _ => UdfKind::Other,
            };
            let is_dir = kind == UdfKind::Dir;
            if is_dir && (chars & 0x02) == 0 {
                return Err(UdfError::BadDescriptor);
            }
            self.out.try_reserve(1).map_err(|_| UdfError::Allocation)?;
            self.out.push(UdfEntry {
                path: path.clone(),
                size: if matches!(kind, UdfKind::File | UdfKind::Other) { child.info_len } else { 0 },
                mode: udf_mode(child.perms, &kind),
                mtime: child.mtime,
                icb: child.addr,
                kind,
            });
            if is_dir {
                if !self.seen.insert(child.addr) {
                    return Err(UdfError::LoopDetected);
                }
                self.dir(&child, &path, depth + 1)?;
            }
        }
        Ok(())
    }
}

/// List every file, directory and symlink of the file set in pre-order
/// (on-disk File Identifier order), skipping deleted and parent entries.
pub fn list_entries(image: &[u8], vol: &UdfVolume, limits: &UdfLimits) -> Result<Vec<UdfEntry>, UdfError> {
    let ctx = Ctx { image, vol };
    let root = read_fe(&ctx, vol.root)?;
    if root.file_type != 4 {
        return Err(UdfError::NoFileSet);
    }
    let mut walk = Walk { ctx: &ctx, limits, seen: HashSet::new(), out: Vec::new() };
    walk.seen.insert(root.addr);
    walk.dir(&root, "", 0)?;
    Ok(walk.out)
}

/// Contents of the file whose ICB is `icb` (from [`UdfEntry::icb`]).
/// Unrecorded or unallocated extents read as zeros.
pub fn read_file(image: &[u8], vol: &UdfVolume, icb: UdfAddr, limits: &UdfLimits) -> Result<Vec<u8>, UdfError> {
    let ctx = Ctx { image, vol };
    let fe = read_fe(&ctx, icb)?;
    if fe.file_type == 4 {
        return Ok(Vec::new());
    }
    read_fe_data(&ctx, &fe, limits, limits.max_file_size)
}
