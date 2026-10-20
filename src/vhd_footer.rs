/// Microsoft Virtual Hard Disk (VHD) Image Format Specification v1.0
/// Footer, Dynamic Header, Block Allocation Table, and virtual offset mapping.
/// All integers are big-endian. No unsafe, no allocation before limits pass.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdError {
    Truncated,
    BadCookie,
    BadChecksum,
    UnsupportedVersion,
    UnsupportedDiskType,
    BadDynamicHeader,
    BadBlockSize,
    LimitExceeded,
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdDiskType {
    Fixed,
    Dynamic,
    Differencing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdFooter {
    pub features: u32,
    pub version: u32,
    pub data_offset: u64,
    pub timestamp: u32,
    pub creator_app: [u8; 4],
    pub creator_version: u32,
    pub creator_os: [u8; 4],
    pub original_size: u64,
    pub current_size: u64,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    pub disk_type: VhdDiskType,
    pub checksum: u32,
    pub unique_id: [u8; 16],
    pub saved_state: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdDynamicHeader {
    pub table_offset: u64,
    pub header_version: u32,
    pub max_table_entries: u32,
    pub block_size: u32,
    pub checksum: u32,
    pub parent_unique_id: [u8; 16],
    pub parent_timestamp: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdMapping {
    Data(u64),
    Zero,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdImage {
    pub footer: VhdFooter,
    pub dynamic: Option<VhdDynamicHeader>,
    pub bat: Vec<u32>,
}

/// Compute VHD checksum: sum of all bytes except the 4 at checksum_offset, then bitwise NOT.
pub fn vhd_checksum(bytes: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u32 = 0;
    let end = bytes.len();
    let co_end = checksum_offset.saturating_add(4);
    let mut i = 0;
    while i < end {
        if i >= checksum_offset && i < co_end {
            i += 1;
            continue;
        }
        sum = sum.wrapping_add(bytes[i] as u32);
        i += 1;
    }
    !sum
}

fn parse_be_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn parse_be_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3],
        bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7],
    ])
}

pub fn parse_footer(bytes: &[u8]) -> Result<VhdFooter, VhdError> {
    if bytes.len() < 512 {
        return Err(VhdError::Truncated);
    }
    let footer = &bytes[..512];
    if &footer[0..8] != b"conectix" {
        return Err(VhdError::BadCookie);
    }
    let features = parse_be_u32(footer, 8);
    let version = parse_be_u32(footer, 12);
    let data_offset = parse_be_u64(footer, 16);
    let timestamp = parse_be_u32(footer, 24);
    let mut creator_app = [0u8; 4];
    creator_app.copy_from_slice(&footer[28..32]);
    let creator_version = parse_be_u32(footer, 32);
    let mut creator_os = [0u8; 4];
    creator_os.copy_from_slice(&footer[36..40]);
    let original_size = parse_be_u64(footer, 40);
    let current_size = parse_be_u64(footer, 48);
    let cylinders = u16::from_be_bytes([footer[56], footer[57]]);
    let heads = footer[58];
    let sectors_per_track = footer[59];
    let disk_type_raw = parse_be_u32(footer, 60);
    let checksum = parse_be_u32(footer, 64);
    let mut unique_id = [0u8; 16];
    unique_id.copy_from_slice(&footer[68..84]);
    let saved_state = footer[84];

    if vhd_checksum(footer, 64) != checksum {
        return Err(VhdError::BadChecksum);
    }
    if version >> 16 != 1 {
        return Err(VhdError::UnsupportedVersion);
    }
    let disk_type = match disk_type_raw {
        2 => VhdDiskType::Fixed,
        3 => VhdDiskType::Dynamic,
        4 => VhdDiskType::Differencing,
        _ => return Err(VhdError::UnsupportedDiskType),
    };

    Ok(VhdFooter {
        features, version, data_offset, timestamp, creator_app, creator_version,
        creator_os, original_size, current_size, cylinders, heads, sectors_per_track,
        disk_type, checksum, unique_id, saved_state,
    })
}

pub fn parse_dynamic_header(bytes: &[u8]) -> Result<VhdDynamicHeader, VhdError> {
    if bytes.len() < 1024 {
        return Err(VhdError::Truncated);
    }
    if &bytes[0..8] != b"cxsparse" {
        return Err(VhdError::BadDynamicHeader);
    }
    let _data_offset = parse_be_u64(bytes, 8);
    let table_offset = parse_be_u64(bytes, 16);
    let header_version = parse_be_u32(bytes, 24);
    let max_table_entries = parse_be_u32(bytes, 28);
    let block_size = parse_be_u32(bytes, 32);
    let checksum = parse_be_u32(bytes, 36);

    if vhd_checksum(bytes, 36) != checksum {
        return Err(VhdError::BadChecksum);
    }
    if header_version != 0x0001_0000 {
        return Err(VhdError::UnsupportedVersion);
    }
    if block_size < 512 || block_size == 0 || (block_size & (block_size - 1)) != 0 {
        return Err(VhdError::BadBlockSize);
    }

    let mut parent_unique_id = [0u8; 16];
    parent_unique_id.copy_from_slice(&bytes[40..56]);
    let parent_timestamp = parse_be_u32(bytes, 56);

    Ok(VhdDynamicHeader {
        table_offset, header_version, max_table_entries, block_size, checksum,
        parent_unique_id, parent_timestamp,
    })
}

fn round_up_512(val: u64) -> u64 {
    (val + 511) & !511
}

pub fn open_vhd(image: &[u8], max_bat_entries: u32) -> Result<VhdImage, VhdError> {
    if image.len() < 512 {
        return Err(VhdError::Truncated);
    }
    let footer = parse_footer(&image[image.len() - 512..])?;

    match footer.disk_type {
        VhdDiskType::Fixed => {
            if footer.current_size > (image.len() as u64).saturating_sub(512) {
                return Err(VhdError::Truncated);
            }
            Ok(VhdImage {
                footer,
                dynamic: None,
                bat: Vec::new(),
            })
        }
        VhdDiskType::Dynamic | VhdDiskType::Differencing => {
            let data_off = footer.data_offset;
            if data_off.saturating_add(1024) > image.len() as u64 {
                return Err(VhdError::Truncated);
            }
            let hdr = parse_dynamic_header(&image[data_off as usize..data_off as usize + 1024])?;

            if hdr.max_table_entries > max_bat_entries {
                return Err(VhdError::LimitExceeded);
            }
            let total_capacity: u64 = hdr.max_table_entries as u64 * hdr.block_size as u64;
            if total_capacity < footer.current_size {
                return Err(VhdError::BadDynamicHeader);
            }

            let bat_off = hdr.table_offset as usize;
            let bat_len = (hdr.max_table_entries as usize) * 4;
            if bat_off.saturating_add(bat_len) > image.len() {
                return Err(VhdError::Truncated);
            }

            let mut bat = Vec::with_capacity(hdr.max_table_entries as usize);
            for i in 0..hdr.max_table_entries {
                let off = bat_off + (i as usize) * 4;
                let entry = u32::from_be_bytes([
                    image[off], image[off + 1], image[off + 2], image[off + 3],
                ]);
                bat.push(entry);
            }

            Ok(VhdImage {
                footer,
                dynamic: Some(hdr),
                bat,
            })
        }
    }
}

impl VhdImage {
    pub fn map_offset(&self, virtual_offset: u64) -> Result<VhdMapping, VhdError> {
        if virtual_offset >= self.footer.current_size {
            return Err(VhdError::OutOfRange);
        }
        match self.footer.disk_type {
            VhdDiskType::Fixed => Ok(VhdMapping::Data(virtual_offset)),
            VhdDiskType::Dynamic | VhdDiskType::Differencing => {
                let hdr = self.dynamic.as_ref().unwrap();
                let bs = hdr.block_size as u64;
                let i = virtual_offset / bs;
                let within = virtual_offset % bs;
                let bat_idx = i as usize;
                if bat_idx >= self.bat.len() {
                    return Err(VhdError::OutOfRange);
                }
                if self.bat[bat_idx] == 0xFFFF_FFFF {
                    return Ok(VhdMapping::Zero);
                }
                let bitmap_size = round_up_512((((bs / 512) as u64) + 7) / 8);
                let offset = self.bat[bat_idx] as u64 * 512 + bitmap_size + within;
                Ok(VhdMapping::Data(offset))
            }
        }
    }

    pub fn read_at(&self, image: &[u8], offset: u64, len: usize) -> Result<Vec<u8>, VhdError> {
        if len == 0 && offset == self.footer.current_size {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len as u64).ok_or(VhdError::OutOfRange)?;
        if end > self.footer.current_size {
            return Err(VhdError::OutOfRange);
        }

        let mut result = Vec::with_capacity(len);
        let mut pos = offset;
        let mut remaining = len;

        while remaining > 0 {
            let mapping = self.map_offset(pos)?;
            match mapping {
                VhdMapping::Zero => {
                    let bs = self.dynamic.as_ref().map(|h| h.block_size as u64).unwrap_or(0);
                    let block_end = if bs > 0 { ((pos / bs) + 1) * bs } else { self.footer.current_size };
                    let to_read = (block_end - pos) as usize;
                    let actual = remaining.min(to_read);
                    result.extend(core::iter::repeat(0u8).take(actual));
                    pos += actual as u64;
                    remaining -= actual;
                }
                VhdMapping::Data(img_off) => {
                    let bs = self.dynamic.as_ref().map(|h| h.block_size as u64).unwrap_or(0);
                    let block_end = if bs > 0 { ((pos / bs) + 1) * bs } else { self.footer.current_size };
                    let to_read = (block_end - pos) as usize;
                    let actual = remaining.min(to_read);
                    let src_start = img_off as usize;
                    let src_end = src_start + actual;
                    if src_end > image.len() {
                        return Err(VhdError::Truncated);
                    }
                    result.extend_from_slice(&image[src_start..src_end]);
                    pos += actual as u64;
                    remaining -= actual;
                }
            }
        }
        Ok(result)
    }
}
