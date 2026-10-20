//! VMware Virtual Disk Format 1.1 — hosted sparse extent header, grain directory, grain table mapping.
//! All integers are little-endian; header offsets are in 512-byte sectors.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    BadHeader,
    Compressed,
    BadGrainSize,
    BadGrainTable,
    LimitExceeded,
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmdkHeader {
    pub version: u32,
    pub flags: u32,
    pub capacity: u64,
    pub grain_size: u64,
    pub descriptor_offset: u64,
    pub descriptor_size: u64,
    pub num_gtes_per_gt: u32,
    pub rgd_offset: u64,
    pub gd_offset: u64,
    pub overhead: u64,
    pub unclean_shutdown: bool,
    pub compress_algorithm: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkMapping {
    Data(u64),
    Zero,
    Unallocated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkImage {
    pub header: VmdkHeader,
    pub gd: Vec<u32>,
}

pub const VMDK_MAGIC: &[u8; 4] = b"KDMV";
pub const FLAG_ZEROED_GTE: u32 = 1 << 2;
pub const FLAG_COMPRESSED: u32 = 1 << 16;

fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn sector_offset(s: u64) -> Option<usize> {
    let b = s.checked_mul(512)?;
    usize::try_from(b).ok()
}

pub fn parse_header(bytes: &[u8]) -> Result<VmdkHeader, VmdkError> {
    if bytes.len() < 512 {
        return Err(VmdkError::Truncated);
    }
    if &bytes[0..4] != VMDK_MAGIC {
        return Err(VmdkError::BadMagic);
    }
    let version = u32_le(bytes, 4);
    if version < 1 || version > 3 {
        return Err(VmdkError::UnsupportedVersion);
    }
    let flags = u32_le(bytes, 8);
    if flags & FLAG_COMPRESSED != 0 {
        return Err(VmdkError::Compressed);
    }
    let compress_algorithm = u16::from_le_bytes(bytes[77..79].try_into().unwrap());
    if compress_algorithm != 0 {
        return Err(VmdkError::Compressed);
    }
    let capacity = u64_le(bytes, 12);
    let grain_size = u64_le(bytes, 20);
    if grain_size < 8 || grain_size > 65536 || grain_size & (grain_size - 1) != 0 {
        return Err(VmdkError::BadGrainSize);
    }
    let descriptor_offset = u64_le(bytes, 28);
    let descriptor_size = u64_le(bytes, 36);
    let num_gtes_per_gt = u32_le(bytes, 44);
    if num_gtes_per_gt != 512 {
        return Err(VmdkError::BadHeader);
    }
    let rgd_offset = u64_le(bytes, 48);
    let gd_offset = u64_le(bytes, 56);
    if gd_offset == 0 || gd_offset == u64::MAX {
        return Err(VmdkError::BadHeader);
    }
    let overhead = u64_le(bytes, 64);
    let unclean_shutdown = bytes[72] != 0;
    Ok(VmdkHeader {
        version,
        flags,
        capacity,
        grain_size,
        descriptor_offset,
        descriptor_size,
        num_gtes_per_gt,
        rgd_offset,
        gd_offset,
        overhead,
        unclean_shutdown,
        compress_algorithm,
    })
}

pub fn descriptor<'a>(image: &'a [u8], header: &VmdkHeader) -> Result<&'a [u8], VmdkError> {
    if header.descriptor_offset == 0 {
        return Ok(&[]);
    }
    let off = sector_offset(header.descriptor_offset).ok_or(VmdkError::Truncated)?;
    let sz = (header.descriptor_size as usize) * 512;
    let end = off.checked_add(sz).ok_or(VmdkError::Truncated)?;
    if end > image.len() {
        return Err(VmdkError::Truncated);
    }
    let slice = &image[off..end];
    if let Some(nul) = slice.iter().position(|&b| b == 0) {
        Ok(&slice[..nul])
    } else {
        Ok(slice)
    }
}

pub fn open_vmdk(image: &[u8], max_gd_entries: u32) -> Result<VmdkImage, VmdkError> {
    let header = parse_header(image)?;
    let gb_sectors = header.grain_size;
    // number of grains = ceil(capacity / grain_size)
    let num_grains = if header.capacity % gb_sectors == 0 {
        header.capacity / gb_sectors
    } else {
        header.capacity / gb_sectors + 1
    };
    // number of gd entries = ceil(num_grains / 512)
    let num_gdes: u64 = if num_grains % 512 == 0 {
        num_grains / 512
    } else {
        num_grains / 512 + 1
    };
    if num_gdes > max_gd_entries as u64 {
        return Err(VmdkError::LimitExceeded);
    }
    let num_gdes_u32 = num_gdes as u32;
    // read gd entries from sector gd_offset
    let gd_off = sector_offset(header.gd_offset).ok_or(VmdkError::Truncated)?;
    let gd_end = gd_off.checked_add((num_gdes_u32 as usize) * 4).ok_or(VmdkError::Truncated)?;
    if gd_end > image.len() {
        return Err(VmdkError::Truncated);
    }
    let mut gd = Vec::with_capacity(num_gdes_u32 as usize);
    for i in 0..num_gdes_u32 {
        let pos = gd_off + (i as usize) * 4;
        gd.push(u32::from_le_bytes(image[pos..pos + 4].try_into().unwrap()));
    }
    Ok(VmdkImage { header, gd })
}

impl VmdkImage {
    pub fn disk_size(&self) -> u64 {
        self.header.capacity.saturating_mul(512)
    }

    pub fn map_offset(&self, image: &[u8], virtual_offset: u64) -> Result<VmdkMapping, VmdkError> {
        let disk = self.disk_size();
        if virtual_offset >= disk {
            return Err(VmdkError::OutOfRange);
        }
        let gb = self.header.grain_size * 512;
        let grain = virtual_offset / gb;
        let gde_idx = grain / 512;
        let gde = self.gd[gde_idx as usize];
        if gde == 0 {
            return Ok(VmdkMapping::Unallocated);
        }
        let gte_off = (gde as usize) * 512 + ((grain % 512) as usize) * 4;
        let gte_end = gte_off + 4;
        if gte_end > image.len() {
            return Err(VmdkError::Truncated);
        }
        let gte = u32::from_le_bytes(image[gte_off..gte_end].try_into().unwrap());
        if gte == 0 {
            Ok(VmdkMapping::Unallocated)
        } else if self.header.flags & FLAG_ZEROED_GTE != 0 && gte == 1 {
            Ok(VmdkMapping::Zero)
        } else {
            let sector = gte as u64 * 512 + (virtual_offset % gb);
            Ok(VmdkMapping::Data(sector))
        }
    }

    pub fn read_at(&self, image: &[u8], offset: u64, len: usize) -> Result<Vec<u8>, VmdkError> {
        let disk = self.disk_size();
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len as u64).ok_or(VmdkError::OutOfRange)?;
        if end > disk {
            return Err(VmdkError::OutOfRange);
        }
        let gb = self.header.grain_size * 512;
        let mut result = Vec::with_capacity(len);
        let mut cur = offset;
        while cur < end {
            let grain_start = (cur / gb) * gb;
            let grain_end = grain_start + gb;
            let piece_end = if grain_end < end { grain_end } else { end };
            let piece_len = (piece_end - cur) as usize;
            match self.map_offset(image, cur)? {
                VmdkMapping::Zero | VmdkMapping::Unallocated => {
                    result.extend_from_slice(&vec![0u8; piece_len]);
                }
                VmdkMapping::Data(file_off) => {
                    let file_end = file_off.checked_add(piece_len as u64).ok_or(VmdkError::Truncated)?;
                    let file_end_usize = usize::try_from(file_end).map_err(|_| VmdkError::Truncated)?;
                    if file_end_usize > image.len() {
                        return Err(VmdkError::Truncated);
                    }
                    result.extend_from_slice(&image[file_off as usize..file_end_usize]);
                }
            }
            cur = piece_end;
        }
        Ok(result)
    }
}
