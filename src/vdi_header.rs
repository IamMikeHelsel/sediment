//! VirtualBox VDI disk image header, block map and virtual offset mapping.
//! Implements the VDI format as documented in the VirtualBox SDK / VDICore.h.
//! All integers are little-endian. std only, no unsafe, no allocation before limits pass.

use std::convert::Infallible;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdiError {
    Truncated,
    BadSignature,
    UnsupportedVersion,
    BadHeader,
    UnsupportedImageType,
    BadBlockSize,
    BadBlockMap,
    LimitExceeded,
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdiImageType {
    Dynamic = 1,
    Fixed = 2,
    Undo = 3,
    Differencing = 4,
}

impl VdiImageType {
    fn from_u32(v: u32) -> Option<VdiImageType> {
        match v {
            1 => Some(VdiImageType::Dynamic),
            2 => Some(VdiImageType::Fixed),
            3 => Some(VdiImageType::Undo),
            4 => Some(VdiImageType::Differencing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdiHeader {
    pub version: u32,
    pub header_size: u32,
    pub image_type: VdiImageType,
    pub image_flags: u32,
    pub description: Vec<u8>,
    pub offset_bmap: u32,
    pub offset_data: u32,
    pub sector_size: u32,
    pub disk_size: u64,
    pub block_size: u32,
    pub block_extra: u32,
    pub blocks_in_image: u32,
    pub blocks_allocated: u32,
    pub uuid_image: [u8; 16],
    pub uuid_parent: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdiMapping {
    Data(u64),
    Zero,
    Unallocated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdiImage {
    pub header: VdiHeader,
    pub bmap: Vec<u32>,
}

pub const VDI_SIGNATURE: u32 = 0xBEDA_107F;
pub const VDI_UNALLOCATED: u32 = 0xFFFF_FFFF;
pub const VDI_ZERO: u32 = 0xFFFF_FFFE;

fn le_u32(b: &[u8], off: usize) -> u32 {
    let [a, b, c, d] = b[off..off + 4] else { return 0 };
    u32::from_le_bytes([a, b, c, d])
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    let [a, b, c, d, e, f, g, h] = b[off..off + 8] else { return 0 };
    u64::from_le_bytes([a, b, c, d, e, f, g, h])
}

/// Parse the VDI header from the first bytes of a disk image.
pub fn parse_header(bytes: &[u8]) -> Result<VdiHeader, VdiError> {
    // 1. Truncated check
    if bytes.len() < 0x1C8 {
        return Err(VdiError::Truncated);
    }

    // 2. Signature
    let sig = le_u32(bytes, 0x40);
    if sig != VDI_SIGNATURE {
        return Err(VdiError::BadSignature);
    }

    // 3. Version
    let version = le_u32(bytes, 0x44);
    if version >> 16 != 1 {
        return Err(VdiError::UnsupportedVersion);
    }

    // 4. Header size
    let header_size = le_u32(bytes, 0x48);
    if header_size < 0x180 {
        return Err(VdiError::BadHeader);
    }

    // 5. Image type
    let image_type_raw = le_u32(bytes, 0x4C);
    let image_type = VdiImageType::from_u32(image_type_raw).ok_or(VdiError::UnsupportedImageType)?;

    // 6. sector_size check
    let sector_size = le_u32(bytes, 0x168);
    if sector_size != 512 {
        return Err(VdiError::BadHeader);
    }

    // 7. block_size: power of two and >= 512
    let block_size = le_u32(bytes, 0x178);
    if block_size < 512 || block_size & (block_size - 1) != 0 {
        return Err(VdiError::BadBlockSize);
    }

    // 8. block_extra, blocks_in_image, blocks_allocated
    let block_extra = le_u32(bytes, 0x17C);
    let blocks_in_image = le_u32(bytes, 0x180);
    let blocks_allocated = le_u32(bytes, 0x184);

    // disk_size
    let disk_size = le_u64(bytes, 0x170);

    // Check: disk_size > blocks_in_image * block_size
    if blocks_in_image > 0
        && disk_size > blocks_in_image as u64 * block_size as u64
    {
        return Err(VdiError::BadHeader);
    }
    if blocks_allocated > blocks_in_image {
        return Err(VdiError::BadHeader);
    }

    // image_flags
    let image_flags = le_u32(bytes, 0x50);

    // description: 256 bytes at 0x54, up to first NUL
    let desc_start = 0x54;
    let desc_end = desc_start + 256;
    let desc_bytes = &bytes[desc_start..desc_end.min(bytes.len())];
    let desc_len = desc_bytes.iter().position(|&b| b == 0).unwrap_or(desc_bytes.len());
    let description: Vec<u8> = desc_bytes[..desc_len].to_vec();

    // offset_bmap, offset_data
    let offset_bmap = le_u32(bytes, 0x154);
    let offset_data = le_u32(bytes, 0x158);

    // uuid_image [0x188..0x198], uuid_parent [0x1B8..0x1C8]
    let mut uuid_image = [0u8; 16];
    let mut uuid_parent = [0u8; 16];
    uuid_image.copy_from_slice(&bytes[0x188..0x198]);
    uuid_parent.copy_from_slice(&bytes[0x1B8..0x1C8]);

    Ok(VdiHeader {
        version,
        header_size,
        image_type,
        image_flags,
        description,
        offset_bmap,
        offset_data,
        sector_size,
        disk_size,
        block_size,
        block_extra,
        blocks_in_image,
        blocks_allocated,
        uuid_image,
        uuid_parent,
    })
}

/// Open a VDI image, parsing header and block map.
pub fn open_vdi(image: &[u8], max_blocks: u32) -> Result<VdiImage, VdiError> {
    let header = parse_header(image)?;

    if header.blocks_in_image > max_blocks {
        return Err(VdiError::LimitExceeded);
    }

    let blocks_in_image = header.blocks_in_image;
    let offset_bmap = header.offset_bmap as u64;
    let bmap_size = (blocks_in_image as u64) * 4;

    // Block map must fit inside image
    if offset_bmap.checked_add(bmap_size).map(|end| end as usize <= image.len()).unwrap_or(false) == false {
        return Err(VdiError::Truncated);
    }

    let bmap_start = offset_bmap as usize;
    let mut bmap = Vec::with_capacity(blocks_in_image as usize);
    for i in 0..blocks_in_image {
        let entry_off = bmap_start + (i as usize) * 4;
        let entry = u32::from_le_bytes(
            image[entry_off..entry_off + 4].try_into().unwrap()
        );
        // Entry must be VDI_UNALLOCATED, VDI_ZERO, or < blocks_allocated
        if entry != VDI_UNALLOCATED && entry != VDI_ZERO && entry >= header.blocks_allocated {
            return Err(VdiError::BadBlockMap);
        }
        bmap.push(entry);
    }

    Ok(VdiImage { header, bmap })
}

impl VdiImage {
    /// Map a virtual offset to a physical location.
    pub fn map_offset(&self, virtual_offset: u64) -> Result<VdiMapping, VdiError> {
        if virtual_offset >= self.header.disk_size {
            return Err(VdiError::OutOfRange);
        }
        let bs = self.header.block_size as u64;
        let block_idx = virtual_offset / bs;
        let entry = self.bmap[block_idx as usize];
        if entry == VDI_UNALLOCATED {
            return Ok(VdiMapping::Unallocated);
        }
        if entry == VDI_ZERO {
            return Ok(VdiMapping::Zero);
        }
        let offset_data = self.header.offset_data as u64;
        let block_extra = self.header.block_extra as u64;
        let physical = offset_data
            + entry as u64 * (bs + block_extra)
            + block_extra
            + (virtual_offset % bs);
        Ok(VdiMapping::Data(physical))
    }

    /// Read bytes from the virtual disk at the given offset.
    pub fn read_at(&self, image: &[u8], offset: u64, len: usize) -> Result<Vec<u8>, VdiError> {
        // Check overflow and range before allocating
        let end = offset.checked_add(len as u64).ok_or(VdiError::OutOfRange)?;
        if end > self.header.disk_size {
            return Err(VdiError::OutOfRange);
        }
        // len==0 at disk_size is ok
        if len == 0 {
            return Ok(Vec::new());
        }

        let bs = self.header.block_size as u64;
        let mut result = Vec::with_capacity(len);
        let mut cur = offset;
        while cur < end {
            let block_start = (cur / bs) * bs;
            let block_end = block_start + bs;
            let piece_end = if block_end < end { block_end } else { end };
            let piece_len = (piece_end - cur) as usize;
            let block_idx = (cur / bs) as usize;
            let entry = self.bmap[block_idx];

            if entry == VDI_UNALLOCATED || entry == VDI_ZERO {
                result.extend_from_slice(&vec![0u8; piece_len]);
            } else {
                let offset_data = self.header.offset_data as u64;
                let block_extra = self.header.block_extra as u64;
                let phys = offset_data
                    + entry as u64 * (bs + block_extra)
                    + block_extra
                    + (cur - block_start);
                let phys_end = phys + piece_len as u64;
                // Check that the physical range is within image
                if phys_end as usize > image.len() || phys as usize > image.len() {
                    return Err(VdiError::Truncated);
                }
                result.extend_from_slice(&image[phys as usize..phys_end as usize]);
            }
            cur = piece_end;
        }
        Ok(result)
    }
}
