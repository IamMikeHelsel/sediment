//! El Torito boot catalog parsing (ISO-9660, 2048-byte sectors).
const SECTOR: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToritoError { Truncated, NoBootRecord, BadCatalog, BadChecksum, BadEntry, LimitExceeded }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform { X86, PowerPc, Mac, Efi, Other(u8) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media { NoEmulation, Floppy12, Floppy144, Floppy288, HardDisk, Other(u8) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootImage { pub platform: Platform, pub bootable: bool, pub media: Media, pub load_segment: u16, pub system_type: u8, pub sector_count: u16, pub load_rba: u32 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCatalog { pub catalog_lba: u32, pub platform: Platform, pub id: [u8; 24], pub images: Vec<BootImage> }

impl Platform {
    fn from_u8(v: u8) -> Self {
        match v { 0 => Platform::X86, 1 => Platform::PowerPc, 2 => Platform::Mac, 0xEF => Platform::Efi, _ => Platform::Other(v) }
    }
}
impl Media {
    fn from_u8(v: u8) -> Self {
        match v & 0x0F { 0 => Media::NoEmulation, 1 => Media::Floppy12, 2 => Media::Floppy144, 3 => Media::Floppy288, 4 => Media::HardDisk, m => Media::Other(m) }
    }
}

impl BootImage {
    pub fn byte_len(&self) -> u64 {
        match self.media {
            Media::Floppy12 => 1_228_800,
            Media::Floppy144 => 1_474_560,
            Media::Floppy288 => 2_949_120,
            _ => (self.sector_count as u64) * 512,
        }
    }
}

fn le16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o+1]]) }
fn le32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3]]) }

/// Walk volume descriptors at sectors 16, 17, … (at most 64).
pub fn find_boot_record(iso: &[u8]) -> Result<u32, ToritoError> {
    for i in 0..64 {
        let off = (16 + i) as usize * SECTOR;
        if off + SECTOR > iso.len() { return Err(ToritoError::Truncated); }
        let sec = &iso[off..off+SECTOR];
        if &sec[1..6] != b"CD001" { return Err(ToritoError::NoBootRecord); }
        if sec[255] == 0xFF { return Err(ToritoError::NoBootRecord); }
        if sec[0] == 0 {
            if &sec[7..30] == b"EL TORITO SPECIFICATION" && sec[30..39].iter().all(|&b| b == 0) {
                return Ok(le32(sec, 71));
            }
        }
    }
    Err(ToritoError::NoBootRecord)
}

/// Parse catalog at catalog_lba * 2048.
pub fn parse_catalog(iso: &[u8], catalog_lba: u32, max_images: usize) -> Result<BootCatalog, ToritoError> {
    let cat_off = (catalog_lba as usize).checked_mul(SECTOR).ok_or(ToritoError::Truncated)?;
    if cat_off + 64 > iso.len() { return Err(ToritoError::Truncated); }

    // Validation entry (entry 0): 32 bytes, 16 little-endian u16 words, sum must be 0
    if iso[cat_off] != 1 || iso[cat_off+30] != 0x55 || iso[cat_off+31] != 0xAA { return Err(ToritoError::BadCatalog); }
    let sum: u16 = (cat_off..cat_off+32).step_by(2).fold(0u16, |s, o| s.wrapping_add(u16::from_le_bytes([iso[o], iso[o+1]])));
    if sum != 0 { return Err(ToritoError::BadChecksum); }
    let plat0 = Platform::from_u8(iso[cat_off+1]);
    let id = iso[cat_off+4..cat_off+28].try_into().unwrap();

    let mut images: Vec<BootImage> = Vec::new();
    let mut cur_plat = plat0;

    // Entry 1: initial/default
    let e1_off = cat_off + 32;
    if e1_off + 32 > iso.len() { return Err(ToritoError::Truncated); }
    if iso[e1_off] != 0x88 && iso[e1_off] != 0x00 { return Err(ToritoError::BadEntry); }
    images.push(BootImage { platform: plat0, bootable: iso[e1_off] == 0x88, media: Media::from_u8(iso[e1_off+1]), load_segment: le16(iso, e1_off+2), system_type: iso[e1_off+4], sector_count: le16(iso, e1_off+6), load_rba: le32(iso, e1_off+8) });
    if images.len() > max_images { return Err(ToritoError::LimitExceeded); }

    // Entry 2+: section headers and entries
    let mut entry_idx = 2usize;
    loop {
        let e_off = (entry_idx * 32).checked_add(cat_off).ok_or(ToritoError::Truncated)?;
        if e_off + 32 > iso.len() { return Err(ToritoError::Truncated); }

        if iso[e_off] == 0x90 || iso[e_off] == 0x91 {
            let is_final = iso[e_off] == 0x91;
            cur_plat = Platform::from_u8(iso[e_off+1]);
            let nsec = le16(iso, e_off+2) as usize;
            entry_idx += 1;
            for _ in 0..nsec {
                let s_off = (entry_idx * 32).checked_add(cat_off).ok_or(ToritoError::Truncated)?;
                if s_off + 32 > iso.len() { return Err(ToritoError::Truncated); }
                if iso[s_off] != 0x88 && iso[s_off] != 0x00 { return Err(ToritoError::BadEntry); }
                images.push(BootImage { platform: cur_plat, bootable: iso[s_off] == 0x88, media: Media::from_u8(iso[s_off+1]), load_segment: le16(iso, s_off+2), system_type: iso[s_off+4], sector_count: le16(iso, s_off+6), load_rba: le32(iso, s_off+8) });
                if images.len() > max_images { return Err(ToritoError::LimitExceeded); }
                entry_idx += 1;
                // skip extension records
                loop {
                    let ne_off = (entry_idx * 32).checked_add(cat_off).ok_or(ToritoError::Truncated)?;
                    if ne_off + 32 > iso.len() { break; }
                    if iso[ne_off] != 0x44 { break; }
                    entry_idx += 1;
                }
            }
            if is_final { break; }
            // After non-final header, next must be 0x90/0x91
            let next_off = (entry_idx * 32).checked_add(cat_off).ok_or(ToritoError::Truncated)?;
            if next_off + 32 > iso.len() { return Err(ToritoError::Truncated); }
            if iso[next_off] != 0x90 && iso[next_off] != 0x91 { return Err(ToritoError::BadEntry); }
        } else {
            break;
        }
    }
    Ok(BootCatalog { catalog_lba, platform: plat0, id, images })
}

/// find_boot_record + parse_catalog.
pub fn read_eltorito(iso: &[u8], max_images: usize) -> Result<BootCatalog, ToritoError> {
    let lba = find_boot_record(iso)?;
    parse_catalog(iso, lba, max_images)
}

/// Extract boot image bytes from the ISO.
pub fn boot_image_data(iso: &[u8], img: &BootImage, max_output: usize) -> Result<Vec<u8>, ToritoError> {
    let blen = img.byte_len();
    if blen > max_output as u64 { return Err(ToritoError::LimitExceeded); }
    let start = (img.load_rba as u64).checked_mul(SECTOR as u64).ok_or(ToritoError::Truncated)?;
    let end = start.checked_add(blen).ok_or(ToritoError::Truncated)?;
    let so = start as usize;
    let eo = end as usize;
    if eo > iso.len() { return Err(ToritoError::Truncated); }
    Ok(iso[so..eo].to_vec())
}
