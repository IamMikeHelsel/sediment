//! UEFI PI firmware volume scan, FFS file list + section list + UI names.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FvError { Truncated, BadSignature, BadChecksum, BadHeader, BadFile, BadSection, LimitExceeded }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FvBlock { pub num_blocks: u32, pub length: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FvHeader {
    pub offset: usize, pub fs_guid: [u8; 16], pub length: u64, pub attributes: u32,
    pub header_length: u16, pub ext_header_offset: u16, pub revision: u8,
    pub blocks: Vec<FvBlock>, pub fv_name: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfsFile {
    pub offset: usize, pub name: [u8; 16], pub file_type: u8, pub attributes: u8,
    pub size: u64, pub state: u8, pub data_offset: usize, pub data_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfsSection {
    pub offset: usize, pub section_type: u8, pub size: u32,
    pub data_offset: usize, pub data_len: usize,
}

pub const ERASE_POLARITY: u32 = 0x800;

fn round_up_8(v: usize) -> usize { (v + 7) & !7 }
fn round_up_4(v: usize) -> usize { (v + 3) & !3 }

fn add(a: usize, b: usize) -> Result<usize, FvError> {
    a.checked_add(b).ok_or(FvError::Truncated)
}

pub fn parse_fv_header(data: &[u8], offset: usize) -> Result<FvHeader, FvError> {
    let len = data.len();
    let off56 = add(offset, 56)?;
    if off56 > len { return Err(FvError::Truncated); }
    if data[offset + 40..offset + 44] != *b"_FVH" { return Err(FvError::BadSignature); }
    let attributes = u32::from_le_bytes(data[offset + 44..offset + 48].try_into().unwrap());
    let header_length = u16::from_le_bytes(data[offset + 48..offset + 50].try_into().unwrap());
    let ext_header_offset = u16::from_le_bytes(data[offset + 52..offset + 54].try_into().unwrap());
    let revision = data[offset + 55];
    let length = u64::from_le_bytes(data[offset + 32..offset + 40].try_into().unwrap());
    let fs_guid: [u8; 16] = data[offset + 16..offset + 32].try_into().unwrap();

    if header_length < 64 || header_length & 1 != 0 { return Err(FvError::BadHeader); }
    let hl_end = add(offset, header_length as usize)?;
    if hl_end > len { return Err(FvError::Truncated); }

    let hl_words = header_length as usize / 2;
    let s: u16 = (0..hl_words)
        .map(|i| u16::from_le_bytes(data[offset + i * 2..offset + i * 2 + 2].try_into().unwrap()))
        .fold(0u16, |a, w| a.wrapping_add(w));
    if s != 0 { return Err(FvError::BadChecksum); }

    if revision != 2 || length < header_length as u64 { return Err(FvError::BadHeader); }
    if offset as u64 + length > len as u64 { return Err(FvError::Truncated); }

    let mut blocks: Vec<FvBlock> = Vec::new();
    let mut pos = 56usize;
    loop {
        let pos_end = add(pos, 8)?;
        if pos_end > header_length as usize { return Err(FvError::BadHeader); }
        let nb = u32::from_le_bytes(data[offset + pos..offset + pos + 4].try_into().unwrap());
        let bl = u32::from_le_bytes(data[offset + pos + 4..offset + pos + 8].try_into().unwrap());
        if nb == 0 && bl == 0 { break; }
        blocks.push(FvBlock { num_blocks: nb, length: bl });
        pos += 8;
    }

    let fv_name: Option<[u8; 16]> = if ext_header_offset != 0 {
        let eho = ext_header_offset as usize;
        let eho20 = add(eho, 20)?;
        if eho20 > length as usize { return Err(FvError::BadHeader); }
        let ext_hdr_end = add(offset, eho20)?;
        if ext_hdr_end > len { return Err(FvError::Truncated); }
        let ext_size = u32::from_le_bytes(data[ext_hdr_end - 4..ext_hdr_end].try_into().unwrap()) as usize;
        let fv_name_off = add(offset, eho)?;
        let fv_name_end = add(fv_name_off, 16)?;
        if fv_name_end > ext_hdr_end { return Err(FvError::Truncated); }
        Some(data[fv_name_off..fv_name_end].try_into().unwrap())
    } else {
        None
    };

    Ok(FvHeader {
        offset, fs_guid, length, attributes, header_length,
        ext_header_offset, revision, blocks, fv_name,
    })
}

pub fn find_volumes(data: &[u8], max_volumes: usize) -> Result<Vec<FvHeader>, FvError> {
    let mut result: Vec<FvHeader> = Vec::new();
    let mut limit_hit = false;
    let mut i = 0usize;
    while i + 56 <= data.len() {
        if data[i + 40..i + 44] == *b"_FVH" {
            if let Ok(fv) = parse_fv_header(data, i) {
                let fv_len = fv.length as usize;
                if result.len() >= max_volumes {
                    limit_hit = true;
                    i = round_up_8(add(i, fv_len)?);
                    continue;
                }
                result.push(fv);
                i = round_up_8(add(i, fv_len)?);
                continue;
            }
        }
        i += 8;
    }
    if limit_hit { return Err(FvError::LimitExceeded); }
    Ok(result)
}

pub fn list_files(data: &[u8], fv: &FvHeader, max_files: usize) -> Result<Vec<FfsFile>, FvError> {
    let vol_start = fv.offset;
    let vol_end = add(vol_start, fv.length as usize)?;
    if vol_end > data.len() { return Err(FvError::Truncated); }

    let erase_byte = if fv.attributes & ERASE_POLARITY != 0 { 0xFFu8 } else { 0x00u8 };

    let mut file_off = if fv.ext_header_offset != 0 {
        let eho = fv.ext_header_offset as usize;
        let ext_end = add(add(vol_start, eho)?, 20)?;
        if ext_end > data.len() { return Err(FvError::Truncated); }
        let ext_size = u32::from_le_bytes(data[ext_end - 4..ext_end].try_into().unwrap()) as usize;
        round_up_8(add(eho, ext_size)?)
    } else {
        round_up_8(fv.header_length as usize)
    };

    let vol_size = fv.length as usize;
    let mut files: Vec<FfsFile> = Vec::new();
    loop {
        if file_off + 24 > vol_size { break; }

        let mut all_erase = true;
        for j in 0..24 {
            if data[vol_start + file_off + j] != erase_byte {
                all_erase = false;
                break;
            }
        }
        if all_erase { break; }

        if files.len() >= max_files { return Err(FvError::LimitExceeded); }

        let name: [u8; 16] = data[vol_start + file_off .. vol_start + file_off + 16].try_into().unwrap();
        let file_type = data[vol_start + file_off + 18];
        let attributes = data[vol_start + file_off + 19];
        let state_raw = data[vol_start + file_off + 23];

        let is_large = attributes & 0x01 != 0;
        let header_size = if is_large { 32u64 } else { 24u64 };

        let size: u64 = if is_large {
            u64::from_le_bytes(data[vol_start + file_off + 24..vol_start + file_off + 32].try_into().unwrap())
        } else {
            u64::from_le_bytes([
                data[vol_start + file_off + 20],
                data[vol_start + file_off + 21],
                data[vol_start + file_off + 22],
                0, 0, 0, 0, 0,
            ])
        };

        if size < header_size || size > (vol_size - file_off) as u64 {
            return Err(FvError::BadFile);
        }

        let mut sum: u8 = 0;
        for j in 0..header_size as usize {
            if j != 17 && j != 23 {
                sum = sum.wrapping_add(data[vol_start + file_off + j]);
            }
        }
        if sum != 0 { return Err(FvError::BadFile); }

        let state = if erase_byte == 0xFF { !state_raw } else { state_raw };
        let data_offset = add(add(vol_start, file_off)?, header_size as usize)?;
        let data_len = (size - header_size) as usize;
        let file_abs_offset = add(vol_start, file_off)?;

        files.push(FfsFile {
            offset: file_abs_offset,
            name, file_type, attributes, size, state,
            data_offset, data_len,
        });

        file_off = round_up_8(add(file_off, size as usize)?);
    }
    Ok(files)
}

pub fn list_sections(data: &[u8], file: &FfsFile, max_sections: usize) -> Result<Vec<FfsSection>, FvError> {
    let body_start = file.data_offset;
    let body_end = add(body_start, file.data_len)?;
    if body_end > data.len() { return Err(FvError::Truncated); }

    let mut sections: Vec<FfsSection> = Vec::new();
    let mut o = 0usize;
    while o + 4 <= body_end - body_start {
        if sections.len() >= max_sections { return Err(FvError::LimitExceeded); }

        let size_small = u32::from_le_bytes([
            data[body_start + o],
            data[body_start + o + 1],
            data[body_start + o + 2],
            0,
        ]);
        let section_type = data[body_start + o + 3];

        let (size, hdr_size) = if size_small == 0xFFFFFF {
            if o + 8 > body_end - body_start { return Err(FvError::BadSection); }
            let size_large = u32::from_le_bytes([
                data[body_start + o + 4],
                data[body_start + o + 5],
                data[body_start + o + 6],
                data[body_start + o + 7],
            ]);
            (size_large, 8u32)
        } else {
            (size_small, 4u32)
        };

        if size < hdr_size || size > (body_end - body_start - o) as u32 {
            return Err(FvError::BadSection);
        }

        let abs_offset = add(file.data_offset, o)?;
        let data_off = add(abs_offset, hdr_size as usize)?;
        let data_len = (size - hdr_size) as usize;

        sections.push(FfsSection {
            offset: abs_offset,
            section_type, size,
            data_offset: data_off, data_len,
        });

        o += round_up_4(size as usize);
    }
    Ok(sections)
}

pub fn section_ui_name(data: &[u8], s: &FfsSection) -> Option<String> {
    if s.section_type != 0x15 { return None; }
    let base = s.data_offset;
    let end = base.checked_add(s.data_len)?;
    if end > data.len() { return None; }
    let bytes = &data[base..end];
    if bytes.len() % 2 != 0 { return None; }
    // Decode UTF-16LE up to first null unit
    let mut chars: Vec<char> = Vec::new();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if unit == 0 { break; }
        // Check for surrogate pairs
        if (0xD800..=0xDBFF).contains(&unit) {
            // High surrogate - need low surrogate
            if i + 4 <= bytes.len() {
                let low = u16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
                if (0xDC00..=0xDFFF).contains(&low) {
                    let codepoint = 0x10000u32 + ((unit as u32 - 0xD800) << 10) + (low as u32 - 0xDC00);
                    if let Some(c) = char::from_u32(codepoint) {
                        chars.push(c);
                    }
                    i += 4;
                    continue;
                }
            }
            return None;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            // Lone low surrogate
            return None;
        }
        if let Some(c) = char::from_u32(unit as u32) {
            chars.push(c);
        } else {
            return None;
        }
        i += 2;
    }
    if chars.is_empty() { return None; }
    Some(chars.into_iter().collect())
}
