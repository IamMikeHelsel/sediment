//! Facts 7-Zip prints for a `.gz` file in `7zz l -slt` list mode.
//!
//! Reads only the first member header and the last 8 bytes of the file,
//! without decompressing.  Spec: RFC 1952 section 2.3.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipInfoError {
    Truncated,
    BadSignature,
    BadHeader,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipInfo {
    /// Length of the first member header (10 + optional fields).
    pub headers_size: u32,
    /// MTIME; 0 → None.
    pub mtime: Option<u32>,
    /// XFL value.
    pub xfl: u8,
    /// Host OS value.
    pub host_os: u8,
    /// FNAME bytes without the terminating 0.
    pub name: Option<Vec<u8>>,
    /// FCOMMENT bytes without the terminating 0.
    pub comment: Option<Vec<u8>>,
    /// LE u32 at data.len() - 8.
    pub crc32: u32,
    /// LE u32 at data.len() - 4 (ISIZE).
    pub size: u32,
    /// data.len().
    pub packed_size: u64,
}

/// Return the human-readable name for a gzip Host OS value.
///
/// 0 "FAT", 1 "AMIGA", 2 "VMS", 3 "Unix", 4 "VM/CMS", 5 "Atari", 6 "HPFS",
/// 7 "Macintosh", 8 "Z-System", 9 "CP/M", 10 "TOPS-20", 11 "NTFS",
/// 12 "SMS/QDOS", 13 "Acorn", 14 "VFAT", 15 "MVS", 16 "BeOS", 17 "Tandem",
/// 18 "OS/400", 19 "OS/X"; any other value → its decimal number.
pub fn host_os_name(os: u8) -> String {
    match os {
        0 => "FAT".to_owned(),
        1 => "AMIGA".to_owned(),
        2 => "VMS".to_owned(),
        3 => "Unix".to_owned(),
        4 => "VM/CMS".to_owned(),
        5 => "Atari".to_owned(),
        6 => "HPFS".to_owned(),
        7 => "Macintosh".to_owned(),
        8 => "Z-System".to_owned(),
        9 => "CP/M".to_owned(),
        10 => "TOPS-20".to_owned(),
        11 => "NTFS".to_owned(),
        12 => "SMS/QDOS".to_owned(),
        13 => "Acorn".to_owned(),
        14 => "VFAT".to_owned(),
        15 => "MVS".to_owned(),
        16 => "BeOS".to_owned(),
        17 => "Tandem".to_owned(),
        18 => "OS/400".to_owned(),
        19 => "OS/X".to_owned(),
        v => v.to_string(),
    }
}

/// Parse the first member header of a gzip file and the trailer from the end.
///
/// `max_field` caps the length of FNAME/FCOMMENT fields (without the 0 byte).
/// Returns `LimitExceeded` if a field exceeds `max_field`.
pub fn gzip_info(data: &[u8], max_field: usize) -> Result<GzipInfo, GzipInfoError> {
    // 1. Minimum header check.
    if data.len() < 10 {
        return Err(GzipInfoError::Truncated);
    }
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err(GzipInfoError::BadSignature);
    }
    if data[2] != 8 {
        return Err(GzipInfoError::BadHeader);
    }
    let flg = data[3];
    if flg & 0xe0 != 0 {
        return Err(GzipInfoError::BadHeader);
    }

    let mtime = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let xfl = data[8];
    let host_os = data[9];
    let mut p: usize = 10;

    // 2. FEXTRA (0x04).
    if flg & 0x04 != 0 {
        if p + 2 > data.len() {
            return Err(GzipInfoError::Truncated);
        }
        let xlen = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
        p += 2;
        p = p.checked_add(xlen).ok_or(GzipInfoError::Truncated)?;
        if p > data.len() {
            return Err(GzipInfoError::Truncated);
        }
    }

    // 3. FNAME (0x08), then FCOMMENT (0x10) – zero-terminated.
    let mut name: Option<Vec<u8>> = None;
    let mut comment: Option<Vec<u8>> = None;

    for &bit in &[0x08u8, 0x10] {
        if flg & bit != 0 {
            let start = p;
            // Search for the terminating 0.
            let zero_pos = data[start..].iter().position(|&b| b == 0);
            let zero_pos = zero_pos.ok_or(GzipInfoError::Truncated)?;
            let field_len = zero_pos; // length without the 0
            if field_len > max_field {
                return Err(GzipInfoError::LimitExceeded);
            }
            let field_data = data[start..start + field_len].to_vec();
            p = start + field_len + 1; // skip past the 0
            if bit == 0x08 {
                name = Some(field_data);
            } else {
                comment = Some(field_data);
            }
        }
    }

    // 4. FHCRC (0x02): skip 2 bytes.  FTEXT (0x01) is ignored.
    if flg & 0x02 != 0 {
        if p + 2 > data.len() {
            return Err(GzipInfoError::Truncated);
        }
        p += 2;
    }

    // 5. headers_size = p.
    let headers_size = p as u32;

    // 6. Need at least 8 more bytes for the trailer.
    if data.len() < p + 8 {
        return Err(GzipInfoError::Truncated);
    }

    // Last 8 bytes: crc32 (LE u32) at data.len()-8, size (LE u32) at data.len()-4.
    let len = data.len();
    let crc32 = u32::from_le_bytes([data[len - 8], data[len - 7], data[len - 6], data[len - 5]]);
    let size = u32::from_le_bytes([data[len - 4], data[len - 3], data[len - 2], data[len - 1]]);

    Ok(GzipInfo {
        headers_size,
        mtime: if mtime == 0 { None } else { Some(mtime) },
        xfl,
        host_os,
        name,
        comment,
        crc32,
        size,
        packed_size: len as u64,
    })
}
