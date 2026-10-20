/// RPM v3 package parsing: lead, signature header, main header, file list, payload offset.
/// Spec: rpm.org "RPM Package format" / LSB 4.1 "Package File Format".
/// All integers are big-endian. std only, no unsafe, never panic.

use std::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmError {
    Truncated,
    BadLeadMagic,
    UnsupportedSignatureType,
    BadHeaderMagic,
    LimitExceeded,
    BadEntry,
    BadString,
    MissingTag,
    BadFileList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpmLimits {
    pub max_index_entries: u32,
    pub max_store_bytes: u32,
    pub max_files: usize,
}

impl Default for RpmLimits {
    fn default() -> Self {
        Self {
            max_index_entries: 4096,
            max_store_bytes: 16 << 20,
            max_files: 65536,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpmIndexEntry {
    pub tag: u32,
    pub kind: u32,
    pub offset: u32,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmLead {
    pub major: u8,
    pub minor: u8,
    pub kind: u16,
    pub arch_num: u16,
    pub name: String,
    pub os_num: u16,
    pub signature_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmHeader {
    pub entries: Vec<RpmIndexEntry>,
    pub store: Vec<u8>,
}

impl RpmHeader {
    pub fn find(&self, tag: u32) -> Option<&RpmIndexEntry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    pub fn get_string(&self, tag: u32) -> Result<Option<String>, RpmError> {
        let entry = match self.find(tag) {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.kind != 6 && entry.kind != 9 {
            return Err(RpmError::BadEntry);
        }
        let off = entry.offset as usize;
        if off >= self.store.len() {
            return Err(RpmError::BadEntry);
        }
        let end = self.store[off..].iter().position(|&b| b == 0).ok_or(RpmError::BadString)?;
        let s = std::str::from_utf8(&self.store[off..off + end]).map_err(|_| RpmError::BadString)?;
        Ok(Some(s.to_string()))
    }

    pub fn get_string_array(&self, tag: u32) -> Result<Option<Vec<String>>, RpmError> {
        let entry = match self.find(tag) {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.kind != 8 {
            return Err(RpmError::BadEntry);
        }
        let off = entry.offset as usize;
        if off > self.store.len() {
            return Err(RpmError::BadEntry);
        }
        let count = entry.count as usize;
        let mut result = Vec::with_capacity(count);
        let mut pos = off;
        for _ in 0..count {
            let end = self.store[pos..].iter().position(|&b| b == 0).ok_or(RpmError::BadString)?;
            let s = std::str::from_utf8(&self.store[pos..pos + end]).map_err(|_| RpmError::BadString)?;
            result.push(s.to_string());
            pos += end + 1;
        }
        Ok(Some(result))
    }

    pub fn get_u32_array(&self, tag: u32) -> Result<Option<Vec<u32>>, RpmError> {
        let entry = match self.find(tag) {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.kind != 4 {
            return Err(RpmError::BadEntry);
        }
        let off = entry.offset as usize;
        let total = (entry.count as u64).checked_mul(4).ok_or(RpmError::BadEntry)?;
        if (off as u64) + total > self.store.len() as u64 {
            return Err(RpmError::BadEntry);
        }
        let count = entry.count as usize;
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let slice = &self.store[off + i * 4..off + i * 4 + 4];
            result.push(u32::from_be_bytes(slice.try_into().unwrap()));
        }
        Ok(Some(result))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    pub lead: RpmLead,
    pub signature: RpmHeader,
    pub header: RpmHeader,
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: Option<String>,
    pub payload_format: Option<String>,
    pub payload_compressor: Option<String>,
    pub files: Vec<String>,
    pub payload_offset: u64,
}

pub fn parse_lead(data: &[u8]) -> Result<RpmLead, RpmError> {
    if data.len() < 96 {
        return Err(RpmError::Truncated);
    }
    if &data[0..4] != &[0xed, 0xab, 0xee, 0xdb] {
        return Err(RpmError::BadLeadMagic);
    }
    let major = data[4];
    let minor = data[5];
    let kind = u16::from_be_bytes([data[6], data[7]]);
    let arch_num = u16::from_be_bytes([data[8], data[9]]);
    let name_bytes = &data[10..76];
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(66);
    let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
    let os_num = u16::from_be_bytes([data[76], data[77]]);
    let signature_type = u16::from_be_bytes([data[78], data[79]]);
    Ok(RpmLead { major, minor, kind, arch_num, name, os_num, signature_type })
}

pub fn parse_header(data: &[u8], limits: &RpmLimits) -> Result<(RpmHeader, usize), RpmError> {
    if data.len() < 16 {
        return Err(RpmError::Truncated);
    }
    if &data[0..4] != &[0x8e, 0xad, 0xe8, 0x01] {
        return Err(RpmError::BadHeaderMagic);
    }
    let nindex = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let hsize = u32::from_be_bytes(data[12..16].try_into().unwrap());
    if nindex > limits.max_index_entries || hsize > limits.max_store_bytes {
        return Err(RpmError::LimitExceeded);
    }
    let total = 16u64 + 16u64 * nindex as u64 + hsize as u64;
    if total > data.len() as u64 {
        return Err(RpmError::Truncated);
    }
    let mut entries = Vec::with_capacity(nindex as usize);
    let mut pos = 16;
    for _ in 0..nindex {
        let tag = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        let kind = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let offset = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        let count = u32::from_be_bytes(data[pos + 12..pos + 16].try_into().unwrap());
        entries.push(RpmIndexEntry { tag, kind, offset, count });
        pos += 16;
    }
    let store = data[pos..pos + hsize as usize].to_vec();
    let consumed = pos + hsize as usize;
    Ok((RpmHeader { entries, store }, consumed))
}

fn round_up_8(n: usize) -> usize {
    (n + 7) & !7
}

pub fn parse_rpm(data: &[u8], limits: &RpmLimits) -> Result<RpmPackage, RpmError> {
    let lead = parse_lead(data)?;
    if lead.signature_type != 5 {
        return Err(RpmError::UnsupportedSignatureType);
    }
    let sig = parse_header(&data[96..], limits)?;
    let main_start = round_up_8(96 + sig.1);
    if main_start > data.len() {
        return Err(RpmError::Truncated);
    }
    let main = parse_header(&data[main_start..], limits)?;
    let payload_offset = (main_start + main.1) as u64;

    let name = main.0.get_string(1000)?.ok_or(RpmError::MissingTag)?;
    let version = main.0.get_string(1001)?.ok_or(RpmError::MissingTag)?;
    let release = main.0.get_string(1002)?.ok_or(RpmError::MissingTag)?;
    let arch = main.0.get_string(1022)?;
    let payload_format = main.0.get_string(1124)?;
    let payload_compressor = main.0.get_string(1125)?;

    let files = if let Some(basenames) = main.0.get_string_array(1117)? {
        let dirnames = main.0.get_string_array(1118)?.ok_or(RpmError::BadFileList)?;
        let dirindexes = main.0.get_u32_array(1116)?.ok_or(RpmError::BadFileList)?;
        if dirindexes.len() != basenames.len() {
            return Err(RpmError::BadFileList);
        }
        if basenames.len() > limits.max_files {
            return Err(RpmError::LimitExceeded);
        }
        let mut files = Vec::with_capacity(basenames.len());
        for i in 0..basenames.len() {
            let di = dirindexes[i] as usize;
            if di >= dirnames.len() {
                return Err(RpmError::BadFileList);
            }
            files.push(format!("{}{}", dirnames[di], basenames[i]));
        }
        files
    } else {
        Vec::new()
    };

    Ok(RpmPackage {
        lead,
        signature: sig.0,
        header: main.0,
        name,
        version,
        release,
        arch,
        payload_format,
        payload_compressor,
        files,
        payload_offset,
    })
}
