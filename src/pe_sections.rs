use std::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError { Truncated, BadMzSignature, BadPeSignature, BadOptionalHeader, BadSectionName, LimitExceeded }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory { pub rva: u32, pub size: u32 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeader {
    pub machine: u16, pub number_of_sections: u16, pub timestamp: u32, pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32, pub characteristics: u16, pub pe32_plus: bool, pub entry_point: u32,
    pub image_base: u64, pub section_alignment: u32, pub file_alignment: u32, pub size_of_image: u32,
    pub size_of_headers: u32, pub subsystem: u16, pub dll_characteristics: u16, pub data_directories: Vec<DataDirectory>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection { pub name: String, pub virtual_size: u32, pub virtual_address: u32, pub raw_size: u32,
                       pub raw_pointer: u32, pub characteristics: u32 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile { pub pe_offset: u32, pub header: PeHeader, pub sections: Vec<PeSection> }

fn rd16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 <= data.len() { Some(u16::from_le_bytes([data[off], data[off+1]])) } else { None }
}
fn rd32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= data.len() { Some(u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])) } else { None }
}
fn rd64(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 <= data.len() {
        Some(u64::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3],
                                  data[off+4], data[off+5], data[off+6], data[off+7]]))
    } else { None }
}

pub fn parse_pe(data: &[u8], max_sections: usize) -> Result<PeFile, PeError> {
    // Step 1: len < 64 -> Truncated; bytes 0..2 != "MZ" -> BadMzSignature
    if data.len() < 64 { return Err(PeError::Truncated); }
    if &data[0..2] != b"MZ" { return Err(PeError::BadMzSignature); }
    let pe_offset = rd32(data, 0x3C).ok_or(PeError::Truncated)?;

    // Step 2: 24 bytes at pe_offset must exist; first 4 != "PE\0\0" -> BadPeSignature
    let pe_off = pe_offset as usize;
    if pe_off + 24 > data.len() { return Err(PeError::Truncated); }
    if &data[pe_off..pe_off+4] != b"PE\0\0" { return Err(PeError::BadPeSignature); }

    // COFF header at pe_offset+4
    let coff_off = pe_off + 4;
    let machine = rd16(data, coff_off).ok_or(PeError::Truncated)?;
    let number_of_sections = rd16(data, coff_off+2).ok_or(PeError::Truncated)?;
    let timestamp = rd32(data, coff_off+4).ok_or(PeError::Truncated)?;
    let pointer_to_symbol_table = rd32(data, coff_off+8).ok_or(PeError::Truncated)?;
    let number_of_symbols = rd32(data, coff_off+12).ok_or(PeError::Truncated)?;
    let size_of_optional_header = rd16(data, coff_off+16).ok_or(PeError::Truncated)?;
    let characteristics = rd16(data, coff_off+18).ok_or(PeError::Truncated)?;

    // Step 3: Optional header
    let opt_off = pe_off + 24;
    let soh = size_of_optional_header as usize;
    if soh > data.len() || opt_off + soh > data.len() { return Err(PeError::Truncated); }
    if soh < 2 { return Err(PeError::BadOptionalHeader); }

    let magic = rd16(data, opt_off).ok_or(PeError::BadOptionalHeader)?;
    let pe32_plus = match magic {
        0x20B => true,
        0x10B => false,
        _ => return Err(PeError::BadOptionalHeader),
    };

    let min_opt_size: usize = if pe32_plus { 112 } else { 96 };
    if soh < min_opt_size { return Err(PeError::BadOptionalHeader); }

    let entry_point = rd32(data, opt_off+16).ok_or(PeError::BadOptionalHeader)?;
    let image_base = if pe32_plus {
        rd64(data, opt_off+24).ok_or(PeError::BadOptionalHeader)?
    } else {
        rd32(data, opt_off+28).ok_or(PeError::BadOptionalHeader)? as u64
    };
    let section_alignment = rd32(data, opt_off+32).ok_or(PeError::BadOptionalHeader)?;
    let file_alignment = rd32(data, opt_off+36).ok_or(PeError::BadOptionalHeader)?;
    let size_of_image = rd32(data, opt_off+56).ok_or(PeError::BadOptionalHeader)?;
    let size_of_headers = rd32(data, opt_off+60).ok_or(PeError::BadOptionalHeader)?;
    let subsystem = rd16(data, opt_off+68).ok_or(PeError::BadOptionalHeader)?;
    let dll_characteristics = rd16(data, opt_off+70).ok_or(PeError::BadOptionalHeader)?;

    let nrva_off = if pe32_plus { 108u32 } else { 92u32 };
    let number_of_rva_and_sizes = rd32(data, opt_off + nrva_off as usize)
        .ok_or(PeError::BadOptionalHeader)?;
    if number_of_rva_and_sizes > 16 { return Err(PeError::BadOptionalHeader); }

    let dd_start_off = if pe32_plus { 112u32 } else { 96u32 };
    let dd_off = opt_off + dd_start_off as usize;
    let num_dd = number_of_rva_and_sizes as usize;
    if dd_off + num_dd * 8 > opt_off + soh { return Err(PeError::BadOptionalHeader); }

    let mut data_directories = Vec::with_capacity(num_dd);
    for i in 0..num_dd {
        let base = dd_off + i * 8;
        let rva = rd32(data, base).ok_or(PeError::BadOptionalHeader)?;
        let size = rd32(data, base + 4).ok_or(PeError::BadOptionalHeader)?;
        data_directories.push(DataDirectory { rva, size });
    }

    // Step 4: number_of_sections > max_sections -> LimitExceeded
    if number_of_sections as usize > max_sections { return Err(PeError::LimitExceeded); }

    // Step 5: Section table right after optional header
    let sec_table_off = opt_off + soh;
    let sec_count = number_of_sections as usize;
    if sec_table_off + sec_count * 40 > data.len() { return Err(PeError::Truncated); }

    // Step 6: Parse sections and resolve long names
    let mut sections = Vec::with_capacity(sec_count);
    let sym_tab_base = (pointer_to_symbol_table as u64) + (number_of_symbols as u64) * 18;
    let sym_tab_base_usize = sym_tab_base as usize;

    for i in 0..sec_count {
        let s_off = sec_table_off + i * 40;
        let name_bytes = &data[s_off..s_off+8];
        let virtual_size = rd32(data, s_off+8).ok_or(PeError::Truncated)?;
        let virtual_address = rd32(data, s_off+12).ok_or(PeError::Truncated)?;
        let raw_size = rd32(data, s_off+16).ok_or(PeError::Truncated)?;
        let raw_pointer = rd32(data, s_off+20).ok_or(PeError::Truncated)?;
        let characteristics = rd32(data, s_off+36).ok_or(PeError::Truncated)?;

        let name = if name_bytes[0] == b'/' {
            let rest = &name_bytes[1..8];
            let num_str: String = rest.iter()
                .take_while(|&&b| b.is_ascii_digit())
                .map(|&b| b as char)
                .collect();
            if num_str.is_empty() { return Err(PeError::BadSectionName); }
            let offset: u64 = num_str.parse::<u64>().map_err(|_| PeError::BadSectionName)?;
            if pointer_to_symbol_table == 0 { return Err(PeError::BadSectionName); }
            let str_off = sym_tab_base_usize + offset as usize;
            if str_off >= data.len() { return Err(PeError::BadSectionName); }
            let end = data[str_off..].iter().position(|&b| b == 0)
                .ok_or(PeError::BadSectionName)?;
            if str_off + end >= data.len() { return Err(PeError::BadSectionName); }
            String::from_utf8_lossy(&data[str_off..str_off+end]).into_owned()
        } else {
            let end = name_bytes.iter().position(|&b| b == 0)
                .unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).into_owned()
        };

        sections.push(PeSection { name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics });
    }

    Ok(PeFile {
        pe_offset,
        header: PeHeader {
            machine, number_of_sections, timestamp, pointer_to_symbol_table,
            number_of_symbols, characteristics, pe32_plus, entry_point,
            image_base, section_alignment, file_alignment, size_of_image,
            size_of_headers, subsystem, dll_characteristics, data_directories,
        },
        sections,
    })
}

pub fn section_raw_data<'a>(data: &'a [u8], s: &PeSection) -> Result<&'a [u8], PeError> {
    let length = if s.virtual_size != 0 {
        s.raw_size.min(s.virtual_size)
    } else {
        s.raw_size
    };
    if length == 0 { return Ok(&[]); }
    let rp = s.raw_pointer as usize;
    let end = rp.checked_add(length as usize).ok_or(PeError::Truncated)?;
    if end > data.len() { return Err(PeError::Truncated); }
    Ok(&data[rp..end])
}
