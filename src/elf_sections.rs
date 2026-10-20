//! ELF32/64 (LE/BE) header, section table with names, program headers, section data.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError { Truncated, BadMagic, BadClass, BadEncoding, BadHeader, BadStringTable, LimitExceeded }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass { Elf32, Elf64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian { Little, Big }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    pub class: ElfClass, pub endian: Endian, pub os_abi: u8, pub file_type: u16, pub machine: u16,
    pub entry: u64, pub phoff: u64, pub shoff: u64, pub flags: u32,
    pub phentsize: u16, pub phnum: u16, pub shentsize: u16, pub shnum: u16, pub shstrndx: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    pub index: usize, pub name: String, pub sh_type: u32, pub flags: u64, pub addr: u64, pub offset: u64,
    pub size: u64, pub link: u32, pub info: u32, pub addralign: u64, pub entsize: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSegment {
    pub p_type: u32, pub flags: u32, pub offset: u64, pub vaddr: u64, pub paddr: u64,
    pub filesz: u64, pub memsz: u64, pub align: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile {
    pub header: ElfHeader, pub sections: Vec<ElfSection>, pub segments: Vec<ElfSegment>,
}
pub const SHT_NOBITS: u32 = 8;

fn rd_u16(b: &[u8], le: bool) -> u16 {
    if le { u16::from_le_bytes(b[0..2].try_into().unwrap()) }
    else { u16::from_be_bytes(b[0..2].try_into().unwrap()) }
}
fn rd_u32(b: &[u8], le: bool) -> u32 {
    if le { u32::from_le_bytes(b[0..4].try_into().unwrap()) }
    else { u32::from_be_bytes(b[0..4].try_into().unwrap()) }
}
fn rd_u64(b: &[u8], le: bool) -> u64 {
    if le { u64::from_le_bytes(b[0..8].try_into().unwrap()) }
    else { u64::from_be_bytes(b[0..8].try_into().unwrap()) }
}

pub fn parse_header(data: &[u8]) -> Result<ElfHeader, ElfError> {
    if data.len() < 16 { return Err(ElfError::Truncated); }
    if data[0..4] != [0x7F, b'E', b'L', b'F'] { return Err(ElfError::BadMagic); }
    let cls = match data[4] { 1 => ElfClass::Elf32, 2 => ElfClass::Elf64, _ => return Err(ElfError::BadClass) };
    let le = match data[5] { 1 => true, 2 => false, _ => return Err(ElfError::BadEncoding) };
    if data[6] != 1 { return Err(ElfError::BadHeader); }
    let min_hdr = match cls { ElfClass::Elf32 => 52, ElfClass::Elf64 => 64 };
    if data.len() < min_hdr as usize { return Err(ElfError::Truncated); }
    let file_type = rd_u16(&data[16..], le);
    let machine = rd_u16(&data[18..], le);
    let version = rd_u32(&data[20..], le);
    if version != 1 { return Err(ElfError::BadHeader); }
    let (entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = match cls {
        ElfClass::Elf64 => {
            let e = rd_u64(&data[24..], le);
            let p = rd_u64(&data[32..], le);
            let s = rd_u64(&data[40..], le);
            let f = rd_u32(&data[48..], le);
            let eh = rd_u16(&data[52..], le);
            (e, p, s, f, eh,
             rd_u16(&data[54..], le), rd_u16(&data[56..], le),
             rd_u16(&data[58..], le), rd_u16(&data[60..], le),
             rd_u16(&data[62..], le))
        }
        ElfClass::Elf32 => {
            let e = rd_u32(&data[24..], le) as u64;
            let p = rd_u32(&data[28..], le) as u64;
            let s = rd_u32(&data[32..], le) as u64;
            let f = rd_u32(&data[36..], le);
            let eh = rd_u16(&data[40..], le);
            (e, p, s, f, eh,
             rd_u16(&data[42..], le), rd_u16(&data[44..], le),
             rd_u16(&data[46..], le), rd_u16(&data[48..], le),
             rd_u16(&data[50..], le))
        }
    };
    if ehsize < min_hdr { return Err(ElfError::BadHeader); }
    let min_sh = if cls == ElfClass::Elf32 { 40u16 } else { 64 };
    let min_ph = if cls == ElfClass::Elf32 { 32u16 } else { 56 };
    if (shnum > 0 && shentsize < min_sh) || (phnum > 0 && phentsize < min_ph) {
        return Err(ElfError::BadHeader);
    }
    Ok(ElfHeader { class: cls, endian: if le { Endian::Little } else { Endian::Big },
                   os_abi: data[7], file_type, machine, entry, phoff, shoff, flags,
                   phentsize, phnum, shentsize, shnum, shstrndx })
}

fn parse_section_64(data: &[u8], le: bool, idx: usize) -> ElfSection {
    ElfSection {
        index: idx, name: String::new(),
        sh_type: rd_u32(&data[4..], le),
        flags: rd_u64(&data[8..], le),
        addr: rd_u64(&data[16..], le),
        offset: rd_u64(&data[24..], le),
        size: rd_u64(&data[32..], le),
        link: rd_u32(&data[40..], le),
        info: rd_u32(&data[44..], le),
        addralign: rd_u64(&data[48..], le),
        entsize: rd_u64(&data[56..], le),
    }
}
fn parse_section_32(data: &[u8], le: bool, idx: usize) -> ElfSection {
    ElfSection {
        index: idx, name: String::new(),
        sh_type: rd_u32(&data[4..], le),
        flags: rd_u32(&data[8..], le) as u64,
        addr: rd_u32(&data[12..], le) as u64,
        offset: rd_u32(&data[16..], le) as u64,
        size: rd_u32(&data[20..], le) as u64,
        link: rd_u32(&data[24..], le),
        info: rd_u32(&data[28..], le),
        addralign: rd_u32(&data[32..], le) as u64,
        entsize: rd_u32(&data[36..], le) as u64,
    }
}
fn parse_segment_64(data: &[u8], le: bool) -> ElfSegment {
    ElfSegment {
        p_type: rd_u32(&data[0..], le),
        flags: rd_u32(&data[4..], le),
        offset: rd_u64(&data[8..], le),
        vaddr: rd_u64(&data[16..], le),
        paddr: rd_u64(&data[24..], le),
        filesz: rd_u64(&data[32..], le),
        memsz: rd_u64(&data[40..], le),
        align: rd_u64(&data[48..], le),
    }
}
fn parse_segment_32(data: &[u8], le: bool) -> ElfSegment {
    ElfSegment {
        p_type: rd_u32(&data[0..], le),
        flags: rd_u32(&data[24..], le),
        offset: rd_u32(&data[4..], le) as u64,
        vaddr: rd_u32(&data[8..], le) as u64,
        paddr: rd_u32(&data[12..], le) as u64,
        filesz: rd_u32(&data[16..], le) as u64,
        memsz: rd_u32(&data[20..], le) as u64,
        align: rd_u32(&data[28..], le) as u64,
    }
}

pub fn parse_elf(data: &[u8], max_sections: usize) -> Result<ElfFile, ElfError> {
    let h = parse_header(data)?;
    let le = h.endian == Endian::Little;
    let shoff = h.shoff;
    let shnum = h.shnum as usize;
    let shentsize = h.shentsize as usize;
    let phoff = h.phoff;
    let phnum = h.phnum as usize;
    let phentsize = h.phentsize as usize;

    if shnum > max_sections || phnum > max_sections {
        return Err(ElfError::LimitExceeded);
    }

    // Check section table bounds: shoff + shnum * shentsize
    if shnum > 0 {
        let tbl_size = shnum as u64 * shentsize as u64;
        let end = shoff.checked_add(tbl_size).ok_or(ElfError::Truncated)?;
        if end > data.len() as u64 { return Err(ElfError::Truncated); }
    }
    // Check program header table bounds: phoff + phnum * phentsize
    if phnum > 0 {
        let tbl_size = phnum as u64 * phentsize as u64;
        let end = phoff.checked_add(tbl_size).ok_or(ElfError::Truncated)?;
        if end > data.len() as u64 { return Err(ElfError::Truncated); }
    }

    // Parse section headers
    let mut sections: Vec<ElfSection> = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let off = shoff + (i * shentsize) as u64;
        let slice = &data[off as usize..off as usize + shentsize];
        let s = match h.class {
            ElfClass::Elf64 => parse_section_64(slice, le, i),
            ElfClass::Elf32 => parse_section_32(slice, le, i),
        };
        sections.push(s);
    }

    // Parse program headers
    let mut segments: Vec<ElfSegment> = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let off = phoff + (i * phentsize) as u64;
        let slice = &data[off as usize..off as usize + phentsize];
        let seg = match h.class {
            ElfClass::Elf64 => parse_segment_64(slice, le),
            ElfClass::Elf32 => parse_segment_32(slice, le),
        };
        segments.push(seg);
    }

    // Resolve section names from shstrtab
    let shstrndx = h.shstrndx as usize;
    if shstrndx > 0 {
        if shstrndx >= shnum { return Err(ElfError::BadStringTable); }
        let strsec = &sections[shstrndx];
        if strsec.sh_type == SHT_NOBITS { return Err(ElfError::BadStringTable); }
        let str_data = section_data(data, strsec)?;
        let str_len = str_data.len();
        for sec in sections.iter_mut() {
            let name_off = match h.class {
                ElfClass::Elf64 => rd_u32(&data[shoff as usize + sec.index * shentsize..], le),
                ElfClass::Elf32 => rd_u32(&data[shoff as usize + sec.index * shentsize..], le),
            };
            if name_off as usize >= str_len { return Err(ElfError::BadStringTable); }
            let start = name_off as usize;
            let end = str_data[start..].iter().position(|&b| b == 0).unwrap_or(str_len - start);
            sec.name = String::from_utf8_lossy(&str_data[start..start + end]).into_owned();
        }
    }

    Ok(ElfFile { header: h, sections, segments })
}

pub fn section_data<'a>(data: &'a [u8], s: &ElfSection) -> Result<&'a [u8], ElfError> {
    if s.sh_type == SHT_NOBITS { return Ok(&[]); }
    let end = s.offset.checked_add(s.size).ok_or(ElfError::Truncated)?;
    if end > data.len() as u64 { return Err(ElfError::Truncated); }
    Ok(&data[s.offset as usize..end as usize])
}
