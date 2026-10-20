use std::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoError { Truncated, BadMagic, BadCommand, LimitExceeded }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachHeader {
    pub is_64: bool,
    pub big_endian: bool,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachSegment {
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub flags: u32,
    pub sections: Vec<MachSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachFile {
    pub header: MachHeader,
    pub commands: Vec<LoadCommand>,
    pub segments: Vec<MachSegment>,
    pub uuid: Option<[u8; 16]>,
}

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;

fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn read_u64_be(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}
fn read_u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn parse_name(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn parse_fat(data: &[u8], max_arches: usize) -> Result<Option<Vec<FatArch>>, MachoError> {
    if data.len() < 4 { return Err(MachoError::Truncated); }
    let magic = read_u32_be(data);
    let (entry_bytes, magic64) = match magic {
        0xCAFEBABE => (20, false),
        0xCAFEBABF => (32, true),
        _ => return Ok(None),
    };
    if data.len() < 8 { return Err(MachoError::Truncated); }
    let nfat_arch = read_u32_be(&data[4..8]) as usize;
    if nfat_arch > max_arches { return Err(MachoError::LimitExceeded); }
    let table_end = 8 + entry_bytes * nfat_arch;
    if table_end > data.len() { return Err(MachoError::Truncated); }
    let mut arches = Vec::with_capacity(nfat_arch);
    for i in 0..nfat_arch {
        let off = 8 + i * entry_bytes;
        let cputype = read_u32_be(&data[off..off + 4]);
        let cpusubtype = read_u32_be(&data[off + 4..off + 8]);
        if magic64 {
            let offset = read_u64_be(&data[off + 8..off + 16]);
            let size = read_u64_be(&data[off + 16..off + 24]);
            let align = read_u32_be(&data[off + 24..off + 28]);
            if offset.checked_add(size).map(|e| e as usize > data.len()).unwrap_or(true) {
                return Err(MachoError::Truncated);
            }
            arches.push(FatArch { cputype, cpusubtype, offset, size, align });
        } else {
            let offset = read_u32_be(&data[off + 8..off + 12]) as u64;
            let size = read_u32_be(&data[off + 12..off + 16]) as u64;
            let align = read_u32_be(&data[off + 16..off + 20]);
            if offset.checked_add(size).map(|e| e as usize > data.len()).unwrap_or(true) {
                return Err(MachoError::Truncated);
            }
            arches.push(FatArch { cputype, cpusubtype, offset, size, align });
        }
    }
    Ok(Some(arches))
}

pub fn parse_macho(slice: &[u8], max_commands: usize) -> Result<MachFile, MachoError> {
    if slice.len() < 4 { return Err(MachoError::Truncated); }
    let magic = read_u32_le(slice);
    let (is_64, big_endian) = match magic {
        0xFEEDFACE => (false, false),
        0xFEEDFACF => (true, false),
        0xCEFAEDFE => (false, true),
        0xCFFAEDFE => (true, true),
        _ => return Err(MachoError::BadMagic),
    };
    let hdr_size: u64 = if is_64 { 32 } else { 28 };
    if slice.len() < hdr_size as usize { return Err(MachoError::Truncated); }
    let rd = if big_endian { read_u32_be } else { read_u32_le };
    let cputype = rd(&slice[4..8]);
    let cpusubtype = rd(&slice[8..12]);
    let filetype = rd(&slice[12..16]);
    let ncmds = rd(&slice[16..20]);
    let sizeofcmds = rd(&slice[20..24]);
    let flags = rd(&slice[24..28]);
    let header_end = hdr_size + sizeofcmds as u64;
    if header_end as usize > slice.len() { return Err(MachoError::Truncated); }
    if ncmds as usize > max_commands { return Err(MachoError::LimitExceeded); }
    let mut commands = Vec::with_capacity(ncmds as usize);
    let mut segments = Vec::new();
    let mut uuid: Option<[u8; 16]> = None;
    let cmd_start = hdr_size as usize;
    let cmd_end = cmd_start + sizeofcmds as usize;
    let mut pos = cmd_start;
    let mut remaining = ncmds;
    // u64 reader based on endian-ness of the file
    let rd64 = if big_endian { read_u64_be } else { read_u64_le };
    while remaining > 0 {
        let area_left = cmd_end - pos;
        if area_left < 8 { return Err(MachoError::BadCommand); }
        let cmd = rd(&slice[pos..pos + 4]);
        let cmdsize = rd(&slice[pos + 4..pos + 8]);
        if cmdsize < 8 || cmdsize % 4 != 0 || cmdsize as usize > area_left {
            return Err(MachoError::BadCommand);
        }
        let offset = pos;
        commands.push(LoadCommand { cmd, cmdsize, offset });
        if cmd == LC_SEGMENT || cmd == LC_SEGMENT_64 {
            let k: u64 = if is_64 { 8 } else { 4 };
            let fixed: u64 = if is_64 { 72 } else { 56 };
            if (cmdsize as u64) < fixed { return Err(MachoError::BadCommand); }
            let segname = parse_name(&slice[pos + 8..pos + 24]);
            // field offsets within the load command (relative to cmd start)
            let vmaddr_off = 24u64;
            let vmsize_off = 24 + k;
            let fileoff_off = 24 + 2 * k;
            let filesize_off = 24 + 3 * k;
            let maxprot_off = 24 + 4 * k;
            let initprot_off = 28 + 4 * k;
            let nsects_off = 32 + 4 * k;
            let seg_flags_off = 36 + 4 * k;
            let vmaddr = if is_64 {
                rd64(&slice[pos + vmaddr_off as usize..pos + vmaddr_off as usize + 8])
            } else {
                rd(&slice[pos + vmaddr_off as usize..pos + vmaddr_off as usize + 4]) as u64
            };
            let vmsize = if is_64 {
                rd64(&slice[pos + vmsize_off as usize..pos + vmsize_off as usize + 8])
            } else {
                rd(&slice[pos + vmsize_off as usize..pos + vmsize_off as usize + 4]) as u64
            };
            let fileoff = if is_64 {
                rd64(&slice[pos + fileoff_off as usize..pos + fileoff_off as usize + 8])
            } else {
                rd(&slice[pos + fileoff_off as usize..pos + fileoff_off as usize + 4]) as u64
            };
            let filesize = if is_64 {
                rd64(&slice[pos + filesize_off as usize..pos + filesize_off as usize + 8])
            } else {
                rd(&slice[pos + filesize_off as usize..pos + filesize_off as usize + 4]) as u64
            };
            let maxprot = rd(&slice[pos + maxprot_off as usize..pos + maxprot_off as usize + 4]);
            let initprot = rd(&slice[pos + initprot_off as usize..pos + initprot_off as usize + 4]);
            let nsects = rd(&slice[pos + nsects_off as usize..pos + nsects_off as usize + 4]);
            let seg_flags = rd(&slice[pos + seg_flags_off as usize..pos + seg_flags_off as usize + 4]);
            let sect_sz: u64 = if is_64 { 80 } else { 68 };
            let sect_data_end = fixed + sect_sz * (nsects as u64);
            if (cmdsize as u64) < sect_data_end { return Err(MachoError::BadCommand); }
            let mut secs = Vec::with_capacity(nsects as usize);
            let sect_base = fixed;
            for si in 0..nsects as usize {
                let so = sect_base + (si as u64) * sect_sz;
                let sectname = parse_name(&slice[pos + so as usize..pos + so as usize + 16]);
                let segname_s = parse_name(&slice[pos + so as usize + 16..pos + so as usize + 32]);
                let (addr, sz, s_offset, s_align, s_flags) = if is_64 {
                    let a = rd64(&slice[pos + so as usize + 32..pos + so as usize + 40]);
                    let s = rd64(&slice[pos + so as usize + 40..pos + so as usize + 48]);
                    let o = rd(&slice[pos + so as usize + 48..pos + so as usize + 52]);
                    let al = rd(&slice[pos + so as usize + 52..pos + so as usize + 56]);
                    let fl = rd(&slice[pos + so as usize + 64..pos + so as usize + 68]);
                    (a, s, o, al, fl)
                } else {
                    let a = rd(&slice[pos + so as usize + 32..pos + so as usize + 36]) as u64;
                    let s = rd(&slice[pos + so as usize + 36..pos + so as usize + 40]) as u64;
                    let o = rd(&slice[pos + so as usize + 40..pos + so as usize + 44]);
                    let al = rd(&slice[pos + so as usize + 44..pos + so as usize + 48]);
                    let fl = rd(&slice[pos + so as usize + 56..pos + so as usize + 60]);
                    (a, s, o, al, fl)
                };
                secs.push(MachSection { sectname, segname: segname_s, addr, size: sz, offset: s_offset, align: s_align, flags: s_flags });
            }
            segments.push(MachSegment { segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, flags: seg_flags, sections: secs });
        } else if cmd == LC_UUID {
            if cmdsize < 24 { return Err(MachoError::BadCommand); }
            if uuid.is_none() {
                uuid = Some(slice[pos + 8..pos + 24].try_into().unwrap());
            }
        }
        pos += cmdsize as usize;
        remaining -= 1;
    }
    Ok(MachFile { header: MachHeader { is_64, big_endian, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags }, commands, segments, uuid })
}

pub fn section_data<'a>(slice: &'a [u8], s: &MachSection) -> Result<&'a [u8], MachoError> {
    let f = s.flags & 0xff;
    if f == 0x01 || f == 0x0C || f == 0x12 {
        return Ok(&[]);
    }
    // size must fit and the range must be within the slice
    if s.size > slice.len() as u64 {
        return Err(MachoError::Truncated);
    }
    let end = s.offset.checked_add(s.size as u32).ok_or(MachoError::Truncated)?;
    if end as usize > slice.len() { return Err(MachoError::Truncated); }
    Ok(&slice[s.offset as usize..end as usize])
}
