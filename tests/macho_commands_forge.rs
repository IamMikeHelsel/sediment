use sediment_engine::macho_commands::{FatArch, MachoError, parse_fat, parse_macho, section_data};

// Expected values: `otool -hl` and `lipo -detailed_info` (Xcode toolchain); see gen/macho_commands.py.
const FAT: &[u8] = include_bytes!("macho_commands_fixtures/fat.o");
const FAT64: &[u8] = include_bytes!("macho_commands_fixtures/fat64.o");
const M32: &[u8] = include_bytes!("macho_commands_fixtures/m32.o");
const DYLIB: &[u8] = include_bytes!("macho_commands_fixtures/lib.dylib");
const BE32: &[u8] = include_bytes!("macho_commands_fixtures/be32.o");

fn slice(data: &[u8], a: &FatArch) -> Vec<u8> {
    data[a.offset as usize..(a.offset + a.size) as usize].to_vec()
}

#[test]
fn fat_table() {
    let arches = parse_fat(FAT, 8).unwrap().unwrap();
    assert_eq!(arches, [
        FatArch { cputype: 0x0100_0007, cpusubtype: 3, offset: 48, size: 832, align: 3 },
        FatArch { cputype: 0x0100_000C, cpusubtype: 0, offset: 880, size: 808, align: 3 },
    ]);
    let arches64 = parse_fat(FAT64, 8).unwrap().unwrap();
    assert_eq!(arches64.iter().map(|a| (a.cputype, a.offset, a.size, a.align)).collect::<Vec<_>>(),
               [(0x0100_0007, 72, 832, 3), (0x0100_000C, 904, 808, 3)]);
    assert_eq!(slice(FAT, &arches[1]), slice(FAT64, &arches64[1]));
    assert_eq!(parse_fat(M32, 8), Ok(None));
    assert_eq!(parse_fat(DYLIB, 8), Ok(None));
}

#[test]
fn fat_errors() {
    assert_eq!(parse_fat(&FAT[..3], 8), Err(MachoError::Truncated));
    assert_eq!(parse_fat(&FAT[..6], 8), Err(MachoError::Truncated));
    assert_eq!(parse_fat(FAT, 1), Err(MachoError::LimitExceeded));
    assert_eq!(parse_fat(&FAT[..27], 8), Err(MachoError::Truncated)); // second fat_arch entry cut
    assert_eq!(parse_fat(&FAT[..FAT.len() - 1], 8), Err(MachoError::Truncated)); // last slice cut
    let mut b = FAT64.to_vec();
    b[8 + 8..8 + 16].copy_from_slice(&u64::MAX.to_be_bytes()); // offset overflow
    assert_eq!(parse_fat(&b, 8), Err(MachoError::Truncated));
}

#[test]
fn arm64_slice_commands_and_sections() {
    let a = parse_fat(FAT, 8).unwrap().unwrap()[1];
    let s = slice(FAT, &a);
    let m = parse_macho(&s, 64).unwrap();
    let h = m.header;
    assert!(h.is_64 && !h.big_endian);
    assert_eq!((h.cputype, h.cpusubtype, h.filetype, h.ncmds, h.sizeofcmds, h.flags), (0x0100_000C, 0, 1, 5, 536, 0x2000));
    let cmds: Vec<(u32, u32)> = m.commands.iter().map(|c| (c.cmd, c.cmdsize)).collect();
    assert_eq!(cmds, [(0x19, 392), (0x32, 24), (0x2e, 16), (0x2, 24), (0xb, 80)]);
    assert_eq!(m.commands[0].offset, 32);
    assert_eq!(m.commands[1].offset, 32 + 392);
    assert_eq!(m.segments.len(), 1);
    let seg = &m.segments[0];
    assert_eq!((seg.segname.as_str(), seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize), ("", 0, 0x38, 568, 56));
    assert_eq!((seg.maxprot, seg.initprot, seg.flags), (7, 7, 0));
    let secs: Vec<(&str, &str, u64, u64, u32, u32, u32)> = seg.sections.iter()
        .map(|x| (x.sectname.as_str(), x.segname.as_str(), x.addr, x.size, x.offset, x.align, x.flags)).collect();
    assert_eq!(secs, [
        ("__text", "__TEXT", 0, 0x10, 568, 2, 0x8000_0400),
        ("__data", "__DATA", 0x10, 4, 584, 2, 0),
        ("__const", "__TEXT", 0x14, 3, 588, 0, 0),
        ("__compact_unwind", "__LD", 0x18, 0x20, 592, 3, 0x0200_0000),
    ]);
    assert_eq!(section_data(&s, &seg.sections[2]).unwrap(), b"hi\0");
    assert_eq!(section_data(&s, &seg.sections[1]).unwrap(), &5u32.to_le_bytes());
    assert_eq!(m.uuid, None);
}

#[test]
fn x86_64_slice() {
    let a = parse_fat(FAT, 8).unwrap().unwrap()[0];
    let m = parse_macho(&slice(FAT, &a), 64).unwrap();
    assert_eq!((m.header.cputype, m.header.cpusubtype, m.header.ncmds, m.header.sizeofcmds), (0x0100_0007, 3, 4, 600));
    assert_eq!(m.commands.iter().map(|c| (c.cmd, c.cmdsize)).collect::<Vec<_>>(), [(0x19, 472), (0x32, 24), (0x2, 24), (0xb, 80)]);
    let names: Vec<&str> = m.segments[0].sections.iter().map(|s| s.sectname.as_str()).collect();
    assert_eq!(names, ["__text", "__data", "__const", "__compact_unwind", "__eh_frame"]);
}

#[test]
fn macho32_little_endian() {
    let m = parse_macho(M32, 64).unwrap();
    assert!(!m.header.is_64 && !m.header.big_endian);
    assert_eq!((m.header.cputype, m.header.ncmds, m.header.sizeofcmds), (7, 4, 516));
    assert_eq!(m.commands.iter().map(|c| c.cmd).collect::<Vec<_>>(), [0x1, 0x24, 0x2, 0xb]);
    assert_eq!(m.commands.iter().map(|c| c.cmdsize).collect::<Vec<_>>(), [396, 16, 24, 80]);
    let seg = &m.segments[0];
    assert_eq!((seg.vmsize, seg.fileoff, seg.filesize, seg.sections.len()), (0x64, 544, 100, 5));
    let e = &seg.sections[4];
    assert_eq!((e.sectname.as_str(), e.segname.as_str(), e.addr, e.size, e.offset), ("__eh_frame", "__TEXT", 0x30, 0x34, 592));
    assert_eq!(section_data(M32, &seg.sections[2]).unwrap(), b"hi\0");
}

#[test]
fn macho32_big_endian() {
    let m = parse_macho(BE32, 8).unwrap();
    assert!(!m.header.is_64 && m.header.big_endian);
    assert_eq!((m.header.cputype, m.header.filetype, m.header.ncmds, m.header.sizeofcmds), (18, 1, 2, 148));
    let t = &m.segments[0].sections[0];
    assert_eq!((t.sectname.as_str(), t.addr, t.size, t.offset, t.align, t.flags), ("__text", 0x100, 8, 176, 2, 0x8000_0400));
    assert_eq!(section_data(BE32, t).unwrap(), &[0x38, 0x60, 0x00, 0x2a, 0x4e, 0x80, 0x00, 0x20]);
    assert_eq!(m.uuid, Some(core::array::from_fn(|i| 0xA0 + i as u8)));
}

#[test]
fn dylib_segments_and_uuid() {
    let m = parse_macho(DYLIB, 64).unwrap();
    assert_eq!((m.header.filetype, m.header.ncmds, m.header.sizeofcmds, m.header.flags), (6, 14, 872, 0x0010_0085));
    assert_eq!(m.commands.iter().map(|c| c.cmd).collect::<Vec<_>>(),
               [0x19, 0x19, 0x19, 0xd, 0x8000_0034, 0x8000_0033, 0x2, 0xb, 0x1b, 0x32, 0x2a, 0xc, 0x26, 0x29]);
    let segs: Vec<(&str, u64, u64, u64, u64, usize)> = m.segments.iter()
        .map(|s| (s.segname.as_str(), s.vmaddr, s.vmsize, s.fileoff, s.filesize, s.sections.len())).collect();
    assert_eq!(segs, [("__TEXT", 0, 0x1000, 0, 4096, 3), ("__DATA", 0x1000, 0x1000, 4096, 4096, 1), ("__LINKEDIT", 0x2000, 0x1000, 8192, 168, 0)]);
    let t = &m.segments[0].sections[0];
    assert_eq!((t.sectname.as_str(), t.addr, t.size, t.offset), ("__text", 0x3c8, 0xe, 968));
    assert_eq!(m.uuid, Some([0xFC, 0xBE, 0xA0, 0x02, 0x9B, 0xAF, 0x35, 0x58, 0x98, 0xE3, 0x85, 0x31, 0x11, 0x48, 0xBF, 0xF7]));
}

#[test]
fn zerofill_and_range_checks() {
    let m = parse_macho(BE32, 8).unwrap();
    let mut t = m.segments[0].sections[0].clone();
    t.flags = 0x1; // S_ZEROFILL
    t.size = 1 << 40;
    assert_eq!(section_data(BE32, &t), Ok(&[][..]));
    t.flags = 0;
    assert_eq!(section_data(BE32, &t), Err(MachoError::Truncated));
    t.offset = u32::MAX;
    t.size = u64::MAX;
    assert_eq!(section_data(BE32, &t), Err(MachoError::Truncated));
}

#[test]
fn header_and_command_errors() {
    assert_eq!(parse_macho(&M32[..3], 64), Err(MachoError::Truncated));
    assert_eq!(parse_macho(b"\xca\xfe\xba\xbe\0\0\0\x02", 64), Err(MachoError::BadMagic));
    assert_eq!(parse_macho(&M32[..27], 64), Err(MachoError::Truncated));
    assert_eq!(parse_macho(&DYLIB[..31], 64), Err(MachoError::Truncated));
    assert_eq!(parse_macho(M32, 3), Err(MachoError::LimitExceeded));
    assert_eq!(parse_macho(&BE32[..28 + 147], 8), Err(MachoError::Truncated)); // sizeofcmds past the end
    let mut b = BE32.to_vec();
    b[28 + 4..28 + 8].copy_from_slice(&6u32.to_be_bytes()); // cmdsize < 8
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
    let mut b = BE32.to_vec();
    b[28 + 4..28 + 8].copy_from_slice(&126u32.to_be_bytes()); // not a multiple of 4
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
    let mut b = BE32.to_vec();
    b[28 + 4..28 + 8].copy_from_slice(&200u32.to_be_bytes()); // runs past sizeofcmds
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
    let mut b = BE32.to_vec();
    b[28 + 48..28 + 52].copy_from_slice(&2u32.to_be_bytes()); // nsects 2 does not fit in cmdsize 124
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
    let mut b = BE32.to_vec();
    b[16..20].copy_from_slice(&3u32.to_be_bytes()); // ncmds 3 but only 2 commands in sizeofcmds
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
    let mut b = BE32.to_vec();
    let u = 28 + 124;
    b[u + 4..u + 8].copy_from_slice(&16u32.to_be_bytes()); // LC_UUID too short
    b[20..24].copy_from_slice(&(124u32 + 16).to_be_bytes());
    assert_eq!(parse_macho(&b, 8), Err(MachoError::BadCommand));
}

#[test]
fn hostile_inputs_never_panic() {
    for f in [FAT, FAT64, M32, DYLIB, BE32] {
        for n in (0..f.len().min(2048)).step_by(3) {
            let _ = parse_fat(&f[..n], 8);
            let _ = parse_macho(&f[..n], 64);
        }
        for i in 0..f.len().min(1100) {
            let mut b = f.to_vec();
            b[i] ^= 0x5a;
            let _ = parse_fat(&b, 8);
            if let Ok(m) = parse_macho(&b, 64) {
                for s in m.segments.iter().flat_map(|s| &s.sections) {
                    let _ = section_data(&b, s);
                }
            }
        }
    }
}
