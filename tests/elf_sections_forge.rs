use sediment_engine::elf_sections::{ElfClass, ElfError, ElfSection, Endian, parse_elf, parse_header, section_data};

const A64: &[u8] = include_bytes!("elf_sections_fixtures/a64.o");
const PPC: &[u8] = include_bytes!("elf_sections_fixtures/ppc.o");
const I386: &[u8] = include_bytes!("elf_sections_fixtures/i386.o");
const EXE: &[u8] = include_bytes!("elf_sections_fixtures/exe64");

fn by_name<'a>(s: &'a [ElfSection], n: &str) -> &'a ElfSection {
    s.iter().find(|x| x.name == n).unwrap_or_else(|| panic!("no section {n}"))
}

// Expectations from `readelf -hSlW` (GNU binutils 2.42).
#[test]
fn elf64_le_relocatable_header() {
    let h = parse_header(A64).unwrap();
    assert_eq!((h.class, h.endian), (ElfClass::Elf64, Endian::Little));
    assert_eq!((h.file_type, h.machine, h.entry), (1, 183, 0));
    assert_eq!((h.phoff, h.shoff, h.phnum), (0, 640, 0));
    assert_eq!((h.shentsize, h.shnum, h.shstrndx), (64, 12, 1));
}

#[test]
fn elf64_le_sections() {
    let f = parse_elf(A64, 64).unwrap();
    assert!(f.segments.is_empty());
    let names: Vec<&str> = f.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["", ".strtab", ".text", ".rela.text", ".data", ".rodata", ".comment", ".note.GNU-stack",
                       ".eh_frame", ".rela.eh_frame", ".llvm_addrsig", ".symtab"]);
    let t = by_name(&f.sections, ".text");
    assert_eq!((t.index, t.sh_type, t.flags, t.offset, t.size, t.addralign), (2, 1, 0x6, 0x40, 0x10, 4));
    let r = by_name(&f.sections, ".rela.text");
    assert_eq!((r.sh_type, r.flags, r.link, r.info, r.entsize, r.offset, r.size), (4, 0x40, 11, 2, 0x18, 0x1b0, 0x30));
    let c = by_name(&f.sections, ".comment");
    assert_eq!((c.flags, c.entsize, c.size), (0x30, 1, 0x28));
    assert_eq!(by_name(&f.sections, ".llvm_addrsig").sh_type, 0x6fff_4c03);
    let st = by_name(&f.sections, ".symtab");
    assert_eq!((st.sh_type, st.link, st.info, st.offset, st.size), (2, 1, 8, 0xa8, 0x108));
    assert_eq!(section_data(A64, by_name(&f.sections, ".rodata")).unwrap(), b"hi\0");
    assert_eq!(section_data(A64, by_name(&f.sections, ".data")).unwrap(), &5u32.to_le_bytes());
}

#[test]
fn elf32_big_endian_powerpc() {
    let f = parse_elf(PPC, 64).unwrap();
    assert_eq!((f.header.class, f.header.endian, f.header.machine), (ElfClass::Elf32, Endian::Big, 20));
    assert_eq!((f.header.shoff, f.header.shnum, f.header.shentsize), (488, 14, 40));
    assert_eq!(f.sections.len(), 14);
    let g = by_name(&f.sections, ".got2");
    assert_eq!((g.index, g.flags, g.offset, g.size), (4, 0x3, 0x78, 4));
    let e = by_name(&f.sections, ".eh_frame");
    assert_eq!((e.index, e.offset, e.size, e.addralign), (10, 0xac, 0x30, 4));
    assert_eq!(by_name(&f.sections, ".rela.got2").entsize, 0x0c);
    assert_eq!(section_data(PPC, by_name(&f.sections, ".data")).unwrap(), &5u32.to_be_bytes());
    assert_eq!(by_name(&f.sections, ".llvm_addrsig").flags, 0x8000_0000);
}

#[test]
fn elf32_little_endian_i386() {
    let f = parse_elf(I386, 64).unwrap();
    assert_eq!((f.header.class, f.header.endian, f.header.machine), (ElfClass::Elf32, Endian::Little, 3));
    let r = by_name(&f.sections, ".rel.text");
    assert_eq!((r.index, r.sh_type, r.offset, r.size, r.entsize, r.link, r.info), (3, 9, 0x11c, 0x10, 8, 11, 2));
    let t = by_name(&f.sections, ".text");
    assert_eq!((t.offset, t.size), (0x34, 0x17));
    assert_eq!(section_data(I386, t).unwrap().len(), 0x17);
}

#[test]
fn executable_program_headers() {
    let f = parse_elf(EXE, 64).unwrap();
    assert_eq!((f.header.file_type, f.header.entry, f.header.phoff, f.header.phnum), (2, 0x4000bc, 64, 2));
    assert_eq!(f.segments.len(), 2);
    let l = &f.segments[0];
    assert_eq!((l.p_type, l.flags, l.offset, l.vaddr, l.paddr), (1, 5, 0xb0, 0x4000b0, 0x4000b0));
    assert_eq!((l.filesz, l.memsz, l.align), (0x5c, 0x5c, 8));
    let s = &f.segments[1];
    assert_eq!((s.p_type, s.flags, s.filesz, s.align), (0x6474_e551, 6, 0, 0x10));
    let names: Vec<&str> = f.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["", ".text", ".rodata", ".eh_frame", ".comment", ".symtab", ".strtab", ".shstrtab"]);
    let ro = by_name(&f.sections, ".rodata");
    assert_eq!((ro.addr, ro.offset), (0x4000c0, 0xc0));
    assert_eq!(section_data(EXE, ro).unwrap(), b"sediment\0");
}

#[test]
fn nobits_and_out_of_range_section_data() {
    let mut s = parse_elf(A64, 64).unwrap().sections[2].clone();
    s.sh_type = 8;
    s.size = 1 << 40;
    assert_eq!(section_data(A64, &s), Ok(&[][..]));
    s.sh_type = 1;
    assert_eq!(section_data(A64, &s), Err(ElfError::Truncated));
    s.offset = u64::MAX;
    s.size = 2;
    assert_eq!(section_data(A64, &s), Err(ElfError::Truncated));
}

#[test]
fn header_errors_in_order() {
    assert_eq!(parse_header(&A64[..15]), Err(ElfError::Truncated));
    let mut b = A64.to_vec();
    b[1] = b'X';
    assert_eq!(parse_header(&b), Err(ElfError::BadMagic));
    let mut b = A64.to_vec();
    b[4] = 3;
    assert_eq!(parse_header(&b), Err(ElfError::BadClass));
    let mut b = A64.to_vec();
    b[5] = 0;
    assert_eq!(parse_header(&b), Err(ElfError::BadEncoding));
    let mut b = A64.to_vec();
    b[6] = 2;
    assert_eq!(parse_header(&b), Err(ElfError::BadHeader));
    assert_eq!(parse_header(&A64[..63]), Err(ElfError::Truncated));
    assert_eq!(parse_header(&PPC[..52]).map(|h| h.shnum), Ok(14));
    let mut b = A64.to_vec();
    b[20] = 2; // e_version
    assert_eq!(parse_header(&b), Err(ElfError::BadHeader));
    let mut b = A64.to_vec();
    b[58] = 32; // e_shentsize too small for ELF64
    assert_eq!(parse_header(&b), Err(ElfError::BadHeader));
}

#[test]
fn table_and_limit_errors() {
    assert_eq!(parse_elf(A64, 11), Err(ElfError::LimitExceeded));
    assert!(parse_elf(A64, 12).is_ok());
    // Section header table cut off.
    assert_eq!(parse_elf(&A64[..A64.len() - 1], 64), Err(ElfError::Truncated));
    // shoff overflowing.
    let mut b = A64.to_vec();
    b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(parse_elf(&b, 64), Err(ElfError::Truncated));
    // shstrndx past the table.
    let mut b = A64.to_vec();
    b[62..64].copy_from_slice(&40u16.to_le_bytes());
    assert_eq!(parse_elf(&b, 64), Err(ElfError::BadStringTable));
    // shstrndx 0: no names, still parses.
    let mut b = A64.to_vec();
    b[62..64].copy_from_slice(&0u16.to_le_bytes());
    assert!(parse_elf(&b, 64).unwrap().sections.iter().all(|s| s.name.is_empty()));
    // A name offset past the string table.
    let mut b = A64.to_vec();
    let at = 640 + 2 * 64;
    b[at..at + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    assert_eq!(parse_elf(&b, 64), Err(ElfError::BadStringTable));
    // Program headers cut off (phoff points near the end).
    let mut b = EXE.to_vec();
    let n = b.len() as u64 - 60;
    b[32..40].copy_from_slice(&n.to_le_bytes());
    assert_eq!(parse_elf(&b, 64), Err(ElfError::Truncated));
}

#[test]
fn hostile_inputs_never_panic() {
    for f in [A64, PPC, I386, EXE] {
        for n in 0..f.len() {
            let _ = parse_elf(&f[..n], 1024);
        }
        for i in (16..f.len()).step_by(3) {
            let mut b = f.to_vec();
            b[i] ^= 0xff;
            if let Ok(e) = parse_elf(&b, 1024) {
                for s in &e.sections {
                    let _ = section_data(&b, s);
                }
            }
        }
    }
}
