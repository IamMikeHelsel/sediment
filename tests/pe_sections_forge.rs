use sediment_engine::pe_sections::{DataDirectory, PeError, parse_pe, section_raw_data};

// poly.dll: Microsoft.PowerShell.PSReadLine.Polyfiller.dll (PE32, .NET, i386) shipped with VS Code.
// app.efi : `objcopy -O pei-aarch64-little --subsystem efi-app ...` of a tiny static ELF (PE32+, ARM64, COFF symbols).
// x64.exe : `yaml2obj gen/x64.yaml` (LLVM 18; PE32+, AMD64, .bss with no raw data).
// Expected values come from `llvm-readobj --file-headers --sections` (LLVM 18.1.3).
const POLY: &[u8] = include_bytes!("pe_sections_fixtures/poly.dll");
const EFI: &[u8] = include_bytes!("pe_sections_fixtures/app.efi");
const X64: &[u8] = include_bytes!("pe_sections_fixtures/x64.exe");

#[test]
fn pe32_dotnet_dll_headers() {
    let f = parse_pe(POLY, 96).unwrap();
    assert_eq!(f.pe_offset, 128);
    let h = &f.header;
    assert_eq!((h.machine, h.number_of_sections, h.timestamp), (0x14c, 3, 0xA064_07A9));
    assert_eq!((h.pointer_to_symbol_table, h.number_of_symbols, h.characteristics), (0, 0, 0x2022));
    assert!(!h.pe32_plus);
    assert_eq!((h.entry_point, h.image_base), (0x2FE6, 0x1000_0000));
    assert_eq!((h.section_alignment, h.file_alignment, h.size_of_image, h.size_of_headers), (8192, 512, 32768, 512));
    assert_eq!((h.subsystem, h.dll_characteristics), (3, 0x8560));
    assert_eq!(h.data_directories.len(), 16);
}

#[test]
fn pe32_sections_and_data() {
    let f = parse_pe(POLY, 96).unwrap();
    let got: Vec<(&str, u32, u32, u32, u32, u32)> = f.sections.iter()
        .map(|s| (s.name.as_str(), s.virtual_size, s.virtual_address, s.raw_size, s.raw_pointer, s.characteristics)).collect();
    assert_eq!(got, [
        (".text", 0xFEC, 0x2000, 4096, 0x200, 0x6000_0020),
        (".rsrc", 0x4C4, 0x4000, 1536, 0x1200, 0x4000_0040),
        (".reloc", 0xC, 0x6000, 512, 0x1800, 0x4200_0040),
    ]);
    let text = section_raw_data(POLY, &f.sections[0]).unwrap();
    assert_eq!(text.len(), 0xFEC);
    assert_eq!(&text[..4], &[0xc5, 0x2f, 0, 0]);
    assert_eq!(section_raw_data(POLY, &f.sections[2]).unwrap().len(), 0xC);
}

#[test]
fn pe32_plus_efi_with_long_section_name() {
    let f = parse_pe(EFI, 96).unwrap();
    let h = &f.header;
    assert!(h.pe32_plus);
    assert_eq!((h.machine, h.characteristics, h.subsystem), (0xAA64, 0x207, 10));
    assert_eq!((h.entry_point, h.image_base, h.size_of_image), (0xBC, 0x40_0000, 4304));
    assert_eq!((h.pointer_to_symbol_table, h.number_of_symbols), (0x800, 14));
    let names: Vec<&str> = f.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".rodata", ".eh_frame"]); // ".eh_frame" is stored as "/4"
    let ro = &f.sections[1];
    assert_eq!((ro.virtual_size, ro.virtual_address, ro.raw_size, ro.raw_pointer), (9, 0xC0, 512, 0x400));
    assert_eq!(section_raw_data(EFI, ro).unwrap(), b"sediment\0");
    assert_eq!(section_raw_data(EFI, &f.sections[2]).unwrap().len(), 0x3C);
}

#[test]
fn pe32_plus_yaml2obj_bss_and_directories() {
    let f = parse_pe(X64, 96).unwrap();
    let h = &f.header;
    assert_eq!((h.machine, h.characteristics, h.subsystem, h.dll_characteristics), (0x8664, 0x22, 2, 0x100));
    assert_eq!((h.entry_point, h.image_base, h.size_of_image), (0x1000, 0x1_4000_0000, 16384));
    assert_eq!(h.data_directories[1], DataDirectory { rva: 0x2000, size: 40 });
    assert_eq!(h.data_directories[0], DataDirectory { rva: 0, size: 0 });
    assert_eq!(section_raw_data(X64, &f.sections[0]).unwrap(), &[0xB8, 0x2A, 0, 0, 0]);
    assert_eq!(section_raw_data(X64, &f.sections[1]).unwrap(), b"sediment");
    let bss = &f.sections[2];
    assert_eq!((bss.name.as_str(), bss.virtual_size, bss.raw_size, bss.raw_pointer, bss.characteristics),
               (".bss", 0x100, 0, 0, 0xC000_0080));
    assert_eq!(section_raw_data(X64, bss).unwrap(), b"");
}

#[test]
fn raw_data_uses_raw_size_when_virtual_size_is_zero() {
    let mut s = parse_pe(X64, 96).unwrap().sections[1].clone();
    s.virtual_size = 0;
    assert_eq!(section_raw_data(X64, &s).unwrap().len(), 512);
    s.raw_pointer = X64.len() as u32 - 100;
    assert_eq!(section_raw_data(X64, &s), Err(PeError::Truncated));
    s.raw_pointer = u32::MAX;
    assert_eq!(section_raw_data(X64, &s), Err(PeError::Truncated));
}

#[test]
fn signature_errors_in_order() {
    assert_eq!(parse_pe(&X64[..63], 96), Err(PeError::Truncated));
    let mut b = X64.to_vec();
    b[0] = b'Z';
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadMzSignature));
    let mut b = X64.to_vec();
    b[0x3c..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert_eq!(parse_pe(&b, 96), Err(PeError::Truncated));
    let mut b = X64.to_vec();
    b[0x81] = b'X';
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadPeSignature));
    assert_eq!(parse_pe(&X64[..0x80 + 23], 96), Err(PeError::Truncated));
}

#[test]
fn optional_header_errors() {
    let opt = 0x80 + 24;
    let mut b = X64.to_vec();
    b[opt] = 0x07; // magic 0x207
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadOptionalHeader));
    let mut b = X64.to_vec();
    b[opt + 108..opt + 112].copy_from_slice(&17u32.to_le_bytes());
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadOptionalHeader));
    let mut b = X64.to_vec();
    b[0x80 + 20..0x80 + 22].copy_from_slice(&100u16.to_le_bytes()); // SizeOfOptionalHeader < 112 for PE32+
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadOptionalHeader));
    let mut b = X64.to_vec();
    b[0x80 + 20..0x80 + 22].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadOptionalHeader));
    let mut b = X64.to_vec();
    b[0x80 + 20..0x80 + 22].copy_from_slice(&0xF000u16.to_le_bytes());
    assert_eq!(parse_pe(&b, 96), Err(PeError::Truncated));
    // Fewer data directories than 16 is fine.
    let mut b = X64.to_vec();
    b[opt + 108..opt + 112].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(parse_pe(&b, 96).unwrap().header.data_directories.len(), 2);
}

#[test]
fn section_table_errors() {
    assert_eq!(parse_pe(X64, 2), Err(PeError::LimitExceeded));
    assert_eq!(parse_pe(X64, 3).unwrap().sections.len(), 3);
    let table_end = 0x80 + 24 + 0xF0 + 3 * 40;
    assert_eq!(parse_pe(&X64[..table_end - 1], 96), Err(PeError::Truncated));
    assert_eq!(parse_pe(&X64[..table_end], 96).unwrap().sections.len(), 3);
    // Long-name reference that cannot be resolved.
    let mut b = EFI.to_vec();
    let at = b.windows(8).position(|w| w == b"/4\0\0\0\0\0\0").unwrap();
    b[at..at + 8].copy_from_slice(b"/99999\0\0");
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadSectionName));
    b[at..at + 8].copy_from_slice(b"/x\0\0\0\0\0\0");
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadSectionName));
    // No symbol table at all: "/4" cannot be resolved either.
    let mut b = X64.to_vec();
    let at = 0x80 + 24 + 0xF0;
    b[at..at + 8].copy_from_slice(b"/4\0\0\0\0\0\0");
    assert_eq!(parse_pe(&b, 96), Err(PeError::BadSectionName));
}

#[test]
fn hostile_inputs_never_panic() {
    for f in [POLY, EFI, X64] {
        for n in (0..f.len()).step_by(7) {
            let _ = parse_pe(&f[..n], 96);
        }
        for i in (0..f.len().min(1024)).step_by(2) {
            let mut b = f.to_vec();
            b[i] ^= 0xA5;
            if let Ok(p) = parse_pe(&b, 96) {
                for s in &p.sections {
                    let _ = section_raw_data(&b, s);
                }
            }
        }
    }
}
