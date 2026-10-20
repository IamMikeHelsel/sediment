use sediment_engine::uefi_fv::{FvBlock, FvError, find_volumes, list_files, list_sections, parse_fv_header, section_ui_name};

// Built by gen/uefi_fv.py from the PI spec vol 3 layouts (see its docstring for the map).
const FW: &[u8] = include_bytes!("uefi_fv_fixtures/fw.bin");

const FFS2_GUID: [u8; 16] = [0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3];
const FILE1: [u8; 16] = [0xa4, 0xa3, 0xa2, 0xa1, 0xb2, 0xb1, 0xc2, 0xc1, 0xd1, 0xd2, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6];

fn refix_fv_checksum(b: &mut [u8], at: usize) {
    let hl = u16::from_le_bytes([b[at + 48], b[at + 49]]) as usize;
    b[at + 50] = 0;
    b[at + 51] = 0;
    let s = b[at..at + hl].chunks(2).fold(0u16, |a, w| a.wrapping_add(u16::from_le_bytes([w[0], w[1]])));
    b[at + 50..at + 52].copy_from_slice(&0u16.wrapping_sub(s).to_le_bytes());
}

#[test]
fn finds_both_volumes_and_skips_junk() {
    let v = find_volumes(FW, 8).unwrap();
    assert_eq!(v.iter().map(|f| (f.offset, f.length)).collect::<Vec<_>>(), [(0x40, 0x400), (0x450, 0x200)]);
    assert_eq!(parse_fv_header(FW, 0), Err(FvError::Truncated)); // stray "_FVH" with a huge header length
    assert_eq!(find_volumes(FW, 1), Err(FvError::LimitExceeded));
    assert_eq!(find_volumes(&FW[..0x40], 8), Ok(vec![]));
}

#[test]
fn volume_header_fields() {
    let a = parse_fv_header(FW, 0x40).unwrap();
    assert_eq!(a.fs_guid, FFS2_GUID);
    assert_eq!((a.attributes, a.header_length, a.ext_header_offset, a.revision), (0x0004_FEFF, 72, 0x48, 2));
    assert_eq!(a.blocks, [FvBlock { num_blocks: 4, length: 0x100 }]);
    assert_eq!(a.fv_name, Some([0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55]));
    let b = parse_fv_header(FW, 0x450).unwrap();
    assert_eq!((b.attributes, b.header_length, b.ext_header_offset, b.fv_name), (0x0004_F6FF, 80, 0, None));
    assert_eq!(b.blocks, [FvBlock { num_blocks: 2, length: 0x80 }, FvBlock { num_blocks: 1, length: 0x100 }]);
}

#[test]
fn header_errors_in_order() {
    assert_eq!(parse_fv_header(FW, FW.len() - 55), Err(FvError::Truncated));
    assert_eq!(parse_fv_header(FW, usize::MAX), Err(FvError::Truncated));
    assert_eq!(parse_fv_header(FW, 0x48), Err(FvError::BadSignature));
    let mut b = FW.to_vec();
    b[0x40 + 48] = 63;
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadHeader)); // header length < 64 / odd
    let mut b = FW.to_vec();
    b[0x40 + 60] ^= 1;
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadChecksum));
    let mut b = FW.to_vec();
    b[0x40 + 55] = 1;
    refix_fv_checksum(&mut b, 0x40);
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadHeader)); // revision
    let mut b = FW.to_vec();
    b[0x40 + 32..0x40 + 40].copy_from_slice(&0x10_0000u64.to_le_bytes());
    refix_fv_checksum(&mut b, 0x40);
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::Truncated)); // FvLength past the buffer
    let mut b = FW.to_vec();
    b[0x40 + 32..0x40 + 40].copy_from_slice(&64u64.to_le_bytes());
    refix_fv_checksum(&mut b, 0x40);
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadHeader)); // FvLength < HeaderLength
    let mut b = FW.to_vec();
    b[0x40 + 64..0x40 + 72].fill(0x01); // block map terminator replaced
    refix_fv_checksum(&mut b, 0x40);
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadHeader));
    let mut b = FW.to_vec();
    b[0x40 + 52..0x40 + 54].copy_from_slice(&0x3F0u16.to_le_bytes()); // ext header past the volume
    refix_fv_checksum(&mut b, 0x40);
    assert_eq!(parse_fv_header(&b, 0x40), Err(FvError::BadHeader));
}

#[test]
fn files_of_volume_a() {
    let a = parse_fv_header(FW, 0x40).unwrap();
    let f = list_files(FW, &a, 16).unwrap();
    let got: Vec<(usize, u8, u8, u64, u8, usize, usize)> =
        f.iter().map(|x| (x.offset, x.file_type, x.attributes, x.size, x.state, x.data_offset, x.data_len)).collect();
    assert_eq!(got, [
        (0xA0, 0x07, 0, 0x4C, 0x07, 0xB8, 0x34),
        (0xF0, 0x01, 0, 0x45, 0x07, 0x108, 0x2D),
        (0x138, 0xF0, 0, 0x28, 0x07, 0x150, 0x10),
    ]);
    assert_eq!(f[0].name, FILE1);
    assert_eq!(f[1].name, [0x0c, 0x0d, 0x0e, 0x0f, 0x0a, 0x0b, 0x08, 0x09, 7, 6, 5, 4, 3, 2, 1, 0]);
    assert_eq!(list_files(FW, &a, 2), Err(FvError::LimitExceeded));
}

#[test]
fn sections_and_ui_name() {
    let a = parse_fv_header(FW, 0x40).unwrap();
    let f = list_files(FW, &a, 16).unwrap();
    let s = list_sections(FW, &f[0], 16).unwrap();
    assert_eq!(s.iter().map(|x| (x.offset, x.section_type, x.size, x.data_offset, x.data_len)).collect::<Vec<_>>(),
               [(0xB8, 0x10, 0x24, 0xBC, 0x20), (0xDC, 0x15, 0x10, 0xE0, 0x0C)]);
    assert_eq!(&FW[s[0].data_offset..s[0].data_offset + 2], b"MZ");
    assert_eq!(section_ui_name(FW, &s[1]).as_deref(), Some("Hello"));
    assert_eq!(section_ui_name(FW, &s[0]), None);
    let s2 = list_sections(FW, &f[1], 16).unwrap();
    assert_eq!(s2.iter().map(|x| (x.offset, x.section_type, x.size, x.data_len)).collect::<Vec<_>>(),
               [(0x108, 0x19, 0x0F, 11), (0x118, 0x02, 0x1D, 0x19)]);
    assert_eq!(&FW[s2[0].data_offset..s2[0].data_offset + 11], b"raw-payload");
    assert_eq!(list_sections(FW, &f[0], 1), Err(FvError::LimitExceeded));
}

#[test]
fn volume_b_large_file_and_large_section() {
    let b = parse_fv_header(FW, 0x450).unwrap();
    let f = list_files(FW, &b, 16).unwrap();
    assert_eq!(f.len(), 1);
    let x = &f[0];
    assert_eq!((x.offset, x.file_type, x.attributes, x.size, x.state, x.data_offset, x.data_len), (0x4A0, 0x02, 0x01, 80, 0x07, 0x4C0, 48));
    let s = list_sections(FW, x, 4).unwrap();
    assert_eq!(s.iter().map(|y| (y.offset, y.section_type, y.size, y.data_offset, y.data_len)).collect::<Vec<_>>(),
               [(0x4C0, 0x19, 48, 0x4C8, 40)]);
    assert_eq!(&FW[0x4C8..0x4C8 + 40], &(0u8..40).collect::<Vec<_>>()[..]);
}

#[test]
fn file_errors() {
    let a = parse_fv_header(FW, 0x40).unwrap();
    let mut b = FW.to_vec();
    b[0xA0 + 18] = 0x09; // type changed -> header checksum broken
    assert_eq!(list_files(&b, &a, 16), Err(FvError::BadFile));
    let mut b = FW.to_vec();
    b[0xA0 + 23] = 0x00; // State is excluded from the header checksum
    assert_eq!(list_files(&b, &a, 16).unwrap()[0].state, 0xFF);
    let mut b = FW.to_vec();
    b[0xA0 + 20..0xA0 + 23].copy_from_slice(&[0x00, 0x08, 0x00]); // size 0x800 > volume
    b[0xA0 + 16] = b[0xA0 + 16].wrapping_sub(0x08).wrapping_add(0x4C);
    assert_eq!(list_files(&b, &a, 16), Err(FvError::BadFile));
    let mut b = FW.to_vec();
    b[0xA0 + 20..0xA0 + 23].copy_from_slice(&[0x10, 0x00, 0x00]); // size 16 < header
    b[0xA0 + 16] = b[0xA0 + 16].wrapping_sub(0x10).wrapping_add(0x4C);
    assert_eq!(list_files(&b, &a, 16), Err(FvError::BadFile));
    assert_eq!(list_files(&FW[..0x300], &a, 16), Err(FvError::Truncated));
}

#[test]
fn section_errors() {
    let a = parse_fv_header(FW, 0x40).unwrap();
    let f = list_files(FW, &a, 16).unwrap();
    let mut b = FW.to_vec();
    b[0xB8] = 0x60; // PE32 section size 0x60 > file data
    assert_eq!(list_sections(&b, &f[0], 16), Err(FvError::BadSection));
    let mut b = FW.to_vec();
    b[0xB8] = 0x02; // size 2 < 4
    assert_eq!(list_sections(&b, &f[0], 16), Err(FvError::BadSection));
    let mut short = f[0].clone();
    short.data_offset = FW.len() - 4;
    assert_eq!(list_sections(FW, &short, 16), Err(FvError::Truncated));
}

#[test]
fn hostile_inputs_never_panic() {
    for n in (0..FW.len()).step_by(5) {
        let _ = find_volumes(&FW[..n], 8);
    }
    for i in 0..FW.len() {
        for x in [0x01u8, 0x80, 0xFF] {
            let mut b = FW.to_vec();
            b[i] ^= x;
            for fv in find_volumes(&b, 8).unwrap_or_default() {
                for f in list_files(&b, &fv, 64).unwrap_or_default() {
                    for s in list_sections(&b, &f, 64).unwrap_or_default() {
                        let _ = section_ui_name(&b, &s);
                    }
                }
            }
        }
    }
}
