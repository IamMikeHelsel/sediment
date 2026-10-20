use sediment_engine::uefi_section_decode::{decode_section, parse_section_header, SectionError, SectionHeader, LZMA_CUSTOM_DECOMPRESS_GUID};

// Built by gen/uefi_section_decode.py; the LZMA data is Python lzma FORMAT_ALONE output.
const STD: &[u8] = include_bytes!("uefi_section_decode_fixtures/lzma_std.sec");
const EXT: &[u8] = include_bytes!("uefi_section_decode_fixtures/lzma_ext.sec");
const PAD: &[u8] = include_bytes!("uefi_section_decode_fixtures/lzma_pad.sec");

fn payload(seed: u32, n: u32) -> Vec<u8> {
    (0..n).flat_map(|i| format!("uefi {seed} row {i:05}\n").into_bytes()).collect()
}

#[test]
fn headers() {
    assert_eq!(parse_section_header(STD), Ok(SectionHeader { section_type: 2, size: 245, header_len: 4 }));
    assert_eq!(parse_section_header(EXT), Ok(SectionHeader { section_type: 2, size: 370, header_len: 8 }));
    assert_eq!(parse_section_header(&[0x10, 0, 0, 0x19]), Ok(SectionHeader { section_type: 0x19, size: 16, header_len: 4 }));
    assert_eq!(parse_section_header(&[1, 2, 3]), Err(SectionError::Truncated));
    assert_eq!(parse_section_header(&[0xff, 0xff, 0xff, 0x02, 0, 0, 0]), Err(SectionError::Truncated));
    assert_eq!(parse_section_header(&[3, 0, 0, 0x10]), Err(SectionError::BadSize));
    assert_eq!(parse_section_header(&[0xff, 0xff, 0xff, 0x02, 7, 0, 0, 0]), Err(SectionError::BadSize));
}

#[test]
fn lzma_sections_decode() {
    assert_eq!(LZMA_CUSTOM_DECOMPRESS_GUID[..4], [0x98, 0x58, 0x4E, 0xEE]);
    assert_eq!(decode_section(STD, 1 << 20).unwrap(), payload(1, 200));
    assert_eq!(decode_section(EXT, 1 << 20).unwrap(), payload(2, 300));
    assert_eq!(decode_section(PAD, 1 << 20).unwrap(), payload(1, 200));
    let mut tail = STD.to_vec();
    tail.extend([0xAA; 7]); // bytes after the section are not part of it
    assert_eq!(decode_section(&tail, 1 << 20).unwrap(), payload(1, 200));
}

#[test]
fn lzma_errors() {
    assert_eq!(decode_section(STD, 3399), Err(SectionError::LimitExceeded));
    assert_eq!(decode_section(&STD[..200], 1 << 20), Err(SectionError::Truncated));
    let mut g = STD.to_vec();
    g[4] ^= 1; // other GUID
    assert_eq!(decode_section(&g, 1 << 20), Err(SectionError::Unsupported));
    let mut d = STD.to_vec();
    d[20] = 23; // DataOffset inside the header
    assert_eq!(decode_section(&d, 1 << 20), Err(SectionError::BadDataOffset));
    d[20] = 0xF6; // DataOffset 246 > size 245
    assert_eq!(decode_section(&d, 1 << 20), Err(SectionError::BadDataOffset));
    let mut c = STD.to_vec();
    c[24] = 0xE1; // invalid LZMA properties byte
    assert_eq!(decode_section(&c, 1 << 20), Err(SectionError::Corrupt));
    let mut short = STD[..120].to_vec(); // shrink the section: stream cut
    short[0] = 120;
    assert_eq!(decode_section(&short, 1 << 20), Err(SectionError::Corrupt));
    let mut b = vec![0u8; 23];
    b[0] = 23;
    b[3] = 2;
    assert_eq!(decode_section(&b, 1 << 20), Err(SectionError::BadSize));
}

#[test]
fn compression_section() {
    let mut s = vec![0, 0, 0, 0x01];
    s.extend(11u32.to_le_bytes());
    s.push(0);
    s.extend(b"hello world");
    s[0] = s.len() as u8;
    assert_eq!(decode_section(&s, 64).unwrap(), b"hello world".to_vec());
    assert_eq!(decode_section(&s, 10), Err(SectionError::LimitExceeded));
    let mut m = s.clone();
    m[4] = 12;
    assert_eq!(decode_section(&m, 64), Err(SectionError::LengthMismatch));
    let mut t = s.clone();
    t[8] = 1; // EFI_STANDARD_COMPRESSION (Tiano)
    assert_eq!(decode_section(&t, 64), Err(SectionError::Unsupported));
    assert_eq!(decode_section(&[8, 0, 0, 1, 0, 0, 0, 0], 64), Err(SectionError::BadSize));
    assert_eq!(decode_section(&[9, 0, 0, 1, 0, 0, 0, 0, 0], 64).unwrap(), Vec::<u8>::new());
}

#[test]
fn leaf_sections_are_not_encapsulation() {
    // EFI_SECTION_RAW (0x19) and EFI_SECTION_PE32 (0x10)
    assert_eq!(decode_section(&[8, 0, 0, 0x19, 1, 2, 3, 4], 64), Err(SectionError::NotEncapsulation));
    assert_eq!(decode_section(&[4, 0, 0, 0x10], 64), Err(SectionError::NotEncapsulation));
}

#[test]
fn hostile_bytes_never_panic() {
    let mut seed = 0x9E37_79B9u32;
    for _ in 0..300 {
        let mut v = STD.to_vec();
        for _ in 0..8 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed as usize >> 8) % v.len();
            v[i] = (seed >> 16) as u8;
        }
        let _ = decode_section(&v, 1 << 16);
        let _ = decode_section(&v[..(seed as usize) % v.len()], 1 << 16);
    }
}
