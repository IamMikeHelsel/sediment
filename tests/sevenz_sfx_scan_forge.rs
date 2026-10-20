use sediment_engine::sevenz_sfx_scan::{check_next_header, find_7z_start, start_header_at, SevenZStart, SfxError, SEVENZ_SIGNATURE};

// Made by 7-Zip 26.04 (gen/sevenz_sfx_scan.py). Expected outcomes below are what `7zz l -t7z` reports for each variant.
const ARC: &[u8] = include_bytes!("sevenz_sfx_scan_fixtures/a.7z");

fn stub() -> Vec<u8> { (0..3000u32).map(|i| ((i * 37 + 11) & 0xff) as u8).collect() }

fn variant(mods: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut d = stub();
    for (o, b) in mods { d[*o..*o + b.len()].copy_from_slice(b); }
    d.extend_from_slice(ARC);
    d
}

const REAL: SevenZStart = SevenZStart { offset: 0, next_header_offset: 25, next_header_size: 78, next_header_crc: 0x7337_E40B };

#[test]
fn bare_archive_at_zero() {
    assert_eq!(SEVENZ_SIGNATURE, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    let s = find_7z_start(ARC, usize::MAX).unwrap();
    assert_eq!(s, REAL);
    assert_eq!(check_next_header(ARC, &s), Ok(()));
    assert_eq!(start_header_at(ARC, 0), Some(REAL));
    assert_eq!(start_header_at(ARC, 1), None);
}

#[test]
fn plain_stub_offset_3000() {
    let d = variant(&[]);
    let s = find_7z_start(&d, usize::MAX).unwrap();
    assert_eq!(s, SevenZStart { offset: 3000, ..REAL }); // 7zz: Offset = 3000
    assert_eq!(check_next_header(&d, &s), Ok(()));
    assert_eq!(find_7z_start(&d, 2999), None);
    assert_eq!(find_7z_start(&d, 3000).map(|s| s.offset), Some(3000));
}

#[test]
fn bad_crc_and_bare_signature_are_skipped() {
    let d0 = variant(&[(100, ARC[..6].to_vec())]);
    assert_eq!(find_7z_start(&d0, usize::MAX).map(|s| s.offset), Some(3000));
    let mut h = ARC[..32].to_vec();
    h[8..12].fill(0);
    let d1 = variant(&[(100, h)]);
    assert_eq!(start_header_at(&d1, 100), None);
    assert_eq!(find_7z_start(&d1, usize::MAX).map(|s| s.offset), Some(3000));
}

#[test]
fn first_valid_start_header_wins_even_if_broken() {
    // Exact copy of the start header at 700: 7zz picks it and fails with "Headers Error".
    let d2 = variant(&[(700, ARC[..32].to_vec())]);
    let s = find_7z_start(&d2, usize::MAX).unwrap();
    assert_eq!(s, SevenZStart { offset: 700, ..REAL });
    assert_eq!(check_next_header(&d2, &s), Err(SfxError::BadNextHeaderCrc));
    // Valid start-header CRC but next header 1 TiB away: 7zz says "Unexpected end of archive".
    let mut h = ARC[..8].to_vec();
    h.extend(0x5C19_A804u32.to_le_bytes());
    h.extend((1u64 << 40).to_le_bytes());
    h.extend(10u64.to_le_bytes());
    h.extend(0u32.to_le_bytes());
    let d3 = variant(&[(1500, h)]);
    let s = find_7z_start(&d3, usize::MAX).unwrap();
    assert_eq!(s, SevenZStart { offset: 1500, next_header_offset: 1 << 40, next_header_size: 10, next_header_crc: 0 });
    assert_eq!(check_next_header(&d3, &s), Err(SfxError::Truncated));
}

#[test]
fn truncation_and_overflow() {
    assert_eq!(find_7z_start(&[], usize::MAX), None);
    assert_eq!(find_7z_start(&ARC[..31], usize::MAX), None);
    assert_eq!(start_header_at(ARC, usize::MAX), None);
    assert_eq!(start_header_at(ARC, ARC.len() - 31), None);
    let short = &ARC[..ARC.len() - 1];
    let s = find_7z_start(short, usize::MAX).unwrap();
    assert_eq!(check_next_header(short, &s), Err(SfxError::Truncated));
    let huge = SevenZStart { offset: 0, next_header_offset: u64::MAX - 10, next_header_size: 100, next_header_crc: 0 };
    assert_eq!(check_next_header(ARC, &huge), Err(SfxError::Truncated));
    let empty = SevenZStart { offset: ARC.len() - 32, next_header_offset: 0, next_header_size: 0, next_header_crc: 0 };
    assert_eq!(check_next_header(ARC, &empty), Ok(()));
    let mut flip = ARC.to_vec();
    let n = flip.len();
    flip[n - 5] ^= 1; // inside the next header
    assert_eq!(check_next_header(&flip, &REAL), Err(SfxError::BadNextHeaderCrc));
}
