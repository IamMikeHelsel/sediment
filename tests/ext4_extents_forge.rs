use sediment_engine::ext4_extents::{Extent, ExtentError, map_logical, parse_extents, parse_header, read_extent_file};
use sediment_engine::gzip_wrapper::decode_gzip;

// gen/ext4_extents.py: mke2fs 1.47.0 -t ext4 -b 1024 -d; i_block bytes pulled from the inode table with Python;
// expected extents are the `debugfs -R "ex /F"` listings stored next to them (*.ex.txt).
const IMG: &[u8] = include_bytes!("ext4_extents_fixtures/ext4.img.gz");
const SMALL: &[u8; 60] = include_bytes!("ext4_extents_fixtures/small.txt.iblock");
const BIG: &[u8; 60] = include_bytes!("ext4_extents_fixtures/big.bin.iblock");
const SPARSE: &[u8; 60] = include_bytes!("ext4_extents_fixtures/sparse.bin.iblock");
const BS: u32 = 1024;

fn img() -> Vec<u8> {
    decode_gzip(IMG, 4 << 20, 1 << 16).unwrap()
}

fn ext(logical: u32, len: u16, physical: u64) -> Extent {
    Extent { logical, len, physical, uninit: false }
}

fn big_data() -> Vec<u8> {
    (0..300000u32).map(|i| ((i * 13 + i / 4096) & 255) as u8).collect()
}

fn sparse_data() -> Vec<u8> {
    let mut v = vec![0u8; 61 * 1024 + 100];
    for b in [0usize, 1, 2, 10, 20, 21, 30, 40, 50, 60, 61] {
        let n = if b == 61 { 100 } else { 1024 };
        for i in 0..n {
            v[b * 1024 + i] = ((b * 31 + i) & 255) as u8;
        }
    }
    v
}

#[test]
fn root_headers() {
    let h = parse_header(SMALL).unwrap();
    assert_eq!((h.entries, h.max, h.depth), (1, 4, 0));
    let h = parse_header(BIG).unwrap();
    assert_eq!((h.entries, h.max, h.depth), (3, 4, 0));
    let h = parse_header(SPARSE).unwrap();
    assert_eq!((h.entries, h.max, h.depth), (1, 4, 1));
}

#[test]
fn leaf_extents_match_debugfs() {
    let a = img();
    assert_eq!(parse_extents(&a, BS, SMALL, 100).unwrap(), [ext(0, 1, 391)]);
    assert_eq!(parse_extents(&a, BS, BIG, 100).unwrap(), [ext(0, 2, 32), ext(2, 15, 35), ext(17, 276, 115)]);
}

#[test]
fn depth_one_tree_matches_debugfs() {
    let a = img();
    assert_eq!(parse_extents(&a, BS, SPARSE, 100).unwrap(), [
        ext(0, 3, 392), ext(10, 1, 395), ext(20, 2, 396), ext(30, 1, 398), ext(40, 1, 399), ext(50, 1, 401), ext(60, 2, 402)]);
}

#[test]
fn map_logical_blocks() {
    let a = img();
    let ex = parse_extents(&a, BS, SPARSE, 100).unwrap();
    assert_eq!(map_logical(&ex, 0), Some(392));
    assert_eq!(map_logical(&ex, 2), Some(394));
    assert_eq!(map_logical(&ex, 3), None);
    assert_eq!(map_logical(&ex, 21), Some(397));
    assert_eq!(map_logical(&ex, 61), Some(403));
    assert_eq!(map_logical(&ex, 62), None);
    let big = parse_extents(&a, BS, BIG, 100).unwrap();
    assert_eq!(map_logical(&big, 17), Some(115));
    assert_eq!(map_logical(&big, 292), Some(390));
}

#[test]
fn read_files() {
    let a = img();
    assert_eq!(read_extent_file(&a, BS, SMALL, 12, 1 << 20).unwrap(), b"tiny extent\n");
    assert_eq!(read_extent_file(&a, BS, BIG, 300000, 1 << 20).unwrap(), big_data());
    assert_eq!(read_extent_file(&a, BS, SPARSE, 61 * 1024 + 100, 1 << 20).unwrap(), sparse_data());
    assert_eq!(read_extent_file(&a, BS, BIG, 300000, 299_999).unwrap_err(), ExtentError::LimitExceeded);
}

#[test]
fn uninitialized_extent_reads_zeros() {
    let a = img();
    let mut ib = *BIG;
    let len = u16::from_le_bytes([ib[12 + 12 + 4], ib[12 + 12 + 5]]) | 0x8000; // second extent: 15 blocks, uninit
    ib[28..30].copy_from_slice(&len.to_le_bytes());
    let ex = parse_extents(&a, BS, &ib, 100).unwrap();
    assert_eq!(ex[1], Extent { logical: 2, len: 15, physical: 35, uninit: true });
    assert_eq!(map_logical(&ex, 5), None);
    let mut want = big_data();
    want[2 * 1024..17 * 1024].fill(0);
    assert_eq!(read_extent_file(&a, BS, &ib, 300000, 1 << 20).unwrap(), want);
}

#[test]
fn header_errors() {
    let mut ib = *SMALL;
    ib[0] = 0;
    assert_eq!(parse_header(&ib).unwrap_err(), ExtentError::BadMagic);
    let mut ib = *SMALL;
    ib[2] = 5; // entries > max
    assert_eq!(parse_header(&ib).unwrap_err(), ExtentError::BadHeader);
    let mut ib = *SMALL;
    ib[4] = 5; // max 5 does not fit in 60 bytes
    assert_eq!(parse_header(&ib).unwrap_err(), ExtentError::BadHeader);
    let mut ib = *SMALL;
    ib[6] = 6;
    assert_eq!(parse_header(&ib).unwrap_err(), ExtentError::TooDeep);
    assert_eq!(parse_header(&SMALL[..11]).unwrap_err(), ExtentError::Truncated);
}

#[test]
fn tree_errors() {
    let a = img();
    let mut ib = *SPARSE;
    ib[6] = 2; // root claims depth 2; child node says depth 0
    assert_eq!(parse_extents(&a, BS, &ib, 100).unwrap_err(), ExtentError::BadHeader);
    let mut ib = *SPARSE;
    ib[16..20].copy_from_slice(&100_000u32.to_le_bytes()); // index leaf block past the image
    assert_eq!(parse_extents(&a, BS, &ib, 100).unwrap_err(), ExtentError::Truncated);
    let mut ib = *BIG;
    ib[24..28].copy_from_slice(&1u32.to_le_bytes()); // second extent overlaps the first
    assert_eq!(parse_extents(&a, BS, &ib, 100).unwrap_err(), ExtentError::BadHeader);
    let mut ib = *BIG;
    ib[16..18].copy_from_slice(&0u16.to_le_bytes()); // zero-length extent
    assert_eq!(parse_extents(&a, BS, &ib, 100).unwrap_err(), ExtentError::BadHeader);
    assert_eq!(parse_extents(&a, BS, SPARSE, 6).unwrap_err(), ExtentError::LimitExceeded);
    assert_eq!(read_extent_file(&a[..300 * 1024], BS, BIG, 300000, 1 << 20).unwrap_err(), ExtentError::Truncated);
}

#[test]
fn hostile_i_block_never_panics() {
    let a = img();
    for base in [SMALL, BIG, SPARSE] {
        for i in 0..60 {
            for x in [0x01u8, 0x10, 0x80, 0xff] {
                let mut ib = *base;
                ib[i] ^= x;
                let _ = parse_extents(&a, BS, &ib, 1000);
                let _ = read_extent_file(&a, BS, &ib, 70_000, 1 << 20);
            }
        }
    }
}
