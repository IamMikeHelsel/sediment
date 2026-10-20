use sediment_engine::lzip_container::{decode_dict_size, decode_lzip, decode_member, LzipError};

const TEXT: &[u8] = include_bytes!("lzip_container_fixtures/text.lz");
const EMPTY: &[u8] = include_bytes!("lzip_container_fixtures/empty.lz");
const MULTI: &[u8] = include_bytes!("lzip_container_fixtures/multi.lz");
const MD: u64 = 1 << 29;

fn text() -> Vec<u8> {
    (0..300).flat_map(|i| format!("line {i}: the quick brown fox\n").into_bytes()).collect()
}

#[test]
fn dict_size_spec_vectors() {
    assert_eq!(decode_dict_size(0xD3), Ok(327_680));
    assert_eq!(decode_dict_size(0x0C), Ok(4096));
    assert_eq!(decode_dict_size(0x10), Ok(65_536));
    assert_eq!(decode_dict_size(0x92), Ok(196_608));
    assert_eq!(decode_dict_size(0x1D), Ok(512 << 20));
    for bad in [0x0B, 0x1E, 0x1F, 0x00, 0x2C] {
        assert_eq!(decode_dict_size(bad), Err(LzipError::BadDictSize), "{bad:#x}");
    }
}

#[test]
fn single_member() {
    let (d, m) = decode_member(TEXT, MD, 1 << 20).unwrap();
    assert_eq!(d, text());
    assert_eq!((m.dict_size, m.data_size, m.member_size), (65_536, 8890, TEXT.len() as u64));
    assert_eq!(decode_lzip(TEXT, MD, 1 << 20).unwrap(), text());
    let (d, m) = decode_member(EMPTY, MD, 0).unwrap();
    assert!(d.is_empty());
    assert_eq!((m.crc32, m.member_size), (0, 36));
}

#[test]
fn multi_member_concat() {
    let mut want = b"hello ".to_vec();
    for _ in 0..50 { want.extend_from_slice(b"world\n"); }
    assert_eq!(decode_lzip(MULTI, MD, 1 << 20).unwrap(), want);
    let (d, m) = decode_member(MULTI, MD, 1 << 20).unwrap();
    assert_eq!((d.as_slice(), m.member_size), (&b"hello "[..], 42));
    let mut two = TEXT.to_vec();
    two.extend_from_slice(EMPTY);
    assert_eq!(decode_lzip(&two, MD, 1 << 20).unwrap(), text());
}

#[test]
fn header_errors() {
    assert_eq!(decode_lzip(&[], MD, 100).err(), Some(LzipError::Truncated));
    assert_eq!(decode_member(&TEXT[..5], MD, 100).err(), Some(LzipError::Truncated));
    let mut v = TEXT.to_vec(); v[0] = b'X';
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::BadMagic));
    let mut v = TEXT.to_vec(); v[4] = 0;
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::UnsupportedVersion));
    let mut v = TEXT.to_vec(); v[5] = 0x0B;
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::BadDictSize));
}

#[test]
fn trailer_errors() {
    let n = TEXT.len();
    let mut v = TEXT.to_vec(); v[n - 20] ^= 1;
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::CrcMismatch));
    let mut v = TEXT.to_vec(); v[n - 16] ^= 1;
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::SizeMismatch));
    let mut v = TEXT.to_vec(); v[n - 8] ^= 1;
    assert_eq!(decode_member(&v, MD, 1 << 20).err(), Some(LzipError::SizeMismatch));
    assert_eq!(decode_member(&TEXT[..n - 1], MD, 1 << 20).err(), Some(LzipError::Truncated));
    assert_eq!(decode_member(&TEXT[..n - 25], MD, 1 << 20).err(), Some(LzipError::Truncated));
}

#[test]
fn trailing_data() {
    let mut v = TEXT.to_vec(); v.extend_from_slice(b"junk!!");
    assert_eq!(decode_lzip(&v, MD, 1 << 20).err(), Some(LzipError::TrailingData));
    let mut v = TEXT.to_vec(); v.extend_from_slice(b"LZ");
    assert_eq!(decode_lzip(&v, MD, 1 << 20).err(), Some(LzipError::Truncated));
}

#[test]
fn limits() {
    assert_eq!(decode_lzip(TEXT, MD, 8889).err(), Some(LzipError::LimitExceeded));
    assert_eq!(decode_lzip(TEXT, 65_535, 1 << 20).err(), Some(LzipError::LimitExceeded));
    assert_eq!(decode_lzip(MULTI, MD, 305).err(), Some(LzipError::LimitExceeded));
    assert_eq!(decode_lzip(MULTI, MD, 306).unwrap().len(), 306);
}

#[test]
fn hostile_never_panics() {
    let mut seed = 0x9E37_79B9u32;
    for _ in 0..300 {
        let mut v = MULTI.to_vec();
        for _ in 0..4 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed as usize >> 4) % v.len();
            v[i] = (seed >> 16) as u8;
        }
        let _ = decode_lzip(&v, MD, 1 << 16);
        let _ = decode_lzip(&v[..(seed as usize) % v.len()], MD, 1 << 16);
    }
}
