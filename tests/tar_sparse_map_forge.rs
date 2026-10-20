use sediment_engine::crc32::crc32;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::tar_sparse_map::{expand, parse_map_text, parse_old_gnu, MapText, SparseError, SparseMap, SparseRegion};

// Fixtures: GNU tar 1.35 --sparse (gen/make_fixtures.sh). Offsets, maps and CRCs: Python tarfile (gen/expected.py).
fn tar(gz: &[u8]) -> Vec<u8> {
    decode_gzip(gz, 1 << 22, 1 << 12).unwrap()
}
fn r(offset: u64, length: u64) -> SparseRegion {
    SparseRegion { offset, length }
}
fn sum(m: &SparseMap) -> usize {
    m.regions.iter().map(|r| r.length as usize).sum()
}

#[test]
fn old_gnu_header_slots_only() {
    let t = tar(include_bytes!("tar_sparse_map_fixtures/old_small.tar.gz"));
    let (m, ext) = parse_old_gnu(&t[..512], &t[512..], 100).unwrap();
    assert_eq!(ext, 0);
    assert_eq!(m.real_size, 40000);
    assert_eq!(m.regions, vec![r(0, 1024), r(12288, 512), r(24576, 1536)]);
    let out = expand(&m, &t[512..512 + sum(&m)], 1 << 20).unwrap();
    assert_eq!((out.len(), crc32(&out)), (40000, 0xCE21B4BF));
}

#[test]
fn old_gnu_two_extension_blocks() {
    let t = tar(include_bytes!("tar_sparse_map_fixtures/old_many.tar.gz"));
    let (m, ext) = parse_old_gnu(&t[..512], &t[512..], 100).unwrap();
    assert_eq!((ext, m.real_size, m.regions.len()), (1024, 246093, 31));
    assert_eq!(m.regions[..3], [r(4096, 512), r(12288, 512), r(20480, 512)]);
    assert_eq!(m.regions[29..], [r(241664, 512), r(245760, 333)]);
    let data = &t[512 + ext..];
    assert_eq!(sum(&m), 15693);
    let out = expand(&m, data, 1 << 20).unwrap();
    assert_eq!((out.len(), crc32(&out)), (246093, 0xD82734C3));
    assert_eq!(parse_old_gnu(&t[..512], &t[512..], 30), Err(SparseError::LimitExceeded));
    assert_eq!(parse_old_gnu(&t[..512], &t[512..1000], 100), Err(SparseError::Truncated));
    assert_eq!(parse_old_gnu(&t[..300], &t[512..], 100), Err(SparseError::Truncated));
}

#[test]
fn pax_0_1_map_keyword() {
    let t = tar(include_bytes!("tar_sparse_map_fixtures/pax01.tar.gz"));
    let key = b"GNU.sparse.map=";
    let i = t[..1024].windows(key.len()).position(|w| w == key).unwrap() + key.len();
    let j = i + t[i..].iter().position(|&b| b == b'\n').unwrap();
    let (m, used) = parse_map_text(&t[i..j], MapText::Pax01, 246093, 100).unwrap();
    assert_eq!((used, m.regions.len(), m.real_size), (j - i, 31, 246093));
    assert_eq!(m.regions[30], r(245760, 333));
    let out = expand(&m, &t[1536..], 1 << 20).unwrap();
    assert_eq!(crc32(&out), 0xD82734C3);
}

#[test]
fn pax_1_0_data_prefixed_map() {
    let t = tar(include_bytes!("tar_sparse_map_fixtures/pax10_small.tar.gz"));
    let (m, used) = parse_map_text(&t[1536..], MapText::Pax10, 40000, 100).unwrap();
    assert_eq!(used, 512);
    assert_eq!(m.regions, vec![r(0, 1024), r(12288, 512), r(24576, 1536)]);
    assert_eq!(crc32(&expand(&m, &t[2048..], 1 << 20).unwrap()), 0xCE21B4BF);
    let t = tar(include_bytes!("tar_sparse_map_fixtures/pax10.tar.gz"));
    let (m, used) = parse_map_text(&t[1536..], MapText::Pax10, 987136, 1000).unwrap();
    assert_eq!((used, m.regions.len(), sum(&m)), (1536, 120, 61440));
    assert_eq!(m.regions[119], r(978944, 512));
    let out = expand(&m, &t[3072..], 1 << 20).unwrap();
    assert_eq!((out.len(), crc32(&out)), (987136, 0x9C69D322));
}

#[test]
fn map_text_errors() {
    let p = |s: &[u8], k| parse_map_text(s, k, 1000, 10);
    assert_eq!(p(b"", MapText::Pax01).unwrap().0.regions, vec![]);
    assert_eq!(p(b"0,10,500,0", MapText::Pax01).unwrap().0.regions, vec![r(0, 10)]);
    assert_eq!(p(b"0,10,500", MapText::Pax01), Err(SparseError::BadMap));
    assert_eq!(p(b"0,,5,5", MapText::Pax01), Err(SparseError::BadMap));
    assert_eq!(p(b"0,1x", MapText::Pax01), Err(SparseError::BadMap));
    assert_eq!(p(b"100,10,50,10", MapText::Pax01), Err(SparseError::BadMap)); // not sorted
    assert_eq!(p(b"0,20,10,5", MapText::Pax01), Err(SparseError::BadMap)); // overlap
    assert_eq!(p(b"990,11", MapText::Pax01), Err(SparseError::BadMap)); // past real_size
    assert_eq!(p(b"18446744073709551615,2", MapText::Pax01), Err(SparseError::BadMap));
    assert_eq!(p(b"99999999999999999999,1", MapText::Pax01), Err(SparseError::BadMap));
    assert_eq!(p(b"1\n0\n10\n", MapText::Pax10).unwrap(), (SparseMap { regions: vec![r(0, 10)], real_size: 1000 }, 512));
    assert_eq!(p(b"2\n0\n10\n20", MapText::Pax10), Err(SparseError::Truncated));
    assert_eq!(p(b"1\n\n10\n", MapText::Pax10), Err(SparseError::BadMap));
    let many: Vec<u8> = b"11\n".iter().copied().chain((0..11).flat_map(|k| format!("{}\n1\n", k * 2).into_bytes())).collect();
    assert_eq!(p(&many, MapText::Pax10), Err(SparseError::LimitExceeded));
}

#[test]
fn expand_limits_and_truncation() {
    let m = SparseMap { regions: vec![r(2, 3), r(8, 2)], real_size: 12 };
    assert_eq!(expand(&m, b"abcdeXYZ", 12).unwrap(), b"\0\0abc\0\0\0de\0\0".to_vec());
    assert_eq!(expand(&m, b"abcd", 12), Err(SparseError::Truncated));
    assert_eq!(expand(&m, b"abcde", 11), Err(SparseError::LimitExceeded));
    let huge = SparseMap { regions: vec![], real_size: u64::MAX };
    assert_eq!(expand(&huge, b"", 1 << 20), Err(SparseError::LimitExceeded));
    assert!(expand(&huge, b"", usize::MAX).is_err()); // try_reserve, never abort
    assert_eq!(expand(&SparseMap { regions: vec![], real_size: 0 }, b"", 0).unwrap(), Vec::<u8>::new());
}
