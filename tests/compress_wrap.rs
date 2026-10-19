// SPDX-License-Identifier: MIT OR Apache-2.0
use sediment_engine::compress_wrap::*;
use sediment_engine::gzip_wrapper::decode_gzip;

#[test]
fn gzip_round_trips_every_level() {
    let mut data = Vec::new();
    for i in 0..5000 {
        data.extend_from_slice(format!("{i} gzip line\n").as_bytes());
    }
    for level in 0..=9 {
        let g = compress(Compression::Gzip, &data, level, compress_bound(data.len()).unwrap()).unwrap();
        assert_eq!(&g[..3], &[0x1f, 0x8b, 8]);
        assert_eq!(&g[4..8], &[0, 0, 0, 0], "mtime must be 0 for determinism");
        assert_eq!(decode_gzip(&g, data.len(), 100_000).unwrap(), data);
        if level > 0 {
            assert!(g.len() < data.len() / 2);
        }
    }
    let empty = gzip_compress(&[], 6, 64).unwrap();
    assert_eq!(decode_gzip(&empty, 0, 10).unwrap(), Vec::<u8>::new());
}

#[test]
fn stubs_and_errors() {
    assert_eq!(compress(Compression::Xz, b"x", 6, 100), Err(WrapError::Unsupported));
    assert_eq!(compress(Compression::Bzip2, b"x", 6, 100), Err(WrapError::Unsupported));
    assert_eq!(xz_compress(b"x", 6, 100), Err(WrapError::Unsupported));
    assert_eq!(bzip2_compress(b"x", 6, 100), Err(WrapError::Unsupported));
    assert_eq!(compress(Compression::Gzip, b"x", 10, 100), Err(WrapError::InvalidLevel));
    assert_eq!(compress(Compression::Gzip, b"x", 6, 17), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Gzip, &[7; 1000], 0, 100), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::None, b"abc", 0, 3), Ok(b"abc".to_vec()));
    assert_eq!(compress(Compression::None, b"abc", 0, 2), Err(WrapError::LimitExceeded));
}
