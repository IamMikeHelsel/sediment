// SPDX-License-Identifier: MIT OR Apache-2.0
use sediment_engine::bzip2_decode::decode_bzip2;
use sediment_engine::compress_wrap::*;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::xz_decode::decode_xz;

fn text(lines: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..lines {
        data.extend_from_slice(format!("{i} wrap line {}\n", i % 7).as_bytes());
    }
    data
}

fn lcg(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7FFF_FFFF;
            (x >> 16) as u8
        })
        .collect()
}

fn unwrap_any(kind: Compression, c: &[u8], n: usize) -> Vec<u8> {
    match kind {
        Compression::None => c.to_vec(),
        Compression::Gzip => decode_gzip(c, n, 1_000_000).unwrap(),
        Compression::Xz => decode_xz(c, 1 << 27, n).unwrap(),
        Compression::Bzip2 => decode_bzip2(c, n).unwrap(),
    }
}

const ALL: [Compression; 4] = [Compression::None, Compression::Gzip, Compression::Xz, Compression::Bzip2];

#[test]
fn gzip_round_trips_every_level() {
    let data = text(5000);
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
fn xz_round_trips_every_level() {
    let data = text(3000);
    for level in 0..=9 {
        let x = compress(Compression::Xz, &data, level, compress_bound_for(Compression::Xz, data.len()).unwrap()).unwrap();
        assert_eq!(&x[..6], b"\xfd7zXZ\x00");
        assert_eq!(x[7], 0x04, "CRC64 check");
        assert_eq!(&x[x.len() - 2..], b"YZ");
        assert_eq!(decode_xz(&x, 1 << 27, data.len()).unwrap(), data, "level {level}");
        assert!(x.len() < data.len() / 3, "level {level}: {}", x.len());
    }
    let empty = xz_compress(&[], 6, 1000).unwrap();
    assert_eq!(decode_xz(&empty, 1 << 20, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn bzip2_round_trips_every_level_with_mapped_block_size() {
    let data = text(3000);
    for level in 0..=9 {
        let b = compress(Compression::Bzip2, &data, level, compress_bound_for(Compression::Bzip2, data.len()).unwrap()).unwrap();
        let digit = bzip2_block_level(level).unwrap();
        assert_eq!(&b[..4], &[b'B', b'Z', b'h', b'0' + digit]);
        assert_eq!(decode_bzip2(&b, data.len()).unwrap(), data, "level {level}");
        assert!(b.len() < data.len() / 3);
    }
    let empty = bzip2_compress(&[], 9, 100).unwrap();
    assert_eq!(decode_bzip2(&empty, 0).unwrap(), Vec::<u8>::new());
}

/// Count bzip2 block magics (blocks are not byte aligned after the first).
fn bzip2_blocks(b: &[u8]) -> usize {
    let magic: u64 = 0x3141_5926_5359;
    let mut acc: u64 = 0;
    let mut n = 0;
    for i in 0..b.len() * 8 {
        let bit = (b[i / 8] >> (7 - i % 8)) & 1;
        acc = ((acc << 1) | bit as u64) & ((1 << 48) - 1);
        if i >= 47 && acc == magic {
            n += 1;
        }
    }
    n
}

#[test]
fn level_mapping_table() {
    let got: Vec<u8> = (0..=9).map(|l| bzip2_block_level(l).unwrap()).collect();
    assert_eq!(got, [1, 1, 1, 5, 5, 9, 9, 9, 9, 9]);
    assert_eq!(bzip2_block_level(10), Err(WrapError::InvalidLevel));
    // 250 kB of varied data spans three 100 kB blocks at -mx1, one at -mx9.
    let data: Vec<u8> = lcg(250_000, 7).iter().map(|b| b'a' + b % 4).collect();
    let bound = compress_bound_for(Compression::Bzip2, data.len()).unwrap();
    let one = compress(Compression::Bzip2, &data, 1, bound).unwrap();
    let four = compress(Compression::Bzip2, &data, 4, bound).unwrap();
    let nine = compress(Compression::Bzip2, &data, 9, bound).unwrap();
    assert_eq!(bzip2_blocks(&one), 3);
    assert_eq!(bzip2_blocks(&four), 1);
    assert_eq!(bzip2_blocks(&nine), 1);
    for c in [&one, &four, &nine] {
        assert_eq!(decode_bzip2(c, data.len()).unwrap(), data);
    }
}

#[test]
fn bounds_hold_for_incompressible_and_tiny_inputs() {
    for &n in &[0usize, 1, 2, 17, 4096, 65_535, 65_536, 65_537, 200_003] {
        let data = lcg(n, n as u32 + 1);
        for kind in ALL {
            let bound = compress_bound_for(kind, n).unwrap();
            for level in [0u8, 1, 5, 9] {
                let c = compress(kind, &data, level, bound).unwrap_or_else(|e| panic!("{kind:?} n={n} l={level}: {e:?}"));
                assert!(c.len() <= bound);
                assert_eq!(unwrap_any(kind, &c, n), data, "{kind:?} n={n} l={level}");
            }
        }
    }
    assert_eq!(compress_bound_for(Compression::None, 5), Some(5));
    assert_eq!(compress_bound_for(Compression::Gzip, 5), compress_bound(5));
    for kind in ALL {
        let want = if kind == Compression::None { Some(usize::MAX) } else { None };
        assert_eq!(compress_bound_for(kind, usize::MAX), want);
    }
}

#[test]
fn deterministic_output() {
    let data = text(800);
    for kind in ALL {
        for level in [0u8, 3, 9] {
            let b = compress_bound_for(kind, data.len()).unwrap();
            assert_eq!(compress(kind, &data, level, b), compress(kind, &data, level, b));
        }
    }
}

#[test]
fn errors() {
    for kind in ALL {
        assert_eq!(compress(kind, b"x", 10, 100), Err(WrapError::InvalidLevel), "{kind:?}");
        assert_eq!(compress(kind, b"x", 255, 100), Err(WrapError::InvalidLevel), "{kind:?}");
    }
    assert_eq!(xz_compress(b"x", 10, 100), Err(WrapError::InvalidLevel));
    assert_eq!(bzip2_compress(b"x", 10, 100), Err(WrapError::InvalidLevel));
    assert_eq!(compress(Compression::Gzip, b"x", 6, 17), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Gzip, &[7; 1000], 0, 100), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Xz, b"hello", 6, 10), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Xz, b"hello", 6, 0), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Bzip2, b"hello", 6, 10), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::Bzip2, b"hello", 6, 0), Err(WrapError::LimitExceeded));
    assert_eq!(compress(Compression::None, b"abc", 0, 3), Ok(b"abc".to_vec()));
    assert_eq!(compress(Compression::None, b"abc", 0, 2), Err(WrapError::LimitExceeded));
    // Exactly-at-limit output is accepted, one byte less is not.
    let x = xz_compress(b"hello", 6, 1000).unwrap();
    assert_eq!(xz_compress(b"hello", 6, x.len()), Ok(x.clone()));
    assert_eq!(xz_compress(b"hello", 6, x.len() - 1), Err(WrapError::LimitExceeded));
    let b = bzip2_compress(b"hello", 6, 1000).unwrap();
    assert_eq!(bzip2_compress(b"hello", 6, b.len()), Ok(b.clone()));
    assert_eq!(bzip2_compress(b"hello", 6, b.len() - 1), Err(WrapError::LimitExceeded));
}
