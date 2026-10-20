use sediment_engine::android_sparse::{expand, parse_header, SparseError, SparseHeader, SPARSE_MAGIC};

// Built by gen/android_sparse.py; 7-Zip 26.04 extracts both to exactly the expected raw bytes.
const BASIC: &[u8] = include_bytes!("android_sparse_fixtures/basic.simg"); // blk 4096: raw 2, fill 3, skip 4, raw 1, crc
const SMALL: &[u8] = include_bytes!("android_sparse_fixtures/small.simg"); // blk 512: skip 2, raw 3, crc, fill 1

fn pat(seed: usize, n: usize) -> Vec<u8> { (0..n).map(|i| (((i * 7 + seed * 13) ^ (i >> 8)) & 0xff) as u8).collect() }

fn basic_raw() -> Vec<u8> {
    let mut v = pat(1, 8192);
    for _ in 0..3 * 1024 { v.extend([0xEF, 0xBE, 0xAD, 0xDE]); }
    v.extend(vec![0u8; 4 * 4096]);
    v.extend(pat(2, 4096));
    v
}

fn put32(v: &mut [u8], o: usize, x: u32) { v[o..o + 4].copy_from_slice(&x.to_le_bytes()); }

#[test]
fn header_fields() {
    assert_eq!(SPARSE_MAGIC, 0xED26_FF3A);
    assert_eq!(parse_header(BASIC), Ok(SparseHeader { major: 1, minor: 0, blk_sz: 4096, total_blks: 10, total_chunks: 5, image_checksum: 0 }));
    assert_eq!(parse_header(SMALL).unwrap().blk_sz, 512);
}

#[test]
fn expands_like_7zip() {
    assert_eq!(expand(BASIC, 1 << 20).unwrap(), basic_raw());
    let mut want = vec![0u8; 1024];
    want.extend(pat(3, 1536));
    for _ in 0..128 { want.extend([4, 3, 2, 1]); }
    assert_eq!(expand(SMALL, 3072).unwrap(), want);
    let mut t = BASIC.to_vec();
    t.extend(b"trailing junk");
    assert_eq!(expand(&t, 1 << 20).unwrap().len(), 40960);
    let mut c = BASIC.to_vec(); // CRC32 chunk value is not verified
    put32(&mut c, 12368 + 12, 0x1234_5678);
    assert_eq!(expand(&c, 1 << 20).unwrap(), basic_raw());
    let mut e = BASIC[..28].to_vec(); // 0 blocks, 0 chunks
    put32(&mut e, 16, 0);
    put32(&mut e, 20, 0);
    assert_eq!(expand(&e, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn header_errors() {
    assert_eq!(parse_header(&BASIC[..3]), Err(SparseError::Truncated));
    assert_eq!(parse_header(&BASIC[..27]), Err(SparseError::Truncated));
    let mut m = BASIC.to_vec(); m[0] ^= 1;
    assert_eq!(parse_header(&m), Err(SparseError::BadMagic));
    let mut h = BASIC.to_vec(); h[4] = 2;
    assert_eq!(parse_header(&h), Err(SparseError::Unsupported));
    let mut h = BASIC.to_vec(); h[6] = 1; // minor 1 is accepted
    assert!(expand(&h, 1 << 20).is_ok());
    let mut h = BASIC.to_vec(); h[8] = 32;
    assert_eq!(parse_header(&h), Err(SparseError::BadHeader));
    let mut h = BASIC.to_vec(); h[10] = 16;
    assert_eq!(parse_header(&h), Err(SparseError::BadHeader));
    for bad in [0u32, 2, 1000, 1536] {
        let mut h = BASIC.to_vec(); put32(&mut h, 12, bad);
        assert_eq!(parse_header(&h), Err(SparseError::BadHeader), "blk_sz {bad}");
    }
}

#[test]
fn chunk_and_length_errors() {
    assert_eq!(expand(BASIC, 40959), Err(SparseError::LimitExceeded));
    let mut h = BASIC.to_vec(); put32(&mut h, 16, 11); // total_blks too big
    assert_eq!(expand(&h, 1 << 20), Err(SparseError::BadLength));
    let mut h = BASIC.to_vec(); put32(&mut h, 16, 9); // too small
    assert_eq!(expand(&h, 1 << 20), Err(SparseError::BadLength));
    let mut h = BASIC.to_vec(); put32(&mut h, 20, 3); // fewer chunks than blocks need
    assert_eq!(expand(&h, 1 << 20), Err(SparseError::BadLength));
    let mut h = BASIC.to_vec(); put32(&mut h, 20, 6); // a 6th chunk header is missing
    assert_eq!(expand(&h, 1 << 20), Err(SparseError::Truncated));
    assert_eq!(expand(&BASIC[..BASIC.len() - 100], 1 << 20), Err(SparseError::Truncated));
    let mut f = BASIC.to_vec(); put32(&mut f, 8232 + 8, 17); // FILL total_sz
    assert_eq!(expand(&f, 1 << 20), Err(SparseError::BadChunk));
    let mut r = BASIC.to_vec(); put32(&mut r, 28 + 8, 12 + 8191); // RAW total_sz
    assert_eq!(expand(&r, 1 << 20), Err(SparseError::BadChunk));
    let mut s = BASIC.to_vec(); put32(&mut s, 8248 + 8, 16); // DONT_CARE total_sz
    assert_eq!(expand(&s, 1 << 20), Err(SparseError::BadChunk));
    let mut c = BASIC.to_vec(); put32(&mut c, 12368 + 4, 1); // CRC32 chunk_sz must be 0
    assert_eq!(expand(&c, 1 << 20), Err(SparseError::BadChunk));
    let mut u = BASIC.to_vec(); u[8248] = 0xC5; // unknown type 0xCAC5
    assert_eq!(expand(&u, 1 << 20), Err(SparseError::BadChunk));
}

#[test]
fn hostile_sizes_never_panic() {
    let mut h = BASIC.to_vec();
    put32(&mut h, 16, u32::MAX);
    put32(&mut h, 12, 1 << 31);
    assert_eq!(expand(&h, usize::MAX >> 1), Err(SparseError::LimitExceeded));
    let mut r = BASIC.to_vec();
    put32(&mut r, 28 + 4, u32::MAX);
    assert!(expand(&r, 1 << 20).is_err());
    let mut seed = 7u32;
    for _ in 0..300 {
        let mut v = SMALL.to_vec();
        for _ in 0..6 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed as usize >> 8) % v.len();
            v[i] = (seed >> 16) as u8;
        }
        let _ = expand(&v, 1 << 16);
    }
}
