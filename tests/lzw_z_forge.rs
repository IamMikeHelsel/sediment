use sediment_engine::crc32::crc32;
use sediment_engine::lzw_z::{LzwError, decompress_z};

// Fixtures made by `compress -b N`, verified with GNU gzip -dc. (len, crc32 of original).
fn check(z: &[u8], len: usize, crc: u32) {
    let out = decompress_z(z, 1 << 20).expect("decode");
    assert_eq!(out.len(), len);
    assert_eq!(crc32(&out), crc);
}

#[test]
fn text_16_bits() {
    check(include_bytes!("lzw_z_fixtures/text_b16.Z"), 6000, 0xd3aeb332);
}

#[test]
fn text_9_bits_table_full() {
    check(include_bytes!("lzw_z_fixtures/text_b9.Z"), 6000, 0xd3aeb332);
}

#[test]
fn text_12_bits() {
    check(include_bytes!("lzw_z_fixtures/text_b12.Z"), 20000, 0x6944c82c);
}

#[test]
fn clear_codes_9_bits() {
    check(include_bytes!("lzw_z_fixtures/clear_b9.Z"), 22700, 0x6a8474cb);
}

#[test]
fn kwkwk_run() {
    let out = decompress_z(include_bytes!("lzw_z_fixtures/kwkwk.Z"), 1 << 20).unwrap();
    assert_eq!(out, vec![b'a'; 1000]);
}

#[test]
fn non_block_mode_hand_vector() {
    // maxbits 12, no block mode: codes 65,66,256,258 -> "ABABABA" (256 is data, 258 is KwKwK).
    let z = [0x1f, 0x9d, 0x0c, 0x41, 0x84, 0x00, 0x14, 0x08];
    assert_eq!(decompress_z(&z, 100).unwrap(), b"ABABABA");
}

#[test]
fn clear_skips_rest_of_code_group() {
    // codes 65,66,CLEAR, then 5 skipped 9-bit all-ones codes, then 67,68 -> "ABCD".
    let z = [0x1f, 0x9d, 0x90, 0x41, 0x84, 0x00, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0x43, 0x88, 0x00];
    assert_eq!(decompress_z(&z, 100).unwrap(), b"ABCD");
}

#[test]
fn header_only_is_empty() {
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0x90], 10).unwrap(), Vec::<u8>::new());
    // fewer than 9 bits of codes: nothing decoded
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0x90, 0x41], 10).unwrap(), Vec::<u8>::new());
}

#[test]
fn header_errors() {
    assert_eq!(decompress_z(&[], 10), Err(LzwError::Truncated));
    assert_eq!(decompress_z(&[0x1f, 0x9d], 10), Err(LzwError::Truncated));
    assert_eq!(decompress_z(&[0x1f, 0x8b, 0x90], 10), Err(LzwError::BadMagic));
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0x88], 10), Err(LzwError::BadHeader)); // 8 bits
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0x91], 10), Err(LzwError::BadHeader)); // 17 bits
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0xb0], 10), Err(LzwError::BadHeader)); // reserved 0x20
    assert_eq!(decompress_z(&[0x1f, 0x9d, 0xd0], 10), Err(LzwError::BadHeader)); // reserved 0x40
}

#[test]
fn first_code_must_be_literal() {
    // block mode, first code 257
    let z = [0x1f, 0x9d, 0x90, 0x01, 0x01];
    assert_eq!(decompress_z(&z, 10), Err(LzwError::InvalidCode));
}

#[test]
fn code_beyond_free_ent_is_invalid() {
    // block mode: 65 then 300 (free_ent is 257)
    let z = [0x1f, 0x9d, 0x90, 0x41, 0x58, 0x02];
    assert_eq!(decompress_z(&z, 10), Err(LzwError::InvalidCode));
}

#[test]
fn output_limit() {
    let z = include_bytes!("lzw_z_fixtures/kwkwk.Z");
    assert_eq!(decompress_z(z, 999), Err(LzwError::LimitExceeded));
    assert_eq!(decompress_z(z, 1000).unwrap().len(), 1000);
    let t = include_bytes!("lzw_z_fixtures/text_b16.Z");
    assert_eq!(decompress_z(t, 0), Err(LzwError::LimitExceeded));
}

#[test]
fn truncated_and_garbage_never_panic() {
    let t: &[u8] = include_bytes!("lzw_z_fixtures/clear_b9.Z");
    for cut in [3usize, 4, 5, 100, 1001, 7000, t.len() - 1] {
        let _ = decompress_z(&t[..cut], 1 << 20);
    }
    let mut x: u32 = 12345;
    for len in 3..300usize {
        let mut v = vec![0x1f, 0x9d, 0x80 | (9 + (len % 8) as u8)];
        for _ in 3..len {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            v.push((x >> 16) as u8);
        }
        let _ = decompress_z(&v, 1 << 16);
    }
}

#[test]
fn truncated_prefix_decodes_a_prefix() {
    let t: &[u8] = include_bytes!("lzw_z_fixtures/text_b16.Z");
    let full = decompress_z(t, 1 << 20).unwrap();
    let part = decompress_z(&t[..600], 1 << 20).unwrap();
    assert!(!part.is_empty() && part.len() < full.len());
    assert_eq!(&full[..part.len()], &part[..]);
}
