// SPDX-License-Identifier: MIT OR Apache-2.0
use sediment_engine::crc32::crc32;
use sediment_engine::zip_extra_read::*;

fn rec(id: u16, data: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

#[test]
fn iterate_and_find() {
    let mut block = rec(0xcafe, b"xy");
    block.extend(rec(UNIX_OWNER_ID, &[1, 1, 5, 1, 6]));
    let fields = parse_extra_fields(&block, 8).unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], ExtraField { id: 0xcafe, data: b"xy" });
    assert_eq!(parse_extra_fields(&block, 1).unwrap_err(), ExtraError::LimitExceeded);
    assert_eq!(find_extra(&block, UNIX_OWNER_ID).unwrap(), Some(&[1u8, 1, 5, 1, 6][..]));
    assert_eq!(find_extra(&block, AES_EXTRA_ID).unwrap(), None);
    let mut dup = block.clone();
    dup.extend(rec(0xcafe, b""));
    assert_eq!(find_extra(&dup, 0xcafe).unwrap_err(), ExtraError::Invalid);
    assert_eq!(parse_extra_fields(&block[..block.len() - 1], 8).unwrap_err(), ExtraError::Truncated);
    assert_eq!(parse_extra_fields(&[1, 0, 0], 8).unwrap_err(), ExtraError::Truncated);
    assert!(parse_extra_fields(&[], 0).unwrap().is_empty());
    // The iterator stops after reporting an error.
    let mut it = extra_fields(&[1, 0, 9, 0]);
    assert_eq!(it.next(), Some(Err(ExtraError::Truncated)));
    assert_eq!(it.next(), None);
}

#[test]
fn unicode_path() {
    let raw = b"caf\x82.txt";
    let mut data = vec![1];
    data.extend_from_slice(&crc32(raw).to_le_bytes());
    data.extend_from_slice("café.txt".as_bytes());
    let up = parse_unicode_path(&data).unwrap();
    assert!(up.matches(raw));
    assert!(!up.matches(b"other"));
    let block = rec(UNICODE_PATH_ID, &data);
    assert_eq!(unicode_path_for(&block, raw).unwrap(), Some("café.txt".as_bytes()));
    assert_eq!(unicode_path_for(&block, b"stale").unwrap(), None);
    assert_eq!(unicode_path_for(&[], raw).unwrap(), None);
    let mut v2 = data.clone();
    v2[0] = 2;
    assert_eq!(parse_unicode_path(&v2).unwrap_err(), ExtraError::Unsupported);
    let mut bad = data.clone();
    bad.push(0xff);
    assert_eq!(parse_unicode_path(&bad).unwrap_err(), ExtraError::Invalid);
    assert_eq!(parse_unicode_path(&data[..4]).unwrap_err(), ExtraError::Truncated);
}

#[test]
fn extended_timestamp() {
    let mut local = vec![7];
    for t in [100i32, -200, 300] {
        local.extend_from_slice(&t.to_le_bytes());
    }
    let ts = parse_extended_timestamp(&local).unwrap();
    assert_eq!((ts.mtime, ts.atime, ts.ctime), (Some(100), Some(-200), Some(300)));
    // Central form: flags advertise three, only mtime present.
    let ts = parse_extended_timestamp(&local[..5]).unwrap();
    assert_eq!((ts.mtime, ts.atime, ts.ctime), (Some(100), None, None));
    // Only atime flagged.
    let mut a = vec![2];
    a.extend_from_slice(&5i32.to_le_bytes());
    assert_eq!(parse_extended_timestamp(&a).unwrap().atime, Some(5));
    assert_eq!(parse_extended_timestamp(&[]).unwrap_err(), ExtraError::Truncated);
    assert_eq!(parse_extended_timestamp(&local[..3]).unwrap_err(), ExtraError::Invalid);
    let mut extra = local.clone();
    extra[0] = 1;
    assert_eq!(parse_extended_timestamp(&extra).unwrap_err(), ExtraError::Invalid);
}

#[test]
fn unix_owner() {
    let o = parse_unix_owner(&[1, 4, 0xe8, 3, 0, 0, 2, 50, 0]).unwrap();
    assert_eq!((o.uid, o.gid), (1000, 50));
    let o = parse_unix_owner(&[1, 0, 1, 7]).unwrap();
    assert_eq!((o.uid, o.gid), (0, 7));
    let mut wide = vec![1, 9];
    wide.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0]);
    wide.extend_from_slice(&[1, 2]);
    assert_eq!(parse_unix_owner(&wide).unwrap().uid, 1);
    wide[10] = 1;
    assert_eq!(parse_unix_owner(&wide).unwrap_err(), ExtraError::Unsupported);
    assert_eq!(parse_unix_owner(&[2, 0, 0]).unwrap_err(), ExtraError::Unsupported);
    assert_eq!(parse_unix_owner(&[1, 4, 0]).unwrap_err(), ExtraError::Truncated);
    assert_eq!(parse_unix_owner(&[1, 0, 0, 9]).unwrap_err(), ExtraError::Invalid);
    assert_eq!(parse_unix_owner(&[1, 255]).unwrap_err(), ExtraError::Truncated);
}

#[test]
fn ntfs_times() {
    let mut d = vec![0, 0, 0, 0];
    d.extend_from_slice(&[9, 0, 2, 0, 0xaa, 0xbb]); // unknown tag skipped
    d.extend_from_slice(&[1, 0, 24, 0]);
    for v in [1u64, 2, 3] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    let t = parse_ntfs(&d).unwrap().unwrap();
    assert_eq!((t.mtime, t.atime, t.ctime), (1, 2, 3));
    assert_eq!(parse_ntfs(&d[..10]).unwrap(), None);
    assert_eq!(parse_ntfs(&d[..20]).unwrap_err(), ExtraError::Truncated);
    assert_eq!(parse_ntfs(&[0, 0]).unwrap_err(), ExtraError::Truncated);
    let mut short = vec![0, 0, 0, 0, 1, 0, 8, 0];
    short.extend_from_slice(&[0; 8]);
    assert_eq!(parse_ntfs(&short).unwrap_err(), ExtraError::Invalid);
    assert_eq!(filetime_to_unix(116_444_736_000_000_000), (0, 0));
    assert_eq!(filetime_to_unix(116_444_735_999_999_999), (-1, 999_999_900));
    assert_eq!(filetime_to_unix(0).0, -11_644_473_600);
    let _ = filetime_to_unix(u64::MAX);
}

#[test]
fn aes_record() {
    let a = parse_aes(&[2, 0, b'A', b'E', 3, 8, 0]).unwrap();
    assert_eq!(a, AesInfo { vendor_version: 2, strength: 3, actual_method: 8 });
    assert_eq!(a.key_bits(), 256);
    assert_eq!(parse_aes(&[1, 0, b'A', b'E', 1, 0, 0]).unwrap().key_bits(), 128);
    assert_eq!(parse_aes(&[1, 0, b'A', b'E', 2, 0, 0]).unwrap().key_bits(), 192);
    assert_eq!(parse_aes(&[1, 0, b'A', b'X', 1, 0, 0]).unwrap_err(), ExtraError::Invalid);
    assert_eq!(parse_aes(&[3, 0, b'A', b'E', 1, 0, 0]).unwrap_err(), ExtraError::Unsupported);
    assert_eq!(parse_aes(&[1, 0, b'A', b'E', 4, 0, 0]).unwrap_err(), ExtraError::Invalid);
    assert_eq!(parse_aes(&[1, 0, b'A', b'E', 1, 0]).unwrap_err(), ExtraError::Truncated);
    assert_eq!(parse_aes(&[1, 0, b'A', b'E', 1, 0, 0, 0]).unwrap_err(), ExtraError::Invalid);
}

#[test]
fn every_parser_survives_arbitrary_bytes() {
    let mut x: u64 = 1;
    for len in 0..64usize {
        for _ in 0..200 {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (x >> 56) as u8
                })
                .collect();
            let _ = parse_extra_fields(&data, 16);
            let _ = parse_unicode_path(&data);
            let _ = parse_extended_timestamp(&data);
            let _ = parse_unix_owner(&data);
            let _ = parse_ntfs(&data);
            let _ = parse_aes(&data);
        }
    }
}
