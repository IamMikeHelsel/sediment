// SPDX-License-Identifier: MIT OR Apache-2.0
mod zip_ext_common;

use sediment_engine::zip64::*;
use zip_ext_common::*;

#[test]
fn locates_python_zip64_eocd() {
    let bytes = fixture("zip64_eocd.zip");
    let loc = locate_central_directory(&bytes).unwrap();
    let (locator, record) = loc.zip64.expect("zip64 records");
    assert_eq!(loc.entries, 5);
    assert_eq!(record.entries_total, 5);
    assert_eq!(record.offset as u64, locator.record_offset);
    assert_eq!(record.total_len(), ZIP64_RECORD_MIN_LEN);
    assert_eq!(loc.eocd.entries_total, 5, "python keeps the real count when it fits");
    assert_eq!(loc.cd_start + loc.cd_size, record.offset);
    assert_eq!(loc.prefix, 0);
}

#[test]
fn classic_archive_has_no_zip64_records() {
    let bytes = fixture("zip64_forced.zip");
    let loc = locate_central_directory(&bytes).unwrap();
    assert!(loc.zip64.is_none());
    assert_eq!(loc.entries, 4);
    assert_eq!(loc.comment, b"forced zip64");
}

#[test]
fn prefix_is_detected_for_zip64() {
    let bytes = fixture("prefixed_zip64.zip");
    let loc = locate_central_directory(&bytes).unwrap();
    assert_eq!(loc.prefix, 512);
    let (locator, record) = loc.zip64.unwrap();
    assert_eq!(record.offset as u64, locator.record_offset + 512);
}

#[test]
fn saturated_classic_with_zip64_record() {
    let entries: Vec<_> = (0..3u8).map(|i| (vec![b'a' + i], vec![i])).collect();
    let bytes = build_stored(&entries, Tail::Zip64);
    let loc = locate_central_directory(&bytes).unwrap();
    assert_eq!(loc.entries, 3);
    assert_eq!(loc.eocd.entries_total, 0xffff);
}

#[test]
fn inconsistent_classic_and_zip64_counts_rejected() {
    let entries: Vec<_> = (0..3u8).map(|i| (vec![b'a' + i], vec![i])).collect();
    let mut bytes = build_stored(&entries, Tail::Zip64);
    let n = bytes.len();
    // Unsaturated classic count 2 disagrees with zip64 count 3.
    bytes[n - 22 + 8..n - 22 + 12].copy_from_slice(&[2, 0, 2, 0]);
    assert_eq!(locate_central_directory(&bytes).unwrap_err(), Zip64Error::Invalid);
}

#[test]
fn multi_disk_unsupported() {
    let entries = vec![(b"a".to_vec(), b"x".to_vec())];
    let mut bytes = build_stored(&entries, Tail::Zip64);
    let n = bytes.len();
    // Locator total_disks = 2.
    bytes[n - 22 - 4..n - 22].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(locate_central_directory(&bytes).unwrap_err(), Zip64Error::Unsupported);
    let mut bytes = build_stored(&entries, Tail::Classic);
    let n = bytes.len();
    bytes[n - 22 + 4] = 1;
    assert_eq!(locate_central_directory(&bytes).unwrap_err(), Zip64Error::Unsupported);
}

#[test]
fn record_and_locator_parsers() {
    let entries = vec![(b"a".to_vec(), b"x".to_vec())];
    let bytes = build_stored(&entries, Tail::Zip64);
    let n = bytes.len();
    let loc = parse_zip64_locator(&bytes, n - 42).unwrap();
    assert_eq!(loc.total_disks, 1);
    let rec = parse_zip64_end_record(&bytes, loc.record_offset as usize).unwrap();
    assert_eq!(rec.version_needed, 45);
    assert_eq!(parse_zip64_locator(&bytes, 0).unwrap_err(), Zip64Error::Invalid);
    assert_eq!(parse_zip64_locator(&bytes, n - 3).unwrap_err(), Zip64Error::Truncated);
    assert_eq!(parse_zip64_end_record(&bytes, usize::MAX).unwrap_err(), Zip64Error::Truncated);
    // record_size < 44 is invalid; huge record_size is truncated.
    let mut bad = bytes.clone();
    let r = loc.record_offset as usize;
    bad[r + 4..r + 12].copy_from_slice(&43u64.to_le_bytes());
    assert_eq!(parse_zip64_end_record(&bad, r).unwrap_err(), Zip64Error::Invalid);
    bad[r + 4..r + 12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(parse_zip64_end_record(&bad, r).unwrap_err(), Zip64Error::Truncated);
}

#[test]
fn eocd_search_bounds() {
    assert_eq!(find_classic_eocd(&[]).unwrap_err(), Zip64Error::Truncated);
    assert_eq!(find_classic_eocd(&[0u8; 100]).unwrap_err(), Zip64Error::Invalid);
    // Comment length pointing past EOF is not accepted.
    let mut b = build_stored(&[], Tail::Classic);
    let n = b.len();
    b[n - 2] = 5;
    assert!(find_classic_eocd(&b).is_err());
    // A max-length comment is found.
    let mut b = build_stored(&[], Tail::Classic);
    let n = b.len();
    b[n - 2..].copy_from_slice(&0xffffu16.to_le_bytes());
    b.extend(std::iter::repeat_n(b'c', 0xffff));
    let e = find_classic_eocd(&b).unwrap();
    assert_eq!(e.comment.len(), 0xffff);
}

#[test]
fn zip64_extra_field_order() {
    let mut data = Vec::new();
    put64(&mut data, 1);
    put64(&mut data, 2);
    put64(&mut data, 3);
    put32(&mut data, 4);
    let all = Zip64Needs { uncompressed_size: true, compressed_size: true, local_header_offset: true, disk_start: true };
    let z = parse_zip64_extra(&data, all).unwrap();
    assert_eq!((z.uncompressed_size, z.compressed_size, z.local_header_offset, z.disk_start), (Some(1), Some(2), Some(3), Some(4)));
    // Only the offset is saturated: it is the first field present.
    let z = parse_zip64_extra(&data, Zip64Needs::central(5, 6, 0xffff_ffff, 0)).unwrap();
    assert_eq!(z.local_header_offset, Some(1));
    assert_eq!(z.uncompressed_size, None);
    // Local headers carry both sizes when either is saturated.
    let needs = Zip64Needs::local(0xffff_ffff, 7);
    assert!(needs.uncompressed_size && needs.compressed_size);
    assert!(!Zip64Needs::local(1, 2).any());
    assert_eq!(parse_zip64_extra(&data[..15], all).unwrap_err(), Zip64Error::Truncated);
    assert_eq!(parse_zip64_extra(&data[..27], all).unwrap_err(), Zip64Error::Truncated);
}
