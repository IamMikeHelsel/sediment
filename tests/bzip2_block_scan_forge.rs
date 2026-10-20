use sediment_engine::bzip2_block_scan::{scan_all, scan_stream, Bz2Block, Bz2ScanError};

// Fixtures: gen/make_fixtures.py (Python bz2). Offsets: bzip2recover 1.0.8 ("runs from S" -> magic at S-48);
// CRCs: CRC-32/BZIP2 of each recovered block; stored combined CRC read from the file (gen/expected.py).
const THREE: &[u8] = include_bytes!("bzip2_block_scan_fixtures/three_blocks.bz2");
const TWO: &[u8] = include_bytes!("bzip2_block_scan_fixtures/two_streams.bz2");
const EMPTY: &[u8] = include_bytes!("bzip2_block_scan_fixtures/empty.bz2");
const UNALIGNED: &[u8] = include_bytes!("bzip2_block_scan_fixtures/unaligned.bz2");

fn b(bit_offset: u64, stored_crc: u32) -> Bz2Block {
    Bz2Block { bit_offset, stored_crc }
}

#[test]
fn three_blocks_level_1() {
    let s = scan_stream(THREE, 0, 100).unwrap();
    assert_eq!(s.level, 1);
    assert_eq!(s.blocks, vec![b(32, 0x4F470E9B), b(99021, 0xC3790AB8), b(197854, 0x158AB2DB)]);
    assert_eq!(s.eos_bit_offset, 248856);
    assert_eq!((s.stored_combined_crc, s.computed_combined_crc), (0xAE649DC7, 0xAE649DC7));
    assert_eq!(s.end_byte, THREE.len());
    assert_eq!(scan_all(THREE, 100).unwrap(), vec![s]);
}

#[test]
fn two_concatenated_streams() {
    let v = scan_all(TWO, 100).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!((v[0].byte_offset, v[0].level, v[0].end_byte), (0, 9, 42));
    assert_eq!(v[0].blocks, vec![b(32, 0xC1C080E2)]);
    assert_eq!((v[0].eos_bit_offset, v[0].stored_combined_crc, v[0].computed_combined_crc), (256, 0xC1C080E2, 0xC1C080E2));
    assert_eq!((v[1].byte_offset, v[1].level, v[1].end_byte), (42, 1, TWO.len()));
    assert_eq!(v[1].blocks, vec![b(368, 0x5101FD8E), b(98874, 0xB95C7024)]);
    assert_eq!((v[1].eos_bit_offset, v[1].stored_combined_crc, v[1].computed_combined_crc), (120304, 0x1B5F8B38, 0x1B5F8B38));
    assert_eq!(scan_stream(TWO, 42, 9).unwrap(), v[1]);
}

#[test]
fn empty_stream_and_trailing_garbage() {
    let s = scan_stream(EMPTY, 0, 0).unwrap();
    assert!(s.blocks.is_empty());
    assert_eq!((s.eos_bit_offset, s.stored_combined_crc, s.computed_combined_crc, s.end_byte), (32, 0, 0, 14));
    let mut d = TWO.to_vec();
    d.extend_from_slice(b"BZx9 trailing junk");
    assert_eq!(scan_all(&d, 100).unwrap().len(), 2);
    let mut d = EMPTY.to_vec();
    d.extend_from_slice(b"BZ");
    assert_eq!(scan_all(&d, 100).unwrap().len(), 1);
}

#[test]
fn unaligned_stream_ends_round_up() {
    let v = scan_all(UNALIGNED, 10).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!((v[0].blocks.clone(), v[0].eos_bit_offset, v[0].end_byte), (vec![b(32, 0x44F71378)], 297, 48));
    assert_eq!(v[0].stored_combined_crc, 0x44F71378);
    assert_eq!((v[1].byte_offset, v[1].blocks.clone(), v[1].eos_bit_offset, v[1].end_byte), (48, vec![b(416, 0x19939B6B)], 595, 85));
    assert_eq!(v[1].computed_combined_crc, 0x19939B6B);
}

#[test]
fn stored_crc_corruption_is_visible() {
    let mut d = THREE.to_vec();
    d[10] ^= 0xFF; // bits 80..88 = top byte of block 0's CRC
    let s = scan_stream(&d, 0, 100).unwrap();
    assert_eq!(s.blocks[0].stored_crc, 0x4F470E9B ^ 0xFF00_0000);
    assert_eq!(s.stored_combined_crc, 0xAE649DC7);
    assert_ne!(s.computed_combined_crc, s.stored_combined_crc);
}

#[test]
fn errors() {
    assert_eq!(scan_all(b"", 10), Err(Bz2ScanError::Truncated));
    assert_eq!(scan_all(b"BZh", 10), Err(Bz2ScanError::Truncated));
    assert_eq!(scan_all(b"BZh0\x31\x41\x59\x26\x53\x59", 10), Err(Bz2ScanError::BadHeader));
    assert_eq!(scan_all(b"PK\x03\x04 not bzip2", 10), Err(Bz2ScanError::BadHeader));
    assert_eq!(scan_all(&THREE[..7], 10), Err(Bz2ScanError::Truncated));
    assert_eq!(scan_all(&THREE[..12], 10), Err(Bz2ScanError::Truncated)); // magic but no full CRC
    assert_eq!(scan_all(&THREE[..20000], 10), Err(Bz2ScanError::MissingEndOfStream));
    assert_eq!(scan_all(&THREE[..THREE.len() - 2], 10), Err(Bz2ScanError::Truncated)); // EOS without full CRC
    assert_eq!(scan_all(THREE, 2), Err(Bz2ScanError::LimitExceeded));
    assert_eq!(scan_all(TWO, 2), Err(Bz2ScanError::LimitExceeded));
    assert_eq!(scan_stream(THREE, THREE.len(), 9), Err(Bz2ScanError::Truncated));
    let mut seed = 7u32;
    for _ in 0..300 {
        let mut d = TWO[..400].to_vec();
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        d[4 + (seed as usize >> 8) % 396] ^= (seed >> 3) as u8;
        let _ = scan_all(&d, 4);
    }
}
