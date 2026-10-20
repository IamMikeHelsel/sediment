use sediment_engine::ihex_decode::{HexImage, IhexError, Segment, decode_ihex};

// Records generated with the spec checksum rule (see gen_vectors.py in the ticket).
const BASIC: &str = ":10010000000102030405060708090A0B0C0D0E0F77\n:10011000101112131415161718191A1B1C1D1E1F67\n:00000001FF\n";

fn dec(s: &str) -> Result<HexImage, IhexError> { decode_ihex(s.as_bytes(), 1 << 20) }

#[test]
fn basic_contiguous() {
    let img = dec(BASIC).unwrap();
    assert_eq!(img.segments, vec![Segment { address: 0x100, data: (0..32).collect() }]);
    assert_eq!((img.start_segment, img.start_linear), (None, None));
}

#[test]
fn classic_single_record() {
    let img = dec(":0300300002337A1E\n:00000001FF").unwrap();
    assert_eq!(img.segments, vec![Segment { address: 0x30, data: vec![0x02, 0x33, 0x7a] }]);
}

#[test]
fn extended_linear_and_start_linear() {
    let img = dec(":020000040800F2\n:04FFFE00AABBCCDDF1\n:0400000508000131BD\n:00000001FF\n").unwrap();
    assert_eq!(img.segments, vec![Segment { address: 0x0800_FFFE, data: vec![0xaa, 0xbb, 0xcc, 0xdd] }]);
    assert_eq!(img.start_linear, Some(0x0800_0131));
    assert_eq!(img.start_segment, None);
}

#[test]
fn extended_segment_and_start_segment() {
    let img = dec(":020000021000EC\n:020010000102EB\n:0400000312345678E5\n:00000001FF\n").unwrap();
    assert_eq!(img.segments, vec![Segment { address: 0x10010, data: vec![1, 2] }]);
    assert_eq!(img.start_segment, Some((0x1234, 0x5678)));
}

#[test]
fn unordered_records_are_sorted_and_merged() {
    let img = dec(":020010001011CD\n:020000000001FD\n:020002000203F7\n:00001200EE\n:00000001FF\n").unwrap();
    assert_eq!(
        img.segments,
        vec![Segment { address: 0, data: vec![0, 1, 2, 3] }, Segment { address: 0x10, data: vec![0x10, 0x11] }]
    );
}

#[test]
fn line_endings_case_and_blank_lines() {
    let s = "\r\n:10010000000102030405060708090a0b0c0d0e0f77  \r\n\n\t\n:10011000101112131415161718191a1b1c1d1e1f67\t\r\n:00000001ff";
    assert_eq!(dec(s).unwrap(), dec(BASIC).unwrap());
}

#[test]
fn eof_handling() {
    assert_eq!(dec(":0300300002337A1E\n"), Err(IhexError::MissingEof));
    assert_eq!(dec(""), Err(IhexError::MissingEof));
    assert_eq!(dec(":00000001FF\n:00000001FF\n"), Err(IhexError::DataAfterEof));
    assert_eq!(dec(":00000001FF\njunk\n"), Err(IhexError::DataAfterEof));
    assert!(dec(":00000001FF\n\r\n  \n").is_ok());
    assert_eq!(dec(":0100000100FE\n"), Err(IhexError::BadRecord));
}

#[test]
fn syntax_errors() {
    assert_eq!(dec("0300300002337A1E\n:00000001FF"), Err(IhexError::MissingColon));
    assert_eq!(dec(" :00000001FF"), Err(IhexError::MissingColon));
    assert_eq!(dec(":0300300002337A1\n:00000001FF"), Err(IhexError::BadHex));
    assert_eq!(dec(":0300300002337G1E\n:00000001FF"), Err(IhexError::BadHex));
    assert_eq!(dec(":\n:00000001FF"), Err(IhexError::BadLength));
    assert_eq!(dec(":00000001\n"), Err(IhexError::BadLength));
    assert_eq!(dec(":0400300002337A1E\n:00000001FF"), Err(IhexError::BadLength));
    assert_eq!(dec(":0300300002337A1F\n:00000001FF"), Err(IhexError::BadChecksum));
    assert_eq!(dec(":00000006FA\n:00000001FF"), Err(IhexError::BadRecordType));
}

#[test]
fn record_length_rules() {
    assert_eq!(dec(":0100000400FB\n:00000001FF"), Err(IhexError::BadRecord));
    // 02 with 3 data bytes
    assert_eq!(dec(":03000002000000FB\n:00000001FF"), Err(IhexError::BadRecord));
    // 05 with 2 data bytes
    assert_eq!(dec(":020000050000F9\n:00000001FF"), Err(IhexError::BadRecord));
}

#[test]
fn overlap_is_rejected() {
    assert_eq!(dec(":03000000000102FA\n:0100020009F4\n:00000001FF\n"), Err(IhexError::Overlap));
}

#[test]
fn top_of_address_space() {
    let img = dec(":02000004FFFFFC\n:04FFFC0001020304F7\n:00000001FF\n").unwrap();
    assert_eq!(img.segments, vec![Segment { address: 0xFFFF_FFFC, data: vec![1, 2, 3, 4] }]);
    assert_eq!(dec(":02000004FFFFFC\n:04FFFD0001020304F6\n:00000001FF\n"), Err(IhexError::AddressOverflow));
}

#[test]
fn output_limit() {
    assert_eq!(decode_ihex(BASIC.as_bytes(), 32).unwrap().segments[0].data.len(), 32);
    assert_eq!(decode_ihex(BASIC.as_bytes(), 31), Err(IhexError::LimitExceeded));
    assert_eq!(decode_ihex(b":00000001FF", 0).unwrap().segments, vec![]);
}

#[test]
fn garbage_never_panics() {
    let base = BASIC.as_bytes();
    let mut x: u32 = 5;
    for round in 0..500usize {
        let mut v = base.to_vec();
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        let i = (x as usize >> 3) % v.len();
        v[i] = (x >> 16) as u8;
        let _ = decode_ihex(&v[..v.len() - round % 7], 1 << 20);
    }
    let _ = decode_ihex(&[0xff, b':', 0xc3, b'\n'], 10);
}
