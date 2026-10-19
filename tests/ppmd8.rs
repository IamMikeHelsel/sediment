// SPDX-License-Identifier: MIT OR Apache-2.0
//! PPMd8 (ZIP method 98) tests. Oracle fixtures come from a pinned 7zz (see
//! tests/gen/ppmd.py and tests/fixtures/ppmd/manifest.txt).
mod ppmd_support;

use ppmd_support::*;
use sediment_engine::ppmd8::*;

const MEM_CAP: u64 = 1 << 28;

fn props(order: u32, mb: u32, restore: RestoreMethod) -> Ppmd8Properties {
    Ppmd8Properties { order: order as u8, memory_mb: mb as u16, restore }
}

fn roundtrip(p: Ppmd8Properties, data: &[u8]) -> Vec<u8> {
    let enc = encode_zip(p, data, MEM_CAP).unwrap();
    let dec = decode_zip(&enc, data.len(), MEM_CAP).unwrap();
    assert!(dec == data, "roundtrip mismatch {:?} len {}", p, data.len());
    // Raw stream without an end marker decodes too.
    let raw = encode(p, data, false, MEM_CAP).unwrap();
    assert_eq!(decode(p, &raw, data.len(), MEM_CAP).unwrap(), data);
    enc
}

fn mixed_input(seed: u64, n: usize) -> Vec<u8> {
    let mut v = gen_text(seed, n / 2, 120);
    v.extend(gen_binary(seed + 1, n / 4));
    v.extend(gen_cycle(seed + 2, n - v.len()));
    v
}

#[test]
fn oracle_decode() {
    for c in load_cases("zip") {
        let p = parse_zip_header(&c.stream).unwrap();
        assert_eq!(p.order as u32, c.order, "{}", c.name);
        assert_eq!(p.memory_mb as u32, c.mem, "{}", c.name);
        let want = if c.restore == 0 { RestoreMethod::Restart } else { RestoreMethod::CutOff };
        assert_eq!(p.restore, want, "{}", c.name);
        let got = decode_zip(&c.stream, c.input.len(), MEM_CAP).unwrap_or_else(|e| panic!("{}: {:?}", c.name, e));
        assert!(got == c.input, "{}: output mismatch", c.name);
        // 7-Zip writes an end marker, so the marker-terminated API works too.
        let got = decode_to_end_marker(p, &c.stream[2..], c.input.len(), MEM_CAP).unwrap();
        assert!(got == c.input, "{}: end-marker decode mismatch", c.name);
    }
}

#[test]
fn oracle_encode_matches_byte_for_byte() {
    for c in load_cases("zip") {
        let p = parse_zip_header(&c.stream).unwrap();
        let enc = encode_zip(p, &c.input, MEM_CAP).unwrap();
        assert!(enc == c.stream, "{}: encoder output differs", c.name);
    }
}

#[test]
fn roundtrip_all_orders_and_methods() {
    let data = mixed_input(10, 12_000);
    for order in 2..=16u32 {
        for r in [RestoreMethod::Restart, RestoreMethod::CutOff] {
            roundtrip(props(order, 1, r), &data);
        }
    }
}

#[test]
fn roundtrip_memory_sizes() {
    let data = mixed_input(20, 20_000);
    for mb in [1u32, 2, 3, 17, 64] {
        for order in [2u32, 6, 16] {
            roundtrip(props(order, mb, RestoreMethod::CutOff), &data);
        }
    }
}

#[test]
fn roundtrip_under_memory_pressure() {
    // Order-16 text exhausts 1 MiB repeatedly, exercising restart, cut-off,
    // ExpandTextArea and block gluing on both encoder and decoder.
    let data = gen_text(31, 160_000, 40);
    for r in [RestoreMethod::Restart, RestoreMethod::CutOff] {
        roundtrip(props(16, 1, r), &data);
    }
    let mut r = Lcg::new(5);
    let noise: Vec<u8> = (0..60_000).map(|_| r.next() as u8).collect();
    roundtrip(props(12, 1, RestoreMethod::CutOff), &noise);
}

#[test]
fn roundtrip_edge_inputs() {
    let p = props(6, 1, RestoreMethod::Restart);
    roundtrip(p, b"");
    roundtrip(p, b"a");
    roundtrip(p, &[0u8; 5000]);
    roundtrip(p, &[0xFFu8; 5000]);
    let all: Vec<u8> = (0..=255u8).cycle().take(256 * 40).collect();
    roundtrip(p, &all);
    roundtrip(props(16, 1, RestoreMethod::CutOff), &all);
    let mut runs = vec![b'x'; 70_000];
    runs.extend(b"yz".repeat(2000));
    roundtrip(props(4, 1, RestoreMethod::Restart), &runs);
}

#[test]
fn compresses_redundant_text() {
    let data = gen_text(5, 50_000, 60);
    let enc = roundtrip(props(6, 8, RestoreMethod::Restart), &data);
    assert!(enc.len() < data.len() / 3, "{} vs {}", enc.len(), data.len());
}

#[test]
fn zip_header() {
    let p = parse_zip_header(&[0x07, 0x10]).unwrap();
    assert_eq!(p, props(8, 1, RestoreMethod::CutOff));
    assert_eq!(p.zip_header(), [0x07, 0x10]);
    assert_eq!(p.memory_size(), 1 << 20);
    let p = parse_zip_header(&[0xFF, 0x0F]).unwrap();
    assert_eq!(p, props(16, 256, RestoreMethod::Restart));
    assert_eq!(parse_zip_header(&[0x07]), Err(Ppmd8Error::UnexpectedEof));
    // Order 1 is below the minimum.
    assert_eq!(parse_zip_header(&[0x00, 0x00]), Err(Ppmd8Error::InvalidProperties));
    assert_eq!(parse_zip_header(&[0x07, 0x20]), Err(Ppmd8Error::UnsupportedProperties));
    assert_eq!(parse_zip_header(&[0x07, 0x30]), Err(Ppmd8Error::InvalidProperties));
    assert_eq!(parse_zip_header(&[0x07, 0xF0]), Err(Ppmd8Error::InvalidProperties));
    assert_eq!(decode_zip(&[], 0, MEM_CAP), Err(Ppmd8Error::UnexpectedEof));
    assert_eq!(
        encode_zip(props(17, 1, RestoreMethod::Restart), b"x", MEM_CAP),
        Err(Ppmd8Error::InvalidProperties)
    );
    assert_eq!(
        encode_zip(props(6, 0, RestoreMethod::Restart), b"x", MEM_CAP),
        Err(Ppmd8Error::InvalidProperties)
    );
    assert_eq!(
        encode_zip(props(6, 257, RestoreMethod::Restart), b"x", MEM_CAP),
        Err(Ppmd8Error::InvalidProperties)
    );
}

#[test]
fn memory_limit_is_enforced_before_allocation() {
    let p = props(6, 256, RestoreMethod::Restart);
    assert_eq!(decode(p, &[0; 4], 1, 1 << 20), Err(Ppmd8Error::LimitExceeded));
    assert_eq!(encode(p, b"abc", true, 1 << 20), Err(Ppmd8Error::LimitExceeded));
    assert_eq!(decode_zip(&[0xF5, 0x0F, 0, 0, 0, 0], 1, 255 << 20), Err(Ppmd8Error::LimitExceeded));
}

#[test]
fn end_marker_api() {
    let data = mixed_input(30, 5000);
    let p = props(6, 1, RestoreMethod::CutOff);
    let enc = encode(p, &data, true, MEM_CAP).unwrap();
    assert_eq!(decode_to_end_marker(p, &enc, data.len(), MEM_CAP).unwrap(), data);
    assert_eq!(decode_to_end_marker(p, &enc, data.len() - 1, MEM_CAP), Err(Ppmd8Error::LimitExceeded));
    assert!(decode(p, &enc, data.len() + 1, MEM_CAP).is_err());
    let raw = encode(p, &data, false, MEM_CAP).unwrap();
    assert!(decode_to_end_marker(p, &raw, 1 << 20, MEM_CAP).is_err());
    // Trailing bytes that are not an end marker are rejected.
    let mut extra = raw.clone();
    extra.extend_from_slice(&[0x55; 8]);
    assert!(decode(p, &extra, data.len(), MEM_CAP).is_err());
}

#[test]
fn truncation_is_detected() {
    let data = gen_text(77, 3000, 100);
    let p = props(8, 1, RestoreMethod::Restart);
    let enc = encode_zip(p, &data, MEM_CAP).unwrap();
    let mut ok = 0;
    for cut in 0..enc.len() {
        // A cut inside the trailing end marker cannot be noticed by a sized
        // decode; it must then still produce exactly the right bytes.
        match decode_zip(&enc[..cut], data.len(), MEM_CAP) {
            Err(_) => {}
            Ok(v) => {
                assert!(v == data, "prefix {cut} of {} decoded to wrong data", enc.len());
                ok += 1;
            }
        }
    }
    assert!(ok <= 4, "{ok} truncated prefixes accepted");
    // Without an end marker every truncation is an error.
    let raw = encode(p, &data, false, MEM_CAP).unwrap();
    for cut in 0..raw.len() {
        assert!(decode(p, &raw[..cut], data.len(), MEM_CAP).is_err(), "raw prefix {cut}");
    }
}

#[test]
fn corrupted_streams_never_panic() {
    let data = mixed_input(40, 4000);
    let mut r = Lcg::new(4321);
    for (order, restore) in [(2u32, RestoreMethod::Restart), (6, RestoreMethod::CutOff), (16, RestoreMethod::CutOff)] {
        let p = props(order, 1, restore);
        let enc = encode_zip(p, &data, MEM_CAP).unwrap();
        for _ in 0..150 {
            let mut bad = enc.clone();
            let flips = 1 + r.next() % 4;
            for _ in 0..flips {
                let i = 2 + (r.next() as usize) % (bad.len() - 2);
                bad[i] ^= 1 << (r.next() % 8);
            }
            if let Ok(v) = decode_zip(&bad, data.len(), MEM_CAP) {
                assert_eq!(v.len(), data.len());
            }
            let _ = decode_to_end_marker(p, &bad[2..], 8000, MEM_CAP);
        }
    }
}

#[test]
fn random_streams_never_panic() {
    let mut r = Lcg::new(77);
    for _ in 0..120 {
        let len = (r.next() % 600) as usize;
        let buf: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
        let order = 2 + (r.next() % 15) as u32;
        let restore = if r.next().is_multiple_of(2) { RestoreMethod::Restart } else { RestoreMethod::CutOff };
        let p = props(order, 1, restore);
        let _ = decode(p, &buf, (r.next() % 3000) as usize, MEM_CAP);
        let _ = decode_to_end_marker(p, &buf, 3000, MEM_CAP);
    }
}
