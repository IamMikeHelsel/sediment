// SPDX-License-Identifier: MIT OR Apache-2.0
//! PPMd7 (7z PPMd, method 030401) tests. Oracle fixtures come from a pinned
//! 7zz (see tests/gen/ppmd.py and tests/fixtures/ppmd/manifest.txt).
mod ppmd_support;

use ppmd_support::*;
use sediment_engine::ppmd7::*;

const MEM_CAP: u64 = 1 << 28;

fn props(order: u32, mem: u32) -> Ppmd7Properties {
    Ppmd7Properties { order: order as u8, memory_size: mem }
}

fn roundtrip(p: Ppmd7Properties, data: &[u8]) -> Vec<u8> {
    let enc = encode(p, data, false, MEM_CAP).unwrap();
    let dec = decode(p, &enc, data.len(), MEM_CAP).unwrap();
    assert!(dec == data, "roundtrip mismatch order {} mem {} len {}", p.order, p.memory_size, data.len());
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
    for c in load_cases("7z") {
        let got = decode(props(c.order, c.mem), &c.stream, c.input.len(), MEM_CAP)
            .unwrap_or_else(|e| panic!("{}: {:?}", c.name, e));
        assert!(got == c.input, "{}: output mismatch", c.name);
    }
}

#[test]
fn oracle_encode_matches_byte_for_byte() {
    for c in load_cases("7z") {
        let enc = encode(props(c.order, c.mem), &c.input, false, MEM_CAP).unwrap();
        assert!(enc == c.stream, "{}: encoder output differs", c.name);
    }
}

#[test]
fn oracle_streams_reject_wrong_properties_or_sizes() {
    let c = load_cases("7z").into_iter().find(|c| c.name == "7z_text_o6").unwrap();
    // Wrong order decodes garbage or fails, never panics, never yields the input.
    for o in [2u32, 5, 7, 32] {
        if let Ok(v) = decode(props(o, c.mem), &c.stream, c.input.len(), MEM_CAP) {
            assert!(v != c.input);
        }
    }
    // Asking for more output than encoded runs off the end of the stream.
    assert!(decode(props(c.order, c.mem), &c.stream, c.input.len() + 100, MEM_CAP).is_err());
}

#[test]
fn roundtrip_all_orders() {
    let data = mixed_input(100, 12_000);
    for order in 2..=64u32 {
        roundtrip(props(order, 1 << 20), &data);
    }
}

#[test]
fn roundtrip_memory_sizes() {
    let data = mixed_input(200, 40_000);
    for mem in [PPMD7_MIN_MEM_SIZE, 2049, 3000, 4095, 1 << 13, 20_000, 1 << 16, 100_003, 1 << 20, 16 << 20] {
        for order in [2u32, 3, 6, 16, 32, 64] {
            roundtrip(props(order, mem), &data);
        }
    }
}

#[test]
fn roundtrip_edge_inputs() {
    let p = props(6, 1 << 16);
    let enc = roundtrip(p, b"");
    assert_eq!(enc.len(), 5);
    assert_eq!(enc[0], 0);
    roundtrip(p, b"a");
    roundtrip(p, &[0u8; 5000]);
    roundtrip(p, &[0xFFu8; 5000]);
    let all: Vec<u8> = (0..=255u8).cycle().take(256 * 40).collect();
    roundtrip(p, &all);
    let rev: Vec<u8> = (0..=255u8).rev().cycle().take(256 * 3).collect();
    roundtrip(props(64, PPMD7_MIN_MEM_SIZE), &rev);
    let mut r = Lcg::new(9);
    let noise: Vec<u8> = (0..30_000).map(|_| r.next() as u8).collect();
    for order in [2u32, 8, 64] {
        roundtrip(props(order, PPMD7_MIN_MEM_SIZE), &noise);
        roundtrip(props(order, 1 << 18), &noise);
    }
    // Long runs push RunLength far positive.
    let mut runs = vec![b'x'; 70_000];
    runs.extend(b"yz".repeat(2000));
    roundtrip(props(4, 1 << 16), &runs);
}

#[test]
fn compresses_redundant_text() {
    let data = gen_text(5, 50_000, 60);
    let enc = roundtrip(props(6, 16 << 20), &data);
    assert!(enc.len() < data.len() / 3, "{} vs {}", enc.len(), data.len());
}

#[test]
fn end_marker_roundtrip() {
    let data = mixed_input(300, 5000);
    for order in [2u32, 6, 64] {
        let p = props(order, 1 << 16);
        let enc = encode(p, &data, true, MEM_CAP).unwrap();
        assert_eq!(decode_to_end_marker(p, &enc, data.len(), MEM_CAP).unwrap(), data);
        assert_eq!(
            decode_to_end_marker(p, &enc, data.len() - 1, MEM_CAP),
            Err(Ppmd7Error::LimitExceeded)
        );
        // A sized decode that hits the marker early is an error.
        assert!(decode(p, &enc, data.len() + 1, MEM_CAP).is_err());
    }
    let p = props(6, 1 << 16);
    let enc = encode(p, b"", true, MEM_CAP).unwrap();
    assert_eq!(decode_to_end_marker(p, &enc, 0, MEM_CAP).unwrap(), b"");
    // No end marker: decoding to a marker must fail rather than run forever.
    let enc = encode(p, &data, false, MEM_CAP).unwrap();
    assert!(decode_to_end_marker(p, &enc, 1 << 20, MEM_CAP).is_err());
}

#[test]
fn properties() {
    let p = parse_properties(&[6, 0, 0, 0, 1]).unwrap();
    assert_eq!(p, props(6, 1 << 24));
    assert_eq!(p.to_bytes(), [6, 0, 0, 0, 1]);
    assert_eq!(parse_properties(&[6, 0, 0, 0]), Err(Ppmd7Error::UnexpectedEof));
    assert_eq!(parse_properties(&[6, 0, 0, 0, 1, 0]), Err(Ppmd7Error::InvalidProperties));
    assert_eq!(parse_properties(&[1, 0, 0, 0, 1]), Err(Ppmd7Error::InvalidProperties));
    assert_eq!(parse_properties(&[65, 0, 0, 0, 1]), Err(Ppmd7Error::InvalidProperties));
    assert_eq!(parse_properties(&[6, 0xFF, 0x07, 0, 0]), Err(Ppmd7Error::InvalidProperties));
    assert!(parse_properties(&[6, 0x00, 0x08, 0, 0]).is_ok());
    assert_eq!(parse_properties(&[6, 0xFF, 0xFF, 0xFF, 0xFF]), Err(Ppmd7Error::InvalidProperties));
    assert!(parse_properties(&[64, 0xDB, 0xFF, 0xFF, 0xFF]).is_ok());
    assert_eq!(encode(props(1, 1 << 16), b"x", false, MEM_CAP), Err(Ppmd7Error::InvalidProperties));
    assert_eq!(decode(props(6, 100), &[0; 5], 1, MEM_CAP), Err(Ppmd7Error::InvalidProperties));
}

#[test]
fn memory_limit_is_enforced_before_allocation() {
    let p = props(6, PPMD7_MAX_MEM_SIZE);
    assert_eq!(decode(p, &[0; 5], 1, 1 << 20), Err(Ppmd7Error::LimitExceeded));
    assert_eq!(encode(p, b"abc", false, 1 << 20), Err(Ppmd7Error::LimitExceeded));
    let p = props(6, 1 << 20);
    assert_eq!(decode(p, &[0; 5], 1, (1 << 20) - 1), Err(Ppmd7Error::LimitExceeded));
}

#[test]
fn bad_stream_header() {
    let p = props(6, 1 << 16);
    // First byte of the range coder must be zero.
    assert_eq!(decode(p, &[1, 0, 0, 0, 0, 0], 1, MEM_CAP), Err(Ppmd7Error::CorruptData));
    assert_eq!(decode(p, &[0, 0xFF, 0xFF, 0xFF, 0xFF], 1, MEM_CAP), Err(Ppmd7Error::CorruptData));
    for n in 0..5 {
        assert_eq!(decode(p, &[0; 5][..n], 0, MEM_CAP), Err(Ppmd7Error::UnexpectedEof));
    }
}

#[test]
fn truncation_is_detected() {
    let data = gen_text(77, 3000, 100);
    let p = props(8, 1 << 16);
    let enc = encode(p, &data, false, MEM_CAP).unwrap();
    for cut in 0..enc.len() {
        let r = decode(p, &enc[..cut], data.len(), MEM_CAP);
        assert!(r.is_err(), "prefix {cut} of {} decoded", enc.len());
    }
}

#[test]
fn corrupted_streams_never_panic() {
    let data = mixed_input(400, 4000);
    let mut r = Lcg::new(1234);
    for (order, mem) in [(2u32, PPMD7_MIN_MEM_SIZE), (6, 1 << 16), (64, 1 << 14)] {
        let p = props(order, mem);
        let enc = encode(p, &data, false, MEM_CAP).unwrap();
        let mut detected = 0;
        for _ in 0..200 {
            let mut bad = enc.clone();
            let flips = 1 + r.next() % 4;
            for _ in 0..flips {
                let i = 1 + (r.next() as usize) % (bad.len() - 1);
                bad[i] ^= 1 << (r.next() % 8);
            }
            match decode(p, &bad, data.len(), MEM_CAP) {
                Ok(v) => assert_eq!(v.len(), data.len()),
                Err(_) => detected += 1,
            }
            let _ = decode_to_end_marker(p, &bad, 8000, MEM_CAP);
        }
        assert!(detected > 150, "only {detected} corruptions detected");
    }
}

#[test]
fn random_streams_never_panic() {
    let mut r = Lcg::new(99);
    for round in 0..300u32 {
        let len = (r.next() % 600) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
        if !buf.is_empty() && round % 2 == 0 {
            buf[0] = 0;
        }
        let order = 2 + (r.next() % 63) as u32;
        let mem = PPMD7_MIN_MEM_SIZE + (r.next() % 70_000) as u32;
        let p = props(order, mem);
        let _ = decode(p, &buf, (r.next() % 3000) as usize, MEM_CAP);
        let _ = decode_to_end_marker(p, &buf, 3000, MEM_CAP);
    }
}
