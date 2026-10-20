// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z PPMd (030401) and BCJ2 (0303011B, four-input coder graph) read tests.
//!
//! Fixtures `fixtures/sevenz/oracle/{ppmd,bcj2}_*.7z` were made by the pinned
//! 7-Zip 26.04 `7zz` over an x86-64 ELF object and a text file (recipe:
//! `tests/gen/sevenz_ppmd_bcj2_oracle.sh`); their `l -slt` listings give the
//! expected sizes and CRC32s.

use sediment_engine::archive_open::SevenZCodecs;
use sediment_engine::bcj2::{BCJ2_METHOD_ID_BYTES, Bcj2Error, bcj2_decode};
use sediment_engine::crc32::crc32;
use sediment_engine::sevenz_header::{SevenZLimits, SevenZReadError};
use sediment_engine::sevenz_read::SevenZArchive;

macro_rules! fx {
    ($p:literal) => {
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz/oracle/", $p, ".7z")).as_slice(),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz/oracle/", $p, ".slt.txt")),
        )
    };
}

const FIXTURES: [(&[u8], &str); 4] = [fx!("ppmd_solid"), fx!("ppmd_o8_nonsolid"), fx!("bcj2_solid"), fx!("bcj2_lzma_nohc")];

fn codecs() -> SevenZCodecs {
    SevenZCodecs { max_output: 1 << 30 }
}

/// `Path -> (Size, CRC)` for files in a `7zz l -slt` listing.
fn slt_files(s: &str) -> Vec<(String, u64, u32)> {
    let body = s.split("\n----------\n").nth(1).expect("slt item section");
    let mut out = Vec::new();
    for blk in body.split("\n\n").filter(|b| !b.trim().is_empty()) {
        let get = |k: &str| blk.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(" = "))).unwrap_or("");
        out.push((get("Path").to_string(), get("Size").parse().unwrap(), u32::from_str_radix(get("CRC"), 16).unwrap()));
    }
    out
}

#[test]
fn oracle_fixtures_extract_with_matching_crcs() {
    for (bytes, slt) in FIXTURES {
        let a = SevenZArchive::open(bytes, &codecs(), SevenZLimits::default()).unwrap();
        let want = slt_files(slt);
        assert_eq!(want.len(), 2);
        for (name, size, crc) in want {
            let i = a.entries().iter().position(|e| e.name == name).unwrap();
            let data = a.extract_entry(i, &codecs()).unwrap();
            assert_eq!(data.len() as u64, size, "{name}");
            assert_eq!(crc32(&data), crc, "{name}");
        }
    }
}

#[test]
fn bcj2_fixture_uses_four_input_graph_with_converted_calls() {
    for (bytes, _) in &FIXTURES[2..] {
        let a = SevenZArchive::open(bytes, &codecs(), SevenZLimits::default()).unwrap();
        let f = &a.folders()[0];
        let bcj2 = f.coders.iter().find(|c| c.method_id == BCJ2_METHOD_ID_BYTES).expect("BCJ2 coder");
        assert_eq!((bcj2.num_in_streams, bcj2.num_out_streams), (4, 1));
        assert_eq!(f.coders.len(), 4);
        assert_eq!(f.bind_pairs.len(), 3);
        assert_eq!(f.packed_streams.len(), 4);
        // The call stream (an LZMA coder output) is non-empty: real E8 operands were moved.
        let call_out = f.bind_pairs.iter().map(|b| f.unpack_sizes[b.out_index]).collect::<Vec<_>>();
        assert!(call_out.iter().filter(|&&s| s > 0).count() >= 2, "{call_out:?}");
    }
}

#[test]
fn ppmd_fixture_properties() {
    let (bytes, _) = FIXTURES[1];
    let a = SevenZArchive::open(bytes, &codecs(), SevenZLimits::default()).unwrap();
    let c = &a.folders()[0].coders[0];
    assert_eq!(c.method_id, [3, 4, 1]);
    assert_eq!(c.properties.len(), 5);
    assert_eq!(c.properties[0], 8);
}

#[test]
fn corrupted_fixtures_never_panic() {
    for (bytes, _) in FIXTURES {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for round in 0..60 {
            let mut b = bytes.to_vec();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            if round % 3 == 0 {
                b.truncate((seed as usize) % b.len());
            } else {
                for k in 0..4 {
                    let pos = ((seed >> (k * 13)) as usize) % b.len();
                    b[pos] ^= 1 << ((seed >> (k * 3)) & 7);
                }
            }
            if let Ok(a) = SevenZArchive::open(&b, &codecs(), SevenZLimits::default()) {
                for i in 0..a.entries().len() {
                    let _ = a.extract_entry(i, &codecs());
                }
            }
        }
    }
}

#[test]
fn bad_ppmd_properties_are_rejected() {
    use sediment_engine::sevenz_header::FolderDecoder;
    let c = codecs();
    for props in [&[][..], &[6, 0, 0, 16][..], &[1, 0, 0, 16, 0][..], &[6, 0, 0, 0, 0][..], &[6, 0, 0, 16, 0, 0][..]] {
        assert_eq!(c.decode(&[3, 4, 1], props, &[0; 16], 4), Err(SevenZReadError::DecoderFailed), "{props:?}");
    }
}

// ---------------------------------------------------------------------------
// BCJ2 round trip through a minimal test-side encoder
// ---------------------------------------------------------------------------

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out: Vec::new() }
    }
    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }
    fn bit(&mut self, prob: &mut u16, bit: bool) {
        let bound = (self.range >> 11) * u32::from(*prob);
        if !bit {
            self.range = bound;
            *prob += (2048 - *prob) >> 5;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
            *prob -= *prob >> 5;
        }
        while self.range < (1 << 24) {
            self.range <<= 8;
            self.shift_low();
        }
    }
    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

fn bcj2_encode(data: &[u8], choose: impl Fn(usize) -> bool) -> [Vec<u8>; 4] {
    let (mut main, mut call, mut jump) = (Vec::new(), Vec::new(), Vec::new());
    let mut rc = RangeEncoder::new();
    let mut probs = [1024u16; 258];
    let mut prev = 0u8;
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        main.push(b);
        let jmp = (b & 0xFE) == 0xE8 || (prev == 0x0F && (b & 0xF0) == 0x80);
        if !jmp || i + 1 == data.len() {
            prev = b;
            i += 1;
            continue;
        }
        let idx = match b {
            0xE8 => prev as usize,
            0xE9 => 256,
            _ => 257,
        };
        if i + 5 <= data.len() && choose(i) {
            rc.bit(&mut probs[idx], true);
            let rel = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let abs = rel.wrapping_add((i + 5) as u32).to_be_bytes();
            if b == 0xE8 { &mut call } else { &mut jump }.extend_from_slice(&abs);
            prev = data[i + 4];
            i += 5;
        } else {
            rc.bit(&mut probs[idx], false);
            prev = b;
            i += 1;
        }
    }
    [main, call, jump, rc.finish()]
}

#[test]
fn bcj2_round_trip_against_test_encoder() {
    let mut data = Vec::new();
    let mut s = 7u32;
    for _ in 0..20_000 {
        s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let r = (s >> 16) as u8;
        data.push(match r % 7 {
            0 => 0xE8,
            1 => 0xE9,
            2 => 0x0F,
            3 => 0x85,
            _ => r,
        });
    }
    data.extend_from_slice(&[0x0F, 0x84, 1, 2]); // Jcc too short to convert at the end
    data.push(0xE8); // candidate opcode as the very last byte
    for mode in 0..3 {
        let choose = |i: usize| match mode {
            0 => false,
            1 => true,
            _ => i % 3 != 0,
        };
        let [main, call, jump, rc] = bcj2_encode(&data, choose);
        assert_eq!(bcj2_decode(&main, &call, &jump, &rc, data.len()).unwrap(), data, "mode {mode}");
        if mode == 1 {
            assert!(!call.is_empty() && !jump.is_empty());
            assert_eq!(bcj2_decode(&main, &call[..call.len() - 1], &jump, &rc, data.len()), Err(Bcj2Error::UnexpectedEof));
        }
        assert!(bcj2_decode(&main[..main.len() / 2], &call, &jump, &rc, data.len()).is_err());
    }
}

#[test]
fn bcj2_random_streams_never_panic() {
    let mut s = 99u64;
    let mut next = || {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (s >> 33) as u8
    };
    for _ in 0..500 {
        let mut stream = |n: usize| (0..n).map(|_| next()).collect::<Vec<u8>>();
        let main = stream(64);
        let call = stream(16);
        let jump = stream(9);
        let mut rc = stream(12);
        rc[0] = 0;
        let r = bcj2_decode(&main, &call, &jump, &rc, 80);
        if let Ok(v) = r {
            assert_eq!(v.len(), 80);
        }
    }
}
