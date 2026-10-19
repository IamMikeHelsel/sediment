// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zstandard decoder tests against fixtures from tests/gen/zstd.py
//! (oracle: Python 3.14 `compression.zstd` / libzstd, plus hand-built
//! RFC 8878 frames).
use sediment_engine::hash_sha256::sha256;
use sediment_engine::zstd_decode::{ZstdError, decode_frame_into, decode_zstd, is_zstd, parse_frame_header};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zstd");
const CAP: usize = 1 << 24;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Case {
    name: String,
    expect: Result<(usize, String), String>,
}

fn manifest() -> Vec<Case> {
    let text = std::fs::read_to_string(format!("{DIR}/manifest.txt")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let expect = match f[1] {
                "OK" => Ok((f[2].parse().unwrap(), f[3].to_string())),
                _ => Err(f[2].to_string()),
            };
            Case { name: f[0].to_string(), expect }
        })
        .collect()
}

#[test]
fn manifest_matches_oracle() {
    let cases = manifest();
    assert!(cases.len() >= 50);
    let mut ok = 0;
    for c in &cases {
        let got = decode_zstd(&fixture(&c.name), CAP);
        match &c.expect {
            Ok((len, sha)) => {
                let d = got.unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
                assert_eq!(d.len(), *len, "{}", c.name);
                assert_eq!(&hex(&sha256(&d)), sha, "{}", c.name);
                ok += 1;
            }
            Err(variant) => {
                let e = got.expect_err(&c.name);
                assert_eq!(&format!("{e:?}"), variant, "{}", c.name);
            }
        }
    }
    assert!(ok >= 35);
}

#[test]
fn small_known_contents() {
    assert_eq!(decode_zstd(&fixture("hello.l3.zst"), CAP).unwrap(), b"Hello, zstd!\n");
    assert_eq!(decode_zstd(&fixture("empty.l3.zst"), CAP).unwrap(), b"");
    assert_eq!(decode_zstd(&fixture("one.l3.zst"), CAP).unwrap(), b"A");
    assert_eq!(decode_zstd(&fixture("hand.rle.zst"), CAP).unwrap(), vec![b'z'; 1000]);
    assert_eq!(decode_zstd(&fixture("zeros.l3.zst"), CAP).unwrap(), vec![0u8; 300_000]);
    let mixed = decode_zstd(&fixture("hand.mixed.zst"), CAP).unwrap();
    assert!(mixed.starts_with(b"Hello, zstd!\nqqq"));
    assert!(mixed.ends_with(b"abcabdtailrrrrrrr"));
}

#[test]
fn frame_headers() {
    let h = parse_frame_header(&fixture("text.win10.zst")).unwrap();
    assert_eq!(h.window_size, 1024);
    assert!(!h.single_segment);
    assert!(h.has_checksum);
    let h = parse_frame_header(&fixture("text.nosize.zst")).unwrap();
    assert_eq!(h.content_size, None);
    let h = parse_frame_header(&fixture("hand.raw.zst")).unwrap();
    assert!(h.single_segment);
    assert_eq!(h.content_size, Some(13));
    assert_eq!(h.window_size, 13);
    assert_eq!(h.header_size, 9);
    let h = parse_frame_header(&fixture("dict.zst")).unwrap();
    assert_ne!(h.dictionary_id, 0);
    assert_eq!(parse_frame_header(b"\x28\xb5\x2f"), Err(ZstdError::Truncated));
    assert_eq!(parse_frame_header(b"\x28\xb5\x2f\xfd"), Err(ZstdError::Truncated));
    assert_eq!(parse_frame_header(b"PK\x03\x04\x00"), Err(ZstdError::BadMagic));
}

#[test]
fn frame_into_reports_consumed_length() {
    let a = fixture("multi.zst");
    let mut out = Vec::new();
    let used = decode_frame_into(&a, &mut out, CAP).unwrap();
    assert_eq!(out, b"Hello, zstd!\n");
    let used2 = decode_frame_into(&a[used..], &mut out, CAP).unwrap();
    assert_eq!(used + used2, a.len());
    assert_eq!(out.len(), 13 + 24_000);
}

#[test]
fn output_limit() {
    let f = fixture("text.l3.zst");
    assert_eq!(decode_zstd(&f, 23_999), Err(ZstdError::LimitExceeded));
    assert_eq!(decode_zstd(&f, 24_000).unwrap().len(), 24_000);
    // No content size declared: the limit trips while decoding.
    let f = fixture("text.nosize.zst");
    assert_eq!(decode_zstd(&f, 10_000), Err(ZstdError::LimitExceeded));
    let f = fixture("zeros.l3.zst");
    assert_eq!(decode_zstd(&f, 1000), Err(ZstdError::LimitExceeded));
    assert_eq!(decode_zstd(&fixture("multi.zst"), 13 + 23_999), Err(ZstdError::LimitExceeded));
}

#[test]
fn detection() {
    assert!(is_zstd(&fixture("text.l3.zst")));
    assert!(is_zstd(&fixture("only_skippable.zst")));
    assert!(!is_zstd(b"\x1f\x8b\x08\x00"));
    assert!(!is_zstd(b"\x28\xb5"));
    assert_eq!(decode_zstd(b"", CAP), Err(ZstdError::Truncated));
    assert_eq!(decode_zstd(b"\x28\xb5", CAP), Err(ZstdError::Truncated));
}

const SINGLE_FRAME: [&str; 12] = [
    "text.l3.zst",
    "text.l19.zst",
    "text.l-5.zst",
    "text.win10.zst",
    "text.stream_blocks.zst",
    "binary.btultra2.zst",
    "lines.ldm.zst",
    "hand.mixed.zst",
    "hand.raw.zst",
    "random.l3.zst",
    "zeros.l3.zst",
    "text.nosize.zst",
];

#[test]
fn every_truncation_fails() {
    for name in SINGLE_FRAME {
        let f = fixture(name);
        for n in 0..f.len() {
            assert!(decode_zstd(&f[..n], CAP).is_err(), "{name} prefix {n}");
        }
    }
}

#[test]
fn corruption_never_panics() {
    for name in SINGLE_FRAME {
        let f = fixture(name);
        let step = (f.len() / 200).max(1);
        for i in (0..f.len()).step_by(step) {
            for x in [0x01u8, 0x80, 0xff, 0x10] {
                let mut g = f.clone();
                g[i] ^= x;
                // Either an error or some output within the cap; checksummed
                // fixtures must not decode to wrong data silently.
                if let Ok(d) = decode_zstd(&g, 1 << 20) {
                    assert!(d.len() <= 1 << 20);
                }
            }
        }
    }
}

#[test]
fn corruption_with_checksum_detected() {
    // Flipping any byte of a checksummed frame's blocks must not yield
    // different data reported as success.
    let f = fixture("text.check.zst");
    let want = decode_zstd(&f, CAP).unwrap();
    for i in 6..f.len() {
        let mut g = f.clone();
        g[i] ^= 0x04;
        if let Ok(d) = decode_zstd(&g, CAP) {
            assert_eq!(d, want, "byte {i}");
        }
    }
}

#[test]
fn hostile_sizes() {
    // Single-segment frame declaring 2^64-1 bytes: rejected before allocating.
    let mut f = vec![0x28, 0xb5, 0x2f, 0xfd, 0xe0];
    f.extend_from_slice(&u64::MAX.to_le_bytes());
    f.extend_from_slice(&[1, 0, 0]);
    assert_eq!(decode_zstd(&f, CAP), Err(ZstdError::LimitExceeded));
    // Window descriptor with the largest exponent; one empty raw block.
    let f = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xff, 0x01, 0x00, 0x00];
    assert_eq!(decode_zstd(&f, CAP), Ok(Vec::new()));
    // Skippable frame claiming 4 GiB.
    let f = [0x50, 0x2a, 0x4d, 0x18, 0xff, 0xff, 0xff, 0xff, 0];
    assert_eq!(decode_zstd(&f, CAP), Err(ZstdError::Truncated));
}
