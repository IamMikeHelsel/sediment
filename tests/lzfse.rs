//! LZFSE/LZVN decoder vs Apple libcompression fixtures (tests/gen/apple.py).
use sediment_engine::hash_sha256::sha256;
use sediment_engine::lzfse::{decode_lzfse, decode_lzfse_prefix, LzfseError};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/apple")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// (name, size, sha256) from the flat manifest.
fn manifest() -> Vec<(String, usize, String)> {
    let s = std::fs::read_to_string(dir().join("lzfse_manifest.json")).unwrap();
    let mut out = Vec::new();
    let mut name = String::new();
    let mut sha = String::new();
    // Keys are sorted: magic, sha256, size.
    for line in s.lines() {
        let t = line.trim().trim_end_matches(',');
        if t.ends_with('{') && t.starts_with('"') {
            name = t.split('"').nth(1).unwrap().to_string();
        } else if let Some(v) = t.strip_prefix("\"sha256\": ") {
            sha = v.trim_matches('"').to_string();
        } else if let Some(v) = t.strip_prefix("\"size\": ") {
            out.push((name.clone(), v.parse().unwrap(), sha.clone()));
        }
    }
    out
}

#[test]
fn oracle_fixtures_decode_exactly() {
    let m = manifest();
    assert!(m.len() >= 10);
    for (name, size, sha) in m {
        let comp = std::fs::read(dir().join(format!("{name}.lzfse"))).unwrap();
        let out = decode_lzfse(&comp, 1 << 24).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(out.len(), size, "{name}");
        assert_eq!(hex(&sha256(&out)), sha, "{name}");
        if size > 0 {
            assert_eq!(decode_lzfse(&comp, size - 1), Err(LzfseError::LimitExceeded), "{name}");
        }
    }
}

#[test]
fn trailing_data_and_prefix() {
    let comp = std::fs::read(dir().join("lzvn_text.lzfse")).unwrap();
    let mut x = comp.clone();
    x.extend_from_slice(b"junk");
    assert!(decode_lzfse(&x, 1 << 20).is_err());
    let (out, used) = decode_lzfse_prefix(&x, 1 << 20).unwrap();
    assert_eq!(used, comp.len());
    assert_eq!(out.len(), 3500);
}

#[test]
fn truncation_and_corruption_never_panic() {
    for (name, _, _) in manifest() {
        let comp = std::fs::read(dir().join(format!("{name}.lzfse"))).unwrap();
        for cut in 0..comp.len() {
            if cut % 7 == 0 || cut + 16 > comp.len() {
                assert!(decode_lzfse(&comp[..cut], 1 << 22).is_err(), "{name} cut {cut}");
            }
        }
        let mut seed = 0x1234_5678u32;
        for _ in 0..300 {
            let mut c = comp.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let i = (seed >> 8) as usize % c.len();
                c[i] ^= (seed >> 24) as u8 | 1;
            }
            let _ = decode_lzfse(&c, 1 << 22);
        }
    }
}
