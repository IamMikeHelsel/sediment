//! UDIF DMG + HFS+ reading vs hdiutil fixtures (tests/gen/apple.py).
use sediment_engine::archive_open_ext::open_named_ext;
use sediment_engine::archive_reader::{ArchiveFormat, ReaderLimits};
use sediment_engine::dmg_read::{DmgImage, DmgReader};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::hash_sha256::sha256;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/apple")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Expected NFC path -> sha256 of the larger tree.
fn tree_manifest() -> BTreeMap<String, String> {
    let s = std::fs::read_to_string(dir().join("tree_manifest.json")).unwrap();
    s.lines()
        .filter_map(|l| {
            let t = l.trim().trim_end_matches(',');
            let mut it = t.split("\": \"");
            let k = it.next()?.strip_prefix('"')?;
            let v = it.next()?.strip_suffix('"')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// HFS+ stores names decomposed; compose the only case the fixtures use.
fn nfc(s: &str) -> String {
    s.replace("e\u{301}", "\u{e9}")
}

fn files_of(name: &str) -> BTreeMap<String, String> {
    let bytes = std::fs::read(dir().join(name)).unwrap();
    let r = open_named_ext(&bytes, name.as_bytes(), ReaderLimits::default()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(r.format(), ArchiveFormat::Dmg);
    let mut out = BTreeMap::new();
    for (i, e) in r.entries().iter().enumerate() {
        let p = nfc(std::str::from_utf8(&e.path).unwrap());
        if e.kind == EntryKind::File && !p.starts_with('.') {
            let d = r.read(i).unwrap_or_else(|err| panic!("{name} {p}: {err:?}"));
            assert_eq!(d.len() as u64, e.size);
            out.insert(p, hex(&sha256(&d)));
        }
    }
    out
}

#[test]
fn every_codec_image_matches_source_tree() {
    let want = tree_manifest();
    assert!(want.len() >= 6);
    for f in ["tree_ulfo.dmg", "tree_udbz.dmg", "tree_ulmo.dmg", "tree_udco.dmg"] {
        assert_eq!(files_of(f), want, "{f}");
    }
}

#[test]
fn gpt_udzo_image_lists_partitions_and_files() {
    let bytes = std::fs::read(dir().join("goodput_udzo.dmg")).unwrap();
    let img = DmgImage::open(&bytes, 1000).unwrap();
    assert!(img.partitions.len() >= 3);
    assert!(img.partitions.iter().any(|p| p.name.contains("Apple_HFS")));
    let got = files_of("goodput_udzo.dmg");
    for k in ["a.txt", "bin/data.bin", "empty", "deep/x/y/z.txt", "caf\u{e9}.txt"] {
        assert!(got.contains_key(k), "{k} missing: {got:?}");
    }
    assert_eq!(got["a.txt"], hex(&sha256(&b"hello sediment\n".repeat(50))));
    let r = DmgReader::new(&bytes, ReaderLimits::default()).unwrap();
    use sediment_engine::archive_reader::ArchiveReader;
    assert!(r.entries().iter().any(|e| e.kind == EntryKind::Dir && e.path == b"deep/x/y"));
}

#[test]
fn truncated_and_corrupt_images_error_cleanly() {
    for f in ["goodput_udzo.dmg", "tree_ulfo.dmg", "tree_udco.dmg"] {
        let bytes = std::fs::read(dir().join(f)).unwrap();
        for cut in [0, 100, bytes.len() / 2, bytes.len() - 1] {
            assert!(DmgReader::new(&bytes[..cut], ReaderLimits::default()).is_err(), "{f} cut {cut}");
        }
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..200 {
            let mut c = bytes.clone();
            for _ in 0..4 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let i = (seed >> 4) as usize % c.len();
                c[i] ^= (seed >> 24) as u8 | 1;
            }
            if let Ok(r) = DmgReader::new(&c, ReaderLimits::default()) {
                use sediment_engine::archive_reader::ArchiveReader;
                for i in 0..r.entries().len() {
                    let _ = r.read(i);
                }
            }
        }
    }
}

#[test]
fn tight_limits_are_enforced() {
    let bytes = std::fs::read(dir().join("tree_ulfo.dmg")).unwrap();
    let l = ReaderLimits { max_entries: 100, max_total_size: 4096, max_entry_size: 1 << 20 };
    assert!(DmgReader::new(&bytes, l).is_err());
}
