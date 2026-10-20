// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZIP methods 93 (Zstandard) and 98 (PPMd var.I rev1) through every zip
//! decode path: `archive_open::open_named` (archive_reader::ZipReader),
//! `zip_reader2::ZipArchive2::read`, and the password-aware opener
//! (`zip_crypt` after WinZip AES decryption, i.e. the AES `actual_method`).
//!
//! Fixtures: tests/gen/zip_methods.py (Python stdlib `zipfile.ZIP_ZSTANDARD`)
//! and tests/gen/zip_methods_7z.sh (7zz `-tzip -mm=PPMd`). Each archive has a
//! `.slt.txt` listing with sizes and CRC-32s from its oracle.

use sediment_engine::archive_open::open_named;
use sediment_engine::archive_open_crypt::open_named_with_password;
use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::crc32::crc32;
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::winzip_aes_kdf::WinZipAesStrength;
use sediment_engine::zip_crypt::{ZipEncryptLimits, ZipEncryption, encrypt_zip};
use sediment_engine::zip_reader2::{Reader2Error, Reader2Limits, ZipArchive2};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zip_methods");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}/{name}")).unwrap()
}

/// `Path -> (Size, CRC)` for regular files in an oracle listing (AE-2 entries
/// carry no CRC).
fn oracle(name: &str) -> Vec<(String, u64, Option<u32>)> {
    let text = std::fs::read_to_string(format!("{FIX}/{name}.slt.txt")).unwrap();
    let mut out = Vec::new();
    for blk in text.split("\n\n") {
        let kv = |k: &str| {
            blk.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(" = ")).map(str::to_string))
        };
        let (Some(path), Some(size)) = (kv("Path"), kv("Size")) else { continue };
        if kv("Attributes").is_some_and(|a| a.starts_with('D')) || kv("Folder").as_deref() == Some("+") {
            continue;
        }
        let crc = kv("CRC").filter(|c| !c.is_empty()).map(|c| u32::from_str_radix(&c, 16).unwrap());
        out.push((path, size.parse().unwrap(), crc));
    }
    assert!(!out.is_empty(), "{name}: empty oracle");
    out
}

fn methods(bytes: &[u8]) -> Vec<u16> {
    let z = ZipArchive2::open(bytes, Reader2Limits::default()).unwrap();
    z.entries().iter().map(|e| e.method).collect()
}

fn check_open_named(name: &str, bytes: &[u8], password: Option<&str>) {
    let want = oracle(name);
    let opened = open_named_with_password(bytes, name.as_bytes(), ReaderLimits::default(), password)
        .unwrap_or_else(|_| panic!("{name}: open failed"));
    let r = &opened.reader;
    let mut seen = 0;
    for (i, e) in r.entries().iter().enumerate() {
        if !matches!(e.kind, EntryKind::File) {
            continue;
        }
        let path = String::from_utf8(e.path.clone()).unwrap();
        let (_, size, crc) = want.iter().find(|w| w.0 == path).unwrap_or_else(|| panic!("{name}: extra {path}"));
        let data = r.read(i).unwrap_or_else(|err| panic!("{name}/{path}: {err:?}"));
        assert_eq!(data.len() as u64, *size, "{name}/{path}");
        if let Some(crc) = crc {
            assert_eq!(crc32(&data), *crc, "{name}/{path}");
        }
        seen += 1;
    }
    assert_eq!(seen, want.len(), "{name}: missing entries");
}

fn check_reader2(name: &str, bytes: &[u8]) {
    let want = oracle(name);
    let z = ZipArchive2::open(bytes, Reader2Limits::default()).unwrap();
    for (path, size, crc) in want {
        let i = z.find(path.as_bytes()).unwrap_or_else(|| panic!("{name}: no {path}"));
        let data = z.read(i, 1 << 24).unwrap_or_else(|e| panic!("{name}/{path}: {e:?}"));
        assert_eq!((data.len() as u64, Some(crc32(&data))), (size, crc), "{name}/{path}");
    }
}

#[test]
fn zstd_python_oracle() {
    for name in ["zstd", "zstd_l19"] {
        let bytes = fixture(&format!("{name}.zip"));
        assert!(methods(&bytes).iter().all(|&m| m == 93), "{name}");
        check_open_named(name, &bytes, None);
        check_reader2(name, &bytes);
        let r = open_named(&bytes, b"x.zip", ReaderLimits::default()).unwrap();
        assert!(r.entries().len() >= 5);
    }
}

#[test]
fn ppmd_7zz_oracle() {
    for name in ["ppmd", "ppmd_o3", "ppmd_o16"] {
        let bytes = fixture(&format!("{name}.zip"));
        assert!(methods(&bytes).contains(&98), "{name}");
        check_open_named(name, &bytes, None);
        check_reader2(name, &bytes);
    }
}

#[test]
fn ppmd_under_winzip_aes_7zz_oracle() {
    let bytes = fixture("ppmd_aes.zip");
    check_open_named("ppmd_aes", &bytes, Some("secret"));
    // AE-2 entries carry no CRC; the plain archive's listing (same input
    // tree) supplies them.
    check_open_named("ppmd", &bytes, Some("secret"));
    let opened = open_named_with_password(&bytes, b"ppmd_aes.zip", ReaderLimits::default(), Some("wrong")).unwrap();
    let i = opened.reader.entries().iter().position(|e| e.path == b"words.txt").unwrap();
    assert!(opened.reader.read(i).is_err());
}

#[test]
fn zstd_under_winzip_aes_roundtrip() {
    let plain = fixture("zstd_l19.zip");
    let enc = encrypt_zip(&plain, b"pw", ZipEncryption::Aes(WinZipAesStrength::Aes256), ZipEncryptLimits::default())
        .unwrap();
    assert!(methods(&enc).iter().all(|&m| m == 99));
    check_open_named("zstd_l19", &enc, Some("pw"));
    let enc = encrypt_zip(&plain, b"pw", ZipEncryption::ZipCrypto, ZipEncryptLimits::default()).unwrap();
    check_open_named("zstd_l19", &enc, Some("pw"));
}

/// Locate the payload of the entry `name` (local header data start/end).
fn payload_range(bytes: &[u8], name: &str) -> (usize, usize) {
    let z = ZipArchive2::open(bytes, Reader2Limits::default()).unwrap();
    let i = z.find(name.as_bytes()).unwrap();
    let raw = z.raw_data(i).unwrap();
    let start = raw.as_ptr() as usize - bytes.as_ptr() as usize;
    (start, start + raw.len())
}

#[test]
fn corrupt_payloads_err_not_panic() {
    for (fx, entry) in [("ppmd.zip", "words.txt"), ("zstd_l19.zip", "words.txt"), ("ppmd.zip", "a.txt")] {
        let good = fixture(fx);
        let (s, e) = payload_range(&good, entry);
        let mut cases: Vec<Vec<u8>> = Vec::new();
        for pos in [s, s + 1, s + 2, s + 5, (s + e) / 2, e - 1] {
            for x in [0x01u8, 0x80, 0xFF] {
                let mut b = good.clone();
                b[pos] ^= x;
                cases.push(b);
            }
        }
        // Zero the whole payload, and a truncated-to-zero payload length.
        let mut b = good.clone();
        b[s..e].fill(0);
        cases.push(b);
        for b in &cases {
            if let Ok(r) = open_named(b, fx.as_bytes(), ReaderLimits::default()) {
                for i in 0..r.entries().len() {
                    let _ = r.read(i);
                }
            }
            if let Ok(z) = ZipArchive2::open(b, Reader2Limits::default()) {
                for i in 0..z.len() {
                    let _ = z.read(i, 1 << 24);
                }
            }
        }
    }
}

#[test]
fn ppmd_freeze_restore_and_bad_order_are_rejected() {
    let good = fixture("ppmd.zip");
    let (s, _) = payload_range(&good, "words.txt");
    let z = ZipArchive2::open(&good, Reader2Limits::default()).unwrap();
    let i = z.find(b"words.txt").unwrap();
    // Restore method 2 (freeze) is valid PPMd but not supported: Unsupported.
    let mut b = good.clone();
    b[s + 1] = (b[s + 1] & 0x0F) | 0x20;
    let z2 = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    assert_eq!(z2.read(i, 1 << 24).err(), Some(Reader2Error::Unsupported));
    // Order 1 (nibble 0) is outside PPMd8's range: Invalid.
    let mut b = good.clone();
    b[s] &= 0xF0;
    let z3 = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    assert_eq!(z3.read(i, 1 << 24).err(), Some(Reader2Error::Invalid));
    let r = open_named(&b, b"x.zip", ReaderLimits::default()).unwrap();
    let j = r.entries().iter().position(|e| e.path == b"words.txt").unwrap();
    assert_eq!(r.read(j).err(), Some(ReaderError::Invalid));
}

#[test]
fn unknown_method_is_still_unsupported() {
    // Rewrite every method field 93 -> 97 (WavPack) in local and central headers.
    let mut b = fixture("zstd.zip");
    for sig in [[0x50u8, 0x4b, 3, 4], [0x50, 0x4b, 1, 2]] {
        let off = if sig[2] == 3 { 8 } else { 10 };
        let mut p = 0;
        while let Some(k) = b[p..].windows(4).position(|w| w == sig) {
            let at = p + k + off;
            if b[at..at + 2] == [93, 0] {
                b[at] = 97;
            }
            p += k + 4;
        }
    }
    let r = open_named(&b, b"x.zip", ReaderLimits::default()).unwrap();
    let i = r.entries().iter().position(|e| e.path == b"a.txt").unwrap();
    assert_eq!(r.read(i).err(), Some(ReaderError::Unsupported));
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    assert_eq!(z.read(z.find(b"a.txt").unwrap(), 1 << 24).err(), Some(Reader2Error::Unsupported));
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sed-zip-methods-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sediment(args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_sediment")).args(args).output().unwrap()
}

#[test]
fn cli_extract_and_test_new_methods() {
    for (fx, pw) in [("ppmd.zip", None), ("ppmd_aes.zip", Some("-psecret")), ("zstd_l19.zip", None)] {
        let arc = std::path::PathBuf::from(format!("{FIX}/{fx}"));
        let mut t: Vec<&std::ffi::OsStr> = vec!["t".as_ref()];
        t.extend(pw.map(std::ffi::OsStr::new));
        t.push(arc.as_os_str());
        let o = sediment(&t);
        assert_eq!(o.status.code(), Some(0), "{fx}: {}", String::from_utf8_lossy(&o.stderr));
        let d = scratch(fx);
        let out = format!("-o{}", d.display());
        let mut x: Vec<&std::ffi::OsStr> = vec!["x".as_ref(), "-y".as_ref(), out.as_ref()];
        x.extend(pw.map(std::ffi::OsStr::new));
        x.push(arc.as_os_str());
        let o = sediment(&x);
        assert_eq!(o.status.code(), Some(0), "{fx}: {}", String::from_utf8_lossy(&o.stderr));
        let words = std::fs::read(d.join("words.txt")).unwrap();
        let want = oracle(&fx[..fx.len() - 4]).into_iter().chain(oracle("ppmd")).find(|w| w.0 == "words.txt").unwrap();
        assert_eq!((words.len() as u64, Some(crc32(&words))), (want.1, want.2.or(Some(crc32(&words)))), "{fx}");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
fn cli_unknown_method_exits_2_with_message() {
    let mut b = fixture("zstd.zip");
    for (sig, off) in [([0x50u8, 0x4b, 3, 4], 8), ([0x50, 0x4b, 1, 2], 10)] {
        let mut p = 0;
        while let Some(k) = b[p..].windows(4).position(|w| w == sig) {
            if b[p + k + off] == 93 {
                b[p + k + off] = 97;
            }
            p += k + 4;
        }
    }
    let d = scratch("unknown");
    let arc = d.join("u.zip");
    std::fs::write(&arc, &b).unwrap();
    let out = format!("-o{}", d.join("out").display());
    let o = sediment(&["x".as_ref(), "-y".as_ref(), out.as_ref(), arc.as_os_str()]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("Unsupported Method"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    let o = sediment(&["t".as_ref(), arc.as_os_str()]);
    assert_eq!(o.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}
