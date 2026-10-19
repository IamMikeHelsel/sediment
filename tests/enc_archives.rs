// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted 7z / ZIP archives: oracle fixtures written by 7-Zip 26.04
//! (`tests/gen/enc_archives_oracle.sh`), round trips through our writers,
//! wrong / missing password classification, and hostile-input sweeps.
//!
//! `ENC_ARCHIVES_REGEN=DIR cargo test --test enc_archives regen` writes our
//! encrypted archives plus their plaintext to DIR for the reverse oracle
//! check (`tests/gen/enc_archives_verify.sh`: 7zz must decrypt them).

use sediment_engine::archive_open_crypt::{OpenCryptError, OpenedArchive, PasswordProblem, open_named_with_password};
use sediment_engine::archive_reader::{ArchiveFormat, ReaderLimits};
use sediment_engine::extract_plan::EntryKind as PlanKind;
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::sevenz_aes_coder::{IvSource, SEVENZ_AES_METHOD_ID, SevenZAesEncoder};
use sediment_engine::sevenz_write::{SevenZMethod, SevenZWriteLimits, SevenZWriteOptions, create_7z, create_7z_with};
use sediment_engine::winzip_aes_kdf::WinZipAesStrength;
use sediment_engine::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};
use sediment_engine::zip_crypt::{
    ZipCryptError, ZipEncryptLimits, ZipEncryption, encrypt_zip, encrypt_zip_with, read_entry,
};
use sediment_engine::zip_reader2::{Encryption, Reader2Limits, ZipArchive2};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/enc_archives");
const UNICODE_PW: &str = "pässwörd€";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}/{name}")).unwrap()
}

/// The plaintext tree written by the oracle script (same Python formulas).
fn src_files() -> Vec<(&'static str, Option<Vec<u8>>)> {
    let a: String = (0..80).map(|i| format!("line {i:04} alpha beta gamma\n")).collect();
    let b: Vec<u8> = (0..1500u32).map(|i| ((i * i * 31 + i * 7 + 3) & 255) as u8).collect();
    vec![
        ("a.txt", Some(a.into_bytes())),
        ("b.bin", Some(b)),
        ("small.txt", Some(b"tiny\n".to_vec())),
        ("empty.txt", Some(Vec::new())),
        ("d", None),
        ("d/c.txt", Some(b"nested file\n".to_vec())),
    ]
}

fn open<'a>(bytes: &'a [u8], name: &str, pw: Option<&str>) -> Result<OpenedArchive<'a>, OpenCryptError> {
    open_named_with_password(bytes, name.as_bytes(), ReaderLimits::default(), pw)
}

/// Every expected path is present with the right content.
fn check_tree(o: &OpenedArchive<'_>) {
    let entries = o.reader.entries();
    for (name, data) in src_files() {
        let i = entries
            .iter()
            .position(|e| e.path.strip_suffix(b"/").unwrap_or(&e.path) == name.as_bytes())
            .unwrap_or_else(|| panic!("missing {name}"));
        match data {
            None => assert_eq!(entries[i].kind, PlanKind::Dir, "{name}"),
            Some(d) => {
                assert_eq!(entries[i].kind, PlanKind::File, "{name}");
                assert_eq!(entries[i].size, d.len() as u64, "{name}");
                assert_eq!(o.reader.read(i).unwrap(), d, "{name}");
            }
        }
    }
    assert_eq!(entries.len(), src_files().len());
    assert_eq!(o.password_problem(), None);
}

fn read_all(o: &OpenedArchive<'_>) -> bool {
    (0..o.reader.entries().len()).all(|i| o.reader.read(i).is_ok())
}

// ---------------------------------------------------------------------------
// Oracle fixtures (7-Zip wrote them; we decrypt)
// ---------------------------------------------------------------------------

#[test]
fn oracle_7z_decrypts() {
    for name in ["aes_lzma2.7z", "aes_hdr.7z", "aes_copy.7z", "aes_nonsolid.7z"] {
        let b = fixture(name);
        let o = open(&b, name, Some("secret")).unwrap();
        assert_eq!(o.reader.format(), ArchiveFormat::SevenZ);
        assert!(o.is_encrypted(), "{name}");
        check_tree(&o);
    }
    let b = fixture("aes_unicode_pw.7z");
    check_tree(&open(&b, "u.7z", Some(UNICODE_PW)).unwrap());
}

#[test]
fn oracle_7z_wrong_and_missing_password() {
    // Header not encrypted: listing works, reading fails with the right reason.
    for name in ["aes_lzma2.7z", "aes_copy.7z", "aes_nonsolid.7z"] {
        let b = fixture(name);
        let o = open(&b, name, None).unwrap();
        assert_eq!(o.reader.entries().len(), 6);
        assert!(o.is_encrypted());
        assert!(!read_all(&o));
        assert_eq!(o.password_problem(), Some(PasswordProblem::Required), "{name}");
        let o = open(&b, name, Some("wrong")).unwrap();
        assert!(!read_all(&o));
        assert_eq!(o.password_problem(), Some(PasswordProblem::Wrong), "{name}");
    }
    // Encrypted header: cannot even list.
    for (name, good) in [("aes_hdr.7z", "secret"), ("aes_unicode_pw.7z", UNICODE_PW)] {
        let b = fixture(name);
        assert_eq!(open(&b, name, None).err(), Some(OpenCryptError::PasswordRequired));
        assert_eq!(open(&b, name, Some("wrong")).err(), Some(OpenCryptError::WrongPassword));
        assert!(open(&b, name, Some(good)).is_ok());
    }
    // Unicode password is UTF-16 in 7z: the ASCII-folded form is wrong.
    let b = fixture("aes_unicode_pw.7z");
    assert_eq!(open(&b, "u.7z", Some("passwords")).err(), Some(OpenCryptError::WrongPassword));
}

#[test]
fn oracle_zip_decrypts() {
    for name in [
        "zipcrypto.zip",
        "zipcrypto_store.zip",
        "aes128.zip",
        "aes192.zip",
        "aes256.zip",
        "aes256_store.zip",
        "infozip_crypt.zip",
    ] {
        let b = fixture(name);
        let o = open(&b, name, Some("secret")).unwrap();
        assert_eq!(o.reader.format(), ArchiveFormat::Zip);
        assert!(o.is_encrypted(), "{name}");
        check_tree(&o);
    }
}

#[test]
fn oracle_zip_schemes_detected() {
    let b = fixture("aes192.zip");
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    let e = z.entries().iter().find(|e| e.raw_name == b"a.txt").unwrap();
    assert!(matches!(e.encryption, Encryption::Aes(i) if i.strength == 2 && i.vendor_version == 2));
    let b = fixture("infozip_crypt.zip");
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    // Info-ZIP streams with data descriptors: check byte comes from the time.
    assert!(z.entries().iter().any(|e| e.encryption == Encryption::Traditional && e.has_data_descriptor()));
}

#[test]
fn oracle_zip_wrong_and_missing_password() {
    for name in ["zipcrypto.zip", "aes128.zip", "aes256.zip", "infozip_crypt.zip"] {
        let b = fixture(name);
        let o = open(&b, name, None).unwrap();
        assert_eq!(o.reader.entries().len(), 6, "{name}");
        assert!(!read_all(&o));
        assert_eq!(o.password_problem(), Some(PasswordProblem::Required), "{name}");
        for pw in ["wrong", "secreT", "", "secret "] {
            let o = open(&b, name, Some(pw)).unwrap();
            assert!(!read_all(&o), "{name} {pw:?}");
            assert_eq!(o.password_problem(), Some(PasswordProblem::Wrong), "{name} {pw:?}");
        }
    }
}

#[test]
fn zip_aes_tamper_detected() {
    let mut b = fixture("aes256_store.zip");
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    let i = z.find(b"b.bin").unwrap();
    let mid = (z.entries()[i].data_start + z.entries()[i].data_end) / 2;
    drop(z);
    b[mid] ^= 1;
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    assert_eq!(read_entry(&z, i, Some(b"secret"), 1 << 20, 64), Err(ZipCryptError::AuthFailed));
    assert_eq!(read_entry(&z, i, None, 1 << 20, 64), Err(ZipCryptError::PasswordRequired));
}

// ---------------------------------------------------------------------------
// Our writers
// ---------------------------------------------------------------------------

struct Tree {
    names: Vec<String>,
    datas: Vec<Vec<u8>>,
    kinds: Vec<EntryKind>,
}

fn tree() -> Tree {
    let mut t = Tree { names: Vec::new(), datas: Vec::new(), kinds: Vec::new() };
    for (n, d) in src_files() {
        t.names.push(n.to_string());
        t.kinds.push(if d.is_some() { EntryKind::File } else { EntryKind::Directory });
        t.datas.push(d.unwrap_or_default());
    }
    t
}

fn entries(t: &Tree) -> Vec<ArchiveEntry<'_>> {
    (0..t.names.len())
        .map(|i| ArchiveEntry {
            name: t.names[i].as_bytes(),
            kind: t.kinds[i],
            data: &t.datas[i],
            mtime: 1_709_618_828,
            mode: if t.kinds[i] == EntryKind::Directory { 0o755 } else { 0o644 },
            link_target: b"",
        })
        .collect()
}

fn our_7z(pw: &str, hdr: bool, opts: SevenZWriteOptions) -> Vec<u8> {
    let t = tree();
    let mut enc = SevenZAesEncoder::with_params(pw, 6, &[], hdr).unwrap();
    enc.set_iv_source(IvSource::Fixed([0x5a; 16]));
    create_7z_with(&entries(&t), &opts, SevenZWriteLimits::default(), Some(&enc)).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[test]
fn sevenz_roundtrip_variants() {
    let mut nonsolid = SevenZWriteOptions::level(5).unwrap();
    nonsolid.solid = false;
    let mut copy = SevenZWriteOptions::level(0).unwrap();
    copy.compress_header = false;
    let mut lzma = SevenZWriteOptions::level(3).unwrap();
    lzma.method = SevenZMethod::Lzma;
    lzma.filter = Some(sediment_engine::filter_bcj::BcjArch::X86);
    for (i, opts) in [SevenZWriteOptions::level(5).unwrap(), nonsolid, copy, lzma].into_iter().enumerate() {
        for hdr in [false, true] {
            let b = our_7z("secret", hdr, opts);
            let o = open(&b, "x.7z", Some("secret")).unwrap();
            assert!(o.is_encrypted(), "variant {i} hdr {hdr}");
            check_tree(&o);
            // Plaintext never appears; names only when the header is plain
            // and uncompressed.
            assert!(!contains(&b, b"line 0042 alpha"), "variant {i}");
            if hdr {
                assert!(!contains(&b, &utf16("small.txt")), "variant {i}");
                assert_eq!(open(&b, "x.7z", None).err(), Some(OpenCryptError::PasswordRequired));
                assert_eq!(open(&b, "x.7z", Some("Secret")).err(), Some(OpenCryptError::WrongPassword));
            } else {
                let o = open(&b, "x.7z", Some("Secret")).unwrap();
                assert!(!read_all(&o));
                assert_eq!(o.password_problem(), Some(PasswordProblem::Wrong));
            }
        }
    }
}

#[test]
fn sevenz_aes_coder_layout() {
    let b = our_7z("secret", false, SevenZWriteOptions::level(5).unwrap());
    let o = open(&b, "x.7z", Some("secret")).unwrap();
    drop(o);
    // The AES coder is present and its property byte encodes 2^6 rounds
    // with a 16-byte IV.
    let mut pat = vec![0x24];
    pat.extend_from_slice(&SEVENZ_AES_METHOD_ID);
    pat.extend_from_slice(&[0x12, 0x46, 0x0f]);
    let hdr_plain = {
        let mut o = SevenZWriteOptions::level(5).unwrap();
        o.compress_header = false;
        our_7z("secret", false, o)
    };
    assert!(contains(&hdr_plain, &pat));
    // Unencrypted archives are still read through the same entry point.
    let t = tree();
    let plain = create_7z(&entries(&t), &SevenZWriteOptions::level(5).unwrap(), SevenZWriteLimits::default()).unwrap();
    let o = open(&plain, "p.7z", None).unwrap();
    assert!(!o.is_encrypted());
    check_tree(&o);
}

#[test]
fn sevenz_unicode_and_empty_password() {
    for pw in [UNICODE_PW, "", "x", "a much longer pass phrase with spaces and 數字"] {
        let b = our_7z(pw, true, SevenZWriteOptions::level(1).unwrap());
        check_tree(&open(&b, "x.7z", Some(pw)).unwrap());
    }
}

fn plain_zip(level: u8) -> Vec<u8> {
    let t = tree();
    create_zip(&entries(&t), ZipCreateOptions { level }, ZipCreateLimits::default()).unwrap().bytes
}

fn counter_rng() -> impl FnMut(&mut [u8]) -> Result<(), ZipCryptError> {
    let mut n = 0u8;
    move |b: &mut [u8]| {
        for x in b.iter_mut() {
            n = n.wrapping_mul(31).wrapping_add(7);
            *x = n;
        }
        Ok(())
    }
}

const SCHEMES: [ZipEncryption; 4] = [
    ZipEncryption::ZipCrypto,
    ZipEncryption::Aes(WinZipAesStrength::Aes128),
    ZipEncryption::Aes(WinZipAesStrength::Aes192),
    ZipEncryption::Aes(WinZipAesStrength::Aes256),
];

#[test]
fn zip_roundtrip_all_schemes() {
    for level in [0, 6] {
        let plain = plain_zip(level);
        for enc in SCHEMES {
            let b = encrypt_zip(&plain, b"secret", enc, ZipEncryptLimits::default()).unwrap();
            let o = open(&b, "x.zip", Some("secret")).unwrap();
            assert!(o.is_encrypted());
            check_tree(&o);
            assert!(!contains(&b, b"line 0042 alpha"));
            let o = open(&b, "x.zip", Some("wrong")).unwrap();
            assert!(!read_all(&o));
            assert_eq!(o.password_problem(), Some(PasswordProblem::Wrong), "{enc:?}");
            // Directories stay unencrypted, everything else is encrypted.
            let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
            for e in z.entries() {
                assert_eq!(e.is_encrypted(), !e.is_dir(), "{enc:?} {:?}", e.raw_name);
            }
        }
    }
}

#[test]
fn zip_encrypt_is_deterministic_with_fixed_rng() {
    let plain = plain_zip(6);
    for enc in SCHEMES {
        let a = encrypt_zip_with(&plain, b"pw", enc, ZipEncryptLimits::default(), &mut counter_rng()).unwrap();
        let b = encrypt_zip_with(&plain, b"pw", enc, ZipEncryptLimits::default(), &mut counter_rng()).unwrap();
        assert_eq!(a, b);
        let c = encrypt_zip(&plain, b"pw", enc, ZipEncryptLimits::default()).unwrap();
        assert_ne!(a, c, "random salts/headers differ");
        assert_eq!(a.len(), c.len());
    }
}

#[test]
fn zip_encrypt_rejects_unsuitable_input() {
    let plain = plain_zip(6);
    let enc = encrypt_zip(&plain, b"pw", ZipEncryption::ZipCrypto, ZipEncryptLimits::default()).unwrap();
    // Already encrypted.
    assert_eq!(
        encrypt_zip(&enc, b"pw", ZipEncryption::ZipCrypto, ZipEncryptLimits::default()),
        Err(ZipCryptError::Unsupported)
    );
    // Data descriptors (Info-ZIP streaming output) are not rewritten.
    assert!(encrypt_zip(&fixture("infozip_crypt.zip"), b"pw", ZipEncryption::ZipCrypto, ZipEncryptLimits::default()).is_err());
    // Limits.
    let tight = ZipEncryptLimits { max_entries: 65534, max_archive_bytes: 100 };
    assert_eq!(encrypt_zip(&plain, b"pw", ZipEncryption::ZipCrypto, tight), Err(ZipCryptError::LimitExceeded));
    let few = ZipEncryptLimits { max_entries: 2, max_archive_bytes: 1 << 20 };
    assert!(encrypt_zip(&plain, b"pw", ZipEncryption::ZipCrypto, few).is_err());
    assert!(encrypt_zip(b"not a zip", b"pw", ZipEncryption::ZipCrypto, ZipEncryptLimits::default()).is_err());
}

#[test]
fn zip_wrong_password_never_returns_garbage() {
    // ZipCrypto's 1-byte check passes ~1/256 wrong passwords; the CRC (or
    // inflate failure) must still reject them.
    let plain = plain_zip(6);
    let b = encrypt_zip_with(&plain, b"secret", ZipEncryption::ZipCrypto, ZipEncryptLimits::default(), &mut counter_rng())
        .unwrap();
    let z = ZipArchive2::open(&b, Reader2Limits::default()).unwrap();
    let i = z.find(b"a.txt").unwrap();
    let mut passed_check = 0;
    for n in 0..2000u32 {
        let pw = format!("guess{n}");
        match read_entry(&z, i, Some(pw.as_bytes()), 1 << 20, 64) {
            Ok(_) => panic!("wrong password {pw} accepted"),
            Err(ZipCryptError::BadPassword) => {}
            Err(ZipCryptError::CrcMismatch) => passed_check += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(passed_check > 0, "expected some header-check collisions in 2000 guesses");
}

// ---------------------------------------------------------------------------
// Hostile input: truncation and bit flips never panic
// ---------------------------------------------------------------------------

fn exercise(bytes: &[u8], name: &str) {
    if let Ok(o) = open(bytes, name, Some("secret")) {
        for i in 0..o.reader.entries().len() {
            let _ = o.reader.read(i);
            let _ = o.reader.crc32(i);
        }
    }
    let _ = open(bytes, name, None);
}

#[test]
fn hostile_truncation_and_flips() {
    let small_7z = {
        let t = Tree {
            names: vec!["f".into(), "g".into()],
            datas: vec![b"hello hello hello".to_vec(), b"world".to_vec()],
            kinds: vec![EntryKind::File, EntryKind::File],
        };
        let mut enc = SevenZAesEncoder::with_params("secret", 0, &[], true).unwrap();
        enc.set_iv_source(IvSource::Fixed([1; 16]));
        create_7z_with(&entries(&t), &SevenZWriteOptions::level(1).unwrap(), SevenZWriteLimits::default(), Some(&enc))
            .unwrap()
    };
    // (name, bytes, truncation step, flip step). The 7-Zip fixture uses the
    // real 2^19-round KDF, so it is sampled more sparsely.
    let inputs: Vec<(&str, Vec<u8>, usize, usize)> = vec![
        ("x.7z", small_7z, 1, 1),
        ("x.7z", fixture("aes_hdr.7z"), 41, 0),
        ("x.zip", fixture("aes128.zip"), 7, 13),
        ("x.zip", fixture("zipcrypto.zip"), 7, 5),
    ];
    for (name, b, trunc_step, flip_step) in &inputs {
        for len in (0..b.len()).step_by(*trunc_step) {
            exercise(&b[..len], name);
        }
        if *flip_step == 0 {
            continue;
        }
        let mut m = b.clone();
        for pos in (0..m.len()).step_by(*flip_step) {
            for bit in [0x01u8, 0x80] {
                m[pos] ^= bit;
                exercise(&m, name);
                m[pos] ^= bit;
            }
        }
    }
}

#[test]
fn hostile_7z_aes_cost_is_capped() {
    // Raise the cycles power of the AES coder to 0x3e (2^62 rounds): must be
    // rejected by the limit, not attempted.
    let mut o = SevenZWriteOptions::level(0).unwrap();
    o.compress_header = false;
    let mut b = our_7z("secret", false, o);
    let mut pat = SEVENZ_AES_METHOD_ID.to_vec();
    pat.extend_from_slice(&[0x12, 0x46]);
    let at = b.windows(pat.len()).position(|w| w == pat).unwrap() + 5;
    b[at] = 0x7e; // IV flag + 62
    // Fix the header CRC so the change is not caught earlier.
    let off = u64::from_le_bytes(b[12..20].try_into().unwrap()) as usize + 32;
    let size = u64::from_le_bytes(b[20..28].try_into().unwrap()) as usize;
    let crc = sediment_engine::crc32::crc32(&b[off..off + size]);
    b[28..32].copy_from_slice(&crc.to_le_bytes());
    let c = sediment_engine::crc32::crc32(&b[12..32]);
    b[8..12].copy_from_slice(&c.to_le_bytes());
    let started = std::time::Instant::now();
    let o = open(&b, "x.7z", Some("secret")).unwrap();
    assert!(!read_all(&o));
    assert!(started.elapsed().as_secs() < 5);
}

// ---------------------------------------------------------------------------
// Reverse oracle material
// ---------------------------------------------------------------------------

#[test]
fn regen() {
    let Ok(dir) = std::env::var("ENC_ARCHIVES_REGEN") else { return };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(dir.join("src/d")).unwrap();
    for (n, d) in src_files() {
        if let Some(d) = d {
            std::fs::write(dir.join("src").join(n), d).unwrap();
        }
    }
    let t = tree();
    let mut ns = SevenZWriteOptions::level(5).unwrap();
    ns.solid = false;
    let mut cp = SevenZWriteOptions::level(0).unwrap();
    cp.compress_header = false;
    for (name, pw, hdr, opts) in [
        ("ours_lzma2.7z", "secret", false, SevenZWriteOptions::level(5).unwrap()),
        ("ours_hdr.7z", "secret", true, SevenZWriteOptions::level(5).unwrap()),
        ("ours_nonsolid_hdr.7z", "secret", true, ns),
        ("ours_copy.7z", "secret", false, cp),
        ("ours_unicode_pw.7z", UNICODE_PW, true, SevenZWriteOptions::level(3).unwrap()),
    ] {
        let enc = SevenZAesEncoder::new(pw, hdr).unwrap();
        let b = create_7z_with(&entries(&t), &opts, SevenZWriteLimits::default(), Some(&enc)).unwrap();
        std::fs::write(dir.join(name), b).unwrap();
    }
    for (name, level, enc) in [
        ("ours_zipcrypto.zip", 6, ZipEncryption::ZipCrypto),
        ("ours_zipcrypto_store.zip", 0, ZipEncryption::ZipCrypto),
        ("ours_aes128.zip", 6, ZipEncryption::Aes(WinZipAesStrength::Aes128)),
        ("ours_aes192.zip", 6, ZipEncryption::Aes(WinZipAesStrength::Aes192)),
        ("ours_aes256.zip", 6, ZipEncryption::Aes(WinZipAesStrength::Aes256)),
        ("ours_aes256_store.zip", 0, ZipEncryption::Aes(WinZipAesStrength::Aes256)),
    ] {
        let b = encrypt_zip(&plain_zip(level), b"secret", enc, ZipEncryptLimits::default()).unwrap();
        std::fs::write(dir.join(name), b).unwrap();
    }
}
