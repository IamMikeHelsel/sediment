// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sediment` CLI with encrypted archives: -p for l/t/x/e/a, -mem, -mhe,
//! exit code 2 for missing / wrong passwords (7-Zip behaviour). Uses the
//! 7-Zip-written fixtures in tests/fixtures/enc_archives.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
static N: AtomicU32 = AtomicU32::new(0);

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/enc_archives").join(name).display().to_string()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-cli-enc-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self, s: &str) -> String {
        self.0.join(s).display().to_string()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const ALL: [&str; 11] = [
    "aes_lzma2.7z",
    "aes_hdr.7z",
    "aes_copy.7z",
    "aes_nonsolid.7z",
    "zipcrypto.zip",
    "zipcrypto_store.zip",
    "aes128.zip",
    "aes192.zip",
    "aes256.zip",
    "aes256_store.zip",
    "infozip_crypt.zip",
];

#[test]
fn test_and_list_with_password() {
    for f in ALL {
        let o = run(&["t", "-psecret", &fixture(f)]);
        assert_eq!(o.status.code(), Some(0), "{f}: {}", stderr(&o));
        assert_eq!(stdout(&o), "OK\t6\t3677\n", "{f}");
        let o = run(&["l", "-psecret", &fixture(f)]);
        assert_eq!(o.status.code(), Some(0), "{f}");
        assert!(stdout(&o).contains("  b.bin\n"), "{f}");
    }
    let o = run(&["t", "-ppässwörd€", &fixture("aes_unicode_pw.7z")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

#[test]
fn wrong_or_missing_password_exits_2() {
    for f in ALL {
        let o = run(&["t", "-pwrong", &fixture(f)]);
        assert_eq!(o.status.code(), Some(2), "{f}");
        assert!(stderr(&o).to_lowercase().contains("wrong password"), "{f}: {}", stderr(&o));
        let o = run(&["t", &fixture(f)]);
        assert_eq!(o.status.code(), Some(2), "{f}");
        assert!(stderr(&o).contains("password required"), "{f}: {}", stderr(&o));
        let d = TempDir::new("wrong");
        let o = run(&["x", "-pwrong", &format!("-o{}", d.path("out")), &fixture(f)]);
        assert_eq!(o.status.code(), Some(2), "{f}");
        assert!(stderr(&o).to_lowercase().contains("wrong password"), "{f}");
    }
    // Listing works without a password unless the header is encrypted.
    assert_eq!(run(&["l", &fixture("aes_lzma2.7z")]).status.code(), Some(0));
    assert_eq!(run(&["l", &fixture("aes256.zip")]).status.code(), Some(0));
    let o = run(&["l", &fixture("aes_hdr.7z")]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["l", "-pnope", &fixture("aes_hdr.7z")]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("Wrong password?"));
    // A bare -p (interactive prompt in 7-Zip) is refused as a command line error (7).
    assert_eq!(run(&["t", "-p", &fixture("aes_hdr.7z")]).status.code(), Some(7));
}

#[test]
fn extract_both_modes() {
    let d = TempDir::new("x");
    let o = run(&["x", "-psecret", &format!("-o{}", d.path("x")), &fixture("aes_hdr.7z")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(fs::read(d.path("x/d/c.txt")).unwrap(), b"nested file\n");
    assert_eq!(fs::read(d.path("x/small.txt")).unwrap(), b"tiny\n");
    let o = run(&["e", "-psecret", &format!("-o{}", d.path("e")), &fixture("aes192.zip")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(fs::read(d.path("e/c.txt")).unwrap(), b"nested file\n");
    assert_eq!(fs::read(d.path("e/b.bin")).unwrap().len(), 1500);
}

fn make_inputs(d: &TempDir) -> String {
    let src = d.path("in");
    fs::create_dir_all(format!("{src}/sub")).unwrap();
    fs::write(format!("{src}/hello.txt"), "hello encrypted world\n".repeat(20)).unwrap();
    fs::write(format!("{src}/sub/empty"), "").unwrap();
    src
}

#[test]
fn add_encrypted_and_read_back() {
    let d = TempDir::new("a");
    let src = make_inputs(&d);
    for (name, extra) in [
        ("o.7z", vec![]),
        ("oh.7z", vec!["-mhe=on"]),
        ("o0.7z", vec!["-mx0", "-mhc=off"]),
        ("zc.zip", vec![]),
        ("a128.zip", vec!["-mem=AES128"]),
        ("a256.zip", vec!["-mem=aes256", "-mx0"]),
    ] {
        let archive = d.path(name);
        let mut args = vec!["a", "-psecret"];
        args.extend(extra.iter().copied());
        args.push(&archive);
        args.push(&src);
        let o = run(&args);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", stderr(&o));
        assert!(!fs::read(&archive).unwrap().windows(14).any(|w| w == b"hello encrypte"), "{name}");
        let o = run(&["t", "-psecret", &archive]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", stderr(&o));
        assert_eq!(run(&["t", "-pSecret", &archive]).status.code(), Some(2), "{name}");
        let out = d.path(&format!("{name}.out"));
        let o = run(&["x", "-psecret", &format!("-o{out}"), &archive]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", stderr(&o));
        assert_eq!(fs::read_to_string(format!("{out}/in/hello.txt")).unwrap(), "hello encrypted world\n".repeat(20));
        assert_eq!(fs::read(format!("{out}/in/sub/empty")).unwrap(), b"");
        let listed = run(&["l", &archive]);
        let expect = if name == "oh.7z" { Some(2) } else { Some(0) };
        assert_eq!(listed.status.code(), expect, "{name}");
    }
}

#[test]
fn add_switch_errors() {
    let d = TempDir::new("e");
    let src = make_inputs(&d);
    // -mhe / -mem without password, on the wrong format, or on tar.
    for args in [
        vec!["a", "-mhe=on", "x.zip"],
        vec!["a", "-mem=AES256", "x.zip"],
        vec!["a", "-psecret", "-mhe=on", "x.zip"],
        vec!["a", "-psecret", "-mem=AES256", "x.7z"],
        vec!["a", "-psecret", "x.tar"],
        vec!["a", "-psecret", "-mem=rot13", "x.zip"],
    ] {
        let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let last = a.len() - 1;
        a[last] = d.path(&a[last]);
        a.push(src.clone());
        let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let o = run(&refs);
        // Command line errors use 7-Zip's exit code 7 (see cli_compat).
        assert_eq!(o.status.code(), Some(7), "{args:?}: {}", stderr(&o));
        assert!(!Path::new(&a[a.len() - 2]).exists(), "{args:?} wrote an archive");
    }
    // An existing archive is not overwritten without -y.
    let arc = d.path("keep.7z");
    fs::write(&arc, b"x").unwrap();
    assert_eq!(run(&["a", "-psecret", &arc, &src]).status.code(), Some(2));
    assert_eq!(fs::read(&arc).unwrap(), b"x");
    assert_eq!(run(&["a", "-psecret", "-y", &arc, &src]).status.code(), Some(0));
    // Unencrypted 7z creation is routed to the 7z writer too.
    let plain = d.path("plain.7z");
    assert_eq!(run(&["a", &plain, &src]).status.code(), Some(0));
    assert_eq!(run(&["t", &plain]).status.code(), Some(0));
}
