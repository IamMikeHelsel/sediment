// SPDX-License-Identifier: MIT OR Apache-2.0
//! `t`/`x`/`e` console text against goldens captured from the pinned 7-Zip
//! 26.04 `7zz` (tests/gen/console_oracle.sh) on a small corrupted-fixture
//! set (tests/gen/console.py). Every case runs with `-ba`, so the banner is
//! not compared; stdout, stderr and the exit code must match byte for byte.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/console")
}

fn scratch() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!("sed-console-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_case(name: &str) -> Run {
    let args = fs::read_to_string(dir().join(format!("{name}.args"))).unwrap();
    let out = scratch();
    let argv: Vec<String> = args.split_whitespace().map(|a| a.replace("{OUT}", out.to_str().unwrap())).collect();
    let o = Command::new(env!("CARGO_BIN_EXE_sediment")).args(&argv).current_dir(dir()).output().unwrap();
    let _ = fs::remove_dir_all(&out);
    Run {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn golden(name: &str, ext: &str) -> String {
    fs::read_to_string(dir().join(format!("{name}.{ext}"))).unwrap()
}

/// Cases whose output matches 7-Zip exactly.
const EXACT: &[&str] = &[
    "t_good",
    "t_badcrc",
    "t_bb1_badcrc",
    "t_junk",
    "t_unsup",
    "t_notarc",
    "t_new7z",
    "t_bb1_new7z",
    "t_wrongpw_7z",
    "t_wrongpw_7zhe",
    "t_wrongpw_aes",
    "t_badhdr7z",
    "t_trunc7z",
    "x_good",
    "x_badcrc",
    "e_good",
    "x_bb1_new7z",
];

#[test]
fn matches_7zz_goldens() {
    let mut bad = Vec::new();
    for name in EXACT {
        let r = run_case(name);
        let want_code: i32 = golden(name, "code").trim().parse().unwrap();
        if r.code != want_code || r.stdout != golden(name, "stdout") || r.stderr != golden(name, "stderr") {
            bad.push(format!(
                "{name}: code {} (want {want_code})\n--- stdout\n{}--- want\n{}--- stderr\n{}--- want\n{}",
                r.code,
                r.stdout,
                golden(name, "stdout"),
                r.stderr,
                golden(name, "stderr")
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// 7-Zip opens a zip without its central directory by scanning local
/// headers; Sediment reports the archive as cut short instead. The exit
/// code and the "Unexpected end of archive" line are the same.
#[test]
fn truncated_zip_is_unexpected_end() {
    let r = run_case("t_trunc");
    assert_eq!(r.code, 2);
    assert!(golden("t_trunc", "stderr").contains("Unexpected end of archive\n"));
    assert!(r.stderr.contains("\nERRORS:\nUnexpected end of archive\n"), "{}", r.stderr);
    assert!(!r.stdout.contains("Everything is Ok"));
}

#[test]
fn banner_unless_ba() {
    let o = Command::new(env!("CARGO_BIN_EXE_sediment")).args(["t", "good.zip"]).current_dir(dir()).output().unwrap();
    let s = String::from_utf8(o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(s.starts_with("\nSediment "), "{s}");
    let len = fs::metadata(dir().join("good.zip")).unwrap().len();
    let want = format!("\n\nScanning the drive for archives:\n1 file, {len} bytes (1 KiB)\n{}", golden("t_good", "stdout"));
    assert!(s.ends_with(&want), "{s}");
}

/// Malformed inputs never panic and always end in exit 2.
#[test]
fn corrupt_fixtures_exit_2_without_panic() {
    for f in ["badcrc.zip", "trunc.zip", "unsup.zip", "notarc.bin", "badhdr.7z", "trunc.7z"] {
        for cmd in ["t", "x"] {
            let out = scratch();
            let mut c = Command::new(env!("CARGO_BIN_EXE_sediment"));
            c.arg(cmd).arg(f).current_dir(dir());
            if cmd == "x" {
                c.arg(format!("-o{}", out.display())).arg("-y");
            }
            let o = c.output().unwrap();
            let _ = fs::remove_dir_all(&out);
            assert_eq!(o.status.code(), Some(2), "{cmd} {f}");
            assert!(!String::from_utf8_lossy(&o.stderr).contains("panicked"), "{cmd} {f}");
            assert!(String::from_utf8_lossy(&o.stderr).starts_with("ERROR: "), "{cmd} {f}");
        }
    }
}

/// `d` and `u` print the 7-Zip update shape (member counts, archive size,
/// "Everything is Ok"); `-ba` drops the banner.
#[test]
fn delete_and_update_shape() {
    let t = scratch();
    let arc = t.join("x.zip");
    fs::copy(dir().join("good.zip"), &arc).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sediment")).args(["d", "-ba", "x.zip", "empty"]).current_dir(&t).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let len = fs::metadata(&arc).unwrap().len();
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!(
            "Updating archive: x.zip\n\nDelete data from archive: 1 file\nKeep old data in archive: 2 files\n\
             Add new data to archive: 0 files\n\n\nArchive size: {len} bytes (1 KiB)\nEverything is Ok\n"
        )
    );
    fs::write(t.join("new.txt"), b"new\n").unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sediment")).args(["u", "x.zip", "new.txt"]).current_dir(&t).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let s = String::from_utf8(o.stdout).unwrap();
    assert!(s.starts_with("\nSediment "), "{s}");
    assert!(s.contains("\nUpdating archive: x.zip\n\nKeep old data in archive: 2 files\nAdd new data to archive: 1 file\n"), "{s}");
    assert!(s.ends_with("Everything is Ok\n"), "{s}");
    let _ = fs::remove_dir_all(&t);
}
