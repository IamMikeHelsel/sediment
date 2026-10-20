// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runs the built `sediment` binary against fixtures from tests/gen/extract.py.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
static N: AtomicU32 = AtomicU32::new(0);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extract").join(name)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-cli-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
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

fn out_arg(p: &Path) -> String {
    format!("-o{}", p.display())
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

#[test]
fn help_text_unchanged() {
    let o = run(&["--help"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(o.stdout, b"Usage: sediment <list|test> ARCHIVE\n");
    assert_eq!(run(&["--help", "x"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["bogus", "a"]).status.code(), Some(2));
    assert_eq!(stderr(&run(&["bogus"])), "sediment: unknown command\n");
}

#[test]
fn legacy_and_new_list_agree() {
    let f = fixture("basic.zip");
    let f = f.to_str().unwrap();
    let legacy = run(&["list", f]);
    let new = run(&["l", "-ba", f]);
    assert_eq!(legacy.status.code(), Some(0));
    // `l` now prints 7-Zip's table; it lists the same members in the same order.
    let names: Vec<String> = stdout(&new).lines().map(|l| l.get(53..).unwrap().to_string()).collect();
    assert_eq!(names, ["docs", "docs/readme.txt", "hello.txt", "bin/run.sh", "a/b/c/deep.txt", "empty.txt"]);
    assert_eq!(
        stdout(&legacy),
        "SIZE\tCRC32\tNAME\n0\t00000000\tdocs/\n1160\t3e84e9d9\tdocs/readme.txt\n13\tf4247453\thello.txt\n\
         18\te9da3a2f\tbin/run.sh\n5\t279eb882\ta/b/c/deep.txt\n0\t00000000\tempty.txt\n"
    );
    let lt = run(&["test", f]);
    let nt = run(&["t", f]);
    assert_eq!(stdout(&lt), "OK\t6\t1196\n");
    assert_eq!(lt.stdout, nt.stdout);
    assert_eq!(nt.status.code(), Some(0));
}

#[test]
fn legacy_exit_codes_kept() {
    let o = run(&["test", fixture("badcrc.zip").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(stderr(&o), "sediment: payload error\n");
    assert_eq!(run(&["list", "/nonexistent/x.zip"]).status.code(), Some(1));
    assert_eq!(run(&["list"]).status.code(), Some(2));
    assert_eq!(run(&["list", "a", "b"]).status.code(), Some(2));
}

#[test]
fn new_commands_fatal_is_2() {
    let o = run(&["t", fixture("badcrc.zip").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(stderr(&o), "sediment: data error: data.txt\n");
    let o = run(&["x", fixture("notzip.bin").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(stderr(&o), "sediment: unsupported archive format\n");
    assert_eq!(run(&["l", "/nonexistent/x.zip"]).status.code(), Some(2));
    // Command line errors use 7-Zip's exit code 7 (see cli_compat).
    assert_eq!(run(&["x"]).status.code(), Some(7));
    assert_eq!(run(&["x", "-q", "a.zip"]).status.code(), Some(7));
    assert_eq!(run(&["x", "-o", "a.zip"]).status.code(), Some(7));
    // Extra names are member wildcards; the missing archive is fatal.
    assert_eq!(run(&["x", "a.zip", "b.zip"]).status.code(), Some(2));
}

#[test]
fn extract_full_paths() {
    let t = TempDir::new("x");
    let out = t.0.join("out");
    let o = run(&["x", &out_arg(&out), fixture("basic.zip").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(fs::read(out.join("hello.txt")).unwrap(), b"hello, world\n");
    assert_eq!(fs::read(out.join("docs/readme.txt")).unwrap(), b"Sediment extraction fixture.\n".repeat(40));
    assert_eq!(fs::read(out.join("a/b/c/deep.txt")).unwrap(), b"deep\n");
    assert_eq!(fs::read(out.join("empty.txt")).unwrap(), b"");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(out.join("bin/run.sh")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o755);
        // DOS time 2020-01-02 03:04:06, interpreted as UTC.
        let secs = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_577_934_246);
    }
}

#[test]
fn extract_overwrite_switches() {
    let t = TempDir::new("ow");
    let f = fixture("basic.zip");
    let f = f.to_str().unwrap();
    let o = out_arg(&t.0);
    assert_eq!(run(&["x", &o, f]).status.code(), Some(0));
    fs::write(t.0.join("hello.txt"), b"mine").unwrap();
    let again = run(&["x", &o, f]);
    assert_eq!(again.status.code(), Some(2));
    assert!(stderr(&again).contains("Exists"));
    assert_eq!(run(&["x", &o, "-aos", f]).status.code(), Some(0));
    assert_eq!(fs::read(t.0.join("hello.txt")).unwrap(), b"mine");
    assert_eq!(run(&["x", "-aou", &o, f]).status.code(), Some(0));
    assert_eq!(fs::read(t.0.join("hello_1.txt")).unwrap(), b"hello, world\n");
    assert_eq!(fs::read(t.0.join("hello.txt")).unwrap(), b"mine");
    assert_eq!(run(&["x", "-y", &o, f]).status.code(), Some(0));
    assert_eq!(fs::read(t.0.join("hello.txt")).unwrap(), b"hello, world\n");
    fs::write(t.0.join("hello.txt"), b"mine").unwrap();
    assert_eq!(run(&["x", &o, "-aoa", "--", f]).status.code(), Some(0));
    assert_eq!(fs::read(t.0.join("hello.txt")).unwrap(), b"hello, world\n");
}

#[test]
fn zip_slip_fixtures_rejected_and_nothing_written() {
    for (name, why) in [
        ("slip.zip", "ParentTraversal"),
        ("slip_nested.zip", "ParentTraversal"),
        ("absolute.zip", "AbsolutePath"),
        ("backslash.zip", "ParentTraversal"),
        ("drive.zip", "DriveLetter"),
        ("symlink_escape.zip", "SymlinkEscape"),
        ("symlink_absolute.zip", "SymlinkEscape"),
        ("symlink_through.zip", "ThroughSymlink"),
    ] {
        let t = TempDir::new("slip");
        let out = t.0.join("a").join("b");
        let o = run(&["x", "-y", "-snl", &out_arg(&out), fixture(name).to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(2), "{name}");
        assert!(stderr(&o).contains(why), "{name}: {}", stderr(&o));
        assert!(!t.0.join("a").exists(), "{name}: output created");
    }
}

#[test]
fn flat_extract_neutralizes_traversal() {
    for (name, base) in [
        ("slip.zip", "evil.txt"),
        ("slip_nested.zip", "evil.txt"),
        ("absolute.zip", "sediment-evil.txt"),
        ("backslash.zip", "evil.txt"),
        ("drive.zip", "evil.txt"),
    ] {
        let t = TempDir::new("eslip");
        let out = t.0.join("a").join("b");
        let o = run(&["e", &out_arg(&out), fixture(name).to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains("unsafe path flattened"));
        assert_eq!(fs::read(out.join(base)).unwrap(), b"evil\n");
        assert!(!t.0.join("a").join(base).exists());
        assert!(!t.0.join(base).exists());
    }
    for name in ["symlink_escape.zip", "symlink_absolute.zip"] {
        let t = TempDir::new("esym");
        let out = t.0.join("o");
        let o = run(&["e", "-snl", &out_arg(&out), fixture(name).to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(2), "{name}");
        assert!(!out.exists());
    }
}

#[test]
fn flat_extract() {
    let t = TempDir::new("e");
    let o = run(&["e", &out_arg(&t.0), fixture("flat.zip").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let mut names: Vec<_> = fs::read_dir(&t.0).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["x.txt", "y.txt"]);

    let t = TempDir::new("e2");
    let f = fixture("flat_dupe.zip");
    let o = run(&["e", &out_arg(&t.0), f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("duplicate name: b/same.txt"));
    let t = TempDir::new("e3");
    let o = run(&["e", "-aou", &out_arg(&t.0), f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(fs::read(t.0.join("same.txt")).unwrap(), b"first\n");
    assert_eq!(fs::read(t.0.join("same_1.txt")).unwrap(), b"second\n");
}

#[test]
fn symlinks_skipped_unless_snl() {
    let t = TempDir::new("snl");
    let f = fixture("symlink_ok.zip");
    let o = run(&["x", &out_arg(&t.0), f.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("symbolic link not extracted"));
    assert!(fs::symlink_metadata(t.0.join("link.txt")).is_err());
    assert_eq!(fs::read(t.0.join("target.txt")).unwrap(), b"target\n");
    #[cfg(unix)]
    {
        let t = TempDir::new("snl2");
        let o = run(&["x", "-snl", &out_arg(&t.0), f.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(fs::read_link(t.0.join("link.txt")).unwrap(), Path::new("target.txt"));
    }
}

#[cfg(unix)]
#[test]
fn preexisting_symlink_in_destination_not_followed() {
    let t = TempDir::new("pre");
    let outside = TempDir::new("pre-outside");
    std::os::unix::fs::symlink(&outside.0, t.0.join("docs")).unwrap();
    let o = run(&["x", "-y", &out_arg(&t.0), fixture("basic.zip").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("SymlinkInDestination"));
    assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 0);
}
