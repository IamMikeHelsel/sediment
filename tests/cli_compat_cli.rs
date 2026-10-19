// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests of the 7-Zip compatible CLI layer (`cli_compat`,
//! `cli_run`, `cli_slt`): selection switches, list files, `-slt`, output
//! routing, overwrite modes, `-spf`, `-sdel`, archive types and exit codes.
//!
//! Inputs: the reference tree and archives of tests/fixtures/cli_wire
//! (tests/gen/cli_wire.py, 7z from the pinned 7zz oracle), the 7zz `-slt`
//! listings of tests/fixtures/sevenz (tests/gen/sevenz_oracle.sh,
//! tests/gen/sevenz.py), and the list files of tests/fixtures/cli_compat
//! (tests/gen/cli_compat.py).
#![allow(clippy::useless_vec, clippy::type_complexity)]
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command as Proc, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sediment_engine::cli_compat::Command;
use sediment_engine::cli_run::{Console, run_args};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
static N: AtomicU32 = AtomicU32::new(0);

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn wire(name: &str) -> PathBuf {
    root().join("tests/fixtures/cli_wire").join(name)
}

fn lists(name: &str) -> PathBuf {
    root().join("tests/fixtures/cli_compat/lists").join(name)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-compat-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        // Canonical so -spf prefixes are predictable (macOS /var -> /private/var).
        TempDir(fs::canonicalize(&p).unwrap())
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn os(s: impl AsRef<std::ffi::OsStr>) -> OsString {
    s.as_ref().to_os_string()
}

fn run_in(dir: Option<&Path>, args: &[OsString]) -> Output {
    let mut c = Proc::new(BIN);
    c.args(args);
    if let Some(d) = dir {
        c.current_dir(d);
    }
    c.output().unwrap()
}

fn run(args: &[OsString]) -> Output {
    run_in(None, args)
}

macro_rules! argv {
    ($($a:expr),* $(,)?) => { vec![$(os($a)),*] };
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// Names (third column) of `l -ba`, without trailing `/`.
fn names(o: &Output) -> Vec<String> {
    assert_eq!(code(o), 0, "{}", text(&o.stderr));
    text(&o.stdout)
        .lines()
        .map(|l| l.splitn(3, '\t').nth(2).unwrap().trim_end_matches('/').to_string())
        .collect()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn strs(v: &[&str]) -> Vec<String> {
    sorted(v.iter().map(|s| s.to_string()).collect())
}

const LONG: &str = "docs/deep/nested/long_long_long_long_long_long_long_long_long_long_long_long_long_long_long_long_long_long_.txt";
const CAFE: &str = "docs/caf\\xc3\\xa9.txt";

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[test]
fn exit_codes() {
    let zip = wire("tree.zip");
    let t = TempDir::new("codes");
    let table: Vec<(Vec<OsString>, i32)> = vec![
        // frozen legacy / dispatcher codes
        (argv![], 2),
        (argv!["bogus", "a"], 2),
        (argv!["list"], 2),
        (argv!["--help", "x"], 2),
        // command line errors -> 7
        (argv!["l"], 7),
        (argv!["x"], 7),
        (argv!["a"], 7),
        (argv!["t", "-q", &zip], 7),
        (argv!["x", "-o", &zip], 7),
        (argv!["l", "-trar", &zip], 7),
        (argv!["l", "-bb9", &zip], 7),
        (argv!["l", "-i!", &zip], 7),
        (argv!["l", &zip, "@/nonexistent/list.lst"], 7),
        (argv!["l", &zip, os(format!("@{}", lists("bad.utf8.lst").display()))], 7),
        (argv!["l", &zip, os(format!("@{}", lists("nul.lst").display()))], 7),
        (argv!["a", t.path("x.unknown"), &zip], 7),
        // fatal -> 2
        (argv!["l", "/nonexistent/x.zip"], 2),
        (argv!["l", "-t7z", &zip], 2),
        (argv!["t", root().join("tests/fixtures/extract/badcrc.zip")], 2),
        (argv!["x", root().join("tests/fixtures/extract/notzip.bin"), os(format!("-o{}", t.path("n").display()))], 2),
        (argv!["a", t.path("x.7z"), "-m0=bogus", &zip], 7),
        (argv!["a", t.path("x.zip"), "-m0=lzma", &zip], 7),
        (argv!["a", t.path("v.zip"), "-so", "-v1k", &zip], 7),
        (argv!["a", t.path("v.zip"), "-v0", &zip], 7),
        (argv!["a", "-an", t.path("v.zip"), &zip], 7),
        (argv!["a", t.0.as_path(), "-tzip", &zip], 2),
        (argv!["a", t.path("none.zip")], 7),
        // success
        (argv!["l", &zip], 0),
        (argv!["l", "-ba", "-slt", &zip], 0),
        (argv!["t", &zip, "nothing-matches"], 0),
        (argv!["t", root().join("tests/fixtures/extract/badcrc.zip"), "-x!data.txt"], 0),
    ];
    for (a, want) in table {
        let o = run(&a);
        assert_eq!(code(&o), want, "{a:?}: {}", text(&o.stderr));
        assert!(!text(&o.stderr).contains("panicked"), "{a:?}");
    }
}

// ---------------------------------------------------------------------------
// Selection: wildcards, -r, -i, -x, list files, -ssc
// ---------------------------------------------------------------------------

#[test]
fn selection_table_across_formats() {
    let all_files = [
        "data/prog.bin",
        "data/random.bin",
        "data/words.txt",
        CAFE,
        "docs/deep/nested/leaf.txt",
        LONG,
        "docs/readme.md",
        "empty.txt",
        "hello.txt",
    ];
    let dirs = ["data", "docs", "docs/deep", "docs/deep/nested", "emptydir"];
    let everything: Vec<&str> = all_files.iter().chain(dirs.iter()).copied().collect();
    let lst = |n: &str| os(format!("@{}", lists(n).display()));
    let from_list = vec!["hello.txt", CAFE, "data/prog.bin", "data/random.bin"];
    let table: Vec<(Vec<OsString>, Vec<&str>)> = vec![
        (argv![], everything.clone()),
        (argv!["*.txt"], vec!["empty.txt", "hello.txt"]),
        (argv!["-r", "*.txt"], vec!["data/words.txt", CAFE, "docs/deep/nested/leaf.txt", LONG, "empty.txt", "hello.txt"]),
        (argv!["-r0", "*.md", "deep"], vec!["docs/readme.md"]),
        (argv!["-ir0!*.md"], vec!["docs/readme.md"]),
        (argv!["docs/deep"], vec!["docs/deep", "docs/deep/nested", "docs/deep/nested/leaf.txt", LONG]),
        (argv!["-r", "nested"], vec!["docs/deep/nested", "docs/deep/nested/leaf.txt", LONG]),
        (argv!["nested"], vec![]),
        (argv!["data\\*.bin"], vec!["data/prog.bin", "data/random.bin"]),
        (argv!["-i!data/*", "hello.txt"], vec!["data/prog.bin", "data/random.bin", "data/words.txt", "hello.txt"]),
        (argv!["-x!*.txt"], everything.iter().copied().filter(|n| *n != "empty.txt" && *n != "hello.txt").collect()),
        (argv!["-xr!*.txt"], everything.iter().copied().filter(|n| !n.ends_with(".txt")).collect()),
        (argv!["docs", "-xr!deep"], vec!["docs", CAFE, "docs/readme.md"]),
        (argv!["-r", "*", "-x!docs", "-x!data"], vec!["emptydir", "empty.txt", "hello.txt"]),
        (argv!["-ssc-", "HELLO.TXT"], vec!["hello.txt"]),
        (argv!["-ssc", "HELLO.TXT"], vec![]),
        (argv!["h?llo.*"], vec!["hello.txt"]),
        (argv!["??????.txt"], vec![]),
        (argv![lst("names.utf8.lst")], from_list.clone()),
        (argv![lst("names.utf8bom.lst")], from_list.clone()),
        (argv![lst("names.utf16le.lst")], from_list.clone()),
        (argv!["-scsUTF-16LE", lst("names.utf16le-nobom.lst")], from_list.clone()),
        (argv!["-scsUTF-16BE", lst("names.utf16be.lst")], from_list.clone()),
        (argv![os(format!("-i{}", lst("names.utf8.lst").to_string_lossy()))], from_list.clone()),
        (argv![os(format!("-x{}", lst("names.utf8.lst").to_string_lossy()))], everything.iter().copied().filter(|n| !from_list.contains(n)).collect()),
    ];
    for arc in ["tree.zip", "tree_ustar.tar", "tree_pax.tar", "tree.tgz", "tree.tar.xz", "tree.tbz2", "7z/tree_lzma2.7z", "7z/tree_copy.7z"] {
        for (sel, want) in &table {
            let mut a = argv!["l", "-ba", wire(arc)];
            a.extend(sel.iter().cloned());
            assert_eq!(sorted(names(&run(&a))), strs(want), "{arc} {sel:?}");
        }
    }
}

#[test]
fn test_command_selection_and_output() {
    let zip = wire("tree.zip");
    let o = run(&argv!["t", "-bb1", &zip, "*.txt"]);
    assert_eq!(code(&o), 0);
    assert_eq!(text(&o.stdout), "T empty.txt\nT hello.txt\nOK\t2\t17\n");
    let o = run(&argv!["t", "-ba", &zip]);
    assert_eq!((code(&o), o.stdout.len()), (0, 0));
    let o = run(&argv!["t", &zip]);
    assert_eq!(text(&o.stdout), "OK\t14\t12714\n");
    // A bad member is reported even when others follow; nothing claims OK.
    let o = run(&argv!["t", root().join("tests/fixtures/extract/badcrc.zip")]);
    assert_eq!(code(&o), 2);
    assert_eq!(text(&o.stderr), "sediment: data error: data.txt\n");
    assert!(o.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// -slt
// ---------------------------------------------------------------------------

/// `l -slt` on 7z archives reproduces the 7zz oracle listing byte for byte
/// from "Listing archive:" on (the archive path is substituted).
#[test]
fn slt_matches_7zz_for_7z() {
    let cases = [
        "oracle/copy_nonsolid_nohc",
        "oracle/copy_solid_hc_times",
        "oracle/copy_solid_nohc",
        "oracle/lzma_nonsolid_nohc",
        "oracle/lzma_solid_hc",
        "oracle/lzma_solid_nohc",
        "oracle/lzma2_nonsolid_nohc",
        "oracle/lzma2_solid_hc",
        "gen/chain",
        "gen/empty",
        "gen/encoded_header",
        "gen/single",
        // Not compared: gen/nonsolid_no_substreams (7zz omits the CRC line
        // when only a folder CRC exists) and gen/solid (an all-undefined
        // CTime property prints an empty "Created = "); the SltEntry API
        // cannot express either.
    ];
    for c in cases {
        let arc = root().join(format!("tests/fixtures/sevenz/{c}.7z"));
        let oracle = fs::read_to_string(root().join(format!("tests/fixtures/sevenz/{c}.slt.txt"))).unwrap();
        let start = oracle.find("Listing archive: ").unwrap();
        let oracle = &oracle[start..];
        let shown = oracle["Listing archive: ".len()..].lines().next().unwrap();
        let o = run(&argv!["l", "-slt", &arc]);
        assert_eq!(code(&o), 0, "{c}");
        let ours = text(&o.stdout).replace(&arc.display().to_string(), shown);
        assert_eq!(ours, oracle, "{c}");
        // -ba drops the archive block only.
        let o = run(&argv!["l", "-slt", "-ba", &arc]);
        let body = &oracle[oracle.find("----------\n").unwrap() + 11..];
        assert_eq!(text(&o.stdout), body, "{c} -ba");
    }
}

#[test]
fn slt_generic_formats() {
    let o = run(&argv!["l", "-slt", "-ba", wire("tree.zip"), "hello.txt", "emptydir"]);
    assert_eq!(
        text(&o.stdout),
        "Path = emptydir\nFolder = +\nSize = 0\nPacked Size = \nModified = 2024-03-05 06:07:08.0000000\n\
Attributes = D drwxr-xr-x\nCRC = \nEncrypted = -\nMethod = \nBlock = \n\n\
Path = hello.txt\nFolder = -\nSize = 17\nPacked Size = \nModified = 2024-03-05 06:07:08.0000000\n\
Attributes = A -rw-r--r--\nCRC = 62906A7F\nEncrypted = -\nMethod = \nBlock = \n\n"
    );
    let o = run(&argv!["l", "-slt", wire("words.txt.gz")]);
    let s = text(&o.stdout);
    assert!(s.starts_with(&format!("Listing archive: {0}\n\n--\nPath = {0}\nType = gzip\nPhysical Size = ", wire("words.txt.gz").display())), "{s}");
    assert!(s.contains("\n----------\nPath = words.txt\nSize = 5670\n"), "{s}");
    assert!(s.contains("\nMethod = Deflate\n"));
    let o = run(&argv!["l", "-slt", "-ba", wire("tree_ustar.tar"), "data"]);
    let s = text(&o.stdout);
    assert!(s.starts_with("Path = data\nFolder = +\n"), "{s}");
    assert_eq!(s.matches("Path = ").count(), 4);
    // Unicode names print as UTF-8, not escaped.
    let o = run(&argv!["l", "-slt", "-ba", wire("7z/tree_lzma2.7z"), "docs/caf?.txt"]);
    assert!(text(&o.stdout).starts_with("Path = docs/café.txt\n"));
}

// ---------------------------------------------------------------------------
// Output streams and log levels
// ---------------------------------------------------------------------------

#[test]
fn stream_routing() {
    let zip = wire("tree.zip");
    let o = run(&argv!["l", &zip, "-bso0"]);
    assert_eq!((code(&o), o.stdout.len(), o.stderr.len()), (0, 0, 0));
    let o = run(&argv!["l", &zip, "-bso2", "hello.txt"]);
    assert_eq!(text(&o.stderr), "SIZE\tCRC32\tNAME\n17\t62906a7f\thello.txt\n");
    assert!(o.stdout.is_empty());
    let o = run(&argv!["l", "/nonexistent.zip", "-bse1"]);
    assert_eq!((code(&o), text(&o.stdout), o.stderr.len()), (2, "sediment: cannot open file\n".to_string(), 0));
    let o = run(&argv!["l", "/nonexistent.zip", "-bse0"]);
    assert_eq!((code(&o), o.stdout.len(), o.stderr.len()), (2, 0, 0));
    let o = run(&argv!["l", "-ba", &zip, "hello.txt"]);
    assert_eq!(text(&o.stdout), "17\t62906a7f\thello.txt\n");
    // Frozen default output for l is unchanged.
    let o = run(&argv!["l", &zip, "hello.txt"]);
    assert_eq!(text(&o.stdout), "SIZE\tCRC32\tNAME\n17\t62906a7f\thello.txt\n");
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let k = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if p.is_dir() {
                out.insert(k, None);
                walk(root, &p, out);
            } else {
                out.insert(k, Some(fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn keys(m: &BTreeMap<String, Option<Vec<u8>>>) -> Vec<String> {
    m.keys().cloned().collect()
}

fn out_arg(p: &Path) -> OsString {
    os(format!("-o{}", p.display()))
}

#[test]
fn extract_with_selection() {
    for arc in ["tree.zip", "tree.tgz", "7z/tree_lzma2.7z"] {
        let t = TempDir::new("xsel");
        let o = run(&argv!["x", wire(arc), out_arg(&t.0), "-ir!*.txt", "-xr!long*"]);
        assert_eq!(code(&o), 0, "{arc}: {}", text(&o.stderr));
        let snap = snapshot(&t.0);
        assert_eq!(
            keys(&snap),
            strs(&["data", "data/words.txt", "docs", "docs/café.txt", "docs/deep", "docs/deep/nested", "docs/deep/nested/leaf.txt", "empty.txt", "hello.txt"]),
            "{arc}"
        );
        assert_eq!(snap["hello.txt"], Some(fs::read(wire("tree/hello.txt")).unwrap()));

        let t = TempDir::new("esel");
        let o = run(&argv!["e", wire(arc), out_arg(&t.0), "-r", "*.txt", "-x!empty.txt"]);
        assert_eq!(code(&o), 0, "{arc}: {}", text(&o.stderr));
        let leaf = LONG.rsplit('/').next().unwrap();
        assert_eq!(keys(&snapshot(&t.0)), strs(&["café.txt", "hello.txt", "leaf.txt", leaf, "words.txt"]), "{arc}");
    }
}

#[test]
fn extract_log_levels() {
    let t = TempDir::new("bb");
    let o = run(&argv!["x", wire("tree.zip"), out_arg(&t.path("a")), "-bb1", "data"]);
    assert_eq!(text(&o.stdout), "- data/prog.bin\n- data/random.bin\n- data/words.txt\nFolders: 1\nFiles: 3\nSize: 8742\n");
    let o = run(&argv!["x", wire("tree.zip"), out_arg(&t.path("b")), "-bb2", "-ba", "data"]);
    assert_eq!(text(&o.stdout), "- data/\n- data/prog.bin\n- data/random.bin\n- data/words.txt\n");
    let o = run(&argv!["x", wire("tree.zip"), out_arg(&t.path("b")), "-bb2", "-aos", "-ba", "data/prog.bin"]);
    assert_eq!(text(&o.stdout), "- skipped data/prog.bin\n");
    let o = run(&argv!["x", wire("tree.zip"), out_arg(&t.path("c")), "data"]);
    assert!(o.stdout.is_empty());
}

#[test]
fn overwrite_modes() {
    let zip = wire("tree.zip");
    let new = fs::read(wire("tree/hello.txt")).unwrap();
    let cases: &[(&[&str], i32, &[(&str, &[u8])])] = &[
        (&[], 2, &[("hello.txt", b"old")]),
        (&["-aos"], 0, &[("hello.txt", b"old")]),
        (&["-aoa"], 0, &[("hello.txt", b"NEW")]),
        (&["-y"], 0, &[("hello.txt", b"NEW")]),
        (&["-aou"], 0, &[("hello.txt", b"old"), ("hello_1.txt", b"NEW")]),
        (&["-aot"], 0, &[("hello.txt", b"NEW"), ("hello_1.txt", b"old")]),
        (&["-y", "-aos"], 0, &[("hello.txt", b"old")]),
    ];
    for (sw, want_code, files) in cases {
        let t = TempDir::new("ao");
        fs::write(t.path("hello.txt"), b"old").unwrap();
        let mut a = argv!["x", &zip, out_arg(&t.0), "hello.txt"];
        a.extend(sw.iter().map(os));
        let o = run(&a);
        assert_eq!(code(&o), *want_code, "{sw:?}: {}", text(&o.stderr));
        let snap = snapshot(&t.0);
        assert_eq!(snap.len(), files.len(), "{sw:?}: {:?}", keys(&snap));
        for (name, content) in *files {
            let want = if *content == b"NEW" { new.clone() } else { content.to_vec() };
            assert_eq!(snap[*name], Some(want), "{sw:?} {name}");
        }
    }
    // -aot never follows a symlinked directory in the destination.
    #[cfg(unix)]
    {
        let t = TempDir::new("aot-link");
        let outside = TempDir::new("aot-outside");
        fs::write(outside.path("leaf.txt"), b"keep").unwrap();
        fs::create_dir_all(t.path("out/docs/deep")).unwrap();
        std::os::unix::fs::symlink(&outside.0, t.path("out/docs/deep/nested")).unwrap();
        let o = run(&argv!["x", &zip, out_arg(&t.path("out")), "-aot", "docs/deep/nested/leaf.txt"]);
        assert_eq!(code(&o), 2, "{}", text(&o.stderr));
        assert_eq!(keys(&snapshot(&outside.0)), strs(&["leaf.txt"]));
        assert_eq!(fs::read(outside.path("leaf.txt")).unwrap(), b"keep");
    }
}

fn console_run(cmd: Command, a: &[OsString], input: Option<&str>) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut cursor = input.map(|s| Cursor::new(s.as_bytes().to_vec()));
    let code = {
        let mut con = Console {
            stdout: &mut out,
            stderr: &mut err,
            interactive: cursor.is_some(),
            stdout_is_terminal: false,
            stdin: cursor.as_mut().map(|c| c as &mut dyn std::io::BufRead),
        };
        run_args(cmd, a, &mut con)
    };
    (code, text(&out), text(&err))
}

#[test]
fn interactive_overwrite_prompt() {
    let zip = wire("tree.zip");
    let new = fs::read(wire("tree/hello.txt")).unwrap();
    let cases: &[(&str, i32, &[(&str, &[u8])])] = &[
        ("q\n", 255, &[("hello.txt", b"old")]),
        ("", 255, &[("hello.txt", b"old")]),
        ("?\n?\n?\n?\n?\n", 255, &[("hello.txt", b"old")]),
        ("s\n", 0, &[("hello.txt", b"old")]),
        ("A\n", 0, &[("hello.txt", b"NEW")]),
        ("x\na\n", 0, &[("hello.txt", b"NEW")]),
        ("u\n", 0, &[("hello.txt", b"old"), ("hello_1.txt", b"NEW")]),
        ("t\n", 0, &[("hello.txt", b"NEW"), ("hello_1.txt", b"old")]),
    ];
    for (answer, want_code, files) in cases {
        let t = TempDir::new("prompt");
        fs::write(t.path("hello.txt"), b"old").unwrap();
        let (c, _, err) = console_run(Command::Extract, &argv![&zip, out_arg(&t.0), "hello.txt"], Some(answer));
        assert_eq!(c, *want_code, "{answer:?}: {err}");
        assert!(err.contains("File already exists"), "{err}");
        let snap = snapshot(&t.0);
        assert_eq!(snap.len(), files.len(), "{answer:?}");
        for (name, content) in *files {
            let want = if *content == b"NEW" { new.clone() } else { content.to_vec() };
            assert_eq!(snap[*name], Some(want), "{answer:?} {name}");
        }
    }
    // No conflict: no prompt; -y: no prompt.
    let t = TempDir::new("prompt-none");
    let (c, _, err) = console_run(Command::Extract, &argv![&zip, out_arg(&t.0), "hello.txt"], Some("q\n"));
    assert_eq!((c, err.as_str()), (0, ""));
    let (c, _, err) = console_run(Command::Extract, &argv![&zip, out_arg(&t.0), "hello.txt", "-y"], Some("q\n"));
    assert_eq!((c, err.as_str()), (0, ""));
}

/// Minimal ustar archive (one regular file) with an arbitrary name.
fn ustar(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let (prefix, base) = match name.len() {
        0..=100 => ("", name),
        _ => name.split_at(name[..name.len() - 1].rfind('/').unwrap()),
    };
    let base = if prefix.is_empty() { base } else { &base[1..] };
    h[..base.len()].copy_from_slice(base.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    h[136..147].copy_from_slice(b"14572460214");
    h[148..156].copy_from_slice(b"        ");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut v = h.to_vec();
    v.extend_from_slice(data);
    v.resize(v.len().div_ceil(512) * 512 + 1024, 0);
    v
}

#[cfg(unix)]
#[test]
fn extract_full_paths() {
    let t = TempDir::new("spf");
    let target = t.path("abs/out.txt");
    let tar = t.path("abs.tar");
    fs::write(&tar, ustar(&target.display().to_string(), b"absolute")).unwrap();
    // Without -spf the absolute member is refused and nothing is written.
    let o = run(&argv!["x", &tar, out_arg(&t.path("rel"))]);
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    assert!(!target.exists());
    // With -spf it goes to its absolute location.
    let o = run(&argv!["x", "-spf", &tar, out_arg(&t.path("rel"))]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(fs::read(&target).unwrap(), b"absolute");
    assert!(!t.path("rel").join("out.txt").exists());
    // Traversal stays refused even with -spf.
    fs::write(&tar, ustar(&format!("{}/../escape.txt", t.0.display()), b"x")).unwrap();
    let o = run(&argv!["x", "-spf", &tar, out_arg(&t.path("rel"))]);
    assert_eq!(code(&o), 2);
    assert!(!t.0.parent().unwrap().join("escape.txt").exists());
}

#[test]
fn typed_open() {
    let o = run(&argv!["l", "-ba", "-tgzip", wire("tree.tgz")]);
    assert_eq!(names(&o), vec!["tree.tar"]);
    let o = run(&argv!["l", "-ba", "-tgz", wire("tree.tgz")]);
    assert_eq!(names(&o), vec!["tree.tar"]);
    let o = run(&argv!["l", "-ba", "-ttar", wire("tree_ustar.tar"), "hello.txt"]);
    assert_eq!(names(&o), vec!["hello.txt"]);
    let o = run(&argv!["l", "-ba", "-tzip", wire("tree.zip"), "hello.txt"]);
    assert_eq!(names(&o), vec!["hello.txt"]);
    let o = run(&argv!["l", "-ba", "-t7z", wire("7z/tree_lzma2.7z"), "hello.txt"]);
    assert_eq!(names(&o), vec!["hello.txt"]);
    let o = run(&argv!["l", "-ba", "-tbzip2", wire("tree.tbz2")]);
    assert_eq!(names(&o), vec!["tree.tar"]);
    let o = run(&argv!["l", "-tzip", wire("tree.tgz")]);
    assert_eq!(code(&o), 2);
    assert_eq!(text(&o.stderr), "sediment: cannot open the file as zip archive\n");
    let o = run(&argv!["l", "-txz", wire("tree.tgz")]);
    assert_eq!(code(&o), 2);
    let t = TempDir::new("txz");
    let o = run(&argv!["x", "-txz", wire("readme.md.xz"), out_arg(&t.0)]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(fs::read(t.path("readme.md")).unwrap(), fs::read(wire("tree/docs/readme.md")).unwrap());
}

// ---------------------------------------------------------------------------
// Adding
// ---------------------------------------------------------------------------

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dst = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_tree(&p, &dst);
        } else {
            fs::copy(&p, &dst).unwrap();
        }
    }
}

/// A scratch copy of the reference tree under `<tmp>/src`.
fn scratch(tag: &str) -> TempDir {
    let t = TempDir::new(tag);
    copy_tree(&wire("tree"), &t.path("src"));
    for d in fs::read_to_string(wire("tree.dirs")).unwrap().lines() {
        fs::create_dir_all(t.path("src").join(d)).unwrap();
    }
    t
}

fn listing(arc: &Path) -> Vec<String> {
    sorted(names(&run(&argv!["l", "-ba", arc])))
}

#[test]
fn add_wildcards_and_filters() {
    let t = scratch("add");
    let src = t.path("src");
    let lst = t.path("names.lst");
    fs::write(&lst, "hello.txt\r\ndocs/café.txt\n\ndata/*.bin\n").unwrap();
    let table: Vec<(Vec<OsString>, Vec<&str>)> = vec![
        (argv!["*.txt"], vec!["empty.txt", "hello.txt"]),
        (argv!["-r", "*.txt"], vec!["data/words.txt", CAFE, "docs/deep/nested/leaf.txt", LONG, "empty.txt", "hello.txt"]),
        (argv!["-r", "leaf.txt"], vec!["docs/deep/nested/leaf.txt"]),
        (argv!["docs", "-xr!*.md", "-x!docs/deep"], vec!["docs", "docs/caf\\xc3\\xa9.txt"]),
        (argv!["-i!data/*.bin"], vec!["prog.bin", "random.bin"]),
        (argv!["data/*.bin", "-x!random.bin"], vec!["prog.bin"]),
        (argv!["*/*.md"], vec!["docs/readme.md"]),
        (argv!["d*", "-xr!*.txt", "-xr!*.bin", "-x!docs/deep"], vec!["data", "docs", "docs/readme.md"]),
        (argv![os(format!("@{}", lst.display()))], vec!["hello.txt", "caf\\xc3\\xa9.txt", "prog.bin", "random.bin"]),
        (argv!["-ssc-", "HELLO.*"], vec!["hello.txt"]),
        (
            argv!["*"],
            vec![
                "data", "data/prog.bin", "data/random.bin", "data/words.txt", "docs", CAFE, "docs/deep", "docs/deep/nested",
                "docs/deep/nested/leaf.txt", LONG, "docs/readme.md", "empty.txt", "emptydir", "hello.txt",
            ],
        ),
    ];
    for (i, (sel, want)) in table.iter().enumerate() {
        for ext in ["zip", "tar", "tar.gz", "tar.xz", "tar.bz2", "7z"] {
            let arc = t.path(&format!("out{i}.{ext}"));
            let mut a = argv!["a", &arc];
            a.extend(sel.iter().cloned());
            let o = run_in(Some(&src), &a);
            assert_eq!(code(&o), 0, "{sel:?} {ext}: {}", text(&o.stderr));
            assert_eq!(listing(&arc), strs(want), "{sel:?} {ext}");
            let o = run(&argv!["t", &arc]);
            assert_eq!(code(&o), 0, "{sel:?} {ext}");
        }
    }
}

#[test]
fn add_round_trip_through_extract() {
    let t = scratch("rt");
    for ext in ["zip", "tar.xz", "tar.bz2", "tgz", "7z"] {
        let arc = t.path(&format!("all.{ext}"));
        let o = run_in(Some(&t.path("src")), &argv!["a", "-mx9", &arc, "-r", "*"]);
        assert_eq!(code(&o), 0, "{ext}: {}", text(&o.stderr));
        let out = t.path(&format!("x-{ext}"));
        let o = run(&argv!["x", &arc, out_arg(&out)]);
        assert_eq!(code(&o), 0, "{ext}: {}", text(&o.stderr));
        assert_eq!(snapshot(&out), snapshot(&t.path("src")), "{ext}");
    }
}

#[test]
fn add_streams() {
    let t = scratch("streams");
    let src = t.path("src");
    let hello = fs::read(src.join("hello.txt")).unwrap();
    for (sw, name) in [("-tgzip", "h.gz"), ("-tbzip2", "h.bz2"), ("-txz", "h.xz"), ("", "auto.gz"), ("", "auto.xz"), ("", "auto.bz2")] {
        let arc = t.path(name);
        let mut a = argv!["a", &arc, "hello.txt"];
        if !sw.is_empty() {
            a.push(os(sw));
        }
        let o = run_in(Some(&src), &a);
        assert_eq!(code(&o), 0, "{name}: {}", text(&o.stderr));
        let out = t.path(&format!("x-{name}"));
        let o = run(&argv!["e", &arc, out_arg(&out)]);
        assert_eq!(code(&o), 0, "{name}: {}", text(&o.stderr));
        let files = snapshot(&out);
        assert_eq!(files.len(), 1, "{name}");
        assert_eq!(files.values().next().unwrap().as_deref(), Some(hello.as_slice()), "{name}");
    }
    // A stream holds exactly one file.
    let o = run_in(Some(&src), &argv!["a", t.path("two.gz"), "hello.txt", "empty.txt"]);
    assert_eq!(code(&o), 2);
    let o = run_in(Some(&src), &argv!["a", t.path("dir.xz"), "docs"]);
    assert_eq!(code(&o), 2);
    assert!(!t.path("two.gz").exists() && !t.path("dir.xz").exists());
}

#[test]
fn add_full_paths_and_output_switches() {
    let t = scratch("spf");
    let src = t.path("src");
    let arc = t.path("full.tar");
    let o = run(&argv!["a", "-spf", "-ba", &arc, src.join("hello.txt"), src.join("data/../docs/deep")]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(o.stdout.is_empty(), "-ba hides the summary");
    let base = src.display().to_string().trim_start_matches('/').to_string();
    let want: Vec<String> = ["hello.txt", "docs/deep", "docs/deep/nested", "docs/deep/nested/leaf.txt", LONG]
        .iter()
        .map(|n| format!("{base}/{n}"))
        .collect();
    assert_eq!(listing(&arc), sorted(want));
    // -bb1 lists added names; the summary line follows.
    let o = run_in(Some(&src), &argv!["a", "-bb1", t.path("bb.zip"), "*.txt"]);
    let s = text(&o.stdout);
    assert!(s.starts_with("+ empty.txt\n+ hello.txt\nCreated "), "{s}");
}

#[test]
fn add_delete_after() {
    let t = scratch("sdel");
    let src = t.path("src");
    let o = run_in(Some(&src), &argv!["a", "-sdel", t.path("data.zip"), "data"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!src.join("data").exists());
    assert_eq!(listing(&t.path("data.zip")), strs(&["data", "data/prog.bin", "data/random.bin", "data/words.txt"]));
    // Excluded files survive, so does their directory.
    let o = run_in(Some(&src), &argv!["a", "-sdel", t.path("docs.zip"), "docs", "-xr!*.md"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(keys(&snapshot(&src.join("docs"))), strs(&["readme.md"]));
    // Nothing is deleted when the archive cannot be written.
    let o = run_in(Some(&src), &argv!["a", "-sdel", "-tzip", t.0.as_path(), "hello.txt"]);
    assert_eq!(code(&o), 2);
    assert!(src.join("hello.txt").exists());
}

#[test]
fn add_missing_inputs_and_existing_archive() {
    let t = scratch("missing");
    let src = t.path("src");
    let arc = t.path("m.zip");
    let o = run_in(Some(&src), &argv!["a", &arc, "hello.txt", "nope.txt", "*.none"]);
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("nope.txt"));
    assert_eq!(listing(&arc), strs(&["hello.txt"]));
    let o = run_in(Some(&src), &argv!["a", &arc, "empty.txt"]);
    assert_eq!(code(&o), 2, "existing archive needs -y");
    let o = run_in(Some(&src), &argv!["a", "-y", &arc, "empty.txt"]);
    assert_eq!(code(&o), 0);
    assert_eq!(listing(&arc), strs(&["empty.txt"]));
    let none = t.path("none.zip");
    let o = run_in(Some(&src), &argv!["a", &none, "nope.txt"]);
    assert_eq!(code(&o), 1);
    assert!(!none.exists());
    let o = run_in(Some(&src), &argv!["a", &none, "-x!*", "hello.txt"]);
    assert_eq!(code(&o), 1);
    assert!(!none.exists());
}

#[test]
fn add_sevenz_with_method_switches() {
    let t = scratch("7z");
    let src = t.path("src");
    for (i, sw) in [&["-m0=LZMA", "-ms=off"][..], &["-mx0"], &["-m0=LZMA2", "-mf=BCJ", "-mhc=off"], &["-t7z"]].iter().enumerate() {
        let arc = t.path(&format!("m{i}.7z"));
        let mut a = argv!["a", &arc, "-r", "*"];
        a.extend(sw.iter().map(os));
        let o = run_in(Some(&src), &a);
        assert_eq!(code(&o), 0, "{sw:?}: {}", text(&o.stderr));
        let slt = text(&run(&argv!["l", "-slt", &arc]).stdout);
        let want = match i {
            0 => "\nMethod = LZMA:",
            1 => "\nMethod = Copy\n",
            2 => " LZMA2:",
            _ => "\nType = 7z\n",
        };
        assert!(slt.contains(want), "{sw:?}: {slt}");
        if i == 0 {
            assert!(slt.contains("\nSolid = -\n"), "{slt}");
        }
        if i == 2 {
            assert!(slt.contains("\nMethod = BCJ LZMA2:"), "{slt}");
        }
        let out = t.path(&format!("x{i}"));
        let o = run(&argv!["x", &arc, out_arg(&out)]);
        assert_eq!(code(&o), 0, "{sw:?}: {}", text(&o.stderr));
        assert_eq!(snapshot(&out), snapshot(&src), "{sw:?}");
    }
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

/// Every fixture archive and many truncations of valid ones: `l -slt`,
/// `t` and selective `x` never panic and exit with 0, 1 or 2.
#[test]
fn malformed_inputs_never_panic() {
    let mut inputs: Vec<PathBuf> = Vec::new();
    for dir in ["tests/fixtures/cli_wire", "tests/fixtures/cli_wire/7z", "tests/fixtures/sevenz/gen", "tests/fixtures/extract"] {
        for e in fs::read_dir(root().join(dir)).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                inputs.push(p);
            }
        }
    }
    let t = TempDir::new("trunc");
    for src in ["tree.zip", "7z/tree_lzma2.7z", "7z/tree_bcj.7z", "tree.tgz"] {
        let data = fs::read(wire(src)).unwrap();
        let step = (data.len() / 12).max(1);
        for (k, cut) in (1..data.len()).step_by(step).enumerate() {
            let p = t.path(&format!("cut{k}-{}", src.replace('/', "_")));
            fs::write(&p, &data[..cut]).unwrap();
            inputs.push(p);
        }
        let mut flipped = data.clone();
        for i in (0..flipped.len()).step_by(97) {
            flipped[i] ^= 0x5a;
        }
        let p = t.path(&format!("flip-{}", src.replace('/', "_")));
        fs::write(&p, &flipped).unwrap();
        inputs.push(p);
    }
    for p in &inputs {
        for a in [argv!["l", "-slt", p], argv!["t", "-bb1", p], argv!["x", p, out_arg(&t.path("x")), "-r", "*.txt", "-aoa"]] {
            let o = run(&a);
            assert!(matches!(code(&o), 0..=2), "{a:?} -> {}: {}", code(&o), text(&o.stderr));
            assert!(!text(&o.stderr).contains("panicked"), "{a:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Standard streams and volumes combined with the compat switches
// ---------------------------------------------------------------------------

fn run_stdin(dir: Option<&Path>, args: &[OsString], input: &[u8]) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut c = Proc::new(BIN);
    c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = dir {
        c.current_dir(d);
    }
    let mut child = c.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    out
}

#[test]
fn so_and_si_with_selection() {
    let zip = wire("tree.zip");
    let tree = |p: &str| fs::read(wire("tree").join(p)).unwrap();
    // -so writes only the selected files, in archive order; -bb1 names go to stderr.
    let o = run(&argv!["x", "-so", "-bb1", &zip, "-r", "*.txt", "-x!empty.txt", "-xr!long*"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let mut want = tree("data/words.txt");
    want.extend(tree("docs/café.txt"));
    want.extend(tree("docs/deep/nested/leaf.txt"));
    want.extend(tree("hello.txt"));
    assert_eq!(o.stdout, want);
    assert_eq!(text(&o.stderr), "- data/words.txt\n- docs/caf\\xc3\\xa9.txt\n- docs/deep/nested/leaf.txt\n- hello.txt\n");
    // -si: every positional is a member name.
    let bytes = fs::read(&zip).unwrap();
    let o = run_stdin(None, &argv!["l", "-si", "-ba", "hello.txt", "data/*.bin"], &bytes);
    assert_eq!(sorted(names(&o)), strs(&["data/prog.bin", "data/random.bin", "hello.txt"]));
    let o = run_stdin(None, &argv!["t", "-si", "-ba"], &bytes);
    assert_eq!((code(&o), o.stdout.len()), (0, 0));
    let o = run_stdin(None, &argv!["l", "-si", "-slt", "-ba", "-tzip", "hello.txt"], &bytes);
    assert!(text(&o.stdout).starts_with("Path = hello.txt\nFolder = -\n"), "{}", text(&o.stdout));
    let t = TempDir::new("si-x");
    let o = run_stdin(None, &argv!["x", "-si", out_arg(&t.0), "docs/deep"], &fs::read(wire("tree.tgz")).unwrap());
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(keys(&snapshot(&t.0)), strs(&["docs", "docs/deep", "docs/deep/nested", "docs/deep/nested/leaf.txt", LONG]));
}

#[test]
fn add_to_stdout_and_volumes() {
    let t = scratch("so-v");
    let src = t.path("src");
    // -so: the archive goes to stdout, the summary to stderr; the name only picks the format.
    let o = run_stdin(Some(&src), &argv!["a", "-so", "out.tar", "-r", "*.txt"], b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stderr).starts_with("Created out.tar ("), "{}", text(&o.stderr));
    assert!(!src.join("out.tar").exists());
    let l = run_stdin(None, &argv!["l", "-si", "-ba"], &o.stdout);
    assert_eq!(sorted(names(&l)), strs(&["data/words.txt", CAFE, "docs/deep/nested/leaf.txt", LONG, "empty.txt", "hello.txt"]));
    // A terminal on stdout is refused (in-process console flag).
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut con = Console { stdout: &mut out, stderr: &mut err, stdin: None, interactive: false, stdout_is_terminal: true };
    assert_eq!(run_args(Command::Add, &argv!["-so", t.path("x.zip"), wire("tree/hello.txt")], &mut con), 7);
    assert!(out.is_empty());
    // -v: volumes that read back through `*.001`, with selection preserved.
    let arc = t.path("v.zip");
    let o = run_in(Some(&src), &argv!["a", "-v2k", &arc, "*", "-xr!*.bin"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains(" in ") && text(&o.stdout).contains(" volumes ("), "{}", text(&o.stdout));
    assert!(!arc.exists() && t.path("v.zip.001").exists() && t.path("v.zip.002").exists());
    let first = t.path("v.zip.001");
    assert!(!listing(&first).iter().any(|n| n.ends_with(".bin")));
    let out = t.path("vx");
    let o = run(&argv!["x", &first, out_arg(&out), "hello.txt"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(keys(&snapshot(&out)), strs(&["hello.txt"]));
    // Existing volumes need -y.
    let o = run_in(Some(&src), &argv!["a", "-v2k", &arc, "*"]);
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    let o = run_in(Some(&src), &argv!["a", "-y", "-v2k", &arc, "*"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}
