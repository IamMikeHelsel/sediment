// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for the `i` command (`cli_info`) and the tail switches of
//! `cli_compat`/`cli_run`/`cli_update`: `-ai`/`-ax`, `-w`, `-stl`, `-ad`,
//! `-bd`, `-bt`, `-stx`, `-sse`, `-ssw`, `-spe` and `-spo`.
//!
//! Inputs: the Python-stdlib archives of tests/fixtures/cli_wire
//! (tests/gen/cli_wire.py) and archives the binary itself creates; zip
//! contents are compared against the fixture tree.
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as Proc, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use sediment_engine::cli_compat::{
    Command, EXCLUDABLE_TYPES, NameItem, NameRule, PathPolicy, Recurse, parse_command_line,
};
use sediment_engine::cli_info::{CODECS, FORMATS, info_text, run_info};
use sediment_engine::cli_update::{EditTail, take_edit_tail};
use sediment_engine::hash_multi::ALL_METHODS;

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
static N: AtomicU32 = AtomicU32::new(0);

fn wire(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_wire").join(name)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-tail-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
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

fn args(a: &[&str]) -> Vec<OsString> {
    a.iter().map(OsString::from).collect()
}

fn run_in(dir: &Path, a: &[&str]) -> Output {
    Proc::new(BIN).args(a).current_dir(dir).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn mtime(p: &Path) -> i64 {
    fs::metadata(p).unwrap().modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn set_mtime(p: &Path, secs: u64) {
    let f = fs::File::options().write(true).open(p).or_else(|_| fs::File::open(p)).unwrap();
    f.set_modified(UNIX_EPOCH + Duration::from_secs(secs)).unwrap();
}

fn write(p: &Path, data: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

/// Three zips with distinct contents: a1.zip, a2.zip, sub/a3.zip.
fn three_zips(t: &TempDir) {
    for (n, member) in [("a1.zip", "hello.txt"), ("a2.zip", "empty.txt"), ("sub/a3.zip", "data/words.txt")] {
        let src = t.path("src");
        let _ = fs::remove_dir_all(&src);
        write(&src.join(member), &fs::read(wire("tree").join(member)).unwrap());
        fs::create_dir_all(t.path(n).parent().unwrap()).unwrap();
        let top = member.split('/').next().unwrap();
        let o = run_in(&src, &["a", t.path(n).to_str().unwrap(), top, "-ba"]);
        assert_eq!(code(&o), 0, "{o:?}");
    }
    fs::remove_dir_all(t.path("src")).unwrap();
}

fn files_under(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[test]
fn parser_accepts_tail_switches() {
    let cl = parse_command_line(Command::Extract, &args(&["-an", "-air!*.zip", "-ax@skip.txt", "-ai!b.zip"])).unwrap();
    assert_eq!(cl.archive, None);
    assert_eq!(
        cl.archive_includes,
        vec![
            NameRule { item: NameItem::Wildcard("*.zip".into()), recurse: Some(Recurse::On) },
            NameRule { item: NameItem::Wildcard("b.zip".into()), recurse: None },
        ]
    );
    assert_eq!(cl.archive_excludes, vec![NameRule { item: NameItem::ListFile("skip.txt".into()), recurse: None }]);

    let cl = parse_command_line(Command::Add, &args(&["-w/tmp/w", "-stl", "-sse", "-ssw", "-ad", "-bd", "-bt", "a.zip", "x"]))
        .unwrap();
    assert_eq!(cl.work_dir, Some(PathBuf::from("/tmp/w")));
    assert!(cl.archive_time_from_newest && cl.stop_on_open_error && cl.timing);
    let cl = parse_command_line(Command::Add, &args(&["-w", "a.zip", "x"])).unwrap();
    assert_eq!(cl.work_dir, Some(std::env::temp_dir()));

    let cl = parse_command_line(Command::Extract, &args(&["-spe", "-spoc", "-stxZIP", "-stxgz", "a.7z"])).unwrap();
    assert!(cl.eliminate_root_dup);
    assert_eq!(cl.path_policy, Some(PathPolicy::Continue));
    assert_eq!(cl.exclude_types, vec!["zip".to_string(), "gz".to_string()]);
    for (s, p) in [("-spod", PathPolicy::Fail), ("-SPOR", PathPolicy::Replace), ("-spoC", PathPolicy::Continue)] {
        assert_eq!(parse_command_line(Command::Extract, &args(&[s, "a.zip"])).unwrap().path_policy, Some(p));
    }
    for t in EXCLUDABLE_TYPES {
        assert!(parse_command_line(Command::Test, &args(&[&format!("-stx{t}"), "a.zip"])).is_ok(), "{t}");
    }
}

#[test]
fn parser_rejects_unknown_variants() {
    for bad in [
        &["-spox", "a.zip"][..],
        &["-spo", "a.zip"],
        &["-stx", "a.zip"],
        &["-stxfoo", "a.zip"],
        &["-stl1", "a.zip"],
        &["-bt0", "a.zip"],
        &["-bd1", "a.zip"],
        &["-ad2", "a.zip"],
        &["-sse-", "a.zip"],
        &["-sswx", "a.zip"],
        &["-spe1", "a.zip"],
        &["-ai", "a.zip"],
        &["-ai*.zip", "a.zip"],
        &["-ax!", "a.zip"],
        &["-an", "-ai!*.zip", "-si"],
    ] {
        assert!(parse_command_line(Command::Extract, &args(bad)).is_err(), "{bad:?}");
    }
    // -ai/-ax select archives to read; `a` has no use for them.
    assert!(parse_command_line(Command::Add, &args(&["-ai!*.zip", "a.zip", "x"])).is_err());
    // -an without -ai still needs -so.
    assert!(parse_command_line(Command::Extract, &args(&["-an"])).is_err());
}

#[test]
fn unknown_variants_exit_7_through_the_binary() {
    let t = TempDir::new("exit7");
    fs::copy(wire("tree.zip"), t.path("tree.zip")).unwrap();
    for s in ["-spoz", "-stxnope", "-bt1", "-stl-", "-ssex", "-ssw0", "-spe-", "-adx", "-bdq", "-ai"] {
        for cmd in ["l", "t", "x", "e"] {
            let o = run_in(&t.0, &[cmd, s, "tree.zip", "-oout"]);
            assert_eq!(code(&o), 7, "{cmd} {s}: {o:?}");
        }
    }
    let o = run_in(&t.0, &["a", "-ai!*.zip", "new.zip", "tree.zip"]);
    assert_eq!(code(&o), 7);
    let o = run_in(&t.0, &["i", "-x"]);
    assert_eq!(code(&o), 7);
}

#[test]
fn edit_tail_switches() {
    let (tail, rest) = take_edit_tail(&args(&["-w", "-stl", "-bt", "-ad", "-bd", "-ssw", "-r", "a.zip", "--", "-stl"])).unwrap();
    assert_eq!(tail, EditTail { work_dir: Some(std::env::temp_dir()), stl: true, timing: true });
    assert_eq!(rest, args(&["-r", "a.zip", "--", "-stl"]));
    let (tail, _) = take_edit_tail(&args(&["-w/x/y", "a.zip"])).unwrap();
    assert_eq!(tail.work_dir, Some(PathBuf::from("/x/y")));
    for bad in ["-stl1", "-bt-", "-adx", "-sswz"] {
        assert!(take_edit_tail(&args(&[bad, "a.zip"])).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------------------
// i
// ---------------------------------------------------------------------------

#[test]
fn info_report_sections_and_rows() {
    let text = info_text();
    let f = text.find("\nFormats:\n").unwrap();
    let c = text.find("\nCodecs:\n").unwrap();
    let h = text.find("\nHashers:\n").unwrap();
    assert!(f < c && c < h);
    for row in FORMATS {
        let line = text[f..c].lines().find(|l| l.split_whitespace().any(|w| w == row.name)).unwrap();
        assert_eq!(line.contains(" R W "), row.write, "{line}");
        for e in row.extensions {
            assert!(line.split_whitespace().any(|w| w == *e), "{line} lacks {e}");
        }
    }
    for name in ["7z", "zip", "tar", "gzip", "bzip2", "xz"] {
        assert!(FORMATS.iter().any(|r| r.name == name && r.read && r.write), "{name}");
    }
    for codec in CODECS {
        assert!(text[c..h].lines().any(|l| l.ends_with(&format!("  {}", codec.name))), "{}", codec.name);
    }
    for m in ALL_METHODS {
        assert!(text[h..].lines().any(|l| l.ends_with(&format!("  {}", m.name()))), "{}", m.name());
    }
}

#[test]
fn info_formats_really_open() {
    // Every read/write format row must round-trip through the binary.
    let t = TempDir::new("info-rw");
    let src = t.path("src");
    write(&src.join("hello.txt"), b"hello\n");
    for (name, file) in [("7z", "x.7z"), ("zip", "x.zip"), ("tar", "x.tar"), ("gzip", "x.tar.gz"), ("bzip2", "x.tar.bz2"), ("xz", "x.tar.xz")] {
        assert!(FORMATS.iter().any(|r| r.name == name && r.write));
        let arc = t.path(file);
        assert_eq!(code(&run_in(&src, &["a", arc.to_str().unwrap(), "hello.txt", "-ba"])), 0, "{file}");
        assert_eq!(code(&run_in(&t.0, &["t", file, "-ba"])), 0, "{file}");
    }
}

#[test]
fn info_command_output() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(run_info(&[], &mut out, &mut err), 0);
    assert_eq!(out, info_text().into_bytes());
    assert_eq!(run_info(&args(&["-ba"]), &mut Vec::new(), &mut Vec::new()), 0);
    assert_eq!(run_info(&args(&["extra"]), &mut Vec::new(), &mut Vec::new()), 7);
    let t = TempDir::new("info");
    let o = run_in(&t.0, &["i"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), info_text());
}

// ---------------------------------------------------------------------------
// -ai / -ax
// ---------------------------------------------------------------------------

#[test]
fn ai_ax_select_archives_for_extract() {
    let t = TempDir::new("aiax-x");
    three_zips(&t);
    let o = run_in(&t.0, &["x", "-an", "-air!a*.zip", "-ax!a2.zip", "-oout", "-y"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(files_under(&t.path("out")), vec!["data/words.txt", "hello.txt"]);
    assert_eq!(fs::read(t.path("out/data/words.txt")).unwrap(), fs::read(wire("tree/data/words.txt")).unwrap());

    // Without r only the current directory is searched.
    let o = run_in(&t.0, &["e", "-an", "-ai!*.zip", "-oflat", "-y"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(files_under(&t.path("flat")), vec!["empty.txt", "hello.txt"]);

    // -axr excludes at any depth; a positional archive combines with -ai.
    let o = run_in(&t.0, &["x", "a2.zip", "-air!*.zip", "-axr!a3.zip", "-oo2", "-y"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(files_under(&t.path("o2")), vec!["empty.txt", "hello.txt"]);
}

#[test]
fn ai_ax_list_test_and_listfiles() {
    let t = TempDir::new("aiax-l");
    three_zips(&t);
    write(&t.path("want.lst"), b"a1.zip\nsub/a3.zip\n");
    write(&t.path("skip.lst"), b"sub/a3.zip\n");
    let o = run_in(&t.0, &["l", "-an", "-ai@want.lst"]);
    assert_eq!(code(&o), 0, "{o:?}");
    let s = stdout(&o);
    assert!(s.contains("Archive: a1.zip") && s.contains("Archive: sub/a3.zip") && s.contains("Archives: 2"), "{s}");
    assert!(s.contains("hello.txt") && s.contains("data/words.txt") && !s.contains("empty.txt"), "{s}");
    let o = run_in(&t.0, &["t", "-an", "-ai@want.lst", "-ax@skip.lst"]);
    assert_eq!(code(&o), 0);
    // 7-Zip console shape (console-output-parity): one archive tested, one member, 17 bytes.
    assert!(stdout(&o).ends_with("Everything is Ok\n\nFiles: 1\nSize:       17\nCompressed: 151\n"), "{}", stdout(&o));
    // Nothing left after -ax: fatal, like a missing archive.
    let o = run_in(&t.0, &["t", "a1.zip", "-ax!*.zip"]);
    assert_eq!(code(&o), 2);
    let o = run_in(&t.0, &["t", "-an", "-ai!*.none"]);
    assert_eq!(code(&o), 2);
    // A damaged archive among several: the worst code wins.
    write(&t.path("bad.zip"), b"PK\x03\x04garbage");
    let o = run_in(&t.0, &["t", "-an", "-ai!*.zip"]);
    assert_eq!(code(&o), 2);
    // Missing list file: command line error.
    let o = run_in(&t.0, &["t", "-an", "-ai@nope.lst"]);
    assert_eq!(code(&o), 2);
}

// ---------------------------------------------------------------------------
// -stl, -w
// ---------------------------------------------------------------------------

fn stamped_tree(t: &TempDir) -> (PathBuf, i64) {
    let src = t.path("stl");
    for f in ["a.txt", "d/b.txt", "d/e/c.txt"] {
        write(&src.join(f), f.as_bytes());
    }
    set_mtime(&src.join("a.txt"), 1_100_000_000);
    set_mtime(&src.join("d/b.txt"), 1_300_000_000);
    set_mtime(&src.join("d/e/c.txt"), 1_200_000_000);
    set_mtime(&src.join("d/e"), 1_000_000_000);
    set_mtime(&src.join("d"), 1_000_000_000);
    (src, 1_300_000_000)
}

#[test]
fn stl_sets_archive_time_on_add() {
    let t = TempDir::new("stl-a");
    let (src, newest) = stamped_tree(&t);
    for ext in ["zip", "7z", "tar", "tar.gz", "tar.xz"] {
        let arc = t.path(&format!("x.{ext}"));
        let o = run_in(&src, &["a", "-stl", arc.to_str().unwrap(), ".", "-ba"]);
        assert_eq!(code(&o), 0, "{ext}: {o:?}");
        assert_eq!(mtime(&arc), newest, "{ext}");
    }
    // Without -stl the archive keeps the time it was written.
    let arc = t.path("plain.zip");
    assert_eq!(code(&run_in(&src, &["a", arc.to_str().unwrap(), ".", "-ba"])), 0);
    assert!(mtime(&arc) > newest + 1_000_000);
}

#[test]
fn stl_and_w_on_update_and_delete() {
    let t = TempDir::new("stl-ud");
    let (src, _) = stamped_tree(&t);
    let work = t.path("work");
    fs::create_dir_all(&work).unwrap();
    let arc = t.path("x.zip");
    let w = format!("-w{}", work.display());
    let o = run_in(&src, &["a", "-stl", &w, arc.to_str().unwrap(), ".", "-ba"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(fs::read_dir(&work).unwrap().count(), 0, "temporary file left in -w dir");

    write(&src.join("new.txt"), b"new");
    set_mtime(&src.join("new.txt"), 1_400_000_000);
    let o = run_in(&src, &["u", "-stl", &w, arc.to_str().unwrap(), "new.txt"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(mtime(&arc), 1_400_000_000);
    assert_eq!(fs::read_dir(&work).unwrap().count(), 0);

    let o = run_in(&src, &["d", "-stl", "-w", arc.to_str().unwrap(), "new.txt"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(mtime(&arc), 1_300_000_000);
    let l = stdout(&run_in(&t.0, &["l", "x.zip", "-ba"]));
    assert!(l.contains("d/b.txt") && !l.contains("new.txt"), "{l}");

    // A missing -w directory is an error and leaves the archive alone.
    let before = fs::read(&arc).unwrap();
    let o = run_in(&src, &["d", "-w/nonexistent/sediment", arc.to_str().unwrap(), "a.txt"]);
    assert_ne!(code(&o), 0);
    assert_eq!(fs::read(&arc).unwrap(), before);
    let o = run_in(&src, &["a", "-y", "-w/nonexistent/sediment", arc.to_str().unwrap(), "."]);
    assert_eq!(code(&o), 2);
    assert_eq!(fs::read(&arc).unwrap(), before);
}

// ---------------------------------------------------------------------------
// -bt, -ad, -bd, -ssw, -stx, -sse
// ---------------------------------------------------------------------------

#[test]
fn bt_prints_timing_and_accepted_switches() {
    let t = TempDir::new("bt");
    fs::copy(wire("tree.zip"), t.path("tree.zip")).unwrap();
    let o = run_in(&t.0, &["t", "-bt", "-ad", "-bd", "-ssw", "tree.zip"]);
    assert_eq!(code(&o), 0);
    let s = stdout(&o);
    assert!(s.contains("Everything is Ok") && s.contains("Global  Time = "), "{s}");
    let plain = stdout(&run_in(&t.0, &["t", "-ad", "-bd", "tree.zip"]));
    assert!(!plain.contains("Time ="));
    let o = run_in(&t.0, &["d", "-bt", "tree.zip", "hello.txt"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stdout(&o).contains("Global  Time = "));
}

#[test]
fn stx_excludes_types() {
    let t = TempDir::new("stx");
    for f in ["tree.zip", "tree.tar.gz", "tree_ustar.tar"] {
        fs::copy(wire(f), t.path(f)).unwrap();
    }
    assert_eq!(code(&run_in(&t.0, &["t", "-stxzip", "tree.zip"])), 2);
    assert_eq!(code(&run_in(&t.0, &["t", "-stx7z", "tree.zip"])), 0);
    assert_eq!(code(&run_in(&t.0, &["t", "-stxgz", "tree.tar.gz"])), 2);
    assert_eq!(code(&run_in(&t.0, &["x", "-stxtar", "tree.tar.gz", "-oo", "-y"])), 2);
    assert!(!t.path("o").exists());
    assert_eq!(code(&run_in(&t.0, &["l", "-stxtar", "tree_ustar.tar"])), 2);
    assert_eq!(code(&run_in(&t.0, &["l", "-stxzip", "tree_ustar.tar"])), 0);
    // With -ai the excluded type fails only its own archive.
    assert_eq!(code(&run_in(&t.0, &["t", "-an", "-ai!tree*", "-stxzip"])), 2);
    assert_eq!(code(&run_in(&t.0, &["t", "-an", "-ai!tree*", "-ax!*.zip", "-stxzip"])), 0);
}

#[test]
fn sse_stops_on_unopenable_input() {
    let t = TempDir::new("sse");
    write(&t.path("ok.txt"), b"ok");
    let o = run_in(&t.0, &["a", "-sse", "x.zip", "ok.txt", "missing.txt"]);
    assert_eq!(code(&o), 2);
    assert!(!t.path("x.zip").exists());
    let o = run_in(&t.0, &["a", "x.zip", "ok.txt", "missing.txt"]);
    assert_eq!(code(&o), 1);
    assert!(t.path("x.zip").exists());
    let o = run_in(&t.0, &["a", "-sse", "y.zip", "ok.txt"]);
    assert_eq!(code(&o), 0);
}

// ---------------------------------------------------------------------------
// -spe, -spo
// ---------------------------------------------------------------------------

#[test]
fn spe_drops_duplicated_root() {
    let t = TempDir::new("spe");
    write(&t.path("proj/a.txt"), b"a");
    write(&t.path("proj/sub/b.txt"), b"b");
    assert_eq!(code(&run_in(&t.0, &["a", "p.zip", "proj", "-ba"])), 0);
    let o = run_in(&t.0, &["x", "p.zip", "-oout/proj", "-spe", "-y"]);
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(files_under(&t.path("out")), vec!["proj/a.txt", "proj/sub/b.txt"]);
    // Different folder name: nothing to drop.
    let o = run_in(&t.0, &["x", "p.zip", "-oother", "-spe", "-y"]);
    assert_eq!(code(&o), 0);
    assert_eq!(files_under(&t.path("other")), vec!["proj/a.txt", "proj/sub/b.txt"]);
    // Without -spe the root is duplicated.
    let o = run_in(&t.0, &["x", "p.zip", "-odup/proj", "-y"]);
    assert_eq!(code(&o), 0);
    assert_eq!(files_under(&t.path("dup")), vec!["proj/proj/a.txt", "proj/proj/sub/b.txt"]);
    // Members outside the root folder: kept as they are.
    write(&t.path("top.txt"), b"t");
    assert_eq!(code(&run_in(&t.0, &["a", "q.zip", "proj", "top.txt", "-ba"])), 0);
    let o = run_in(&t.0, &["x", "q.zip", "-omix/proj", "-spe", "-y"]);
    assert_eq!(code(&o), 0);
    assert_eq!(files_under(&t.path("mix")), vec!["proj/proj/a.txt", "proj/proj/sub/b.txt", "proj/top.txt"]);
}

#[test]
fn spo_path_overwrite_policy() {
    let t = TempDir::new("spo");
    write(&t.path("x.txt"), b"new");
    assert_eq!(code(&run_in(&t.0, &["a", "x.zip", "x.txt", "-ba"])), 0);
    write(&t.path("o/x.txt"), b"old");
    assert_eq!(code(&run_in(&t.0, &["x", "x.zip", "-oo"])), 2);
    assert_eq!(code(&run_in(&t.0, &["x", "x.zip", "-oo", "-spod"])), 2);
    assert_eq!(fs::read(t.path("o/x.txt")).unwrap(), b"old");
    assert_eq!(code(&run_in(&t.0, &["x", "x.zip", "-oo", "-spoc"])), 0);
    assert_eq!(fs::read(t.path("o/x.txt")).unwrap(), b"old");
    assert_eq!(code(&run_in(&t.0, &["x", "x.zip", "-oo", "-spor"])), 0);
    assert_eq!(fs::read(t.path("o/x.txt")).unwrap(), b"new");
    // -ao wins over -spo.
    write(&t.path("o/x.txt"), b"old");
    assert_eq!(code(&run_in(&t.0, &["x", "x.zip", "-oo", "-spor", "-aos"])), 0);
    assert_eq!(fs::read(t.path("o/x.txt")).unwrap(), b"old");
}
