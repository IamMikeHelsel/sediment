// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end CLI tests: every readable format is extracted with the built
//! `sediment` binary and the result is compared byte-for-byte with the
//! reference tree in tests/fixtures/cli_wire (tests/gen/cli_wire.py; 7z
//! archives from tests/gen/cli_wire_7z.sh). Hostile archives must be refused
//! without writing anything.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
const MTIME: u64 = 1_709_618_828;
static N: AtomicU32 = AtomicU32::new(0);

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_wire").join(name)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-wire-{tag}-{}-{}",
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

fn run<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn out_arg(p: &Path) -> String {
    format!("-o{}", p.display())
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Dir,
    File(Vec<u8>),
    Link(Vec<u8>),
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")
}

/// Snapshot of a directory tree (symlinks are not followed).
fn snapshot(root: &Path) -> BTreeMap<String, Node> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Node>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            let k = rel(root, &p);
            if m.file_type().is_symlink() {
                out.insert(k, Node::Link(fs::read_link(&p).unwrap().to_string_lossy().into_owned().into_bytes()));
            } else if m.is_dir() {
                out.insert(k, Node::Dir);
                walk(root, &p, out);
            } else {
                out.insert(k, Node::File(fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

/// The reference tree: committed files plus the directory list.
fn expected_tree() -> BTreeMap<String, Node> {
    let mut t = snapshot(&fx("tree"));
    for d in fs::read_to_string(fx("tree.dirs")).unwrap().lines() {
        t.insert(d.to_string(), Node::Dir);
    }
    t
}

/// Materialize the reference tree under `dst` (for `sediment a`).
fn stage_tree(dst: &Path) {
    for (k, n) in expected_tree() {
        let p = dst.join(&k);
        match n {
            Node::Dir => fs::create_dir_all(&p).unwrap(),
            Node::File(d) => {
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(&p, d).unwrap();
            }
            Node::Link(_) => unreachable!(),
        }
    }
}

const TREE_ARCHIVES: &[&str] = &[
    "tree.zip",
    "tree_stored.zip",
    "tree_ustar.tar",
    "tree_gnu.tar",
    "tree_pax.tar",
    "tree.tar.gz",
    "tree.tgz",
    "tree.tar.bz2",
    "tree.tbz2",
    "tree.tar.xz",
    "tree.txz",
    "bundle.gz",
    "7z/tree_lzma.7z",
    "7z/tree_lzma2.7z",
    "7z/tree_copy.7z",
    "7z/tree_bcj.7z",
    "7z/tree_arm64.7z",
    "7z/tree_delta.7z",
    "7z/tree_bzip2.7z",
    "7z/tree_deflate.7z",
    "7z/tree_deflate64.7z",
];

#[test]
fn x_every_format_matches_reference_tree() {
    let want = expected_tree();
    let n_files = want.values().filter(|n| matches!(n, Node::File(_))).count();
    let total: usize = want.values().map(|n| if let Node::File(d) = n { d.len() } else { 0 }).sum();
    for name in TREE_ARCHIVES {
        let t = TempDir::new("x");
        let out = t.0.join("out");
        let o = run(&["x".as_ref(), out_arg(&out).as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", text(&o.stderr));
        assert_eq!(snapshot(&out), want, "{name}");

        let o = run(&["t".as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}");
        let entries = want.len();
        assert_eq!(text(&o.stdout), format!("OK\t{entries}\t{total}\n"), "{name}");

        let o = run(&["l".as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}");
        let s = text(&o.stdout);
        let mut lines = s.lines();
        assert_eq!(lines.next(), Some("SIZE\tCRC32\tNAME"));
        let names: Vec<&str> = lines.map(|l| l.rsplit('\t').next().unwrap().trim_end_matches('/')).collect();
        assert_eq!(names.len(), entries, "{name}");
        assert!(names.contains(&"docs/deep/nested/leaf.txt"), "{name}");
        assert!(n_files > 0);
    }
}

#[test]
fn x_preserves_mtime_and_mode() {
    for name in ["tree_pax.tar", "tree.tar.xz", "tree.zip", "7z/tree_lzma.7z"] {
        let t = TempDir::new("mt");
        let o = run(&["x".as_ref(), out_arg(&t.0).as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}");
        let m = fs::metadata(t.0.join("hello.txt")).unwrap();
        let secs = m.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, MTIME, "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !name.ends_with(".7z") {
                assert_eq!(m.permissions().mode() & 0o777, 0o644, "{name}");
            }
        }
    }
}

#[test]
fn e_flattens_every_container() {
    let want = expected_tree();
    let mut flat = BTreeMap::new();
    for (k, n) in &want {
        if let Node::File(d) = n {
            flat.insert(k.rsplit('/').next().unwrap().to_string(), Node::File(d.clone()));
        }
    }
    for name in ["tree.zip", "tree_gnu.tar", "tree.tbz2", "tree.txz", "7z/tree_delta.7z"] {
        let t = TempDir::new("e");
        let o = run(&["e".as_ref(), out_arg(&t.0).as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", text(&o.stderr));
        assert_eq!(snapshot(&t.0), flat, "{name}");
    }
}

#[test]
fn single_stream_files_extract_one_member() {
    let tree = expected_tree();
    let file = |k: &str| match &tree[k] {
        Node::File(d) => d.clone(),
        _ => panic!(),
    };
    let cases = [
        ("words.txt.gz", "words.txt", file("data/words.txt"), "5670\t2f28671a\twords.txt\n"),
        ("noname.gz", "noname", file("hello.txt"), "17\t62906a7f\tnoname\n"),
        ("random.bin.bz2", "random.bin", file("data/random.bin"), "1024\t--------\trandom.bin\n"),
        ("readme.md.xz", "readme.md", file("docs/readme.md"), "3920\t--------\treadme.md\n"),
    ];
    for (arc, member, data, listing) in cases {
        let t = TempDir::new("s");
        let o = run(&["x".as_ref(), out_arg(&t.0).as_ref(), fx(arc).as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{arc}: {}", text(&o.stderr));
        let mut want = BTreeMap::new();
        want.insert(member.to_string(), Node::File(data.clone()));
        assert_eq!(snapshot(&t.0), want, "{arc}");
        let o = run(&["l".as_ref(), fx(arc).as_os_str()]);
        assert_eq!(text(&o.stdout), format!("SIZE\tCRC32\tNAME\n{listing}"), "{arc}");
        let o = run(&["t".as_ref(), fx(arc).as_os_str()]);
        assert_eq!(text(&o.stdout), format!("OK\t1\t{}\n", data.len()), "{arc}");
    }
}

#[test]
fn gzip_fname_cannot_escape() {
    let t = TempDir::new("fname");
    let out = t.0.join("a/b/out");
    let o = run(&["x".as_ref(), out_arg(&out).as_ref(), fx("fname_slip.gz").as_os_str()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let mut want = BTreeMap::new();
    for d in ["a", "a/b", "a/b/out"] {
        want.insert(d.to_string(), Node::Dir);
    }
    want.insert("a/b/out/evil.txt".into(), Node::File(b"gz evil\n".to_vec()));
    assert_eq!(snapshot(&t.0), want);
}

#[test]
fn add_then_extract_round_trips() {
    let want = expected_tree();
    for (name, extra) in [
        ("rt.zip", None),
        ("rt0.zip", Some("-mx0")),
        ("rt9.zip", Some("-mx9")),
        ("rt.tar", None),
        ("rt.tar.gz", None),
        ("rt.tgz", Some("-mx1")),
    ] {
        let t = TempDir::new("rt");
        let src = t.0.join("src");
        stage_tree(&src);
        let arc = t.0.join(name);
        let mut args: Vec<std::ffi::OsString> = vec!["a".into()];
        if let Some(e) = extra {
            args.push(e.into());
        }
        args.push(arc.clone().into());
        for top in ["data", "docs", "emptydir", "empty.txt", "hello.txt"] {
            args.push(src.join(top).into());
        }
        let o = run(&args);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", text(&o.stderr));
        let out = t.0.join("out");
        let o = run(&["x".as_ref(), out_arg(&out).as_ref(), arc.as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", text(&o.stderr));
        assert_eq!(snapshot(&out), want, "{name}");
        let o = run(&["t".as_ref(), arc.as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{name}");
    }
}

#[test]
fn add_reports_usage_and_unsupported() {
    let t = TempDir::new("au");
    assert_eq!(run(&["a"]).status.code(), Some(2));
    let f = t.0.join("f.txt");
    fs::write(&f, b"x").unwrap();
    let o = run(&["a".as_ref(), t.0.join("x.tar.bz2").as_os_str(), f.as_os_str()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!t.0.join("x.tar.bz2").exists());
}

/// Every hostile archive is refused by `x` (with and without -snl) and
/// nothing is created inside or outside the output directory.
#[test]
fn x_refuses_slip_archives() {
    let hostile = [
        "slip.tar",
        "slip_nested.tar",
        "abs.tar",
        "link_escape.tar",
        "link_through.tar",
        "hardlink_escape.tar",
        "slip.tar.gz",
        "slip.tar.xz",
        "slip.tar.bz2",
        "7z/slip.7z",
        "7z/abs.7z",
        "7z/drive.7z",
        "7z/backslash_slip.7z",
        "../extract/slip.zip",
        "../extract/slip_nested.zip",
        "../extract/absolute.zip",
        "../extract/symlink_escape.zip",
    ];
    for name in hostile {
        for snl in [false, true] {
            let t = TempDir::new("slip");
            let out = t.0.join("a/b/out");
            let mut args: Vec<std::ffi::OsString> = vec!["x".into(), out_arg(&out).into()];
            if snl {
                args.push("-snl".into());
            }
            args.push(fx(name).into());
            let o = run(&args);
            assert_eq!(o.status.code(), Some(2), "{name} snl={snl}: {}", text(&o.stderr));
            assert!(text(&o.stderr).contains("rejected"), "{name}: {}", text(&o.stderr));
            let left: Vec<String> = snapshot(&t.0).into_keys().filter(|k| !k.starts_with("a/b/out")).collect();
            assert!(left.iter().all(|k| k == "a" || k == "a/b"), "{name}: {left:?}");
            assert!(snapshot(&out).is_empty(), "{name}");
        }
    }
    assert!(!Path::new("/tmp/sediment-cli-wire-evil.txt").exists());
}

#[test]
fn e_neutralizes_slip_paths() {
    for name in ["slip.tar", "slip.tar.gz", "7z/slip.7z"] {
        let t = TempDir::new("eslip");
        let out = t.0.join("a/out");
        let o = run(&["e".as_ref(), out_arg(&out).as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", text(&o.stderr));
        assert!(text(&o.stderr).contains("unsafe path flattened"), "{name}");
        let mut want = BTreeMap::new();
        want.insert("a".to_string(), Node::Dir);
        want.insert("a/out".to_string(), Node::Dir);
        want.insert("a/out/ok.txt".to_string(), Node::File(b"ok\n".to_vec()));
        want.insert("a/out/evil.txt".to_string(), Node::File(b"evil\n".to_vec()));
        assert_eq!(snapshot(&t.0), want, "{name}");
    }
}

#[test]
fn tar_links_need_snl() {
    let t = TempDir::new("links");
    let o = run(&["x".as_ref(), out_arg(&t.0).as_ref(), fx("links.tar").as_os_str()]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("symbolic link not extracted"));
    let s = snapshot(&t.0);
    assert_eq!(s.get("target.txt"), Some(&Node::File(b"tgt\n".to_vec())));
    assert_eq!(s.get("hard.txt"), Some(&Node::File(b"tgt\n".to_vec())));
    assert_eq!(s.get("sub"), Some(&Node::Dir));
    assert!(!s.contains_key("sub/up.txt"));

    #[cfg(unix)]
    {
        let t = TempDir::new("links-snl");
        let o = run(&["x".as_ref(), "-snl".as_ref(), out_arg(&t.0).as_ref(), fx("links.tar").as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
        let s = snapshot(&t.0);
        assert_eq!(s.get("sub/up.txt"), Some(&Node::Link(b"../target.txt".to_vec())));
        assert_eq!(fs::read(t.0.join("sub/up.txt")).unwrap(), b"tgt\n");
    }
}

#[test]
fn sevenz_links_need_snl() {
    let t = TempDir::new("7zlinks");
    let o = run(&["x".as_ref(), out_arg(&t.0).as_ref(), fx("7z/links.7z").as_os_str()]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    let s = snapshot(&t.0);
    assert_eq!(s.get("target.txt"), Some(&Node::File(b"tgt\n".to_vec())));
    assert!(!s.contains_key("sub/up.txt"));
    #[cfg(unix)]
    {
        let t = TempDir::new("7zlinks-snl");
        let o = run(&["x".as_ref(), "-snl".as_ref(), out_arg(&t.0).as_ref(), fx("7z/links.7z").as_os_str()]);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
        assert_eq!(snapshot(&t.0).get("sub/up.txt"), Some(&Node::Link(b"../target.txt".to_vec())));
    }
}

#[test]
fn corrupt_inputs_fail_cleanly() {
    for name in ["bad_crc.tar.gz", "truncated.tar.xz", "corrupt.bz2", "bad_checksum.tar", "7z/tree_ppmd.7z"] {
        let o = run(&["t".as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(2), "{name}: {}", text(&o.stderr));
        assert!(o.stdout.is_empty(), "{name}");
        let t = TempDir::new("bad");
        let o = run(&["x".as_ref(), out_arg(&t.0).as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(2), "{name}: {}", text(&o.stderr));
        assert!(!text(&o.stderr).contains("panicked"), "{name}");
    }
    let o = run(&["t".as_ref(), fx("7z/tree_ppmd.7z").as_os_str()]);
    assert!(text(&o.stderr).contains("unsupported compression method"), "{}", text(&o.stderr));
    let o = run(&["t".as_ref(), fx("bad_crc.tar.gz").as_os_str()]);
    assert_eq!(text(&o.stderr), "sediment: data error (checksum mismatch)\n");
    let o = run(&["l".as_ref(), fx("tree.dirs").as_os_str()]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(text(&o.stderr), "sediment: unsupported archive format\n");
}

/// The frozen `list`/`test` commands stay ZIP-only and byte-identical.
#[test]
fn legacy_commands_unchanged() {
    let o = run(&["list".as_ref(), fx("tree_stored.zip").as_os_str()]);
    assert_eq!(o.status.code(), Some(0));
    let s = text(&o.stdout);
    assert!(s.starts_with("SIZE\tCRC32\tNAME\n0\t00000000\tdata/\n"), "{s}");
    assert!(s.contains("17\t62906a7f\thello.txt\n"));
    let o = run(&["test".as_ref(), fx("tree.zip").as_os_str()]);
    assert_eq!(text(&o.stdout), "OK\t14\t12714\n");
    for name in ["tree_ustar.tar", "tree.tar.gz", "7z/tree_lzma.7z"] {
        let o = run(&["list".as_ref(), fx(name).as_os_str()]);
        assert_eq!(o.status.code(), Some(1), "{name}");
        assert_eq!(text(&o.stderr), "sediment: parse error\n", "{name}");
        assert!(o.stdout.is_empty());
    }
}
