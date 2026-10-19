// SPDX-License-Identifier: MIT OR Apache-2.0
//! Filesystem collection and `sediment a` end to end (Unix: symlinks, modes).
#![cfg(unix)]

mod common;

use std::ffi::OsString;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use common::*;
use sediment_engine::cli_add::{AddArgs, ArchiveFormat, format_from_name, parse_add_args, run_add};
use sediment_engine::compress_wrap::Compression;
use sediment_engine::fs_collect::*;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{ZipLimits, parse_entries};

fn os(p: &Path) -> PathBuf {
    p.to_path_buf()
}

fn set_mtime(p: &Path, t: i64) {
    let f = std::fs::File::open(p).unwrap();
    let st = if t >= 0 { UNIX_EPOCH + Duration::from_secs(t as u64) } else { UNIX_EPOCH - Duration::from_secs((-t) as u64) };
    f.set_modified(st).unwrap();
}

/// Materialise the fixture spec as a real tree under `root`.
fn build_tree(root: &Path, spec: &[SpecEntry]) {
    let path_of = |e: &SpecEntry| root.join(std::str::from_utf8(&e.name).unwrap());
    for e in spec {
        let p = path_of(e);
        match e.kind {
            EntryKind::Directory => std::fs::create_dir_all(&p).unwrap(),
            EntryKind::File => std::fs::write(&p, &e.payload).unwrap(),
            EntryKind::Symlink => symlink(std::str::from_utf8(&e.payload).unwrap(), &p).unwrap(),
        }
    }
    for e in spec.iter().rev() {
        let p = path_of(e);
        if e.kind == EntryKind::Symlink {
            continue;
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(e.mode)).unwrap();
        set_mtime(&p, e.mtime);
    }
}

fn top_level(root: &Path, spec: &[SpecEntry]) -> Vec<OsString> {
    spec.iter()
        .filter(|e| !e.name.contains(&b'/'))
        .map(|e| root.join(std::str::from_utf8(&e.name).unwrap()).into_os_string())
        .collect()
}

fn add(args: &[&dyn AsRef<std::ffi::OsStr>]) -> i32 {
    let v: Vec<OsString> = args.iter().map(|a| a.as_ref().to_os_string()).collect();
    run_add(&v)
}

#[test]
fn end_to_end_from_filesystem_matches_oracle() {
    let spec = load_spec();
    let tmp = TempDir::new("e2e");
    let root = tmp.path().join("tree");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    build_tree(&root, &spec);

    // Collection reproduces the canonical spec order, kinds, modes and mtimes.
    let inputs: Vec<PathBuf> = top_level(&root, &spec).into_iter().map(PathBuf::from).collect();
    let c = collect(&inputs, &CollectOptions::default(), CollectLimits::default()).unwrap();
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert_eq!(c.entries.len(), spec.len());
    let mut actual_spec = spec.clone();
    for (got, (exp, act)) in c.entries.iter().zip(spec.iter().zip(actual_spec.iter_mut())) {
        assert_eq!(got.name, exp.name);
        assert_eq!(got.kind, exp.kind);
        if exp.kind == EntryKind::Symlink {
            assert_eq!(got.link_target, exp.payload);
            act.mtime = got.mtime; // symlink mtimes cannot be set portably
        } else {
            assert_eq!(got.mode, exp.mode, "{}", String::from_utf8_lossy(&got.name));
            assert_eq!(got.mtime, exp.mtime, "{}", String::from_utf8_lossy(&got.name));
        }
        assert_eq!(got.size, if exp.kind == EntryKind::File { exp.payload.len() as u64 } else { 0 });
    }

    let mut names = Vec::new();
    for (name, switches) in [
        ("out_store.zip", vec!["-mx0"]),
        ("out.zip", vec![]),
        ("out9.zip", vec!["-mx=9"]),
        ("out.tar", vec![]),
        ("out.tgz", vec!["-mx9"]),
        ("out.tar.gz", vec!["-mx1"]),
        ("out0.tar.gz", vec!["-mx0"]),
    ] {
        let mut args: Vec<OsString> = switches.iter().map(OsString::from).collect();
        args.push(out.join(name).into_os_string());
        args.extend(top_level(&root, &spec));
        assert_eq!(run_add(&args), 0, "{name}");
        names.push(name);
    }
    write_spec(&out.join("spec.tsv"), &actual_spec);
    oracle_check(&out);

    // Sediment's own readers round-trip the zip outputs.
    for n in names.iter().filter(|n| n.ends_with(".zip")) {
        let b = std::fs::read(out.join(n)).unwrap();
        let parsed = parse_entries(&b, ZipLimits { max_entries: 1000, max_total_size: 1 << 24 }).unwrap();
        let files: Vec<_> = spec.iter().filter(|e| e.kind != EntryKind::Symlink).collect();
        assert_eq!(parsed.len(), files.len());
        for (p, e) in parsed.iter().zip(files) {
            let want: &[u8] = if e.kind == EntryKind::File { &e.payload } else { &[] };
            assert_eq!(&*entry_data(&b, p, p.size, 1000).unwrap(), want);
        }
    }
    // tar.gz decompresses to the identical plain tar (same tree, same bytes).
    let tar = std::fs::read(out.join("out.tar")).unwrap();
    for n in ["out.tgz", "out.tar.gz", "out0.tar.gz"] {
        let gz = std::fs::read(out.join(n)).unwrap();
        assert_eq!(decode_gzip(&gz, 1 << 24, 100_000).unwrap(), tar, "{n}");
    }
    let items = read_tar(&tar);
    assert_eq!(items.len(), actual_spec.len());
    for (it, e) in items.iter().zip(&actual_spec) {
        assert_eq!((it.name.as_slice(), it.mtime), (e.name.as_slice(), e.mtime));
    }

    // Determinism: re-running over the same tree gives identical bytes.
    let mut args: Vec<OsString> = vec!["-y".into(), out.join("out.tar").into_os_string()];
    args.extend(top_level(&root, &spec));
    assert_eq!(run_add(&args), 0);
    assert_eq!(std::fs::read(out.join("out.tar")).unwrap(), tar);
}

#[test]
fn cli_errors_and_overwrite() {
    let tmp = TempDir::new("cli");
    let f = tmp.path().join("f.txt");
    std::fs::write(&f, b"data").unwrap();
    let z = tmp.path().join("a.zip");
    assert_eq!(add(&[&z, &f]), 0);
    assert_eq!(add(&[&z, &f]), 1, "exists without -y");
    assert_eq!(add(&[&"-y", &z, &f]), 0);
    assert_eq!(add(&[&z]), 2, "missing inputs");
    assert_eq!(add(&[]), 2);
    assert_eq!(add(&[&"-mx10", &z, &f]), 2);
    assert_eq!(add(&[&"-q", &z, &f]), 2);
    assert_eq!(add(&[&tmp.path().join("a.rar"), &f]), 2);
    assert_eq!(add(&[&tmp.path().join("a.tar.xz"), &f]), 1);
    assert_eq!(add(&[&tmp.path().join("a.tbz2"), &f]), 1);
    assert_eq!(add(&[&tmp.path().join("b.zip"), &tmp.path().join("missing")]), 1);
    assert!(!tmp.path().join("b.zip").exists());
    let dir_zip = tmp.path().join("d.zip");
    std::fs::create_dir(&dir_zip).unwrap();
    assert_eq!(add(&[&"-y", &dir_zip, &f]), 1, "archive path is a directory");
    // `--` ends switches.
    let dash = tmp.path().join("-y.tar");
    assert_eq!(add(&[&"--", &dash, &f]), 0);
    assert!(dash.exists());
    // No temp files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("sediment-tmp"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn arg_parsing_and_format_detection() {
    let p = |v: &[&str]| parse_add_args(&v.iter().map(OsString::from).collect::<Vec<_>>());
    assert_eq!(
        p(&["-mx7", "x.zip", "a", "-y", "b"]).unwrap(),
        AddArgs { archive: "x.zip".into(), inputs: vec!["a".into(), "b".into()], level: 7, overwrite: true, follow_symlinks: false }
    );
    assert_eq!(p(&["-l", "x.zip", "a"]).unwrap().follow_symlinks, true);
    assert_eq!(p(&["x.zip", "a"]).unwrap().level, 5);
    assert!(p(&["-mx", "x.zip", "a"]).is_err());
    assert!(p(&["-mx=", "x.zip", "a"]).is_err());
    assert!(p(&["-mx99", "x.zip", "a"]).is_err());
    let f = |s: &str| format_from_name(Path::new(s));
    assert_eq!(f("A.ZIP"), Some(ArchiveFormat::Zip));
    assert_eq!(f("a.tar"), Some(ArchiveFormat::Tar(Compression::None)));
    assert_eq!(f("a.Tar.Gz"), Some(ArchiveFormat::Tar(Compression::Gzip)));
    assert_eq!(f("a.tgz"), Some(ArchiveFormat::Tar(Compression::Gzip)));
    assert_eq!(f("a.txz"), Some(ArchiveFormat::Tar(Compression::Xz)));
    assert_eq!(f("a.tar.bz2"), Some(ArchiveFormat::Tar(Compression::Bzip2)));
    assert_eq!(f(".zip"), None);
    assert_eq!(f("a.gz"), None);
    assert_eq!(f("a"), None);
}

#[test]
fn output_inside_input_is_excluded() {
    let tmp = TempDir::new("excl");
    let root = tmp.path().join("r");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    let z = root.join("self.zip");
    assert_eq!(add(&[&z, &root]), 0);
    assert_eq!(add(&[&"-y", &z, &root]), 0, "excluded output is not a warning");
    let b = std::fs::read(&z).unwrap();
    let names: Vec<Vec<u8>> = parse_entries(&b, ZipLimits { max_entries: 10, max_total_size: 1000 })
        .unwrap()
        .iter()
        .map(|e| e.name.to_vec())
        .collect();
    assert_eq!(names, vec![b"r/".to_vec(), b"r/a.txt".to_vec()]);
}

#[test]
fn collect_naming_duplicates_and_limits() {
    let tmp = TempDir::new("names");
    let t = tmp.path();
    std::fs::create_dir_all(t.join("x/sub")).unwrap();
    std::fs::create_dir_all(t.join("y/sub")).unwrap();
    std::fs::write(t.join("x/sub/f"), b"1").unwrap();
    std::fs::write(t.join("y/sub/f"), b"22").unwrap();
    std::fs::write(t.join("x/b.txt"), b"").unwrap();
    std::fs::write(t.join("x/sub.txt"), b"").unwrap();
    let o = CollectOptions::default();
    let l = CollectLimits::default();
    let c = collect(&[os(&t.join("x"))], &o, l).unwrap();
    let names: Vec<&[u8]> = c.entries.iter().map(|e| e.name.as_slice()).collect();
    assert_eq!(names, vec![&b"x"[..], b"x/b.txt", b"x/sub", b"x/sub/f", b"x/sub.txt"]);
    // `dir/..` stores the parent's children at the archive root.
    let c = collect(&[os(&t.join("x/sub/.."))], &o, l).unwrap();
    assert_eq!(c.entries[0].name, b"b.txt");
    assert_eq!(collect(&[os(&t.join("x/sub")), os(&t.join("y/sub"))], &o, l).unwrap_err(), CollectError::InvalidName);
    assert_eq!(collect(&[os(&t.join("nope"))], &o, l).unwrap_err(), CollectError::NotFound);
    let lim = |e, b, d| CollectLimits { max_entries: e, max_total_bytes: b, max_depth: d, max_name_bytes: 4096 };
    assert_eq!(collect(&[os(&t.join("x"))], &o, lim(3, 100, 10)).unwrap_err(), CollectError::LimitExceeded);
    assert_eq!(collect(&[os(&t.join("x")), os(&t.join("y"))], &o, lim(100, 2, 10)).unwrap_err(), CollectError::LimitExceeded);
    assert_eq!(collect(&[os(&t.join("x"))], &o, lim(100, 100, 0)).unwrap_err(), CollectError::LimitExceeded);
    assert_eq!(collect(&[os(&t.join("x"))], &o, lim(100, 100, 1)).unwrap_err(), CollectError::LimitExceeded);
    assert_eq!(collect(&[os(&t.join("x"))], &o, lim(100, 100, 2)).map(|c| c.entries.len()), Ok(5));
    // Size changes between collection and reading are detected.
    let c = collect(&[os(&t.join("y/sub/f"))], &o, l).unwrap();
    std::fs::write(t.join("y/sub/f"), b"333").unwrap();
    assert_eq!(read_entry_data(&c.entries[0], 100), Err(CollectError::Changed));
    assert_eq!(read_entry_data(&c.entries[0], 1), Err(CollectError::LimitExceeded));
}

#[test]
fn symlinks_loops_special_and_unreadable() {
    let tmp = TempDir::new("links");
    let t = tmp.path().join("t");
    std::fs::create_dir_all(t.join("d")).unwrap();
    std::fs::write(t.join("d/file"), b"payload").unwrap();
    symlink("..", t.join("d/up")).unwrap();
    symlink("file", t.join("d/ln")).unwrap();
    let o = CollectOptions::default();
    let l = CollectLimits::default();
    let c = collect(&[os(&t)], &o, l).unwrap();
    let up = c.entries.iter().find(|e| e.name == b"t/d/up").unwrap();
    assert_eq!((up.kind, up.link_target.as_slice()), (EntryKind::Symlink, &b".."[..]));
    // Following: the `..` loop is detected, `ln` becomes a regular file.
    let follow = CollectOptions { follow_symlinks: true, ..Default::default() };
    let c = collect(&[os(&t)], &follow, l).unwrap();
    assert!(c.warnings.iter().any(|w| w.kind == WarningKind::SymlinkLoop));
    let ln = c.entries.iter().find(|e| e.name == b"t/d/ln").unwrap();
    assert_eq!((ln.kind, ln.size), (EntryKind::File, 7));
    // Zip skips symlinks with a note; tar stores them.
    let z = tmp.path().join("l.zip");
    assert_eq!(add(&[&z, &t]), 0);
    assert_eq!(add(&[&tmp.path().join("l.tar"), &t]), 0);
    assert_eq!(add(&[&"-l", &tmp.path().join("follow.tar"), &t]), 3, "loop warning");

    // Special files are skipped with a warning.
    let sock = t.join("s.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let c = collect(&[os(&t)], &o, l).unwrap();
    assert!(c.warnings.iter().any(|w| w.kind == WarningKind::SpecialFile));
    let strict = CollectOptions { strict: true, ..Default::default() };
    assert_eq!(collect(&[os(&t)], &strict, l).unwrap_err(), CollectError::Unreadable);
    drop(_listener);
    std::fs::remove_file(&sock).unwrap();

    // Unreadable files/dirs (skipped when running as root, which can read anything).
    let secret = t.join("secret");
    std::fs::write(&secret, b"x").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0)).unwrap();
    let locked = t.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inner"), b"y").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0)).unwrap();
    if std::fs::File::open(&secret).is_err() {
        let c = collect(&[os(&t)], &o, l).unwrap();
        let kinds: Vec<_> = c.warnings.iter().map(|w| w.kind).collect();
        assert!(kinds.contains(&WarningKind::UnreadableFile));
        assert!(kinds.contains(&WarningKind::UnreadableDirectory));
        assert!(c.entries.iter().any(|e| e.name == b"t/locked"), "unlistable dir itself is stored");
        assert!(!c.entries.iter().any(|e| e.name == b"t/secret"));
        assert_eq!(collect(&[os(&t)], &strict, l).unwrap_err(), CollectError::Unreadable);
        assert_eq!(add(&[&tmp.path().join("w.tar"), &t]), 3);
        assert!(tmp.path().join("w.tar").exists());
    }
}
