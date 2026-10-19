// SPDX-License-Identifier: MIT OR Apache-2.0
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sediment_engine::archive_reader::MemReader;
use sediment_engine::extract_fs::*;
use sediment_engine::extract_plan::*;

static N: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-fs-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entry(path: &str, kind: EntryKind, size: u64) -> PlannedEntry {
    PlannedEntry { path: path.as_bytes().to_vec(), kind, size, mode: None, mtime: None }
}

fn reader(items: &[(&str, EntryKind, &[u8])]) -> MemReader {
    let mut r = MemReader::default();
    for (p, k, d) in items {
        r.push(entry(p, k.clone(), d.len() as u64), d.to_vec());
    }
    r
}

fn run(r: &MemReader, dest: &Path, opts: &ExtractOptions) -> Result<ExtractReport, ExtractFailure> {
    let plan = plan_extraction(&r.entries, &PlanOptions::default()).expect("plan");
    execute_plan(&plan, r, dest, opts)
}

fn no_temp_files(dir: &Path) -> bool {
    fn walk(d: &Path) -> bool {
        fs::read_dir(d).unwrap().all(|e| {
            let e = e.unwrap();
            let name = e.file_name();
            !name.to_string_lossy().starts_with(".sediment-tmp")
                && (!e.file_type().unwrap().is_dir() || walk(&e.path()))
        })
    }
    walk(dir)
}

#[test]
fn extracts_tree() {
    let t = TempDir::new("tree");
    let out = t.path().join("out");
    let r = reader(&[
        ("d/", EntryKind::Dir, b""),
        ("d/a.txt", EntryKind::File, b"alpha"),
        ("x/y/z.bin", EntryKind::File, &[0u8, 1, 2, 255]),
        ("empty", EntryKind::File, b""),
        ("hl", EntryKind::Hardlink { target: b"d/a.txt".to_vec() }, b""),
    ]);
    // Hardlink size must match its source's data.
    let mut r = r;
    r.entries[4].size = 5;
    let rep = run(&r, &out, &ExtractOptions::default()).unwrap();
    assert_eq!(fs::read(out.join("d/a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("x/y/z.bin")).unwrap(), [0, 1, 2, 255]);
    assert_eq!(fs::read(out.join("empty")).unwrap(), b"");
    assert_eq!(fs::read(out.join("hl")).unwrap(), b"alpha");
    assert_eq!(rep.files, 4);
    assert_eq!(rep.bytes, 14);
    assert!(no_temp_files(&out));
}

#[test]
fn overwrite_policies() {
    let t = TempDir::new("ow");
    let out = t.path();
    fs::write(out.join("f.txt"), b"old").unwrap();
    let r = reader(&[("f.txt", EntryKind::File, b"new")]);

    let e = run(&r, out, &ExtractOptions::default()).unwrap_err();
    assert_eq!(e, ExtractFailure { index: Some(0), error: ExtractError::Exists });
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"old");

    let skip = ExtractOptions { overwrite: OverwritePolicy::Skip, ..Default::default() };
    assert_eq!(run(&r, out, &skip).unwrap().skipped_existing, vec![0]);
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"old");

    let ren = ExtractOptions { overwrite: OverwritePolicy::Rename, ..Default::default() };
    let rep = run(&r, out, &ren).unwrap();
    assert_eq!(rep.renamed, vec![(0, out.join("f_1.txt"))]);
    run(&r, out, &ren).unwrap();
    assert_eq!(fs::read(out.join("f_2.txt")).unwrap(), b"new");
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"old");

    let ow = ExtractOptions { overwrite: OverwritePolicy::Overwrite, ..Default::default() };
    run(&r, out, &ow).unwrap();
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"new");
    assert!(no_temp_files(out));
}

#[test]
fn existing_directory_blocks_file() {
    let t = TempDir::new("dirblock");
    fs::create_dir(t.path().join("f")).unwrap();
    let r = reader(&[("f", EntryKind::File, b"x")]);
    let ow = ExtractOptions { overwrite: OverwritePolicy::Overwrite, ..Default::default() };
    assert_eq!(run(&r, t.path(), &ow).unwrap_err().error, ExtractError::PathConflict);
}

#[test]
fn destination_must_be_dir() {
    let t = TempDir::new("notdir");
    let f = t.path().join("file");
    fs::write(&f, b"").unwrap();
    let r = reader(&[("a", EntryKind::File, b"x")]);
    assert_eq!(run(&r, &f, &ExtractOptions::default()).unwrap_err().error, ExtractError::DestinationNotDir);
}

#[test]
fn size_mismatch_detected() {
    let t = TempDir::new("size");
    let mut r = reader(&[("a", EntryKind::File, b"abc")]);
    r.entries[0].size = 2;
    assert_eq!(run(&r, t.path(), &ExtractOptions::default()).unwrap_err().error, ExtractError::SizeMismatch);
    assert!(!t.path().join("a").exists());
    assert!(no_temp_files(t.path()));
}

#[test]
fn symlink_refused_by_default() {
    let t = TempDir::new("symref");
    let r = reader(&[("t", EntryKind::File, b"x"), ("l", EntryKind::Symlink { target: b"t".to_vec() }, b"")]);
    let e = run(&r, t.path(), &ExtractOptions::default()).unwrap_err();
    assert_eq!(e, ExtractFailure { index: Some(1), error: ExtractError::SymlinksNotAllowed });
    // Refusal happens before anything is written.
    assert!(!t.path().join("t").exists());
    let skip = ExtractOptions { symlinks: SymlinkPolicy::Skip, ..Default::default() };
    let rep = run(&r, t.path(), &skip).unwrap();
    assert_eq!(rep.skipped_symlinks, vec![1]);
    assert!(fs::symlink_metadata(t.path().join("l")).is_err());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn symlink_created_when_allowed() {
        let t = TempDir::new("symok");
        let r = reader(&[("t", EntryKind::File, b"x"), ("d/l", EntryKind::Symlink { target: b"../t".to_vec() }, b"")]);
        let opts = ExtractOptions { symlinks: SymlinkPolicy::Create, ..Default::default() };
        let rep = run(&r, t.path(), &opts).unwrap();
        assert_eq!(rep.symlinks, 1);
        assert_eq!(fs::read_link(t.path().join("d/l")).unwrap(), Path::new("../t"));
        assert_eq!(fs::read(t.path().join("d/l")).unwrap(), b"x");
    }

    #[test]
    fn refuses_preexisting_symlink_parent() {
        let t = TempDir::new("prelink");
        let outside = TempDir::new("outside");
        let dest = t.path().join("dest");
        fs::create_dir(&dest).unwrap();
        symlink(outside.path(), dest.join("evil")).unwrap();
        let r = reader(&[("evil/pwned.txt", EntryKind::File, b"x")]);
        let ow = ExtractOptions { overwrite: OverwritePolicy::Overwrite, ..Default::default() };
        assert_eq!(run(&r, &dest, &ow).unwrap_err().error, ExtractError::SymlinkInDestination);
        assert!(!outside.path().join("pwned.txt").exists());
        // Explicit directory entry over a symlink is refused too.
        let r = reader(&[("evil/", EntryKind::Dir, b"")]);
        assert_eq!(run(&r, &dest, &ow).unwrap_err().error, ExtractError::SymlinkInDestination);
    }

    #[test]
    fn overwrite_replaces_symlink_not_target() {
        let t = TempDir::new("prefile");
        let outside = TempDir::new("outside2");
        let victim = outside.path().join("victim");
        fs::write(&victim, b"precious").unwrap();
        symlink(&victim, t.path().join("f")).unwrap();
        let r = reader(&[("f", EntryKind::File, b"new")]);
        let ow = ExtractOptions { overwrite: OverwritePolicy::Overwrite, ..Default::default() };
        run(&r, t.path(), &ow).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        let m = fs::symlink_metadata(t.path().join("f")).unwrap();
        assert!(m.is_file());
        assert_eq!(fs::read(t.path().join("f")).unwrap(), b"new");
        // Default policy refuses instead.
        symlink(&victim, t.path().join("g")).unwrap();
        let r = reader(&[("g", EntryKind::File, b"new")]);
        assert_eq!(run(&r, t.path(), &ExtractOptions::default()).unwrap_err().error, ExtractError::Exists);
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
    }

    #[test]
    fn mode_and_mtime_applied() {
        let t = TempDir::new("meta");
        let mut r = reader(&[("d/", EntryKind::Dir, b""), ("d/run", EntryKind::File, b"#!"), ("d/s", EntryKind::File, b"s")]);
        r.entries[0].mode = Some(0o750);
        r.entries[0].mtime = Some(1_000_000_000);
        r.entries[1].mode = Some(0o4755); // setuid must be stripped
        r.entries[1].mtime = Some(1_577_934_246);
        r.entries[2].mtime = Some(-86_400);
        run(&r, t.path(), &ExtractOptions::default()).unwrap();
        let m = fs::metadata(t.path().join("d/run")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o755);
        assert_eq!(m.modified().unwrap(), UNIX_EPOCH + Duration::from_secs(1_577_934_246));
        let s = fs::metadata(t.path().join("d/s")).unwrap();
        assert_eq!(s.modified().unwrap(), UNIX_EPOCH - Duration::from_secs(86_400));
        let d = fs::metadata(t.path().join("d")).unwrap();
        assert_eq!(d.permissions().mode() & 0o777, 0o750);
        assert_eq!(d.modified().unwrap(), UNIX_EPOCH + Duration::from_secs(1_000_000_000));
    }

    #[test]
    fn mode_and_mtime_optional() {
        let t = TempDir::new("nometa");
        let mut r = reader(&[("f", EntryKind::File, b"x")]);
        r.entries[0].mode = Some(0o700);
        r.entries[0].mtime = Some(0);
        let opts = ExtractOptions { apply_mode: false, apply_mtime: false, ..Default::default() };
        run(&r, t.path(), &opts).unwrap();
        let m = fs::metadata(t.path().join("f")).unwrap();
        assert_ne!(m.modified().unwrap(), UNIX_EPOCH);
    }
}
