// SPDX-License-Identifier: MIT OR Apache-2.0
use sediment_engine::extract_plan::*;

fn file(p: &[u8]) -> PlannedEntry {
    PlannedEntry { path: p.to_vec(), kind: EntryKind::File, size: 1, mode: None, mtime: None }
}
fn dir(p: &[u8]) -> PlannedEntry {
    PlannedEntry { path: p.to_vec(), kind: EntryKind::Dir, size: 0, mode: None, mtime: None }
}
fn link(p: &[u8], t: &[u8]) -> PlannedEntry {
    PlannedEntry { path: p.to_vec(), kind: EntryKind::Symlink { target: t.to_vec() }, size: 0, mode: None, mtime: None }
}
fn hard(p: &[u8], t: &[u8]) -> PlannedEntry {
    PlannedEntry { path: p.to_vec(), kind: EntryKind::Hardlink { target: t.to_vec() }, size: 1, mode: None, mtime: None }
}
fn opts() -> PlanOptions {
    PlanOptions { windows_names: Strictness::Report, ..PlanOptions::default() }
}
fn plan(entries: &[PlannedEntry]) -> Result<Plan, PlanFailure> {
    plan_extraction(entries, &opts())
}

#[test]
fn malicious_single_paths() {
    use PlanError::*;
    let table: &[(&[u8], PlanError)] = &[
        (b"", EmptyPath),
        (b".", EmptyPath),
        (b"./", EmptyPath),
        (b"/", AbsolutePath),
        (b"/etc/passwd", AbsolutePath),
        (b"\\windows\\system32", AbsolutePath),
        (b"//server/share/x", UncPath),
        (b"\\\\server\\share\\x", UncPath),
        (b"\\\\?\\C:\\x", UncPath),
        (b"/\\x", UncPath),
        (b"C:\\evil", DriveLetter),
        (b"C:/evil", DriveLetter),
        (b"c:evil", DriveLetter),
        (b"Z:", DriveLetter),
        (b"..", ParentTraversal),
        (b"../x", ParentTraversal),
        (b"a/../../x", ParentTraversal),
        (b"a/../b", ParentTraversal),
        (b"a/..", ParentTraversal),
        (b"..\\x", ParentTraversal),
        (b"a\\..\\..\\x", ParentTraversal),
        (b"./../x", ParentTraversal),
        (b"a/.../x", ParentTraversal),
        (b"a/.. /x", ParentTraversal),
        (b"a/. ./x", ParentTraversal),
        (b"a/ /x", ParentTraversal),
        (b"a\0b", NulByte),
        (b"\0", NulByte),
        (b"../\0", NulByte),
    ];
    for (path, want) in table {
        let got = plan(&[file(path)]).unwrap_err();
        assert_eq!(got.error, *want, "path {:?}", String::from_utf8_lossy(path));
        assert_eq!(got.index, Some(0));
    }
}

#[test]
fn benign_paths_normalize() {
    let table: &[(&[u8], &[&[u8]])] = &[
        (b"a", &[b"a"]),
        (b"./a", &[b"a"]),
        (b"a//b", &[b"a", b"b"]),
        (b"a/./b/", &[b"a", b"b"]),
        (b"a\\b", &[b"a", b"b"]),
        (b"..a/b..", &[b"..a", b"b.."]),
        (b".hidden", &[b".hidden"]),
        (b"\xff\xfe", &[b"\xff\xfe"]),
        (b"xy:z", &[b"xy:z"]),
    ];
    for (path, want) in table {
        let p = plan(&[file(path)]).expect("benign");
        let comps: Vec<&[u8]> = p.items[0].components.iter().map(|c| c.as_slice()).collect();
        assert_eq!(&comps[..], *want);
    }
}

#[test]
fn symlink_table() {
    use PlanError::*;
    let cases: &[(&[u8], &[u8], Option<PlanError>)] = &[
        (b"l", b"target", None),
        (b"l", b"./target", None),
        (b"d/l", b"../target", None),
        (b"d/e/l", b"../../target", None),
        (b"d/l", b"x/../y", None),
        (b"l", b"..", Some(SymlinkEscape)),
        (b"l", b"../x", Some(SymlinkEscape)),
        (b"d/l", b"../../x", Some(SymlinkEscape)),
        (b"d/l", b"x/../../../y", Some(SymlinkEscape)),
        (b"l", b"/etc/passwd", Some(SymlinkEscape)),
        (b"l", b"\\etc", Some(SymlinkEscape)),
        (b"l", b"C:\\x", Some(SymlinkEscape)),
        (b"l", b"..\\..\\x", Some(SymlinkEscape)),
        (b"l", b"", Some(SymlinkEscape)),
        (b"l", b"a\0b", Some(NulByte)),
        (b"l", b"...", Some(SymlinkEscape)),
    ];
    for (p, t, want) in cases {
        let got = plan(&[link(p, t)]);
        match want {
            None => assert!(got.is_ok(), "{:?} -> {:?}", String::from_utf8_lossy(p), String::from_utf8_lossy(t)),
            Some(e) => assert_eq!(got.unwrap_err().error, *e, "{:?} -> {:?}", String::from_utf8_lossy(p), String::from_utf8_lossy(t)),
        }
    }
}

#[test]
fn write_through_symlink_rejected_any_order() {
    let after = [link(b"l", b"sub"), file(b"l/x")];
    assert_eq!(plan(&after).unwrap_err(), PlanFailure { index: Some(0), error: PlanError::ThroughSymlink });
    let before = [file(b"l/x"), link(b"l", b"sub")];
    assert_eq!(plan(&before).unwrap_err().error, PlanError::ThroughSymlink);
    // Case-insensitive file systems: "L/x" would go through "l".
    let case = [link(b"l", b"sub"), file(b"L/x")];
    assert_eq!(plan(&case).unwrap_err().error, PlanError::ThroughSymlink);
    // Deeper ancestor.
    let deep = [link(b"a/b", b"c"), file(b"a/b/c/d")];
    assert_eq!(plan(&deep).unwrap_err().error, PlanError::ThroughSymlink);
}

#[test]
fn symlink_chain_rejected() {
    // u -> "." is fine alone, but "u/u/.." escapes in reality while it looks
    // inside lexically: walking through an archive symlink is refused.
    let entries = [link(b"u", b"."), link(b"w", b"u/u/..")];
    assert_eq!(plan(&entries).unwrap_err(), PlanFailure { index: Some(1), error: PlanError::SymlinkEscape });
    // Link pointing *at* another link (final component) is allowed.
    assert!(plan(&[file(b"t"), link(b"a", b"t"), link(b"b", b"a")]).is_ok());
}

#[test]
fn hardlinks() {
    let ok = plan(&[file(b"a/f"), hard(b"g", b"a/f")]).unwrap();
    assert_eq!(ok.items[1].kind, PlanKind::Hardlink { source: 0 });
    for bad in [
        vec![hard(b"g", b"missing")],
        vec![hard(b"g", b"f"), file(b"f")],
        vec![hard(b"g", b"../f")],
        vec![hard(b"g", b"/etc/shadow")],
        vec![dir(b"d"), hard(b"g", b"d")],
        vec![file(b"t"), link(b"s", b"t"), hard(b"g", b"s")],
        vec![file(b"g"), hard(b"g", b"g")],
    ] {
        assert_eq!(plan(&bad).unwrap_err().error, PlanError::HardlinkTarget, "{bad:?}");
    }
}

#[test]
fn conflicts() {
    assert_eq!(plan(&[file(b"a"), file(b"a/b")]).unwrap_err().error, PlanError::PathConflict);
    assert_eq!(plan(&[file(b"a/b"), file(b"a")]).unwrap_err().error, PlanError::PathConflict);
    assert_eq!(plan(&[dir(b"a/"), file(b"a")]).unwrap_err().error, PlanError::PathConflict);
    assert_eq!(plan(&[file(b"a"), link(b"a", b"x")]).unwrap_err().error, PlanError::PathConflict);
    // Dir twice is fine, file twice is a warning.
    assert!(plan(&[dir(b"a"), dir(b"a/"), file(b"a/x")]).unwrap().warnings.is_empty());
    let dup = plan(&[file(b"a"), file(b"./a")]).unwrap();
    assert_eq!(dup.warnings, vec![PlanWarning::DuplicatePath { index: 1, other: 0 }]);
}

#[test]
fn case_collisions() {
    let p = plan(&[file(b"README"), file(b"readme")]).unwrap();
    assert_eq!(p.warnings, vec![PlanWarning::CaseCollision { index: 1, other: 0 }]);
    let p = plan(&[file("Ä".as_bytes()), file("ä".as_bytes())]).unwrap();
    assert_eq!(p.warnings.len(), 1);
    let strict = PlanOptions { case_collisions: Strictness::Reject, ..opts() };
    let e = plan_extraction(&[file(b"README"), file(b"readme")], &strict).unwrap_err();
    assert_eq!(e, PlanFailure { index: Some(1), error: PlanError::CaseCollision });
}

#[test]
fn windows_names() {
    for name in [&b"CON"[..], b"con.txt", b"dir/aux", b"LPT1", b"com9.log", b"trailing.", b"trailing ", b"ab:c", b"d/a:b", b"CONIN$"] {
        let p = plan(&[file(name)]).unwrap();
        assert_eq!(p.warnings, vec![PlanWarning::NonPortableName { index: 0 }], "{:?}", String::from_utf8_lossy(name));
        let strict = PlanOptions { windows_names: Strictness::Reject, ..opts() };
        assert_eq!(plan_extraction(&[file(name)], &strict).unwrap_err().error, PlanError::WindowsName);
    }
    for name in [&b"console"[..], b"com10", b"lpt", b"nul_", b"normal.txt"] {
        assert!(plan(&[file(name)]).unwrap().warnings.is_empty(), "{:?}", String::from_utf8_lossy(name));
    }
}

#[test]
fn limits() {
    let mut o = opts();
    o.limits.max_entries = 2;
    let three = [file(b"a"), file(b"b"), file(b"c")];
    assert_eq!(plan_extraction(&three, &o).unwrap_err(), PlanFailure { index: None, error: PlanError::TooManyEntries });

    let mut o = opts();
    o.limits.max_total_bytes = 10;
    let mut big = file(b"a");
    big.size = 6;
    let mut big2 = file(b"b");
    big2.size = 5;
    assert_eq!(plan_extraction(&[big.clone(), big2.clone()], &o).unwrap_err(), PlanFailure { index: Some(1), error: PlanError::TooManyBytes });
    big2.size = 4;
    assert_eq!(plan_extraction(&[big.clone(), big2], &o).unwrap().total_bytes, 10);
    let mut huge = file(b"h");
    huge.size = u64::MAX;
    assert_eq!(plan_extraction(&[big, huge], &opts()).unwrap_err().error, PlanError::TooManyBytes);

    let long = vec![b'a'; 5000];
    assert_eq!(plan(&[file(&long)]).unwrap_err().error, PlanError::PathTooLong);
    let comp = vec![b'a'; 256];
    assert_eq!(plan(&[file(&comp)]).unwrap_err().error, PlanError::PathTooLong);
    let deep: Vec<u8> = b"a/".repeat(200);
    assert_eq!(plan(&[file(&deep)]).unwrap_err().error, PlanError::TooDeep);
}

#[test]
fn first_bad_entry_rejects_whole_archive() {
    let entries = [file(b"ok1"), dir(b"d"), file(b"d/ok2"), file(b"../evil"), file(b"ok3")];
    assert_eq!(plan(&entries).unwrap_err(), PlanFailure { index: Some(3), error: PlanError::ParentTraversal });
}

#[test]
fn plan_preserves_metadata_and_order() {
    let mut f = file(b"x/y");
    f.mode = Some(0o755);
    f.mtime = Some(-5);
    f.size = 42;
    let p = plan(&[dir(b"x"), f]).unwrap();
    assert_eq!(p.items.len(), 2);
    assert_eq!(p.items[1].index, 1);
    assert_eq!(p.items[1].joined(), b"x/y".to_vec());
    assert_eq!((p.items[1].size, p.items[1].mode, p.items[1].mtime), (42, Some(0o755), Some(-5)));
    assert_eq!(p.total_bytes, 42);
}
