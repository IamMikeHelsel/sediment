// SPDX-License-Identifier: MIT OR Apache-2.0
//! Archive update operations (`u`, `d`, `rn`) for zip, tar (+gz/bz2/xz) and
//! 7z: expected listings, byte-for-byte preservation of untouched entries,
//! the Python stdlib as a reading oracle (when `python3` is available),
//! committed 7-Zip-verified 7z outputs, hostile input and limits.
//!
//! Fixtures: tests/fixtures/update_ops (from tests/gen/update_ops.py) and the
//! 7-Zip-made archives in tests/fixtures/sevenz/oracle.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::Command;

use sediment_engine::archive_edit::{EditFormat, EditSource, apply_plan, list_source, open_source};
use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::ReaderLimits;
use sediment_engine::archive_update::*;
use sediment_engine::compress_wrap::Compression;
use sediment_engine::crc32::crc32;
use sediment_engine::extract_plan::EntryKind as PEntryKind;
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::sevenz_header::{SevenZLimits, pack_stream_ranges, parse_archive_header};
use sediment_engine::sevenz_write::SevenZWriteOptions;
use sediment_engine::tar_read::{TarReadLimits, read_entries};
use sediment_engine::sevenz_update::apply_7z;
use sediment_engine::tar_update::apply_tar;
use sediment_engine::zip_reader2::{Reader2Limits, ZipArchive2};
use sediment_engine::zip_update::{ZipUpdateOptions, apply_zip, zip_entries};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/update_ops");
const SEVENZ: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz/oracle");
const GEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/gen/update_ops.py");
const BIN: &str = env!("CARGO_BIN_EXE_sediment");

const LONG_NAME_DIR: &str = "deep/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn long_name() -> String {
    format!("{LONG_NAME_DIR}/{}.txt", "f".repeat(110))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn sevenz_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{SEVENZ}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn expected_list(name: &str) -> Vec<String> {
    std::fs::read_to_string(format!("{FIX}/{name}.list.tsv"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn col(line: &str, i: usize) -> &str {
    line.split('\t').nth(i).unwrap_or("")
}

fn line_name(line: &str) -> &str {
    col(line, 3)
}

fn limits() -> UpdateLimits {
    UpdateLimits::default()
}

/// Listing in the format of `update_ops.py check`, read with Sediment.
fn listing(bytes: &[u8], file_name: &str) -> Vec<String> {
    if bytes.starts_with(b"PK") || file_name.ends_with(".zip") {
        let z = ZipArchive2::open(bytes, Reader2Limits::default()).expect("zip reopens");
        return z
            .entries()
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let name = String::from_utf8_lossy(e.name()).trim_end_matches('/').to_owned();
                if e.is_dir() {
                    format!("D\t0\t00000000\t{name}")
                } else {
                    let d = z.read(i, 1 << 26).expect("member reads");
                    format!("F\t{}\t{:08x}\t{name}", d.len(), crc32(&d))
                }
            })
            .collect();
    }
    let r = open_named(bytes, file_name.as_bytes(), ReaderLimits::default()).expect("archive reopens");
    r.entries()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let name = String::from_utf8_lossy(&e.path).into_owned();
            match &e.kind {
                PEntryKind::Dir => format!("D\t0\t00000000\t{name}"),
                PEntryKind::Symlink { target } => format!("L\t0\t00000000\t{name}\t{}", String::from_utf8_lossy(target)),
                PEntryKind::Hardlink { target } => format!("H\t0\t00000000\t{name}\t{}", String::from_utf8_lossy(target)),
                PEntryKind::File => {
                    let d = r.read(i).expect("member reads");
                    format!("F\t{}\t{:08x}\t{name}", d.len(), crc32(&d))
                }
            }
        })
        .collect()
}

fn python() -> Option<&'static str> {
    Command::new("python3").arg("-c").arg("pass").output().ok().filter(|o| o.status.success()).map(|_| "python3")
}

fn scratch(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("sed-update-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Python stdlib listing of `bytes` (None when python3 is unavailable).
fn python_listing(bytes: &[u8], file_name: &str) -> Option<Vec<String>> {
    let py = python()?;
    let dir = scratch(&format!("py-{}", file_name.replace('/', "_")));
    let p = dir.join(file_name);
    std::fs::write(&p, bytes).unwrap();
    let out = Command::new(py).arg("-I").arg(GEN).arg("check").arg(&p).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "python oracle rejected {file_name}: {}", String::from_utf8_lossy(&out.stderr));
    Some(String::from_utf8(out.stdout).unwrap().lines().skip(1).map(str::to_owned).collect())
}

/// Check our own reading and (when available) the Python oracle.
fn assert_listing(bytes: &[u8], file_name: &str, want: &[String]) {
    assert_eq!(listing(bytes, file_name), want, "sediment listing of {file_name}");
    if let Some(py) = python_listing(bytes, file_name) {
        assert_eq!(py, want, "python listing of {file_name}");
    }
}

fn src_of(bytes: &[u8]) -> EditSource<'_> {
    open_source(bytes, 1 << 30).expect("source opens")
}

fn existing(bytes: &[u8]) -> Vec<ExistingEntry> {
    list_source(&src_of(bytes), &limits()).unwrap()
}

fn delete(bytes: &[u8], pats: &[&str], recursive: bool) -> Vec<u8> {
    let src = src_of(bytes);
    let ex = list_source(&src, &limits()).unwrap();
    let plan = plan_delete(&ex, pats, recursive);
    apply_plan(&src, &plan, 5, &limits()).unwrap().bytes
}

fn rename(bytes: &[u8], pairs: &[(&str, &str)]) -> Vec<u8> {
    let src = src_of(bytes);
    let ex = list_source(&src, &limits()).unwrap();
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs.iter().map(|(a, b)| (a.as_bytes().to_vec(), b.as_bytes().to_vec())).collect();
    let rp = plan_rename(&ex, &pairs).unwrap();
    apply_plan(&src, &rp.plan, 5, &limits()).unwrap().bytes
}

fn drop_names(list: &[String], names: &[&str]) -> Vec<String> {
    list.iter().filter(|l| !names.contains(&line_name(l))).cloned().collect()
}

/// Rename the name column (and hard link targets) by an `old -> new` prefix rule.
fn rename_list(list: &[String], old: &str, new: &str) -> Vec<String> {
    let map = |n: &str| -> String {
        if n == old {
            new.to_owned()
        } else if let Some(rest) = n.strip_prefix(old).filter(|r| r.starts_with('/')) {
            format!("{new}{rest}")
        } else {
            n.to_owned()
        }
    };
    list.iter()
        .map(|l| {
            let mut c: Vec<String> = l.split('\t').map(str::to_owned).collect();
            c[3] = map(&c[3]);
            if c[0] == "H" {
                c[4] = map(&c[4]);
            }
            c.join("\t")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Byte-preservation helpers
// ---------------------------------------------------------------------------

/// name -> raw local record (header, data, descriptor).
fn zip_records(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let z = ZipArchive2::open(bytes, Reader2Limits::default()).unwrap();
    z.entries()
        .iter()
        .map(|e| {
            let end = e.descriptor.map(|d| d.end).unwrap_or(e.data_end);
            (e.name().to_vec(), bytes[e.header_start..end].to_vec())
        })
        .collect()
}

fn assert_zip_kept_identical(before: &[u8], after: &[u8], kept: &[&str]) {
    let b = zip_records(before);
    let a = zip_records(after);
    let zb = ZipArchive2::open(before, Reader2Limits::default()).unwrap();
    let za = ZipArchive2::open(after, Reader2Limits::default()).unwrap();
    for k in kept {
        let rb = b.iter().find(|(n, _)| n == k.as_bytes()).unwrap_or_else(|| panic!("{k} in source"));
        let ra = a.iter().find(|(n, _)| n == k.as_bytes()).unwrap_or_else(|| panic!("{k} in output"));
        assert_eq!(rb.1, ra.1, "local record of {k} preserved");
        let eb = &zb.entries()[zb.find(k.as_bytes()).unwrap()];
        let ea = &za.entries()[za.find(k.as_bytes()).unwrap()];
        assert_eq!(
            (eb.version_made_by, eb.version_needed, eb.flags, eb.method, eb.dos_time, eb.dos_date, eb.crc32),
            (ea.version_made_by, ea.version_needed, ea.flags, ea.method, ea.dos_time, ea.dos_date, ea.crc32)
        );
        assert_eq!((eb.external_attributes, eb.central_extra.len(), eb.comment), (ea.external_attributes, ea.central_extra.len(), ea.comment));
    }
}

/// name -> main header block + padded data of a tar entry.
fn tar_spans(tar: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    read_entries(tar, TarReadLimits::default())
        .unwrap()
        .into_iter()
        .map(|e| {
            let end = e.data_range.end.div_ceil(512) * 512;
            (e.path.clone(), tar[e.data_range.start - 512..end].to_vec())
        })
        .collect()
}

fn assert_tar_kept_identical(before: &[u8], after: &[u8], kept: &[&str]) {
    let b = tar_spans(before);
    let a = tar_spans(after);
    for k in kept {
        let sb = &b.iter().find(|(n, _)| n == k.as_bytes()).unwrap_or_else(|| panic!("{k} in source")).1;
        let sa = &a.iter().find(|(n, _)| n == k.as_bytes()).unwrap_or_else(|| panic!("{k} in output")).1;
        assert_eq!(sb, sa, "tar entry {k} preserved");
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

#[test]
fn zip_fixture_has_descriptors_and_comment() {
    let z = fixture("mixed.zip");
    let a = ZipArchive2::open(&z, Reader2Limits::default()).unwrap();
    assert!(a.entries().iter().all(|e| e.has_data_descriptor()));
    assert_eq!(a.comment(), b"sediment update fixture");
    assert_eq!(listing(&z, "mixed.zip"), expected_list("mixed.zip"));
}

#[test]
fn zip_delete_wildcards() {
    let z = fixture("mixed.zip");
    let src = expected_list("mixed.zip");
    // Anchored: no `.bak` at the root, so nothing matches.
    let plan = plan_delete(&existing(&z), &["*.bak"], false);
    assert!(plan.is_noop());
    // Recursive: both backups go.
    let out = delete(&z, &["*.bak"], true);
    let want = drop_names(&src, &["docs/old.bak", "data/old.bak"]);
    assert_listing(&out, "out.zip", &want);
    assert_zip_kept_identical(&z, &out, &["readme.txt", "docs/", "docs/guide.md", "data/random.bin", "héllo_日本.txt"]);
    assert_eq!(ZipArchive2::open(&out, Reader2Limits::default()).unwrap().comment(), b"sediment update fixture");
    // A directory takes its contents along; `?` wildcard.
    let out = delete(&z, &["doc?", "empty.txt"], false);
    let want = drop_names(&src, &["docs", "docs/guide.md", "docs/notes.txt", "docs/old.bak", "empty.txt"]);
    assert_listing(&out, "out.zip", &want);
    // Anchored pattern with a path.
    let out = delete(&z, &["data/*.bin"], false);
    assert_listing(&out, "out.zip", &drop_names(&src, &["data/random.bin"]));
    // Delete everything: a valid empty archive that keeps the comment.
    let out = delete(&z, &["*"], false);
    assert_listing(&out, "out.zip", &[]);
    assert_eq!(ZipArchive2::open(&out, Reader2Limits::default()).unwrap().comment(), b"sediment update fixture");
}

#[test]
fn zip_rename_dir_unicode_and_flags() {
    let z = fixture("mixed.zip");
    let src = expected_list("mixed.zip");
    let out = rename(&z, &[("docs", "manual"), ("héllo_日本.txt", "plain.txt"), ("readme.txt", "über/readme.txt")]);
    let want = rename_list(&rename_list(&rename_list(&src, "docs", "manual"), "héllo_日本.txt", "plain.txt"), "readme.txt", "über/readme.txt");
    assert_listing(&out, "out.zip", &want);
    let a = ZipArchive2::open(&out, Reader2Limits::default()).unwrap();
    let e = &a.entries()[a.find("über/readme.txt".as_bytes()).unwrap()];
    assert!(e.name_is_utf8(), "UTF-8 flag set for a non-ASCII new name");
    assert!(a.entries()[a.find(b"manual/").unwrap()].is_dir());
    // Compressed data is untouched by a rename.
    let b = ZipArchive2::open(&z, Reader2Limits::default()).unwrap();
    let old = &b.entries()[b.find(b"docs/guide.md").unwrap()];
    let new = &a.entries()[a.find(b"manual/guide.md").unwrap()];
    assert_eq!(&z[old.data_start..old.data_end], &out[new.data_start..new.data_end]);
    assert_zip_kept_identical(&z, &out, &["data/random.bin", "empty.txt"]);
}

#[test]
fn zip_rename_errors() {
    let z = fixture("mixed.zip");
    let ex = existing(&z);
    let p = |a: &str, b: &str| vec![(a.as_bytes().to_vec(), b.as_bytes().to_vec())];
    assert_eq!(plan_rename(&ex, &p("readme.txt", "empty.txt")), Err(UpdateError::NameCollision));
    assert_eq!(plan_rename(&ex, &p("docs/old.bak", "data")), Err(UpdateError::NameCollision));
    assert_eq!(plan_rename(&ex, &p("readme.txt", "../x")), Err(UpdateError::InvalidName));
    assert_eq!(plan_rename(&ex, &p("readme.txt", "/abs")), Err(UpdateError::InvalidName));
    assert_eq!(plan_rename(&ex, &p("readme.txt", "")), Err(UpdateError::InvalidName));
    let r = plan_rename(&ex, &p("missing", "x")).unwrap();
    assert_eq!(r.matches, vec![0]);
    assert!(r.plan.is_noop());
}

fn mem_entry<'a>(name: &'a str, data: &'a [u8], mtime: i64) -> ArchiveEntry<'a> {
    ArchiveEntry { name: name.as_bytes(), kind: EntryKind::File, data, mtime, mode: 0o644, link_target: b"" }
}

fn mem_dir(name: &str, mtime: i64) -> ArchiveEntry<'_> {
    ArchiveEntry { name: name.as_bytes(), kind: EntryKind::Directory, data: b"", mtime, mode: 0o755, link_target: b"" }
}

#[test]
fn zip_update_replace_and_add() {
    let z = fixture("mixed.zip");
    let src = expected_list("mixed.zip");
    let ex = existing(&z);
    // DOS time of the fixture: 2021-05-06 07:08:10 (read as UTC).
    let t = 1_620_284_890;
    assert_eq!(ex[0].mtime, Some(t));
    assert_eq!(ex[0].time_resolution, 2);
    let newer = b"replaced readme\n".to_vec();
    let incoming = [
        mem_entry("readme.txt", &newer, t + 2),          // newer: replaced
        mem_entry("docs/guide.md", b"same time", t + 1), // within DOS resolution: kept
        mem_entry("docs/notes.txt", b"older", t - 100),  // older: kept
        mem_dir("docs", t + 1000),                        // existing dir: kept
        mem_dir("newdir", t),
        mem_entry("newdir/new.txt", b"brand new\n", t),
    ];
    let (plan, s) = plan_update(&ex, &incoming).unwrap();
    assert_eq!(s, UpdateSummary { added: 2, replaced: 1, unchanged: 3 });
    let out = apply_plan(&src_of(&z), &plan, 6, &limits()).unwrap().bytes;
    let mut want = src.clone();
    want[0] = format!("F\t{}\t{:08x}\treadme.txt", newer.len(), crc32(&newer));
    want.push("D\t0\t00000000\tnewdir".into());
    want.push(format!("F\t10\t{:08x}\tnewdir/new.txt", crc32(b"brand new\n")));
    assert_listing(&out, "out.zip", &want);
    assert_zip_kept_identical(&z, &out, &["docs/guide.md", "docs/notes.txt", "data/random.bin"]);
    // A file replacing a directory of the same name.
    let (plan, s) = plan_update(&ex, &[mem_entry("data", b"now a file", t)]).unwrap();
    assert_eq!(s.replaced, 1);
    let out = apply_plan(&src_of(&z), &plan, 0, &limits()).unwrap().bytes;
    assert!(listing(&out, "o.zip").contains(&format!("F\t10\t{:08x}\tdata", crc32(b"now a file"))));
}

#[test]
fn zip_symlink_additions_are_skipped() {
    let z = fixture("seekable.zip");
    let link = ArchiveEntry { name: b"lnk", kind: EntryKind::Symlink, data: b"", mtime: 0, mode: 0o777, link_target: b"a.txt" };
    let (plan, _) = plan_update(&existing(&z), &[link]).unwrap();
    let r = apply_plan(&src_of(&z), &plan, 5, &limits()).unwrap();
    assert_eq!(r.skipped, vec![b"lnk".to_vec()]);
    assert_eq!(listing(&r.bytes, "o.zip"), expected_list("seekable.zip"));
}

#[test]
fn zip_new_archive_from_nothing() {
    let entries = [mem_dir("d", 1_700_000_000), mem_entry("d/x.txt", b"xyz", 1_700_000_000)];
    let (plan, s) = plan_update(&[], &entries).unwrap();
    assert_eq!(s.added, 2);
    let r = apply_zip(&[], &plan, ZipUpdateOptions { level: 9 }, &limits()).unwrap();
    let want = vec!["D\t0\t00000000\td".to_string(), format!("F\t3\t{:08x}\td/x.txt", crc32(b"xyz"))];
    assert_listing(&r.bytes, "new.zip", &want);
    // An empty plan on nothing gives an empty archive.
    let r = apply_zip(&[], &EditPlan::default(), ZipUpdateOptions::default(), &limits()).unwrap();
    assert_eq!(r.bytes.len(), 22);
}

#[test]
fn zip_self_extractor_stub_preserved() {
    let z = fixture("sfx.zip");
    let a = ZipArchive2::open(&z, Reader2Limits::default()).unwrap();
    let stub_len = a.entries()[0].header_start;
    assert!(stub_len > 0);
    let out = delete(&z, &["one.txt"], false);
    assert_eq!(&out[..stub_len], &z[..stub_len]);
    assert_listing(&out, "out.zip", &drop_names(&expected_list("sfx.zip"), &["one.txt"]));
    // Offsets in the output are absolute.
    let o = ZipArchive2::open(&out, Reader2Limits::default()).unwrap();
    assert_eq!(o.entries()[0].local_header_offset as usize, o.entries()[0].header_start);
}

#[test]
fn zip64_extra_offsets_are_patched() {
    let z = fixture("zip64_offsets.zip");
    assert!(ZipArchive2::open(&z, Reader2Limits::default()).unwrap().entries().iter().all(|e| e.zip64));
    let out = delete(&z, &["first.txt"], false);
    assert_listing(&out, "out.zip", &drop_names(&expected_list("zip64_offsets.zip"), &["first.txt"]));
    let o = ZipArchive2::open(&out, Reader2Limits::default()).unwrap();
    assert!(o.entries().iter().all(|e| e.zip64), "ZIP64 extra kept");
    assert_eq!(o.entries()[0].header_start, 0);
    let out = rename(&out, &[("third.txt", "renamed-third.txt")]);
    let want = rename_list(&drop_names(&expected_list("zip64_offsets.zip"), &["first.txt"]), "third.txt", "renamed-third.txt");
    assert_listing(&out, "out.zip", &want);
}

#[test]
fn zip_many_entries_switch_to_zip64_end_record() {
    let names: Vec<String> = (0..70_000).map(|i| format!("f{i:05}")).collect();
    let entries: Vec<ArchiveEntry<'_>> = names.iter().map(|n| mem_entry(n, b"", 1_700_000_000)).collect();
    let (plan, _) = plan_update(&[], &entries[..65_000]).unwrap();
    let base = apply_zip(&[], &plan, ZipUpdateOptions { level: 0 }, &limits()).unwrap().bytes;
    let ex = zip_entries(&base, &limits()).unwrap();
    assert_eq!(ex.len(), 65_000);
    let (plan, s) = plan_update(&ex, &entries).unwrap();
    assert_eq!((s.added, s.unchanged), (5_000, 65_000));
    let out = apply_zip(&base, &plan, ZipUpdateOptions { level: 0 }, &limits()).unwrap().bytes;
    let o = ZipArchive2::open(&out, Reader2Limits::default()).unwrap();
    assert_eq!(o.len(), 70_000);
    assert!(o.is_zip64());
    if let Some(py) = python() {
        let dir = scratch("zip64");
        let p = dir.join("big.zip");
        std::fs::write(&p, &out).unwrap();
        let o = Command::new(py)
            .args(["-I", "-c", "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;print(len(z.namelist()))"])
            .arg(&p)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "70000");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// tar (+ compression)
// ---------------------------------------------------------------------------

const TARS: [&str; 5] = ["pax.tar", "gnu.tar", "pax.tar.gz", "gnu.tar.bz2", "pax.tar.xz"];

fn tar_payload(bytes: &[u8]) -> Vec<u8> {
    src_of(bytes).data.into_owned()
}

#[test]
fn tar_fixtures_list_like_python() {
    for name in TARS {
        assert_eq!(listing(&fixture(name), name), expected_list(name), "{name}");
    }
}

#[test]
fn tar_delete_keeps_untouched_bytes() {
    for name in TARS {
        let t = fixture(name);
        let src = expected_list(name);
        let out = delete(&t, &["*.o", "empty"], true);
        assert_listing(&out, name, &drop_names(&src, &["src/old.o", "empty"]));
        let (before, after) = (tar_payload(&t), tar_payload(&out));
        assert_tar_kept_identical(&before, &after, &["src", "src/main.c", "src/util.c", "src/link", "src/hard", "README", &long_name(), "longlink"]);
        // Compression format is kept.
        assert_eq!(src_of(&out).format, src_of(&t).format, "{name}");
        // Deleting a directory removes its contents.
        let out = delete(&t, &["src"], false);
        assert_listing(&out, name, &drop_names(&src, &["src", "src/main.c", "src/util.c", "src/old.o", "src/link", "src/hard"]));
    }
}

#[test]
fn tar_pax_global_header_survives_deletion_of_first_entry() {
    let t = fixture("pax.tar");
    assert!(contains(&t, b"comment=global header"));
    let out = delete(&t, &["src"], false);
    assert!(contains(&out, b"comment=global header"));
    assert_eq!(&out[156..157], b"g");
}

#[test]
fn tar_rename_short_long_and_hardlinks() {
    let ln = long_name();
    let new_long = format!("renamed/{}/{}.txt", "g".repeat(80), "h".repeat(120));
    for name in TARS {
        let t = fixture(name);
        let src = expected_list(name);
        let out = rename(&t, &[("src", "source"), (&ln, "short.txt"), ("README", &new_long)]);
        let want = rename_list(&rename_list(&rename_list(&src, "src", "source"), &ln, "short.txt"), "README", &new_long);
        assert_listing(&out, name, &want);
        // The hard link now points at the renamed file.
        assert!(want.iter().any(|l| l == "H\t0\t00000000\tsource/hard\tsource/main.c"));
        let (before, after) = (tar_payload(&t), tar_payload(&out));
        assert_tar_kept_identical(&before, &after, &["longlink", "empty"]);
        // Data blocks follow the rewritten headers unchanged.
        let b = read_entries(&before, TarReadLimits::default()).unwrap();
        let a = read_entries(&after, TarReadLimits::default()).unwrap();
        for (x, y) in b.iter().zip(&a) {
            assert_eq!(before[x.data_range.clone()], after[y.data_range.clone()]);
            assert_eq!((x.mode, x.uid, x.gid, &x.uname, &x.gname, x.mtime), (y.mode, y.uid, y.gid, &y.uname, &y.gname, y.mtime));
        }
    }
}

#[test]
fn tar_rename_link_target_over_100_bytes() {
    let t = fixture("gnu.tar");
    let target_dir = "t".repeat(120);
    let out = rename(&t, &[("src", &target_dir)]);
    let want = rename_list(&expected_list("gnu.tar"), "src", &target_dir);
    assert_listing(&out, "gnu.tar", &want);
    let t = fixture("pax.tar");
    let out = rename(&t, &[("src", &target_dir)]);
    assert_listing(&out, "pax.tar", &rename_list(&expected_list("pax.tar"), "src", &target_dir));
}

#[test]
fn tar_update_replace_and_add() {
    for name in TARS {
        let t = fixture(name);
        let src = expected_list(name);
        let ex = existing(&t);
        let base = 1_600_000_000;
        let incoming = [
            mem_entry("README", b"newer readme\n", base + 1),
            mem_entry("src/main.c", b"same", base),
            mem_dir("added", base),
            mem_entry("added/one.txt", b"one\n", base),
        ];
        let (plan, s) = plan_update(&ex, &incoming).unwrap();
        assert_eq!(s, UpdateSummary { added: 2, replaced: 1, unchanged: 1 });
        let out = apply_plan(&src_of(&t), &plan, 3, &limits()).unwrap().bytes;
        let mut want: Vec<String> = src
            .iter()
            .map(|l| if line_name(l) == "README" { format!("F\t13\t{:08x}\tREADME", crc32(b"newer readme\n")) } else { l.clone() })
            .collect();
        want.push("D\t0\t00000000\tadded".into());
        want.push(format!("F\t4\t{:08x}\tadded/one.txt", crc32(b"one\n")));
        assert_listing(&out, name, &want);
    }
}

#[test]
fn tar_new_and_empty_archives() {
    let (plan, _) = plan_update(&[], &[mem_entry("a", b"A", 5)]).unwrap();
    let tar = apply_tar(&[], &plan, &limits()).unwrap();
    assert_eq!(tar.len() % 10240, 0);
    assert_listing(&tar, "new.tar", &[format!("F\t1\t{:08x}\ta", crc32(b"A"))]);
    // Deleting everything leaves an all-zero (empty) tar that can be updated again.
    let empty = delete(&tar, &["*"], false);
    assert!(empty.iter().all(|&b| b == 0));
    let src = src_of(&empty);
    assert_eq!(src.format, EditFormat::Tar(Compression::None));
    assert!(list_source(&src, &limits()).unwrap().is_empty());
    let r = apply_plan(&src, &plan, 5, &limits()).unwrap().bytes;
    assert_eq!(r, tar);
    // An empty compressed tar.
    let gz = apply_plan(&EditSource { format: EditFormat::Tar(Compression::Gzip), data: Cow::Borrowed(&[]) }, &plan, 5, &limits())
        .unwrap()
        .bytes;
    assert_listing(&gz, "new.tar.gz", &[format!("F\t1\t{:08x}\ta", crc32(b"A"))]);
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

const SEVENZS: [&str; 8] = [
    "lzma_solid_hc.7z",
    "lzma_solid_nohc.7z",
    "lzma_nonsolid_nohc.7z",
    "lzma2_solid_hc.7z",
    "lzma2_nonsolid_nohc.7z",
    "copy_solid_nohc.7z",
    "copy_nonsolid_nohc.7z",
    "copy_solid_hc_times.7z",
];

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// Packed streams of every folder: (folder index, concatenated pack bytes).
fn sevenz_packs(bytes: &[u8]) -> Vec<Vec<u8>> {
    let codecs = sediment_engine::archive_open::SevenZCodecs::new(1 << 30);
    let h = parse_archive_header(bytes, &codecs, &SevenZLimits::default()).unwrap();
    let ranges = pack_stream_ranges(bytes.len(), &h.main_streams.pack_info).unwrap();
    let mut out = Vec::new();
    let mut p = 0;
    for f in &h.main_streams.folders {
        let mut v = Vec::new();
        for _ in 0..f.packed_streams.len() {
            v.extend_from_slice(&bytes[ranges[p].0..ranges[p].1]);
            p += 1;
        }
        out.push(v);
    }
    out
}

#[test]
fn sevenz_delete_rename_update_on_7zip_archives() {
    for name in SEVENZS {
        let z = sevenz_fixture(name);
        let src = listing(&z, name);
        assert!(src.iter().any(|l| line_name(l) == "a.txt"), "{name}: {src:?}");

        // Delete an empty-stream item only: every folder is copied verbatim.
        let out = delete(&z, &["emptydir", "empty.txt"], false);
        assert_eq!(sorted(listing(&out, name)), sorted(drop_names(&src, &["emptydir", "empty.txt"])), "{name}");
        assert_eq!(sevenz_packs(&out), sevenz_packs(&z), "{name}: packed streams preserved");

        // Rename: header-only change.
        let out = rename(&z, &[("dir", "folder"), ("a.txt", "renamed/a.txt")]);
        let want = rename_list(&rename_list(&src, "dir", "folder"), "a.txt", "renamed/a.txt");
        assert_eq!(sorted(listing(&out, name)), sorted(want), "{name}");
        assert_eq!(sevenz_packs(&out), sevenz_packs(&z), "{name}: packed streams preserved");

        // Delete a member: its folder is re-encoded, others are copied.
        let out = delete(&z, &["b.bin"], false);
        assert_eq!(sorted(listing(&out, name)), sorted(drop_names(&src, &["b.bin"])), "{name}");
        let before = sevenz_packs(&z);
        let after = sevenz_packs(&out);
        let copied = before.iter().filter(|p| after.contains(p)).count();
        assert!(copied + 1 >= before.len() || name.contains("_solid"), "{name}: untouched folders copied");

        // Update: replace a.txt (newer), add a file.
        let ex = existing(&z);
        let a = ex.iter().find(|e| e.name == b"a.txt").unwrap();
        let t = a.mtime.unwrap();
        let incoming = [mem_entry("a.txt", b"replacement\n", t + 1), mem_entry("hello.txt", b"older\n", t - 10), mem_entry("new/n.txt", b"n\n", t)];
        let (plan, s) = plan_update(&ex, &incoming).unwrap();
        assert_eq!(s, UpdateSummary { added: 1, replaced: 1, unchanged: 1 });
        let out = apply_plan(&src_of(&z), &plan, 5, &limits()).unwrap().bytes;
        let mut want: Vec<String> = src
            .iter()
            .map(|l| if line_name(l) == "a.txt" { format!("F\t12\t{:08x}\ta.txt", crc32(b"replacement\n")) } else { l.clone() })
            .collect();
        want.push(format!("F\t2\t{:08x}\tnew/n.txt", crc32(b"n\n")));
        assert_eq!(sorted(listing(&out, name)), sorted(want), "{name}");
    }
}

#[test]
fn sevenz_keeps_times_and_attributes() {
    let z = sevenz_fixture("copy_solid_hc_times.7z");
    let out = delete(&z, &["b.bin"], false);
    let codecs = sediment_engine::archive_open::SevenZCodecs::new(1 << 30);
    let hb = parse_archive_header(&z, &codecs, &SevenZLimits::default()).unwrap();
    let ha = parse_archive_header(&out, &codecs, &SevenZLimits::default()).unwrap();
    for f in &ha.files {
        let o = hb.files.iter().find(|g| g.name == f.name).unwrap();
        assert_eq!((f.attributes, f.mtime, f.ctime, f.atime, f.is_dir, f.is_empty_file), (o.attributes, o.mtime, o.ctime, o.atime, o.is_dir, o.is_empty_file), "{}", f.name);
    }
}

#[test]
fn sevenz_new_archive_and_empty_result() {
    let entries = [mem_dir("d", 1_700_000_000), mem_entry("d/x.txt", b"xyz", 1_700_000_000), mem_entry("e", b"", 1_700_000_000)];
    let (plan, _) = plan_update(&[], &entries).unwrap();
    let opts = SevenZWriteOptions::level(5).unwrap();
    let out = apply_7z(&[], &plan, &opts, &limits()).unwrap();
    let want = vec!["D\t0\t00000000\td".to_string(), format!("F\t3\t{:08x}\td/x.txt", crc32(b"xyz")), "F\t0\t00000000\te".to_string()];
    assert_eq!(sorted(listing(&out, "n.7z")), sorted(want));
    let empty = delete(&out, &["*"], false);
    assert_eq!(empty.len(), 32);
    assert!(listing(&empty, "e.7z").is_empty());
}

/// Committed outputs, verified with 7-Zip 26.04 `7zz t` and `7zz l -slt`
/// (tests/gen/update_ops_7z_oracle.sh). Regenerate with
/// `UPDATE_OPS_REGEN=1 cargo test --test update_ops sevenz_oracle_outputs`.
#[test]
fn sevenz_oracle_outputs() {
    let dir = format!("{FIX}/7z");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("lzma2_solid_hc.delete.7z", delete(&sevenz_fixture("lzma2_solid_hc.7z"), &["b.bin", "emptydir"], false)),
        ("lzma_nonsolid_nohc.rename.7z", rename(&sevenz_fixture("lzma_nonsolid_nohc.7z"), &[("dir", "folder"), ("hello.txt", "greeting.txt")])),
        ("copy_solid_hc_times.delete.7z", delete(&sevenz_fixture("copy_solid_hc_times.7z"), &["a.txt"], false)),
        ("lzma_solid_hc.update.7z", {
            let z = sevenz_fixture("lzma_solid_hc.7z");
            let (plan, _) = plan_update(&existing(&z), &[mem_entry("a.txt", b"replacement\n", 2_000_000_000), mem_entry("zz/new.txt", b"new\n", 1)]).unwrap();
            apply_plan(&src_of(&z), &plan, 5, &limits()).unwrap().bytes
        }),
    ];
    if std::env::var_os("UPDATE_OPS_REGEN").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (n, b) in &cases {
            std::fs::write(format!("{dir}/{n}"), b).unwrap();
        }
        return;
    }
    for (n, b) in &cases {
        let committed = std::fs::read(format!("{dir}/{n}")).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(&committed, b, "{n}: output is deterministic and matches the 7-Zip-verified file");
        let slt = std::fs::read_to_string(format!("{dir}/{n}.slt.txt")).unwrap();
        for l in listing(b, n) {
            assert!(slt.contains(&format!("Path = {}\n", line_name(&l))), "{n}: 7-Zip lists {}", line_name(&l));
        }
    }
}

// ---------------------------------------------------------------------------
// Hostile input and limits
// ---------------------------------------------------------------------------

/// Run every operation on damaged copies; nothing may panic.
fn hammer(data: &[u8]) {
    let run = |b: &[u8]| {
        let Ok(src) = open_source(b, 1 << 24) else { return };
        let small = UpdateLimits { max_entries: 10_000, max_total_bytes: 1 << 24, max_output_bytes: 1 << 24 };
        let Ok(ex) = list_source(&src, &small) else { return };
        let _ = apply_plan(&src, &plan_delete(&ex, &["*.txt", "src"], true), 1, &small);
        if let Ok(rp) = plan_rename(&ex, &[(b"src".to_vec(), b"x".to_vec()), (b"a.txt".to_vec(), b"q".to_vec())]) {
            let _ = apply_plan(&src, &rp.plan, 1, &small);
        }
        if let Ok((p, _)) = plan_update(&ex, &[mem_entry("a.txt", b"zz", i64::MAX)]) {
            let _ = apply_plan(&src, &p, 1, &small);
        }
    };
    let step = (data.len() / 64).max(1);
    for cut in (0..data.len()).step_by(step) {
        run(&data[..cut]);
    }
    let mut x: u32 = 0x1234_5678;
    for _ in 0..150 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let mut d = data.to_vec();
        let i = (x as usize >> 3) % d.len();
        d[i] ^= 1 << (x % 8);
        run(&d);
    }
}

#[test]
fn hostile_inputs_never_panic() {
    for n in ["mixed.zip", "sfx.zip", "zip64_offsets.zip", "pax.tar", "gnu.tar", "pax.tar.gz"] {
        hammer(&fixture(n));
    }
    for n in ["lzma2_solid_hc.7z", "copy_nonsolid_nohc.7z"] {
        hammer(&sevenz_fixture(n));
    }
    assert_eq!(open_source(b"", 100).unwrap_err(), UpdateError::Unsupported);
    assert_eq!(open_source(b"not an archive at all", 100).unwrap_err(), UpdateError::Unsupported);
}

#[test]
fn single_stream_compressed_files_are_rejected() {
    let gz = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/create/text.txt.gz")).unwrap();
    assert_eq!(open_source(&gz, 1 << 24).unwrap_err(), UpdateError::Unsupported);
}

#[test]
fn plan_length_mismatch_is_an_error() {
    let z = fixture("seekable.zip");
    let bad = EditPlan { actions: vec![EntryAction::Keep], additions: Vec::new() };
    assert_eq!(apply_plan(&src_of(&z), &bad, 5, &limits()).unwrap_err(), UpdateError::InvalidArchive);
    let t = fixture("pax.tar");
    assert_eq!(apply_plan(&src_of(&t), &bad, 5, &limits()).unwrap_err(), UpdateError::InvalidArchive);
    let s = sevenz_fixture("copy_solid_nohc.7z");
    assert_eq!(apply_plan(&src_of(&s), &bad, 5, &limits()).unwrap_err(), UpdateError::InvalidArchive);
}

#[test]
fn limits_are_enforced() {
    let tiny = UpdateLimits { max_entries: 1_000, max_total_bytes: 1 << 20, max_output_bytes: 600 };
    let z = fixture("mixed.zip");
    let src = src_of(&z);
    let ex = list_source(&src, &limits()).unwrap();
    let plan = plan_delete(&ex, &["empty.txt"], false);
    assert_eq!(apply_plan(&src, &plan, 5, &tiny).unwrap_err(), UpdateError::LimitExceeded);
    let few = UpdateLimits { max_entries: 3, ..limits() };
    assert_eq!(list_source(&src, &few).unwrap_err(), UpdateError::LimitExceeded);
    let t = fixture("pax.tar");
    let ts = src_of(&t);
    let ex = list_source(&ts, &limits()).unwrap();
    assert_eq!(apply_plan(&ts, &plan_delete(&ex, &["README"], false), 5, &tiny).unwrap_err(), UpdateError::LimitExceeded);
    assert_eq!(list_source(&ts, &few).unwrap_err(), UpdateError::LimitExceeded);
    let s = sevenz_fixture("lzma2_solid_hc.7z");
    let ss = src_of(&s);
    let ex = list_source(&ss, &limits()).unwrap();
    let small = UpdateLimits { max_output_bytes: 100, ..limits() };
    assert_eq!(apply_plan(&ss, &plan_delete(&ex, &["b.bin"], false), 5, &small).unwrap_err(), UpdateError::LimitExceeded);
    let little_mem = UpdateLimits { max_total_bytes: 10, ..limits() };
    assert!(apply_plan(&ss, &plan_delete(&ex, &["b.bin"], false), 5, &little_mem).is_err());
    assert_eq!(apply_plan(&ss, &plan_delete(&ex, &["b.bin"], false), 10, &limits()).unwrap_err(), UpdateError::EncodeFailed);
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(BIN).current_dir(dir).args(args).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn set_mtime(p: &Path, secs: u64) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)).unwrap();
}

#[test]
fn cli_update_delete_rename_zip() {
    let d = scratch("cli-zip");
    std::fs::create_dir_all(d.join("tree/sub")).unwrap();
    std::fs::write(d.join("tree/a.txt"), b"alpha\n").unwrap();
    std::fs::write(d.join("tree/sub/b.log"), b"beta\n").unwrap();
    set_mtime(&d.join("tree/a.txt"), 1_700_000_000);
    set_mtime(&d.join("tree/sub/b.log"), 1_700_000_000);

    let (c, out, err) = run(&d, &["u", "arch.zip", "tree"]);
    assert_eq!(c, 0, "{err}");
    assert!(out.contains("4 added"), "{out}");
    let first = std::fs::read(d.join("arch.zip")).unwrap();

    // Nothing changed: archive not rewritten.
    let (c, out, _) = run(&d, &["u", "arch.zip", "tree"]);
    assert_eq!(c, 0);
    assert!(out.contains("up to date"), "{out}");
    assert_eq!(std::fs::read(d.join("arch.zip")).unwrap(), first);

    // A newer file is replaced, a new file is added.
    std::fs::write(d.join("tree/a.txt"), b"alpha v2\n").unwrap();
    set_mtime(&d.join("tree/a.txt"), 1_700_000_100);
    std::fs::write(d.join("tree/c.txt"), b"gamma\n").unwrap();
    let (c, out, _) = run(&d, &["u", "-mx9", "arch.zip", "tree"]);
    assert_eq!(c, 0);
    assert!(out.contains("1 added, 1 replaced, 3 unchanged"), "{out}");

    let (c, _, _) = run(&d, &["d", "arch.zip", "*.log"]);
    assert_eq!(c, 0);
    let names = |d: &Path| listing(&std::fs::read(d.join("arch.zip")).unwrap(), "arch.zip").iter().map(|l| line_name(l).to_owned()).collect::<Vec<_>>();
    assert!(names(&d).contains(&"tree/sub/b.log".to_string()), "anchored pattern does not reach sub/");
    let (c, out, _) = run(&d, &["d", "-r", "arch.zip", "*.log"]);
    assert_eq!(c, 0, "{out}");
    assert_eq!(names(&d), ["tree", "tree/a.txt", "tree/sub", "tree/c.txt"]);

    let (c, _, err) = run(&d, &["rn", "arch.zip", "tree", "root", "root/x", "y"]);
    assert_eq!(c, 0, "{err}");
    assert!(err.contains("no entry named root/x"), "{err}");
    assert_eq!(names(&d), ["root", "root/a.txt", "root/sub", "root/c.txt"]);

    // Collision: error and archive untouched.
    let before = std::fs::read(d.join("arch.zip")).unwrap();
    let (c, _, err) = run(&d, &["rn", "arch.zip", "root/a.txt", "root/c.txt"]);
    assert_eq!(c, 1);
    assert!(err.contains("duplicate"), "{err}");
    assert_eq!(std::fs::read(d.join("arch.zip")).unwrap(), before);

    // Usage errors.
    assert_eq!(run(&d, &["rn", "arch.zip", "only-one"]).0, 2);
    assert_eq!(run(&d, &["d", "arch.zip"]).0, 2);
    assert_eq!(run(&d, &["d", "-l", "arch.zip", "x"]).0, 2);
    assert_eq!(run(&d, &["u", "arch.zip"]).0, 2);
    assert_eq!(run(&d, &["u", "-mx10", "arch.zip", "tree"]).0, 2);
    assert_eq!(run(&d, &["u", "arch.unknown", "tree"]).0, 2);
    // Missing archive for d / rn.
    assert_eq!(run(&d, &["d", "nope.zip", "x"]).0, 1);
    // No temporary files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&d).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains("sediment-tmp")).collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn cli_update_tar_and_7z() {
    let d = scratch("cli-tar7z");
    std::fs::create_dir_all(d.join("in")).unwrap();
    std::fs::write(d.join("in/a.txt"), b"alpha\n").unwrap();
    for arch in ["x.tar", "x.tar.gz", "x.tar.bz2", "x.tar.xz", "x.7z"] {
        let (c, _, err) = run(&d, &["u", arch, "in"]);
        assert_eq!(c, 0, "{arch}: {err}");
        let (c, _, err) = run(&d, &["rn", arch, "in/a.txt", "in/b.txt"]);
        assert_eq!(c, 0, "{arch}: {err}");
        let (c, _, err) = run(&d, &["d", arch, "in"]);
        assert_eq!(c, 0, "{arch}: {err}");
        let bytes = std::fs::read(d.join(arch)).unwrap();
        // An empty plain tar is all zero blocks (which `open_named` does not list).
        assert!((arch == "x.tar" && bytes.iter().all(|&b| b == 0)) || listing(&bytes, arch).is_empty(), "{arch}");
        let (c, _, err) = run(&d, &["u", arch, "in"]);
        assert_eq!(c, 0, "{arch}: {err}");
        let (c, out, err) = run(&d, &["t", arch]);
        assert_eq!(c, 0, "{arch}: {err}");
        assert!(out.starts_with("OK\t2\t6"), "{arch}: {out}");
    }
    // A plain .gz cannot be updated.
    std::fs::write(d.join("one.gz"), std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/create/text.txt.gz")).unwrap()).unwrap();
    let (c, _, err) = run(&d, &["d", "one.gz", "x"]);
    assert_eq!(c, 1);
    assert!(err.contains("cannot be updated"), "{err}");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn cli_keeps_permissions_and_symlinked_archive() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let d = scratch("cli-perm");
    std::fs::write(d.join("f.txt"), b"f\n").unwrap();
    std::fs::create_dir_all(d.join("real")).unwrap();
    std::fs::copy(format!("{FIX}/seekable.zip"), d.join("real/a.zip")).unwrap();
    std::fs::set_permissions(d.join("real/a.zip"), std::fs::Permissions::from_mode(0o640)).unwrap();
    symlink("real/a.zip", d.join("link.zip")).unwrap();
    let (c, _, err) = run(&d, &["u", "link.zip", "f.txt"]);
    assert_eq!(c, 0, "{err}");
    assert!(std::fs::symlink_metadata(d.join("link.zip")).unwrap().file_type().is_symlink());
    let m = std::fs::metadata(d.join("real/a.zip")).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o640);
    let names: Vec<String> = listing(&std::fs::read(d.join("real/a.zip")).unwrap(), "a.zip").iter().map(|l| line_name(l).to_owned()).collect();
    assert_eq!(names.last().map(String::as_str), Some("f.txt"));
    let _ = std::fs::remove_dir_all(&d);
}
