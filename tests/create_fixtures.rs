// SPDX-License-Identifier: MIT OR Apache-2.0
//! Committed creation fixtures: Rust builds archives from tests/fixtures/create/spec.tsv
//! (written by tests/gen/create.py), the bytes must match the committed outputs
//! (determinism), Sediment's own readers must round-trip them, and the Python
//! oracle (zipfile/tarfile/gzip) must accept them.
//! Regenerate with `SEDIMENT_REGEN=1 cargo test --test create_fixtures`.

#[path = "create_common/mod.rs"]
mod common;

use common::*;
use sediment_engine::compress_wrap::{Compression, compress, compress_bound};
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::tar_create::{TarCreateLimits, create_tar};
use sediment_engine::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{ZipLimits, parse_entries};

fn build_all(spec: &[SpecEntry]) -> Vec<(&'static str, Vec<u8>)> {
    let entries: Vec<ArchiveEntry<'_>> = spec.iter().map(|e| e.archive_entry()).collect();
    let stored = create_zip(&entries, ZipCreateOptions { level: 0 }, ZipCreateLimits::default()).unwrap();
    let deflated = create_zip(&entries, ZipCreateOptions { level: 6 }, ZipCreateLimits::default()).unwrap();
    let tar = create_tar(&entries, TarCreateLimits::default()).unwrap();
    let tgz = compress(Compression::Gzip, &tar, 6, compress_bound(tar.len()).unwrap()).unwrap();
    vec![
        ("create_store.zip", stored.bytes),
        ("create_deflate.zip", deflated.bytes),
        ("create.tar", tar),
        ("create.tar.gz", tgz),
    ]
}

#[test]
fn fixtures_match_committed_bytes() {
    let spec = load_spec();
    let built = build_all(&spec);
    let regen = std::env::var_os("SEDIMENT_REGEN").is_some();
    for (name, bytes) in &built {
        let path = format!("{FIXTURES}/{name}");
        if regen {
            std::fs::write(&path, bytes).unwrap();
        }
        let committed = std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}; run with SEDIMENT_REGEN=1"));
        assert!(committed == *bytes, "{name} differs from committed fixture");
    }
}

#[test]
fn creation_is_deterministic() {
    let spec = load_spec();
    assert_eq!(build_all(&spec), build_all(&spec));
}

#[test]
fn zip_round_trips_through_sediment_readers() {
    let spec = load_spec();
    let built = build_all(&spec);
    let want: Vec<&SpecEntry> = spec.iter().filter(|e| e.kind != EntryKind::Symlink).collect();
    for (name, bytes) in built.iter().filter(|(n, _)| n.ends_with(".zip")) {
        let entries = parse_entries(bytes, ZipLimits { max_entries: 1000, max_total_size: 1 << 24 }).unwrap();
        assert_eq!(entries.len(), want.len(), "{name}");
        let mut saw_deflate = false;
        for (got, exp) in entries.iter().zip(&want) {
            let mut n = exp.name.clone();
            if exp.kind == EntryKind::Directory {
                n.push(b'/');
            }
            assert_eq!(got.name, n.as_slice());
            let data = entry_data(bytes, got, got.size, 10_000).unwrap();
            let exp_data: &[u8] = if exp.kind == EntryKind::File { &exp.payload } else { &[] };
            assert_eq!(&*data, exp_data);
            if got.method == 8 {
                saw_deflate = true;
                assert!(got.compressed_size < got.size);
            }
            if name.contains("store") {
                assert_eq!(got.method, 0);
            }
        }
        assert_eq!(saw_deflate, !name.contains("store"), "{name}");
    }
}

#[test]
fn tar_round_trips_through_independent_reader() {
    let spec = load_spec();
    let built = build_all(&spec);
    let tar = &built.iter().find(|(n, _)| *n == "create.tar").unwrap().1;
    let gz = &built.iter().find(|(n, _)| *n == "create.tar.gz").unwrap().1;
    assert_eq!(&decode_gzip(gz, 1 << 24, 100_000).unwrap(), tar);
    assert!(gz.len() < tar.len() / 3, "gzip should compress the tar");
    let items = read_tar(tar);
    assert_eq!(items.len(), spec.len());
    for (it, e) in items.iter().zip(&spec) {
        assert_eq!(it.name, e.name);
        assert_eq!(it.mode, e.mode);
        assert_eq!(it.mtime, e.mtime);
        match e.kind {
            EntryKind::File => {
                assert_eq!(it.typeflag, b'0');
                assert_eq!(it.data, e.payload);
            }
            EntryKind::Directory => assert_eq!(it.typeflag, b'5'),
            EntryKind::Symlink => {
                assert_eq!(it.typeflag, b'2');
                assert_eq!(it.link, e.payload);
            }
        }
    }
    // Plain ustar entries are also accepted by the existing ustar_header parser.
    let first = sediment_engine::ustar_header::parse_header(&tar[..512]).unwrap().unwrap();
    assert_eq!(first.name, b"a_dir/");
}

#[test]
fn python_oracle_accepts_committed_fixtures() {
    oracle_check(std::path::Path::new(FIXTURES));
}

#[test]
fn python_oracle_accepts_fresh_outputs() {
    let spec = load_spec();
    let dir = TempDir::new("fresh");
    write_spec(&dir.path().join("spec.tsv"), &spec);
    for (name, bytes) in build_all(&spec) {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    // Also a stored gzip (level 0 goes through gzip_encode).
    let entries: Vec<ArchiveEntry<'_>> = spec.iter().map(|e| e.archive_entry()).collect();
    let tar = create_tar(&entries, TarCreateLimits::default()).unwrap();
    let tgz0 = compress(Compression::Gzip, &tar, 0, compress_bound(tar.len()).unwrap()).unwrap();
    std::fs::write(dir.path().join("level0.tgz"), tgz0).unwrap();
    oracle_check(dir.path());
}
