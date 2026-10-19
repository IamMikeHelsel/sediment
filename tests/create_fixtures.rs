// SPDX-License-Identifier: MIT OR Apache-2.0
//! Committed creation fixtures: Rust builds archives from tests/fixtures/create/spec.tsv
//! (written by tests/gen/create.py), the bytes must match the committed outputs
//! (determinism), Sediment's own readers must round-trip them, and the Python
//! oracle (zipfile/tarfile/gzip) must accept them.
//! Regenerate with `SEDIMENT_REGEN=1 cargo test --test create_fixtures`.

#[path = "create_common/mod.rs"]
mod common;

use common::*;
use sediment_engine::bzip2_decode::decode_bzip2;
use sediment_engine::compress_wrap::{Compression, compress, compress_bound, compress_bound_for};
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::single_compress::compress_single;
use sediment_engine::tar_create::{TarCreateLimits, create_tar};
use sediment_engine::tar_read::{TarEntryKind, TarReadLimits, read_entries};
use sediment_engine::xz_decode::decode_xz;
use sediment_engine::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{ZipLimits, parse_entries};

fn build_all(spec: &[SpecEntry]) -> Vec<(&'static str, Vec<u8>)> {
    let entries: Vec<ArchiveEntry<'_>> = spec.iter().map(|e| e.archive_entry()).collect();
    let stored = create_zip(&entries, ZipCreateOptions { level: 0 }, ZipCreateLimits::default()).unwrap();
    let deflated = create_zip(&entries, ZipCreateOptions { level: 6 }, ZipCreateLimits::default()).unwrap();
    let tar = create_tar(&entries, TarCreateLimits::default()).unwrap();
    let tgz = compress(Compression::Gzip, &tar, 6, compress_bound(tar.len()).unwrap()).unwrap();
    let txz = compress(Compression::Xz, &tar, 6, compress_bound_for(Compression::Xz, tar.len()).unwrap()).unwrap();
    let tbz = compress(Compression::Bzip2, &tar, 9, compress_bound_for(Compression::Bzip2, tar.len()).unwrap()).unwrap();
    let mut v = vec![
        ("create_store.zip", stored.bytes),
        ("create_deflate.zip", deflated.bytes),
        ("create.tar", tar),
        ("create.tar.gz", tgz),
        ("create.tar.xz", txz),
        ("create.tar.bz2", tbz),
    ];
    for (name, kind, level) in SINGLES {
        let base = name.rsplit_once('.').unwrap().0;
        v.push((name, compress_single(kind, spec_payload(spec, base), level).unwrap()));
    }
    v
}

/// Committed single-file streams: (fixture name, format, -mx level). The name
/// minus its extension is the base name of a spec file entry.
const SINGLES: [(&str, Compression, u8); 7] = [
    ("text.txt.gz", Compression::Gzip, 9),
    ("text.txt.xz", Compression::Xz, 6),
    ("text.txt.bz2", Compression::Bzip2, 9),
    ("random.bin.xz", Compression::Xz, 9),
    ("zero.bin.gz", Compression::Gzip, 5),
    ("zero.bin.xz", Compression::Xz, 0),
    ("zero.bin.bz2", Compression::Bzip2, 1),
];

/// Payload of the unique spec file whose last path component is `base`.
fn spec_payload<'a>(spec: &'a [SpecEntry], base: &str) -> &'a [u8] {
    let hits: Vec<&SpecEntry> = spec
        .iter()
        .filter(|e| e.kind == EntryKind::File && e.name.rsplit(|&b| b == b'/').next() == Some(base.as_bytes()))
        .collect();
    assert_eq!(hits.len(), 1, "{base}");
    &hits[0].payload
}

fn decompress_any(name: &str, bytes: &[u8]) -> Vec<u8> {
    let n = 1 << 24;
    if name.ends_with(".gz") {
        decode_gzip(bytes, n, 100_000).unwrap()
    } else if name.ends_with(".xz") {
        decode_xz(bytes, 1 << 27, n).unwrap()
    } else if name.ends_with(".bz2") {
        decode_bzip2(bytes, n).unwrap()
    } else {
        bytes.to_vec()
    }
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
fn compressed_tars_and_singles_round_trip_through_sediment_readers() {
    let spec = load_spec();
    let built = build_all(&spec);
    let tar = built.iter().find(|(n, _)| *n == "create.tar").unwrap().1.clone();
    for (name, bytes) in built.iter().filter(|(n, _)| n.starts_with("create.tar.")) {
        let plain = decompress_any(name, bytes);
        assert_eq!(plain, tar, "{name}");
        assert!(bytes.len() < tar.len() / 3, "{name}: {}", bytes.len());
        // tar_read (independent of tar_create) reads the decompressed archive.
        let entries = read_entries(&plain, TarReadLimits::default()).unwrap();
        assert_eq!(entries.len(), spec.len(), "{name}");
        for (got, e) in entries.iter().zip(&spec) {
            assert_eq!(got.path, e.name);
            assert_eq!((got.mode, got.mtime), (e.mode, e.mtime));
            match e.kind {
                EntryKind::File => {
                    assert_eq!(got.kind, TarEntryKind::File);
                    assert_eq!(&plain[got.data_range.clone()], e.payload.as_slice());
                }
                EntryKind::Directory => assert_eq!(got.kind, TarEntryKind::Directory),
                EntryKind::Symlink => {
                    assert_eq!(got.kind, TarEntryKind::Symlink);
                    assert_eq!(got.link_target.as_deref(), Some(e.payload.as_slice()));
                }
            }
        }
    }
    for (name, _, _) in SINGLES {
        let bytes = &built.iter().find(|(n, _)| *n == name).unwrap().1;
        let base = name.rsplit_once('.').unwrap().0;
        assert_eq!(decompress_any(name, bytes), spec_payload(&spec, base), "{name}");
    }
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
    // Every -mx level of xz and bzip2 (all three bzip2 block sizes).
    for level in 0..=9u8 {
        for (kind, ext) in [(Compression::Xz, "txz"), (Compression::Bzip2, "tbz2")] {
            let c = compress(kind, &tar, level, compress_bound_for(kind, tar.len()).unwrap()).unwrap();
            std::fs::write(dir.path().join(format!("level{level}.{ext}")), c).unwrap();
        }
    }
    oracle_check(dir.path());
}
