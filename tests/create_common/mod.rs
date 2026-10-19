// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared helpers for archive-creation tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/create");
pub const ORACLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/gen/create.py");

#[derive(Debug, Clone)]
pub struct SpecEntry {
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime: i64,
    pub name: Vec<u8>,
    pub payload: Vec<u8>,
}

impl SpecEntry {
    pub fn archive_entry(&self) -> ArchiveEntry<'_> {
        let (data, link): (&[u8], &[u8]) = match self.kind {
            EntryKind::File => (&self.payload, &[]),
            EntryKind::Symlink => (&[], &self.payload),
            EntryKind::Directory => (&[], &[]),
        };
        ArchiveEntry {
            name: &self.name,
            kind: self.kind,
            data,
            mtime: self.mtime,
            mode: self.mode,
            link_target: link,
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn parse_spec(text: &str) -> Vec<SpecEntry> {
    text.lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 5, "bad spec line");
            SpecEntry {
                kind: match f[0] {
                    "F" => EntryKind::File,
                    "D" => EntryKind::Directory,
                    "L" => EntryKind::Symlink,
                    k => panic!("bad kind {k}"),
                },
                mode: u32::from_str_radix(f[1], 8).unwrap(),
                mtime: f[2].parse().unwrap(),
                name: unhex(f[3]),
                payload: unhex(f[4]),
            }
        })
        .collect()
}

pub fn write_spec(path: &Path, spec: &[SpecEntry]) {
    let mut s = String::new();
    for e in spec {
        let k = match e.kind {
            EntryKind::File => "F",
            EntryKind::Directory => "D",
            EntryKind::Symlink => "L",
        };
        s.push_str(&format!("{k}\t{:o}\t{}\t{}\t{}\n", e.mode, e.mtime, hex(&e.name), hex(&e.payload)));
    }
    std::fs::write(path, s).unwrap();
}

pub fn load_spec() -> Vec<SpecEntry> {
    parse_spec(&std::fs::read_to_string(format!("{FIXTURES}/spec.tsv")).unwrap())
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "sediment-test-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Restore permissions that tests may have removed, then delete.
        #[cfg(unix)]
        fn fix(p: &Path) {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::symlink_metadata(p)
                && m.is_dir()
            {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
                if let Ok(rd) = std::fs::read_dir(p) {
                    for e in rd.flatten() {
                        fix(&e.path());
                    }
                }
            }
        }
        #[cfg(unix)]
        fix(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `python3` if it is available (tests that need the oracle skip otherwise).
pub fn python() -> Option<&'static str> {
    Command::new("python3")
        .args(["-I", "-c", "import zipfile, tarfile, gzip, zlib, bz2, lzma"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "python3")
}

/// Run the oracle `check` on `dir`; panics with its output on failure.
pub fn oracle_check(dir: &Path) -> bool {
    let Some(py) = python() else {
        eprintln!("python3 not available; skipping oracle check");
        return false;
    };
    let out = Command::new(py).arg("-I").arg(ORACLE).arg("check").arg(dir).output().unwrap();
    assert!(
        out.status.success(),
        "oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarItem {
    pub name: Vec<u8>,
    pub typeflag: u8,
    pub mode: u32,
    pub mtime: i64,
    pub link: Vec<u8>,
    pub data: Vec<u8>,
}

fn octal(f: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in f {
        if (b'0'..=b'7').contains(&b) {
            v = v * 8 + (b - b'0') as u64;
        } else if b == 0 || b == b' ' {
            if v > 0 {
                break;
            }
        } else {
            panic!("bad octal");
        }
    }
    v
}

fn cstr(f: &[u8]) -> &[u8] {
    &f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())]
}

/// Minimal independent ustar+pax reader used to round-trip `tar_create` output.
pub fn read_tar(bytes: &[u8]) -> Vec<TarItem> {
    assert_eq!(bytes.len() % 512, 0);
    let mut out = Vec::new();
    let mut pos = 0;
    let mut pax: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    while pos + 512 <= bytes.len() {
        let h = &bytes[pos..pos + 512];
        if h.iter().all(|&b| b == 0) {
            assert!(bytes[pos..].iter().all(|&b| b == 0), "data after end marker");
            break;
        }
        let mut sum: u64 = 0;
        for (i, &b) in h.iter().enumerate() {
            sum += if (148..156).contains(&i) { 32 } else { b as u64 };
        }
        assert_eq!(sum, octal(&h[148..156]), "checksum");
        assert_eq!(&h[257..265], b"ustar\x0000");
        let size = octal(&h[124..136]) as usize;
        let typeflag = h[156];
        let dstart = pos + 512;
        let mut size_eff = size;
        if typeflag == b'x' {
            let rec = &bytes[dstart..dstart + size];
            let mut r = 0;
            while r < rec.len() {
                let sp = r + rec[r..].iter().position(|&b| b == b' ').unwrap();
                let len: usize = std::str::from_utf8(&rec[r..sp]).unwrap().parse().unwrap();
                let body = &rec[sp + 1..r + len - 1];
                assert_eq!(rec[r + len - 1], b'\n');
                let eq = body.iter().position(|&b| b == b'=').unwrap();
                pax.push((body[..eq].to_vec(), body[eq + 1..].to_vec()));
                r += len;
            }
            pos = dstart + size.div_ceil(512) * 512;
            continue;
        }
        let mut name = Vec::new();
        let prefix = cstr(&h[345..500]);
        if !prefix.is_empty() {
            name.extend_from_slice(prefix);
            name.push(b'/');
        }
        name.extend_from_slice(cstr(&h[0..100]));
        let mut link = cstr(&h[157..257]).to_vec();
        let mut mtime = octal(&h[136..148]) as i64;
        for (k, v) in pax.drain(..) {
            match k.as_slice() {
                b"path" => name = v,
                b"linkpath" => link = v,
                b"mtime" => mtime = std::str::from_utf8(&v).unwrap().parse().unwrap(),
                b"size" => size_eff = std::str::from_utf8(&v).unwrap().parse().unwrap(),
                _ => {}
            }
        }
        if name.last() == Some(&b'/') {
            name.pop();
        }
        let data = bytes[dstart..dstart + size_eff].to_vec();
        out.push(TarItem {
            name,
            typeflag,
            mode: octal(&h[100..108]) as u32,
            mtime,
            link,
            data,
        });
        pos = dstart + size_eff.div_ceil(512) * 512;
    }
    out
}
