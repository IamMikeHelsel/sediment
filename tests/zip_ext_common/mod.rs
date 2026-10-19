// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared helpers for the zip-ext tests: fixture loading, the oracle
//! manifest, and a tiny synthetic stored-ZIP builder for cases too large to
//! commit (more than 65535 entries) or deliberately hostile.
#![allow(dead_code)]

use std::path::PathBuf;

pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip_ext").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

pub const FIXTURES: &[&str] = &[
    "desc_nosig.zip",
    "encrypted.zip",
    "extras.zip",
    "prefixed.zip",
    "prefixed_zip64.zip",
    "stream_desc.zip",
    "stream_desc64.zip",
    "unicode_flag.zip",
    "zip64_eocd.zip",
    "zip64_forced.zip",
];

#[derive(Debug, Clone)]
pub struct ManifestRow {
    pub file: String,
    pub idx: usize,
    pub raw_name: Vec<u8>,
    pub name: Vec<u8>,
    pub file_size: u64,
    pub compress_size: u64,
    pub crc: u32,
    pub method: u16,
    pub flags: u16,
    pub header_offset: usize,
    /// (crc32, len) of the decoded content, None if Python could not read it.
    pub data: Option<(u32, usize)>,
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn manifest() -> Vec<ManifestRow> {
    let text = String::from_utf8(fixture("manifest.tsv")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 12, "bad manifest line {l}");
            ManifestRow {
                file: f[0].to_string(),
                idx: f[1].parse().unwrap(),
                raw_name: hex(f[2]),
                name: hex(f[3]),
                file_size: f[4].parse().unwrap(),
                compress_size: f[5].parse().unwrap(),
                crc: u32::from_str_radix(f[6], 16).unwrap(),
                method: f[7].parse().unwrap(),
                flags: f[8].parse().unwrap(),
                header_offset: f[9].parse().unwrap(),
                data: if f[10] == "-" {
                    None
                } else {
                    Some((u32::from_str_radix(f[10], 16).unwrap(), f[11].parse().unwrap()))
                },
            }
        })
        .collect()
}

pub fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
pub fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// How the synthetic builder ends the archive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    /// Classic EOCD with the 16-bit count truncated modulo 65536.
    Classic,
    /// ZIP64 record + locator + classic EOCD with saturated fields.
    Zip64,
}

/// Build a stored archive of `(name, data)` entries.
pub fn build_stored(entries: &[(Vec<u8>, Vec<u8>)], tail: Tail) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in entries {
        let off = out.len() as u32;
        let crc = sediment_engine::crc32::crc32(data);
        put32(&mut out, 0x04034b50);
        put16(&mut out, 10);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put32(&mut out, 0);
        put32(&mut out, crc);
        put32(&mut out, data.len() as u32);
        put32(&mut out, data.len() as u32);
        put16(&mut out, name.len() as u16);
        put16(&mut out, 0);
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        put32(&mut cd, 0x02014b50);
        put16(&mut cd, 0x031e);
        put16(&mut cd, 10);
        put16(&mut cd, 0);
        put16(&mut cd, 0);
        put32(&mut cd, 0);
        put32(&mut cd, crc);
        put32(&mut cd, data.len() as u32);
        put32(&mut cd, data.len() as u32);
        put16(&mut cd, name.len() as u16);
        put16(&mut cd, 0);
        put16(&mut cd, 0);
        put16(&mut cd, 0);
        put16(&mut cd, 0);
        put32(&mut cd, 0);
        put32(&mut cd, off);
        cd.extend_from_slice(name);
    }
    let cd_off = out.len() as u64;
    let cd_size = cd.len() as u64;
    out.extend_from_slice(&cd);
    let n = entries.len() as u64;
    match tail {
        Tail::Classic => {
            put32(&mut out, 0x06054b50);
            put16(&mut out, 0);
            put16(&mut out, 0);
            put16(&mut out, n as u16);
            put16(&mut out, n as u16);
            put32(&mut out, cd_size as u32);
            put32(&mut out, cd_off as u32);
            put16(&mut out, 0);
        }
        Tail::Zip64 => {
            let rec = out.len() as u64;
            put32(&mut out, 0x06064b50);
            put64(&mut out, 44);
            put16(&mut out, 0x032d);
            put16(&mut out, 45);
            put32(&mut out, 0);
            put32(&mut out, 0);
            put64(&mut out, n);
            put64(&mut out, n);
            put64(&mut out, cd_size);
            put64(&mut out, cd_off);
            put32(&mut out, 0x07064b50);
            put32(&mut out, 0);
            put64(&mut out, rec);
            put32(&mut out, 1);
            put32(&mut out, 0x06054b50);
            put16(&mut out, 0);
            put16(&mut out, 0);
            put16(&mut out, 0xffff);
            put16(&mut out, 0xffff);
            put32(&mut out, 0xffff_ffff);
            put32(&mut out, 0xffff_ffff);
            put16(&mut out, 0);
        }
    }
    out
}

/// Tiny deterministic PRNG for mutation tests.
pub struct Lcg(pub u64);
impl Lcg {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}
