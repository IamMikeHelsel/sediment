// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z structure layer tests.
//!
//! Fixtures:
//! - `fixtures/sevenz/gen/*.7z`: built by `tests/gen/sevenz.py` from the 7z
//!   format description (Copy method), each with a `*.slt.txt` listing made by
//!   the pinned 7-Zip 26.04 `7zz l -slt` oracle (which also passed `7zz t`).
//! - `fixtures/sevenz/oracle/*.7z`: made by the same pinned `7zz`
//!   (see `tests/gen/sevenz_oracle.sh`), with their `l -slt` listings.

use std::cell::RefCell;

use sediment_engine::crc32::crc32;
use sediment_engine::sevenz_header::{
    FolderDecoder, NoDecoder, SevenZLimits, SevenZReadError, method_id, parse_archive_header, parse_signature_header,
    read_number,
};
use sediment_engine::sevenz_read::{SevenZArchive, SevenZEntry, extract_entry, filetime_to_unix, list};

type E = SevenZReadError;

macro_rules! fx {
    ($p:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz/", $p)).as_slice()
    };
}
macro_rules! fxs {
    ($p:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz/", $p))
    };
}

fn lim() -> SevenZLimits {
    SevenZLimits::default()
}

// ---------------------------------------------------------------------------
// Oracle listing comparison
// ---------------------------------------------------------------------------

fn slt_items(s: &str) -> Vec<Vec<(String, String)>> {
    let body = s.split("\n----------\n").nth(1).expect("slt item section");
    body.split("\n\n")
        .filter(|b| !b.trim().is_empty())
        .map(|b| {
            b.lines()
                .filter_map(|l| l.split_once(" = ").or_else(|| l.strip_suffix(" =").map(|k| (k, ""))))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .collect()
}

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn fmt_time(ft: Option<u64>) -> String {
    let Some(ft) = ft else { return String::new() };
    let (secs, nanos) = filetime_to_unix(ft);
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let r = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}.{:07}", r / 3600, r / 60 % 60, r % 60, nanos / 100)
}

fn fmt_attr(e: &SevenZEntry) -> String {
    let Some(a) = e.attributes else { return String::new() };
    let mut s = String::new();
    for (bit, c) in [(0x1, 'R'), (0x2, 'H'), (0x4, 'S'), (0x10, 'D'), (0x20, 'A')] {
        if a & bit != 0 {
            s.push(c);
        }
    }
    if let Some(m) = e.unix_mode() {
        s.push(' ');
        s.push(match m & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            _ => '-',
        });
        for shift in [6, 3, 0] {
            let t = (m >> shift) & 7;
            s.push(if t & 4 != 0 { 'r' } else { '-' });
            s.push(if t & 2 != 0 { 'w' } else { '-' });
            s.push(if t & 1 != 0 { 'x' } else { '-' });
        }
    }
    s
}

fn fmt_method(ar: &SevenZArchive<'_>, e: &SevenZEntry) -> String {
    let Some(fi) = e.folder_index else { return String::new() };
    let f = &ar.folders()[fi];
    let names: Vec<String> = f
        .coders
        .iter()
        .map(|c| {
            let (name, dict) = match c.method_id.as_slice() {
                [0x00] => ("Copy", None),
                [0x03, 0x01, 0x01] => {
                    let p = &c.properties;
                    ("LZMA", Some(u32::from_le_bytes([p[1], p[2], p[3], p[4]]) as u64))
                }
                [0x21] => {
                    let p = c.properties[0] as u64;
                    ("LZMA2", Some((2 | (p & 1)) << (p / 2 + 11)))
                }
                _ => ("?", None),
            };
            match dict {
                Some(d) if d.is_power_of_two() => format!("{name}:{}", d.trailing_zeros()),
                Some(d) => format!("{name}:{d}"),
                None => name.to_string(),
            }
        })
        .collect();
    names.join(" ")
}

/// Compare our listing against a `7zz l -slt` listing, field by field.
fn assert_matches_oracle(bytes: &[u8], slt: &str) -> Vec<SevenZEntry> {
    let ar = SevenZArchive::open(bytes, &NoDecoder, lim()).expect("open");
    let items = slt_items(slt);
    assert_eq!(items.len(), ar.entries().len(), "entry count");
    for (e, item) in ar.entries().iter().zip(&items) {
        for (k, v) in item {
            let ours = match k.as_str() {
                "Path" => e.name.clone(),
                "Size" => e.size.to_string(),
                "Modified" => fmt_time(e.mtime),
                "Created" => fmt_time(e.ctime),
                "Accessed" => fmt_time(e.atime),
                "Attributes" => fmt_attr(e),
                "CRC" => e.crc.map(|c| format!("{c:08X}")).unwrap_or_default(),
                "Block" => e.folder_index.map(|f| f.to_string()).unwrap_or_default(),
                "Method" => fmt_method(&ar, e),
                "Encrypted" => "-".to_string(),
                _ => continue, // Packed Size: archive-level accounting, not compared
            };
            assert_eq!(&ours, v, "field {k} of {}", e.name);
        }
        assert_eq!(e.is_dir, item.iter().any(|(k, v)| k == "Attributes" && v.starts_with('D')), "{}", e.name);
    }
    ar.entries().to_vec()
}

// ---------------------------------------------------------------------------
// Expected contents
// ---------------------------------------------------------------------------

fn gen_contents(name: &str) -> Option<Vec<u8>> {
    Some(match name {
        "hello.txt" | "one.txt" => b"Hello, 7z!\n".to_vec(),
        "a.txt" | "two.txt" => (0..40).map(|i| format!("alpha line {i}\n")).collect::<String>().into_bytes(),
        "b.bin" | "three.bin" => (0..300u32).map(|i| ((i * 31 + 7) & 0xff) as u8).collect(),
        "dir/h\u{e9}llo_\u{65e5}\u{672c}.txt" => b"unicode name\n".to_vec(),
        "\u{1F600}.txt" => "\u{1F600} smile\n".as_bytes().to_vec(),
        "d.txt" => b"standalone folder\n".to_vec(),
        "empty.txt" | "dir" | "dir/sub" => Vec::new(),
        _ => return None,
    })
}

fn oracle_contents(name: &str) -> Option<Vec<u8>> {
    Some(match name {
        "hello.txt" => b"Hello, 7z!\n".to_vec(),
        "a.txt" => (0..60).map(|i| format!("line {i:04} alpha beta gamma\n")).collect::<String>().into_bytes(),
        "b.bin" => (0..700u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect(),
        "h\u{e9}llo_\u{65e5}\u{672c}.txt" => b"unicode name\n".to_vec(),
        "dir/sub/nested.txt" => b"nested\n".to_vec(),
        "empty.txt" | "dir" | "dir/sub" | "emptydir" => Vec::new(),
        _ => return None,
    })
}

fn extract_all_and_check(bytes: &[u8], expect: fn(&str) -> Option<Vec<u8>>) -> usize {
    let ar = SevenZArchive::open(bytes, &NoDecoder, lim()).unwrap();
    for e in ar.entries() {
        let got = ar.extract_entry(e.index, &NoDecoder).unwrap();
        assert_eq!(got, expect(&e.name).unwrap_or_else(|| panic!("unexpected {}", e.name)), "{}", e.name);
        assert_eq!(got.len() as u64, e.size);
        if let Some(c) = e.crc {
            assert_eq!(crc32(&got), c);
        }
        // Free-function path agrees.
        assert_eq!(extract_entry(bytes, e.index, &NoDecoder, lim()).unwrap(), got);
    }
    ar.entries().len()
}

// ---------------------------------------------------------------------------
// Positive: generated Copy fixtures
// ---------------------------------------------------------------------------

#[test]
fn gen_fixtures_match_oracle_listing() {
    assert_matches_oracle(fx!("gen/single.7z"), fxs!("gen/single.slt.txt"));
    assert_matches_oracle(fx!("gen/solid.7z"), fxs!("gen/solid.slt.txt"));
    assert_matches_oracle(fx!("gen/nonsolid_no_substreams.7z"), fxs!("gen/nonsolid_no_substreams.slt.txt"));
    assert_matches_oracle(fx!("gen/encoded_header.7z"), fxs!("gen/encoded_header.slt.txt"));
    assert_matches_oracle(fx!("gen/chain.7z"), fxs!("gen/chain.slt.txt"));
}

#[test]
fn gen_fixtures_extract() {
    assert_eq!(extract_all_and_check(fx!("gen/single.7z"), gen_contents), 1);
    assert_eq!(extract_all_and_check(fx!("gen/solid.7z"), gen_contents), 8);
    assert_eq!(extract_all_and_check(fx!("gen/nonsolid_no_substreams.7z"), gen_contents), 3);
    assert_eq!(extract_all_and_check(fx!("gen/encoded_header.7z"), gen_contents), 2);
    assert_eq!(extract_all_and_check(fx!("gen/chain.7z"), gen_contents), 1);
}

#[test]
fn single_entry_details() {
    let es = list(fx!("gen/single.7z"), &NoDecoder, lim()).unwrap();
    let e = &es[0];
    assert_eq!(e.name, "hello.txt");
    assert!(e.has_stream && !e.is_dir && !e.is_anti);
    assert_eq!(e.unix_mode(), Some(0o100640));
    assert!(!e.has_dir_attribute());
    assert_eq!(filetime_to_unix(e.mtime.unwrap()), (1_700_000_000, 123_456_700));
    assert_eq!((e.ctime, e.atime), (None, None));
    assert_eq!((e.folder_index, e.index_in_folder, e.stream_index), (Some(0), Some(0), Some(0)));
}

#[test]
fn solid_folder_splits_substreams() {
    let bytes = fx!("gen/solid.7z");
    let ar = SevenZArchive::open(bytes, &NoDecoder, lim()).unwrap();
    assert_eq!(ar.folders().len(), 2);
    assert_eq!(ar.header().main_streams.substreams.num_unpack_streams, vec![4, 1]);
    let es = ar.entries();
    let mapping: Vec<_> = es.iter().map(|e| (e.folder_index, e.index_in_folder, e.stream_index)).collect();
    assert_eq!(
        mapping,
        vec![
            (None, None, None),
            (None, None, None),
            (None, None, None),
            (Some(0), Some(0), Some(0)),
            (Some(0), Some(1), Some(1)),
            (Some(0), Some(2), Some(2)),
            (Some(0), Some(3), Some(3)),
            (Some(1), Some(0), Some(4)),
        ]
    );
    assert!(es[0].is_dir && es[1].is_dir && !es[2].is_dir && !es[2].has_stream);
    assert_eq!(es[1].unix_mode(), Some(0o040700));
    assert!(es[1].has_dir_attribute());
    assert_eq!(es[4].attributes, None);
    let parts = ar.extract_folder(0, &NoDecoder).unwrap();
    assert_eq!(parts.len(), 4);
    for (p, e) in parts.iter().zip(&es[3..7]) {
        assert_eq!(Some(p.clone()), gen_contents(&e.name));
    }
    assert_eq!(ar.extract_folder(1, &NoDecoder).unwrap(), vec![b"standalone folder\n".to_vec()]);
    assert_eq!(ar.extract_folder(2, &NoDecoder), Err(E::IndexOutOfRange));
    assert_eq!(ar.extract_entry(99, &NoDecoder), Err(E::IndexOutOfRange));
}

#[test]
fn empty_archive() {
    let b = fx!("gen/empty.7z");
    assert!(list(b, &NoDecoder, lim()).unwrap().is_empty());
    assert!(fxs!("gen/empty.slt.txt").contains("Physical Size = 32"));
}

#[test]
fn signature_header_fields() {
    let s = parse_signature_header(fx!("gen/nonsolid_no_substreams.7z")).unwrap();
    assert_eq!((s.major_version, s.minor_version), (0, 3));
    let s = parse_signature_header(fx!("oracle/copy_solid_nohc.7z")).unwrap();
    assert_eq!((s.major_version, s.minor_version), (0, 4));
    assert_eq!(s.next_header_offset + s.next_header_size + 32, fx!("oracle/copy_solid_nohc.7z").len() as u64);
}

// ---------------------------------------------------------------------------
// Positive: 7zz-made fixtures
// ---------------------------------------------------------------------------

#[test]
fn oracle_copy_archives_list_and_extract() {
    for (b, s) in [
        (fx!("oracle/copy_solid_nohc.7z"), fxs!("oracle/copy_solid_nohc.slt.txt")),
        (fx!("oracle/copy_nonsolid_nohc.7z"), fxs!("oracle/copy_nonsolid_nohc.slt.txt")),
    ] {
        let es = assert_matches_oracle(b, s);
        assert_eq!(es.len(), 9);
        assert_eq!(extract_all_and_check(b, oracle_contents), 9);
    }
}

#[test]
fn oracle_lzma_archives_list() {
    for (b, s, id, nfolders) in [
        (fx!("oracle/lzma_solid_nohc.7z"), fxs!("oracle/lzma_solid_nohc.slt.txt"), method_id::LZMA, 1),
        (fx!("oracle/lzma_nonsolid_nohc.7z"), fxs!("oracle/lzma_nonsolid_nohc.slt.txt"), method_id::LZMA, 5),
        (fx!("oracle/lzma2_nonsolid_nohc.7z"), fxs!("oracle/lzma2_nonsolid_nohc.slt.txt"), method_id::LZMA2, 5),
    ] {
        let es = assert_matches_oracle(b, s);
        assert_eq!(es.len(), 9);
        let ar = SevenZArchive::open(b, &NoDecoder, lim()).unwrap();
        assert_eq!(ar.folders().len(), nfolders);
        assert!(ar.folders().iter().all(|f| f.coders.len() == 1 && f.coders[0].method_id == id));
        // Without a codec, streamed entries report UnsupportedMethod; empty ones still work.
        for e in ar.entries() {
            let r = ar.extract_entry(e.index, &NoDecoder);
            if e.has_stream {
                assert_eq!(r, Err(E::UnsupportedMethod));
            } else {
                assert_eq!(r, Ok(Vec::new()));
            }
        }
    }
}

/// Records every decode request and fails it.
type Call = (Vec<u8>, Vec<u8>, usize, u64);
struct Recorder(RefCell<Vec<Call>>);
impl FolderDecoder for Recorder {
    fn decode(&self, m: &[u8], p: &[u8], i: &[u8], n: u64) -> Result<Vec<u8>, SevenZReadError> {
        self.0.borrow_mut().push((m.to_vec(), p.to_vec(), i.len(), n));
        Err(E::DecoderFailed)
    }
}

#[test]
fn oracle_encoded_headers_route_through_decoder() {
    for (b, slt) in [
        (fx!("oracle/lzma_solid_hc.7z"), fxs!("oracle/lzma_solid_hc.slt.txt")),
        (fx!("oracle/lzma2_solid_hc.7z"), fxs!("oracle/lzma2_solid_hc.slt.txt")),
        (fx!("oracle/copy_solid_hc_times.7z"), fxs!("oracle/copy_solid_hc_times.slt.txt")),
    ] {
        assert_eq!(list(b, &NoDecoder, lim()), Err(E::UnsupportedMethod));
        let r = Recorder(RefCell::new(Vec::new()));
        assert_eq!(SevenZArchive::open(b, &r, lim()).err(), Some(E::DecoderFailed));
        let calls = r.0.into_inner();
        assert_eq!(calls.len(), 1);
        let (m, p, inlen, n) = &calls[0];
        assert_eq!(m.as_slice(), method_id::LZMA, "headers are LZMA-coded");
        assert_eq!(p.len(), 5);
        assert!(*inlen > 0);
        // The decoded header is larger than its packed form and below the oracle's header total.
        let hs: u64 = slt.lines().find_map(|l| l.strip_prefix("Headers Size = ")).unwrap().parse().unwrap();
        assert!(*n > 0 && *n < 4096 && hs > 0);
    }
}

// ---------------------------------------------------------------------------
// Pluggable decoder
// ---------------------------------------------------------------------------

/// Toy method 0x7F: XOR every byte with props[0].
struct Xor;
impl FolderDecoder for Xor {
    fn decode(&self, m: &[u8], p: &[u8], i: &[u8], n: u64) -> Result<Vec<u8>, SevenZReadError> {
        if m != [0x7f] {
            return Err(E::UnsupportedMethod);
        }
        let k = *p.first().ok_or(E::DecoderFailed)?;
        if i.len() as u64 != n {
            return Err(E::DecoderFailed);
        }
        Ok(i.iter().map(|b| b ^ k).collect())
    }
}

fn num(v: u64) -> Vec<u8> {
    for i in 0..8u32 {
        if v < 1u64 << (8 * i + 7 - i) {
            let first = ((0xffu32 << (8 - i)) as u8) | (v >> (8 * i)) as u8;
            let mut out = vec![first];
            out.extend_from_slice(&v.to_le_bytes()[..i as usize]);
            return out;
        }
    }
    let mut out = vec![0xff];
    out.extend_from_slice(&v.to_le_bytes());
    out
}

fn wrap(body: &[u8], header: &[u8]) -> Vec<u8> {
    let mut start = Vec::new();
    start.extend_from_slice(&(body.len() as u64).to_le_bytes());
    start.extend_from_slice(&(header.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32(header).to_le_bytes());
    let mut out = vec![0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4];
    out.extend_from_slice(&crc32(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(body);
    out.extend_from_slice(header);
    out
}

/// Build a one-file archive with a single coder `coder` (raw folder record
/// bytes after NumCoders) and the given packed body.
fn one_file(coder: &[u8], body: &[u8], unpack: u64, crc: Option<u32>, name: &str) -> Vec<u8> {
    let mut h = vec![0x01, 0x04, 0x06];
    h.extend(num(0));
    h.extend(num(1));
    h.push(0x09);
    h.extend(num(body.len() as u64));
    h.extend([0x00, 0x07, 0x0b]);
    h.extend(num(1));
    h.push(0x00);
    h.extend(num(1));
    h.extend_from_slice(coder);
    h.push(0x0c);
    h.extend(num(unpack));
    if let Some(c) = crc {
        h.extend([0x0a, 0x01]);
        h.extend(c.to_le_bytes());
    }
    h.extend([0x00, 0x00, 0x05]);
    h.extend(num(1));
    let mut names = vec![0u8];
    for u in name.encode_utf16() {
        names.extend(u.to_le_bytes());
    }
    names.extend([0, 0]);
    h.push(0x11);
    h.extend(num(names.len() as u64));
    h.extend(names);
    h.extend([0x00, 0x00]);
    wrap(body, &h)
}

#[test]
fn custom_decoder_plugs_in() {
    let plain = b"plugged codec output";
    let packed: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
    // flags 0x21: id size 1 + has properties; id 7F; 1 prop byte 5A
    let a = one_file(&[0x21, 0x7f, 0x01, 0x5a], &packed, plain.len() as u64, Some(crc32(plain)), "x.bin");
    assert_eq!(extract_entry(&a, 0, &Xor, lim()).unwrap(), plain);
    assert_eq!(extract_entry(&a, 0, &NoDecoder, lim()), Err(E::UnsupportedMethod));
    // Wrong folder CRC is caught after decoding.
    let a = one_file(&[0x21, 0x7f, 0x01, 0x5a], &packed, plain.len() as u64, Some(crc32(plain) ^ 1), "x.bin");
    assert_eq!(extract_entry(&a, 0, &Xor, lim()), Err(E::DataChecksum));
    // Decoder output of the wrong size is rejected.
    let a = one_file(&[0x21, 0x7f, 0x01, 0x5a], &packed, plain.len() as u64 + 1, None, "x.bin");
    assert_eq!(extract_entry(&a, 0, &Xor, lim()), Err(E::DecoderFailed));
}

// ---------------------------------------------------------------------------
// NUMBER encoding
// ---------------------------------------------------------------------------

#[test]
fn number_boundaries() {
    for v in [0u64, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1f_ffff, 0x20_0000, u32::MAX as u64, 1 << 56, u64::MAX - 1, u64::MAX] {
        let enc = num(v);
        assert_eq!(read_number(&enc), Ok((v, enc.len())), "{v:#x}");
        for cut in 0..enc.len() {
            assert_eq!(read_number(&enc[..cut]), Err(E::UnexpectedEof));
        }
    }
    assert_eq!(read_number(&[0x7f, 0xaa]), Ok((0x7f, 1)));
    assert_eq!(read_number(&[0x81, 0x02]), Ok((0x102, 2)));
    assert_eq!(read_number(&[0xfe, 1, 2, 3, 4, 5, 6, 7]), Ok((0x0007_0605_0403_0201, 8)));
}

// ---------------------------------------------------------------------------
// Malformed / hostile input
// ---------------------------------------------------------------------------

fn all_fixtures() -> Vec<&'static [u8]> {
    vec![
        fx!("gen/single.7z"),
        fx!("gen/solid.7z"),
        fx!("gen/nonsolid_no_substreams.7z"),
        fx!("gen/encoded_header.7z"),
        fx!("gen/chain.7z"),
        fx!("oracle/copy_solid_nohc.7z"),
        fx!("oracle/copy_nonsolid_nohc.7z"),
        fx!("oracle/lzma_solid_nohc.7z"),
        fx!("oracle/lzma_solid_hc.7z"),
        fx!("oracle/lzma2_solid_hc.7z"),
    ]
}

fn exercise(bytes: &[u8]) -> Result<(), E> {
    let ar = SevenZArchive::open(bytes, &NoDecoder, lim())?;
    for i in 0..ar.entries().len() {
        let _ = ar.extract_entry(i, &NoDecoder);
    }
    for f in 0..ar.folders().len() {
        let _ = ar.extract_folder(f, &NoDecoder);
    }
    Ok(())
}

#[test]
fn every_truncation_is_an_error() {
    for f in all_fixtures() {
        for cut in 0..f.len() {
            assert!(SevenZArchive::open(&f[..cut], &NoDecoder, lim()).is_err(), "cut {cut}");
        }
    }
}

/// Recompute the next-header CRC and the start-header CRC.
fn refix(a: &mut [u8]) {
    let off = u64::from_le_bytes(a[12..20].try_into().unwrap()).saturating_add(32) as usize;
    let size = u64::from_le_bytes(a[20..28].try_into().unwrap()) as usize;
    if let Some(h) = a.get(off..off.saturating_add(size)) {
        let c = crc32(h);
        a[28..32].copy_from_slice(&c.to_le_bytes());
    }
    let c = crc32(&a[12..32]);
    a[8..12].copy_from_slice(&c.to_le_bytes());
}

#[test]
fn header_mutations_never_panic() {
    for f in all_fixtures() {
        let off = u64::from_le_bytes(f[12..20].try_into().unwrap()) as usize + 32;
        for pos in off..f.len() {
            for val in [0x00u8, 0xff, f[pos] ^ 0x01] {
                let mut m = f.to_vec();
                m[pos] = val;
                refix(&mut m);
                let _ = exercise(&m);
            }
        }
    }
}

#[test]
fn checksum_and_signature_errors() {
    let good = fx!("gen/single.7z");
    let mut m = good.to_vec();
    m[0] = b'8';
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::InvalidSignature));
    let mut m = good.to_vec();
    m[6] = 1;
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::UnsupportedVersion));
    let mut m = good.to_vec();
    m[13] ^= 1;
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::StartHeaderChecksum));
    let mut m = good.to_vec();
    let last = m.len() - 1;
    m[last] ^= 1;
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::HeaderChecksum));
    // Next header pointing past the end.
    let mut m = good.to_vec();
    m[12] = 0xf0;
    refix(&mut m);
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::UnexpectedEof));
    let mut m = good.to_vec();
    m[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    refix(&mut m);
    assert_eq!(list(&m, &NoDecoder, lim()), Err(E::UnexpectedEof));
    assert_eq!(list(&good[..10], &NoDecoder, lim()), Err(E::UnexpectedEof));
}

#[test]
fn data_corruption_detected() {
    // single.7z: data byte at offset 32; CRC lives in SubStreamsInfo.
    let mut m = fx!("gen/single.7z").to_vec();
    m[32] ^= 0x20;
    assert_eq!(extract_entry(&m, 0, &NoDecoder, lim()), Err(E::DataChecksum));
    // solid.7z has pack-stream CRCs, checked before decoding.
    let mut m = fx!("gen/solid.7z").to_vec();
    m[40] ^= 0x20;
    assert_eq!(extract_entry(&m, 3, &NoDecoder, lim()), Err(E::PackChecksum));
    // nonsolid: folder CRC in UnpackInfo only.
    let mut m = fx!("gen/nonsolid_no_substreams.7z").to_vec();
    m[33] ^= 0x20;
    assert_eq!(extract_entry(&m, 0, &NoDecoder, lim()), Err(E::DataChecksum));
    assert_eq!(extract_entry(&m, 1, &NoDecoder, lim()).unwrap(), gen_contents("two.txt").unwrap());
    // 7zz-made solid copy archive.
    let mut m = fx!("oracle/copy_solid_nohc.7z").to_vec();
    m[32] ^= 0x20;
    let es = list(&m, &NoDecoder, lim()).unwrap();
    let hits = es.iter().filter(|e| extract_entry(&m, e.index, &NoDecoder, lim()) == Err(E::DataChecksum)).count();
    assert_eq!(hits, 1);
}

#[test]
fn tight_limits_are_enforced() {
    let solid = fx!("gen/solid.7z");
    let l = SevenZLimits { max_files: 7, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_header_bytes: 100, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_substreams: 4, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_name_units: 20, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_archive_bytes: 1000, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_folders: 1, ..lim() };
    assert_eq!(list(solid, &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_unpack_bytes: 100, ..lim() };
    let ar = SevenZArchive::open(solid, &NoDecoder, l).unwrap();
    assert_eq!(ar.extract_entry(3, &NoDecoder), Err(E::LimitExceeded));
    assert_eq!(ar.extract_entry(7, &NoDecoder).unwrap(), b"standalone folder\n");
    let l = SevenZLimits { max_header_nesting: 0, ..lim() };
    assert_eq!(list(fx!("gen/encoded_header.7z"), &NoDecoder, l), Err(E::LimitExceeded));
    let l = SevenZLimits { max_coders_per_folder: 1, ..lim() };
    assert_eq!(list(fx!("gen/chain.7z"), &NoDecoder, l), Err(E::LimitExceeded));
}

fn copy_coder() -> Vec<u8> {
    vec![0x01, 0x00]
}

#[test]
fn hostile_counts_and_sizes() {
    // Absurd file count.
    let mut h = vec![0x01, 0x05];
    h.extend(num(u64::MAX));
    h.extend([0, 0]);
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::LimitExceeded));
    // File count within limits but no data behind it.
    let mut h = vec![0x01, 0x05];
    h.extend(num(1 << 19));
    h.extend([0, 0]);
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::UnexpectedEof));
    // Absurd pack-stream count.
    let mut h = vec![0x01, 0x04, 0x06, 0x00];
    h.extend(num(1 << 40));
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::LimitExceeded));
    // Absurd folder count.
    let mut h = vec![0x01, 0x04, 0x07, 0x0b];
    h.extend(num(1 << 40));
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::LimitExceeded));
    // Unpack size far beyond the data with Copy.
    let a = one_file(&copy_coder(), b"abc", 1 << 62, None, "big");
    assert_eq!(extract_entry(&a, 0, &NoDecoder, lim()), Err(E::LimitExceeded));
    let a = one_file(&copy_coder(), b"abc", 4, None, "big");
    assert_eq!(extract_entry(&a, 0, &NoDecoder, lim()), Err(E::SizeMismatch));
    // Pack size beyond the archive.
    let mut a = one_file(&copy_coder(), b"abc", 3, None, "x");
    let hdr_off = 32 + 3;
    assert_eq!(a[hdr_off + 6], 0x03); // kSize value
    a[hdr_off + 6] = 0x7f;
    refix(&mut a);
    assert_eq!(extract_entry(&a, 0, &NoDecoder, lim()), Err(E::UnexpectedEof));
}

#[test]
fn hostile_structures() {
    // Alternative-methods bit.
    let a = one_file(&[0x81, 0x00], b"abc", 3, None, "x");
    assert_eq!(list(&a, &NoDecoder, lim()), Err(E::Unsupported));
    // Complex coder with 2 in streams: packed stream count mismatch.
    let a = one_file(&[0x11, 0x00, 0x02, 0x01, 0x00, 0x01], b"abc", 3, None, "x");
    assert!(list(&a, &NoDecoder, lim()).is_err());
    // Zero out streams.
    let a = one_file(&[0x11, 0x00, 0x01, 0x00], b"abc", 3, None, "x");
    assert_eq!(list(&a, &NoDecoder, lim()), Err(E::Malformed));
    // Unpaired surrogate in the name.
    let mut a = one_file(&copy_coder(), b"abc", 3, None, "x");
    let pos = a.windows(4).rposition(|w| w == [b'x', 0, 0, 0]).unwrap();
    a[pos] = 0x00;
    a[pos + 1] = 0xd8;
    refix(&mut a);
    assert_eq!(list(&a, &NoDecoder, lim()), Err(E::InvalidName));
    // Self-referencing encoded header: decodes to itself forever.
    let mut l = 20u64;
    let e = loop {
        let mut e = vec![0x17, 0x06];
        e.extend(num(0));
        e.extend(num(1));
        e.push(0x09);
        e.extend(num(l));
        e.extend([0x00, 0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c]);
        e.extend(num(l));
        e.extend([0x00, 0x00]);
        if e.len() as u64 == l {
            break e;
        }
        l = e.len() as u64;
    };
    let a = wrap(&e, &e);
    assert_eq!(list(&a, &NoDecoder, lim()), Err(E::LimitExceeded));
    // Substream sizes larger than the folder.
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x03, 0x00, 0x07, 0x0b, 0x01, 0x00];
    h.extend([0x01, 0x01, 0x00, 0x0c, 0x03, 0x00]);
    h.extend([0x08, 0x0d, 0x02, 0x09, 0x05, 0x00, 0x00]);
    assert_eq!(list(&wrap(b"abc", &h), &NoDecoder, lim()), Err(E::Malformed));
    // Files with streams but no streams info.
    let mut h = vec![0x01, 0x05, 0x01, 0x11, 0x05, 0x00, b'x', 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::Malformed));
    // ...which becomes fine when the file is marked as an empty stream.
    h.splice(3..3, [0x0e, 0x01, 0x80]);
    let es = list(&wrap(&[], &h), &NoDecoder, lim()).unwrap();
    assert!(es[0].is_dir && !es[0].has_stream);
    // Duplicate property.
    let mut h = vec![0x01, 0x05, 0x01, 0x0e, 0x01, 0x80, 0x0e, 0x01, 0x80];
    h.extend([0x11, 0x05, 0x00, b'x', 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(list(&wrap(&[], &h), &NoDecoder, lim()), Err(E::Malformed));
    // Unknown top-level property / garbage.
    assert_eq!(list(&wrap(&[], &[0x01, 0x42]), &NoDecoder, lim()), Err(E::Malformed));
    assert_eq!(list(&wrap(&[], &[0x99]), &NoDecoder, lim()), Err(E::Malformed));
    assert_eq!(list(&wrap(&[], &[0x01, 0x03]), &NoDecoder, lim()), Err(E::Unsupported));
}

#[test]
fn parse_archive_header_direct() {
    let h = parse_archive_header(fx!("gen/encoded_header.7z"), &NoDecoder, &lim()).unwrap();
    assert_eq!(h.files.len(), 2);
    assert_eq!(h.main_streams.folders.len(), 1);
    assert_eq!(h.main_streams.folders[0].unpack_size(), 11 + 550);
    assert_eq!(h.main_streams.substreams.sizes, vec![11, 550]);
    let h = parse_archive_header(fx!("gen/chain.7z"), &NoDecoder, &lim()).unwrap();
    let f = &h.main_streams.folders[0];
    assert_eq!(f.coders.len(), 2);
    assert_eq!(f.bind_pairs.len(), 1);
    assert_eq!(f.packed_streams, vec![1]);
    assert_eq!(f.main_out_index(), Some(0));
}
