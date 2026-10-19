// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for filter_bcj, filter_delta and filter_swap. Oracle fixtures are
//! produced by tests/gen/filters.py (liblzma via Python's lzma / xz).

use sediment_engine::filter_bcj::*;
use sediment_engine::filter_delta::*;
use sediment_engine::filter_swap::*;
use std::path::PathBuf;

const BIG: usize = 1 << 30;

fn fixture_dir() -> PathBuf {
    // Optional override to run the same checks against a large stress set
    // (`python3 tests/gen/filters.py --stress DIR N`).
    if let Some(dir) = std::env::var_os("SEDIMENT_FILTER_FIXTURES") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/filters")
}

struct Case {
    name: String,
    kind: String,
    param: u64,
    input: Vec<u8>,
    output: Vec<u8>,
}

fn load_cases() -> Vec<Case> {
    let dir = fixture_dir();
    let manifest = std::fs::read_to_string(dir.join("manifest.txt")).expect("manifest");
    let mut cases = Vec::new();
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 3, "bad manifest line {line}");
        let name = parts[0].to_string();
        cases.push(Case {
            input: std::fs::read(dir.join(format!("{name}.in"))).unwrap(),
            output: std::fs::read(dir.join(format!("{name}.out"))).unwrap(),
            kind: parts[1].to_string(),
            param: parts[2].parse().unwrap(),
            name,
        });
    }
    cases
}

fn arch_by_name(s: &str) -> BcjArch {
    match s {
        "x86" => BcjArch::X86,
        "powerpc" => BcjArch::PowerPc,
        "ia64" => BcjArch::Ia64,
        "arm" => BcjArch::Arm,
        "armthumb" => BcjArch::ArmThumb,
        "sparc" => BcjArch::Sparc,
        "arm64" => BcjArch::Arm64,
        "riscv" => BcjArch::RiscV,
        _ => panic!("unknown arch {s}"),
    }
}

/// xorshift64* so tests are deterministic without dependencies.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn stream_bcj(arch: BcjArch, start: u32, input: &[u8], encoding: bool, chunks: &[usize]) -> Vec<u8> {
    let mut s = BcjStream::new(arch, start, encoding, BIG).unwrap();
    let mut out = Vec::new();
    let mut pos = 0;
    let mut k = 0;
    while pos < input.len() {
        let n = chunks[k % chunks.len()].min(input.len() - pos);
        s.update(&input[pos..pos + n], &mut out).unwrap();
        pos += n;
        k += 1;
    }
    s.finish(&mut out).unwrap();
    assert_eq!(s.total_out(), input.len());
    out
}

#[test]
fn fixtures_present_for_every_filter() {
    let cases = load_cases();
    for arch in ["x86", "powerpc", "ia64", "arm", "armthumb", "sparc", "arm64", "riscv"] {
        let kind = format!("bcj:{arch}");
        assert!(cases.iter().filter(|c| c.kind == kind).count() >= 3, "no fixtures for {arch}");
    }
    assert!(cases.iter().filter(|c| c.kind == "delta").count() >= 4);
}

#[test]
fn bcj_matches_liblzma_encoder() {
    for c in load_cases().iter().filter(|c| c.kind.starts_with("bcj:")) {
        let arch = arch_by_name(&c.kind[4..]);
        let start = c.param as u32;
        let enc = bcj_encode(arch, start, &c.input, BIG).unwrap();
        assert!(enc == c.output, "encode mismatch for {}", c.name);
    }
}

#[test]
fn bcj_decoder_inverts_liblzma_output() {
    for c in load_cases().iter().filter(|c| c.kind.starts_with("bcj:")) {
        let arch = arch_by_name(&c.kind[4..]);
        let dec = bcj_decode(arch, c.param as u32, &c.output, BIG).unwrap();
        assert!(dec == c.input, "decode mismatch for {}", c.name);
    }
}

#[test]
fn bcj_fixtures_actually_convert_something() {
    // Guards against fixtures that only exercise the pass-through path.
    for c in load_cases().iter().filter(|c| c.kind.starts_with("bcj:") && c.input.len() > 1000) {
        let differing = c.input.iter().zip(&c.output).filter(|(a, b)| a != b).count();
        assert!(differing > 50, "{} barely converts ({differing} bytes)", c.name);
    }
}

#[test]
fn bcj_streaming_matches_one_shot() {
    let chunk_patterns: [&[usize]; 5] = [&[1], &[2, 3], &[5, 1, 7], &[16], &[13, 64, 1, 2]];
    for c in load_cases().iter().filter(|c| c.kind.starts_with("bcj:")) {
        let arch = arch_by_name(&c.kind[4..]);
        let start = c.param as u32;
        for pat in chunk_patterns {
            assert!(stream_bcj(arch, start, &c.input, true, pat) == c.output, "stream encode {} {:?}", c.name, pat);
            assert!(stream_bcj(arch, start, &c.output, false, pat) == c.input, "stream decode {} {:?}", c.name, pat);
        }
    }
}

#[test]
fn bcj_low_level_coder_contract() {
    for c in load_cases().iter().filter(|c| c.kind.starts_with("bcj:") && c.input.len() > 1000) {
        let arch = arch_by_name(&c.kind[4..]);
        let mut coder = BcjCoder::new(arch, c.param as u32, true).unwrap();
        let mut buf = c.input.clone();
        let done = coder.convert(&mut buf);
        assert!(buf.len() - done <= arch.max_lookahead(), "{}", c.name);
        assert_eq!(coder.position(), (c.param as u32).wrapping_add(done as u32));
        assert!(buf == c.output);
        let mut buf2 = c.input.clone();
        bcj_convert_in_place(arch, c.param as u32, &mut buf2, true).unwrap();
        assert!(buf2 == c.output);
    }
}

#[test]
fn bcj_random_roundtrip_and_no_panic() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for arch in BcjArch::ALL {
        for round in 0..40 {
            let len = rng.below(600);
            let data = rng.bytes(len);
            let align = arch.alignment() as u64;
            let start = ((rng.next() as u32) as u64 / align * align) as u32;
            let start = if round % 4 == 0 { 0 } else { start };
            let enc = bcj_encode(arch, start, &data, BIG).unwrap();
            assert_eq!(enc.len(), data.len());
            let dec = bcj_decode(arch, start, &enc, BIG).unwrap();
            assert!(dec == data, "{arch:?} roundtrip failed (len {len}, start {start:#x})");
            // Decoding arbitrary data must not panic either.
            let junk = bcj_decode(arch, start, &data, BIG).unwrap();
            assert_eq!(junk.len(), data.len());
        }
    }
}

#[test]
fn bcj_roundtrip_dense_patterns() {
    // Inputs made of the trigger bytes themselves stress the edge paths.
    let mut rng = Rng(42);
    let alphabet = [0xE8u8, 0xE9, 0x00, 0xFF, 0xEB, 0xF0, 0xF8, 0x48, 0x01, 0x40, 0x7F, 0xC0, 0x94, 0x90, 0x17, 0xEF, 0x97, 0x13, 0x10, 0x3F];
    for arch in BcjArch::ALL {
        for _ in 0..60 {
            let len = rng.below(300);
            let data: Vec<u8> = (0..len).map(|_| alphabet[rng.below(alphabet.len())]).collect();
            let enc = bcj_encode(arch, 0, &data, BIG).unwrap();
            assert!(bcj_decode(arch, 0, &enc, BIG).unwrap() == data, "{arch:?}");
            for pat in [&[1usize][..], &[3, 4]] {
                assert!(stream_bcj(arch, 0, &data, true, pat) == enc, "{arch:?} stream");
            }
        }
    }
}

#[test]
fn bcj_known_vectors() {
    // x86 CALL rel32 0 at position 0 -> absolute 5.
    assert_eq!(bcj_encode(BcjArch::X86, 0, &[0xE8, 0, 0, 0, 0], BIG).unwrap(), [0xE8, 5, 0, 0, 0]);
    // Fewer than 5 bytes: untouched.
    assert_eq!(bcj_encode(BcjArch::X86, 0, &[0xE8, 0, 0, 0], BIG).unwrap(), [0xE8, 0, 0, 0]);
    // x86 negative displacement, MS byte 0xFF stays sign-like.
    assert_eq!(bcj_encode(BcjArch::X86, 0x100, &[0xE8, 0xF0, 0xFF, 0xFF, 0xFF], BIG).unwrap(), [0xE8, 0xF5, 0x00, 0x00, 0x00]);
    // ARM BL +0 at 0x1000 -> (0x1008)>>2.
    assert_eq!(bcj_encode(BcjArch::Arm, 0x1000, &[0, 0, 0, 0xEB], BIG).unwrap(), [0x02, 0x04, 0x00, 0xEB]);
    // ARM64 BL imm 1 at 0x1000 -> imm 0x401.
    assert_eq!(bcj_encode(BcjArch::Arm64, 0x1000, &0x9400_0001u32.to_le_bytes(), BIG).unwrap(), 0x9400_0401u32.to_le_bytes());
    // PowerPC bl +4 at 8 -> 12.
    assert_eq!(bcj_encode(BcjArch::PowerPc, 8, &0x4800_0005u32.to_be_bytes(), BIG).unwrap(), 0x4800_000Du32.to_be_bytes());
    // PowerPC with AA set is not converted.
    assert_eq!(bcj_encode(BcjArch::PowerPc, 8, &0x4800_0007u32.to_be_bytes(), BIG).unwrap(), 0x4800_0007u32.to_be_bytes());
    // SPARC call +1 word at 0x10 -> 5 words.
    assert_eq!(bcj_encode(BcjArch::Sparc, 0x10, &0x4000_0001u32.to_be_bytes(), BIG).unwrap(), 0x4000_0005u32.to_be_bytes());
    // Empty input everywhere.
    for arch in BcjArch::ALL {
        assert!(bcj_encode(arch, 0, &[], BIG).unwrap().is_empty());
        assert!(bcj_decode(arch, 0, &[], 0).unwrap().is_empty());
    }
}

#[test]
fn bcj_position_wraps_modulo_2_32() {
    // x86 call at the very end of the 32-bit address space.
    let data = [0xE8, 0x10, 0, 0, 0];
    let enc = bcj_encode(BcjArch::X86, 0xFFFF_FFFF, &data, BIG).unwrap();
    // pc + 5 = 4 (mod 2^32); 0x10 + 4 = 0x14
    assert_eq!(enc, [0xE8, 0x14, 0, 0, 0]);
    assert_eq!(bcj_decode(BcjArch::X86, 0xFFFF_FFFF, &enc, BIG).unwrap(), data);
}

#[test]
fn bcj_properties_and_ids() {
    for arch in BcjArch::ALL {
        assert_eq!(parse_bcj_properties(arch, &[]), Ok(0));
        assert_eq!(parse_bcj_properties(arch, &[0x00, 0x10, 0, 0]), Ok(0x1000));
        assert_eq!(parse_bcj_properties(arch, &[0; 3]), Err(BcjError::InvalidProperties));
        assert_eq!(parse_bcj_properties(arch, &[0; 5]), Err(BcjError::InvalidProperties));
        assert_eq!(BcjArch::from_xz_filter_id(arch.xz_filter_id()), Ok(arch));
        assert_eq!(BcjArch::from_sevenz_method_id(arch.sevenz_method_id()), Ok(arch));
        let unaligned = parse_bcj_properties(arch, &[1, 0, 0, 0]);
        if arch.alignment() == 1 {
            assert_eq!(unaligned, Ok(1));
        } else {
            assert_eq!(unaligned, Err(BcjError::UnalignedStartOffset));
            assert_eq!(bcj_encode(arch, 3, &[0; 8], BIG), Err(BcjError::UnalignedStartOffset));
            assert!(BcjCoder::new(arch, 1, false).is_err());
            assert!(BcjStream::new(arch, 1, false, BIG).is_err());
        }
    }
    assert_eq!(BcjArch::from_xz_filter_id(0x21), Err(BcjError::UnsupportedFilter));
    assert_eq!(BcjArch::from_xz_filter_id(0x03), Err(BcjError::UnsupportedFilter));
    assert_eq!(BcjArch::from_sevenz_method_id(0x0303_0102), Err(BcjError::UnsupportedFilter));
    assert_eq!(BcjArch::X86.xz_filter_id(), 4);
    assert_eq!(BcjArch::RiscV.xz_filter_id(), 0x0B);
}

#[test]
fn bcj_limits() {
    let data = [0u8; 100];
    for arch in BcjArch::ALL {
        assert_eq!(bcj_encode(arch, 0, &data, 99), Err(BcjError::LimitExceeded));
        assert_eq!(bcj_decode(arch, 0, &data, 99), Err(BcjError::LimitExceeded));
        assert!(bcj_decode(arch, 0, &data, 100).is_ok());
        let mut s = BcjStream::new(arch, 0, false, 150).unwrap();
        let mut out = Vec::new();
        s.update(&data, &mut out).unwrap();
        assert_eq!(s.update(&data, &mut out), Err(BcjError::LimitExceeded));
        s.update(&data[..50], &mut out).unwrap();
        s.finish(&mut out).unwrap();
        assert_eq!(out.len(), 150);
    }
}

#[test]
fn delta_matches_liblzma() {
    let cases = load_cases();
    for c in cases.iter().filter(|c| c.kind == "delta") {
        let d = c.param as usize;
        assert!(delta_encode(d, &c.input, BIG).unwrap() == c.output, "{}", c.name);
        assert!(delta_decode(d, &c.output, BIG).unwrap() == c.input, "{}", c.name);
        // Streaming in odd chunks.
        for chunk in [1usize, 3, 255, 256, 257] {
            let mut coder = DeltaCoder::new(d, true).unwrap();
            let mut buf = c.input.clone();
            for part in buf.chunks_mut(chunk) {
                coder.convert(part);
            }
            assert!(buf == c.output, "{} chunk {chunk}", c.name);
            let mut dec = DeltaCoder::new(d, false).unwrap();
            for part in buf.chunks_mut(chunk) {
                dec.convert(part);
            }
            assert!(buf == c.input);
        }
    }
}

#[test]
fn delta_semantics_and_errors() {
    assert_eq!(delta_encode(1, &[5, 7, 7, 1], BIG).unwrap(), [5, 2, 0, 250]);
    assert_eq!(delta_encode(2, &[5, 7, 7, 1], BIG).unwrap(), [5, 7, 2, 250]);
    let data: Vec<u8> = (0..600u32).map(|i| (i * 7 % 251) as u8).collect();
    let e = delta_encode(256, &data, BIG).unwrap();
    assert_eq!(&e[..256], &data[..256]);
    for i in 256..600 {
        assert_eq!(e[i], data[i].wrapping_sub(data[i - 256]));
    }
    let mut rng = Rng(7);
    for d in [1usize, 2, 100, 255, 256] {
        let x = rng.bytes(1000);
        assert_eq!(delta_decode(d, &delta_encode(d, &x, BIG).unwrap(), BIG).unwrap(), x);
    }
    assert_eq!(delta_encode(0, &[1], BIG), Err(DeltaError::InvalidDistance));
    assert_eq!(delta_encode(257, &[1], BIG), Err(DeltaError::InvalidDistance));
    assert!(DeltaCoder::new(0, false).is_err());
    assert_eq!(delta_encode(1, &[1, 2], 1), Err(DeltaError::LimitExceeded));
    assert_eq!(parse_delta_properties(&[0]), Ok(1));
    assert_eq!(parse_delta_properties(&[255]), Ok(256));
    assert_eq!(parse_delta_properties(&[]), Err(DeltaError::InvalidProperties));
    assert_eq!(parse_delta_properties(&[0, 0]), Err(DeltaError::InvalidProperties));
    assert_eq!(delta_properties(256), Ok([255]));
    assert_eq!(delta_properties(0), Err(DeltaError::InvalidDistance));
    assert!(delta_encode(4, &[], 0).unwrap().is_empty());
}

#[test]
fn swap_semantics() {
    let x: Vec<u8> = (0..11).collect();
    assert_eq!(swap_convert(SwapWidth::Swap2, &x, BIG).unwrap(), [1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 10]);
    assert_eq!(swap_convert(SwapWidth::Swap4, &x, BIG).unwrap(), [3, 2, 1, 0, 7, 6, 5, 4, 8, 9, 10]);
    for w in [SwapWidth::Swap2, SwapWidth::Swap4] {
        let y = swap_convert(w, &x, BIG).unwrap();
        assert_eq!(swap_convert(w, &y, BIG).unwrap(), x);
        assert_eq!(SwapWidth::from_sevenz_method_id(w.sevenz_method_id()), Ok(w));
        assert_eq!(swap_convert(w, &x, 10), Err(SwapError::LimitExceeded));
        assert!(swap_convert(w, &[], 0).unwrap().is_empty());
        assert_eq!(swap_convert(w, &[9], 1).unwrap(), [9]);
        for chunk in [1usize, 2, 3, 5] {
            let mut s = SwapStream::new(w, BIG);
            let mut out = Vec::new();
            for part in x.chunks(chunk) {
                s.update(part, &mut out).unwrap();
            }
            s.finish(&mut out).unwrap();
            assert_eq!(out, y, "{w:?} chunk {chunk}");
            assert_eq!(s.total_out(), x.len());
        }
        let mut s = SwapStream::new(w, 5);
        let mut out = Vec::new();
        s.update(&x[..5], &mut out).unwrap();
        assert_eq!(s.update(&x[5..6], &mut out), Err(SwapError::LimitExceeded));
    }
    assert_eq!(SwapWidth::from_sevenz_method_id(0x02_0308), Err(SwapError::UnsupportedFilter));
    assert_eq!(SwapWidth::Swap2.sevenz_method_id(), 0x02_0302);
}
