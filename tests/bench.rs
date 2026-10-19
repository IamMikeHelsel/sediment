// SPDX-License-Identifier: MIT OR Apache-2.0
//! bench / cli_bench: generator determinism against the independent Python
//! model (tests/gen/bench_data.py), rating arithmetic, round-trip checks for
//! every codec, table rendering, argument parsing and the `sediment b` CLI.
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sediment_engine::bench::{
    all_codecs, bench_codec, bench_lzma_options, compress_rating, decompress_rating, format_codec_table,
    format_lzma_table, generate_bench_data, lzma_bench_pass, speed_kib, speed_mb, BenchError, BenchRng, Codec,
    CodecResult, LzmaPass, MAX_DATA_SIZE, MIN_DATA_SIZE,
};
use sediment_engine::cli_bench::{parse_bench_args, BENCH_SEED};
use sediment_engine::crc32::crc32;
use sediment_engine::hash_multi::{HashMethod, ALL_METHODS};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn generator_matches_python_model() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bench/data_crc.txt");
    let text = std::fs::read_to_string(path).unwrap();
    let mut n = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (len, window, seed) = (f[0].parse().unwrap(), f[1].parse().unwrap(), f[2].parse().unwrap());
        let data = generate_bench_data(len, window, seed).unwrap();
        assert_eq!(data.len(), len);
        assert_eq!(format!("{:08X}", crc32(&data)), f[3], "{line}");
        n += 1;
    }
    assert_eq!(n, 5);
}

#[test]
fn generator_properties() {
    let a = generate_bench_data(1 << 16, 1 << 16, BENCH_SEED).unwrap();
    let b = generate_bench_data(1 << 16, 1 << 16, BENCH_SEED).unwrap();
    assert_eq!(a, b);
    let c = generate_bench_data(1 << 16, 1 << 16, BENCH_SEED + 1).unwrap();
    assert_ne!(a, c);
    // Prefix stability: a shorter run is a prefix of a longer one.
    let short = generate_bench_data(5000, 1 << 16, BENCH_SEED).unwrap();
    assert_eq!(&a[..5000], &short[..]);
    // Not degenerate: many distinct byte values, compressible but not trivially.
    let mut seen = [false; 256];
    for &x in &a {
        seen[x as usize] = true;
    }
    assert!(seen.iter().filter(|&&s| s).count() > 64);
    let p = lzma_bench_pass(&a, 16).unwrap();
    assert!(p.packed * 100 > p.unpacked * 10 && p.packed * 100 < p.unpacked * 60, "{p:?}");
}

#[test]
fn generator_limits() {
    assert_eq!(generate_bench_data(MIN_DATA_SIZE - 1, 4096, 1), Err(BenchError::InvalidOptions));
    assert_eq!(generate_bench_data(MAX_DATA_SIZE + 1, 4096, 1), Err(BenchError::InvalidOptions));
    assert_eq!(generate_bench_data(4096, 0, 1), Err(BenchError::InvalidOptions));
    assert_eq!(generate_bench_data(MIN_DATA_SIZE, 1, 0).unwrap().len(), MIN_DATA_SIZE);
    assert_eq!(generate_bench_data(4096, usize::MAX, u64::MAX).unwrap().len(), 4096);
}

#[test]
fn rng_zero_seed_is_not_stuck() {
    let mut r = BenchRng::new(0);
    let x = r.next_u64();
    let y = r.next_u64();
    assert_ne!(x, 0);
    assert_ne!(x, y);
}

#[test]
fn rating_arithmetic() {
    let s = Duration::from_secs(1);
    assert_eq!(compress_rating(16, 1_000_000, s), 800);
    assert_eq!(compress_rating(22, 1_000_000, s), 950);
    assert_eq!(compress_rating(22, 2_000_000, Duration::from_millis(500)), 3800);
    assert_eq!(decompress_rating(1_000_000, 500_000, s), 92);
    assert_eq!(speed_kib(1 << 20, s), 1024);
    assert!((speed_mb(5_000_000, Duration::from_secs(2)) - 2.5).abs() < 1e-9);
    // Zero durations must not divide by zero or panic.
    let _ = compress_rating(26, u64::MAX, Duration::ZERO);
    let _ = decompress_rating(u64::MAX, u64::MAX, Duration::ZERO);
    let _ = speed_kib(u64::MAX, Duration::ZERO);
}

#[test]
fn lzma_pass_round_trip_and_options() {
    let data = generate_bench_data(1 << 15, 1 << 16, 3).unwrap();
    let p = lzma_bench_pass(&data, 16).unwrap();
    assert_eq!(p.unpacked, data.len() as u64);
    assert!(p.packed > 0 && p.packed < p.unpacked);
    assert_eq!(lzma_bench_pass(&data, 15), Err(BenchError::InvalidOptions));
    assert_eq!(lzma_bench_pass(&data, 27), Err(BenchError::InvalidOptions));
    assert_eq!(bench_lzma_options(22).unwrap().dictionary_size, 1 << 22);
    // Empty and tiny inputs still round-trip.
    assert_eq!(lzma_bench_pass(&[], 16).unwrap().unpacked, 0);
    assert_eq!(lzma_bench_pass(b"a", 16).unwrap().unpacked, 1);
}

#[test]
fn every_codec_round_trips() {
    let data = generate_bench_data(10_000, 1 << 16, 9).unwrap();
    let codecs = all_codecs();
    assert_eq!(codecs.len(), ALL_METHODS.len() + 4);
    for c in codecs {
        let r = bench_codec(c, &data, 2, 16).unwrap();
        assert_eq!(r.codec, c);
        assert_eq!(r.iterations, 2);
        match c {
            Codec::Hash(_) => {
                assert_eq!(r.packed, None);
                assert_eq!(r.decode, None);
                assert_eq!(r.unpacked, 10_000);
            }
            Codec::Aes256Cbc => {
                assert_eq!(r.unpacked, 10_000 & !15);
                assert_eq!(r.packed, Some(10_000 & !15));
            }
            _ => {
                assert!(r.packed.unwrap() < 10_000, "{c:?}");
                assert!(r.decode.is_some());
            }
        }
    }
    // Incompressible input must still round-trip (stored/expanded paths).
    let mut rng = BenchRng::new(77);
    let noise: Vec<u8> = (0..5000).map(|_| rng.next_u64() as u8).collect();
    for c in [Codec::Deflate, Codec::Bzip2, Codec::Lzma, Codec::Aes256Cbc] {
        bench_codec(c, &noise, 1, 16).unwrap();
    }
    // Empty input.
    for c in all_codecs() {
        bench_codec(c, &[], 1, 16).unwrap();
    }
}

#[test]
fn codec_options_validated() {
    let d = [0u8; 64];
    assert_eq!(bench_codec(Codec::Deflate, &d, 0, 16), Err(BenchError::InvalidOptions));
    assert_eq!(bench_codec(Codec::Deflate, &d, 1001, 16), Err(BenchError::InvalidOptions));
    assert_eq!(bench_codec(Codec::Lzma, &d, 1, 30), Err(BenchError::InvalidOptions));
    assert_eq!(Codec::parse("LZMA"), Ok(Codec::Lzma));
    assert_eq!(Codec::parse("bzip2"), Ok(Codec::Bzip2));
    assert_eq!(Codec::parse("Deflate"), Ok(Codec::Deflate));
    assert_eq!(Codec::parse("aes"), Ok(Codec::Aes256Cbc));
    assert_eq!(Codec::parse("SHA3-256"), Ok(Codec::Hash(HashMethod::Sha3_256)));
    assert_eq!(Codec::parse("zstd"), Err(BenchError::InvalidOptions));
    for c in all_codecs() {
        assert_eq!(Codec::parse(c.name()), Ok(c));
    }
}

#[test]
fn lzma_table_layout() {
    let p = LzmaPass {
        unpacked: 4 << 20,
        packed: 1 << 20,
        compress: Duration::from_secs(1),
        decompress: Duration::from_millis(100),
    };
    let t = format_lzma_table(22, &[p, p]);
    let expected = "\
LZMA: 1 thread, dictionary 2^22 (4096 KiB), 4194304 bytes per pass

      Compressing        | Decompressing
Dict      Speed  Rating  |      Speed  Rating
          KiB/s    MIPS  |      KiB/s    MIPS

22:        4096    3984  |      40960    2181
22:        4096    3984  |      40960    2181
----------------------------------------------
Avr:       4096    3984  |      40960    2181
Tot:               3082
Ratio: 25.00% (4194304 -> 1048576 bytes)
";
    assert_eq!(t, expected);
    // No passes: no panic, no ratio line.
    let empty = format_lzma_table(16, &[]);
    assert!(empty.contains("Avr:"));
    assert!(!empty.contains("Ratio"));
}

#[test]
fn codec_table_layout() {
    let rows = [
        CodecResult {
            codec: Codec::Hash(HashMethod::Crc32),
            unpacked: 1_000_000,
            packed: None,
            iterations: 2,
            encode: Duration::from_millis(10),
            decode: None,
        },
        CodecResult {
            codec: Codec::Deflate,
            unpacked: 1_000_000,
            packed: Some(250_000),
            iterations: 2,
            encode: Duration::from_millis(40),
            decode: Some(Duration::from_millis(8)),
        },
    ];
    let expected = "\
Codec           Size   Ratio  Encode MB/s  Decode MB/s
--------- ---------- ------- ------------ ------------
CRC32        1000000                200.0
Deflate      1000000   25.0%         50.0        250.0
";
    assert_eq!(format_codec_table(&rows), expected);
}

#[test]
fn bench_args() {
    let a = parse_bench_args(&[]).unwrap();
    assert_eq!((a.iterations, a.dict_bits, a.data_size, a.lzma_rating), (2, 22, 1 << 22, true));
    assert_eq!(a.codecs, all_codecs());
    let a = parse_bench_args(&os(&["5", "-md20", "-ds64k"])).unwrap();
    assert_eq!((a.iterations, a.dict_bits, a.data_size), (5, 20, 65536));
    assert_eq!(parse_bench_args(&os(&["-md4m"])).unwrap().dict_bits, 22);
    assert_eq!(parse_bench_args(&os(&["-md5m"])).unwrap().dict_bits, 23);
    assert_eq!(parse_bench_args(&os(&["-md64k"])).unwrap().dict_bits, 16);
    assert_eq!(parse_bench_args(&os(&["-md65537b"])).unwrap().dict_bits, 17);
    assert_eq!(parse_bench_args(&os(&["-md16"])).unwrap().data_size, 65536);
    assert_eq!(parse_bench_args(&os(&["-ds1000000"])).unwrap().data_size, 1_000_000);
    assert_eq!(parse_bench_args(&os(&["-ds256m"])).unwrap().data_size, 256 << 20);
    let a = parse_bench_args(&os(&["-mm=lzma"])).unwrap();
    assert!(a.lzma_rating);
    assert_eq!(a.codecs, vec![Codec::Lzma]);
    let a = parse_bench_args(&os(&["-mm=sha256", "-mmCRC32", "-mm=sha256"])).unwrap();
    assert!(!a.lzma_rating);
    assert_eq!(a.codecs, vec![Codec::Hash(HashMethod::Crc32), Codec::Hash(HashMethod::Sha256)]);
    assert_eq!(parse_bench_args(&os(&["-mm=sha1", "-mm=*"])).unwrap().codecs, all_codecs());
    for bad in [
        &["0"][..],
        &["1001"],
        &["1", "2"],
        &["-md15"],
        &["-md27"],
        &["-md0b"],
        &["-md128m"],
        &["-md"],
        &["-md99999999999999999999k"],
        &["-ds100"],
        &["-ds257m"],
        &["-ds"],
        &["-dsk"],
        &["-mm="],
        &["-mm=zstd"],
        &["-x"],
        &["abc"],
        &["99999"],
    ] {
        assert_eq!(parse_bench_args(&os(bad)), Err(BenchError::InvalidOptions), "{bad:?}");
    }
}

#[test]
fn cli_small_run() {
    let out = Command::new(BIN).args(["b", "1", "-md16", "-ds16k"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("LZMA: 1 thread, dictionary 2^16 (64 KiB), 16384 bytes per pass\n"), "{s}");
    assert!(s.contains("\n16: ") && s.contains("\nAvr: ") && s.contains("\nTot: "));
    for c in all_codecs() {
        assert!(s.lines().any(|l| l.starts_with(&format!("{:<9} ", c.name()))), "{} missing:\n{s}", c.name());
    }
    let out = Command::new(BIN).args(["b", "1", "-md16", "-ds4k", "-mm=md5"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("LZMA"));
    assert_eq!(s.lines().count(), 3, "{s}");
}

#[test]
fn cli_usage_errors() {
    for args in [&["b", "0"][..], &["b", "-mm=bogus"], &["b", "-md40"], &["b", "1", "1"]] {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
    }
}
