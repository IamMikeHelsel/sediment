// SPDX-License-Identifier: MIT OR Apache-2.0
#[path = "create_common/mod.rs"]
mod common;

use sediment_engine::deflate_compress::{CompressError, deflate_bound, deflate_compress};
use sediment_engine::inflate::inflate_raw;

fn lcg(n: usize, mut x: u32) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let mut text = Vec::new();
    for i in 0..3000 {
        text.extend_from_slice(format!("record {i} value {} label-{}\n", i * 7 % 101, i % 13).as_bytes());
    }
    let mut mixed = lcg(40_000, 7);
    mixed.extend_from_slice(&text[..30_000]);
    mixed.extend(std::iter::repeat_n(0u8, 70_000));
    mixed.extend_from_slice(&lcg(1000, 9));
    vec![
        ("empty", vec![]),
        ("one", vec![42]),
        ("two", vec![1, 2]),
        ("abc", b"abcabcabcabcabcabcabc".to_vec()),
        ("zeros", vec![0; 300_000]),
        ("random", lcg(70_000, 1)),
        ("text", text),
        ("mixed", mixed),
        ("all_bytes", (0..=255u8).cycle().take(5000).collect()),
        ("max_match_edge", std::iter::repeat_n(b'q', 258 * 3 + 2).collect()),
    ]
}

#[test]
fn round_trips_all_levels() {
    for (name, data) in samples() {
        for level in 0..=9u8 {
            let bound = deflate_bound(data.len()).unwrap();
            let c = deflate_compress(&data, level, bound).unwrap_or_else(|e| panic!("{name} L{level}: {e:?}"));
            assert!(c.len() <= bound, "{name} L{level} exceeds bound");
            let d = inflate_raw(&c, data.len(), 1_000_000).unwrap_or_else(|e| panic!("{name} L{level}: {e:?}"));
            assert!(d == data, "{name} L{level} mismatch");
        }
    }
}

#[test]
fn compresses_redundant_data() {
    let s = samples();
    let zeros = &s.iter().find(|x| x.0 == "zeros").unwrap().1;
    let text = &s.iter().find(|x| x.0 == "text").unwrap().1;
    assert!(deflate_compress(zeros, 1, usize::MAX).unwrap().len() < 2000);
    let t1 = deflate_compress(text, 1, usize::MAX).unwrap().len();
    let t9 = deflate_compress(text, 9, usize::MAX).unwrap().len();
    assert!(t9 < text.len() / 3, "text ratio {t9}/{}", text.len());
    assert!(t9 <= t1);
    // Incompressible input stays within stored overhead.
    let r = lcg(70_000, 3);
    let c = deflate_compress(&r, 9, usize::MAX).unwrap();
    assert!(c.len() <= r.len() + 5 * 4 + 8);
}

#[test]
fn deterministic() {
    for (_, data) in samples() {
        assert_eq!(deflate_compress(&data, 6, usize::MAX), deflate_compress(&data, 6, usize::MAX));
    }
}

#[test]
fn limits_and_errors() {
    let data = lcg(10_000, 5);
    assert_eq!(deflate_compress(&data, 10, usize::MAX), Err(CompressError::InvalidLevel));
    assert_eq!(deflate_compress(&data, 6, 100), Err(CompressError::LimitExceeded));
    assert_eq!(deflate_compress(&data, 0, 100), Err(CompressError::LimitExceeded));
    assert_eq!(deflate_compress(&[], 6, 0), Err(CompressError::LimitExceeded));
    assert_eq!(deflate_compress(&[], 6, 2).map(|v| v.len()), Ok(2));
    assert!(deflate_bound(usize::MAX).is_none());
}

#[test]
fn python_zlib_inflates_output() {
    let Some(py) = common::python() else { return };
    let dir = common::TempDir::new("deflate");
    let mut paths = Vec::new();
    for (name, data) in samples() {
        for level in [1u8, 6, 9] {
            let c = deflate_compress(&data, level, usize::MAX).unwrap();
            let p = dir.path().join(format!("{name}-{level}"));
            std::fs::write(p.with_extension("raw"), &data).unwrap();
            std::fs::write(p.with_extension("def"), c).unwrap();
            paths.push(p);
        }
    }
    let script = "import sys, zlib\nfor p in sys.argv[1:]:\n    d = zlib.decompress(open(p + '.def','rb').read(), -15)\n    assert d == open(p + '.raw','rb').read(), p\n";
    let out = std::process::Command::new(py)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .args(paths.iter().map(|p| p.to_str().unwrap()))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn skewed_and_varied_inputs_round_trip() {
    // Fibonacci-distributed symbols force Huffman depths past 15 before limiting.
    let mut fib = vec![1usize, 1];
    while fib.len() < 22 {
        let n = fib[fib.len() - 1] + fib[fib.len() - 2];
        fib.push(n);
    }
    let mut order = lcg(200_000, 11);
    let mut data = Vec::new();
    for (sym, &count) in fib.iter().enumerate() {
        data.extend(std::iter::repeat_n(sym as u8 * 11, count));
    }
    // Shuffle deterministically so matches are short and literals dominate.
    for i in (1..data.len()).rev() {
        let j = (u32::from_le_bytes([order[i % 199_990], order[(i + 1) % 199_990], order[(i + 2) % 199_990], 0]) as usize) % (i + 1);
        data.swap(i, j);
    }
    order.clear();
    for level in [1u8, 6, 9] {
        let c = deflate_compress(&data, level, usize::MAX).unwrap();
        assert_eq!(inflate_raw(&c, data.len(), 100_000).unwrap(), data);
    }
    // Many small inputs over different alphabets.
    for seed in 0..300u32 {
        let len = (seed as usize * 37) % 1500;
        let alpha = 1 + seed % 7;
        let d: Vec<u8> = lcg(len, seed).into_iter().map(|b| b % (alpha as u8 * 3)).collect();
        let c = deflate_compress(&d, (seed % 9 + 1) as u8, usize::MAX).unwrap();
        assert_eq!(inflate_raw(&c, d.len(), 10_000).unwrap(), d, "seed {seed}");
    }
}
