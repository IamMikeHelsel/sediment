// SPDX-License-Identifier: MIT OR Apache-2.0
mod ppmd_support;

use ppmd_support::*;
use sediment_engine::ppmd8::*;

const MEM_CAP: u64 = 1 << 28;

#[test]
fn oracle_decode() {
    let mut failures = Vec::new();
    for c in load_cases("zip") {
        let p = parse_zip_header(&c.stream).unwrap();
        assert_eq!(p.order as u32, c.order, "{}", c.name);
        assert_eq!(p.memory_mb as u32, c.mem, "{}", c.name);
        match decode_zip(&c.stream, c.input.len(), MEM_CAP) {
            Ok(got) if got == c.input => {}
            Ok(got) => {
                let pos = got.iter().zip(&c.input).position(|(a, b)| a != b);
                failures.push(format!("{}: mismatch at {:?}", c.name, pos));
            }
            Err(e) => failures.push(format!("{}: {:?}", c.name, e)),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn oracle_encode_matches_byte_for_byte() {
    for c in load_cases("zip") {
        let p = parse_zip_header(&c.stream).unwrap();
        let enc = encode_zip(p, &c.input, MEM_CAP).unwrap();
        assert!(enc == c.stream, "{}: encoder output differs ({} vs {})", c.name, enc.len(), c.stream.len());
    }
}
