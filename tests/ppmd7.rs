// SPDX-License-Identifier: MIT OR Apache-2.0
mod ppmd_support;

use ppmd_support::*;
use sediment_engine::ppmd7::*;

const MEM_CAP: u64 = 1 << 28;

fn props(order: u32, mem: u32) -> Ppmd7Properties {
    Ppmd7Properties { order: order as u8, memory_size: mem }
}

#[test]
fn oracle_decode() {
    for c in load_cases("7z") {
        let got = decode(props(c.order, c.mem), &c.stream, c.input.len(), MEM_CAP)
            .unwrap_or_else(|e| panic!("{}: {:?}", c.name, e));
        assert!(got == c.input, "{}: output mismatch", c.name);
    }
}

#[test]
fn oracle_encode_matches_byte_for_byte() {
    for c in load_cases("7z") {
        let enc = encode(props(c.order, c.mem), &c.input, false, MEM_CAP).unwrap();
        assert!(enc == c.stream, "{}: encoder output differs ({} vs {})", c.name, enc.len(), c.stream.len());
    }
}
