// SPDX-License-Identifier: MIT OR Apache-2.0
//! Heavy PPMd stress run (ignored by default; run with
//! `cargo test --release --test ppmd_stress -- --ignored`).
mod ppmd_support;

use ppmd_support::*;
use sediment_engine::{ppmd7, ppmd8};

const CAP: u64 = 1 << 30;

fn input(r: &mut Lcg, n: usize) -> Vec<u8> {
    let seed = r.next();
    match r.next() % 4 {
        0 => gen_text(seed, n, 20 + r.next() % 2000),
        1 => gen_binary(seed, n),
        2 => (0..n).map(|_| r.next() as u8).collect(),
        _ => {
            let mut v = gen_text(seed, n / 2, 50);
            v.extend(gen_binary(seed, n - n / 2));
            v
        }
    }
}

#[test]
#[ignore]
fn stress_roundtrip_and_fuzz() {
    let mut r = Lcg::new(2026);
    for round in 0..400u32 {
        let n = (r.next() % 400_000) as usize;
        let data = input(&mut r, n);
        let p7 = ppmd7::Ppmd7Properties {
            order: (2 + r.next() % 63) as u8,
            memory_size: ppmd7::PPMD7_MIN_MEM_SIZE + (r.next() % (4 << 20)) as u32,
        };
        let e7 = ppmd7::encode(p7, &data, round % 3 == 0, CAP).unwrap();
        if round % 3 == 0 {
            assert_eq!(ppmd7::decode_to_end_marker(p7, &e7, n, CAP).unwrap(), data, "{p7:?}");
        } else {
            assert_eq!(ppmd7::decode(p7, &e7, n, CAP).unwrap(), data, "{p7:?}");
        }
        let p8 = ppmd8::Ppmd8Properties {
            order: (2 + r.next() % 15) as u8,
            memory_mb: (1 + r.next() % 3) as u16,
            restore: if r.next() % 2 == 0 { ppmd8::RestoreMethod::Restart } else { ppmd8::RestoreMethod::CutOff },
        };
        let e8 = ppmd8::encode_zip(p8, &data, CAP).unwrap();
        assert_eq!(ppmd8::decode_zip(&e8, n, CAP).unwrap(), data, "{p8:?}");
        // Corrupt copies must not panic.
        for _ in 0..4 {
            let mut b7 = e7.clone();
            let mut b8 = e8.clone();
            if b7.len() > 1 {
                let i = 1 + (r.next() as usize) % (b7.len() - 1);
                b7[i] ^= 1 << (r.next() % 8);
            }
            if b8.len() > 2 {
                let i = 2 + (r.next() as usize) % (b8.len() - 2);
                b8[i] ^= 1 << (r.next() % 8);
            }
            let _ = ppmd7::decode(p7, &b7, n, CAP);
            let _ = ppmd8::decode_zip(&b8, n, CAP);
        }
    }
}
