// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression: 7zAES key derivation must have an overall work budget per
//! decoder. An archive whose folders rotate through more salts than the key
//! cache holds used to force a full derivation on every folder decode.

use sediment_engine::sevenz_aes_coder::{
    KDF_BUDGET_MAX_COST_DERIVATIONS, KEY_CACHE_LEN, SEVENZ_AES_METHOD_ID, SevenZAesCoderError, SevenZAesEncoder, SevenZCryptoDecoder,
};
use sediment_engine::sevenz_read::{FolderDecoder, NoDecoder, SevenZReadError};

const CYCLES: u8 = 6;
/// Like the defaults (archives at 2^19, limit 2^24): cost well below the limit.
const MAX: u8 = CYCLES + 3;

fn streams(n_salts: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..n_salts)
        .map(|i| {
            let salt = [i as u8 + 1; 8];
            let enc = SevenZAesEncoder::with_params("pw", CYCLES, &salt, false).unwrap();
            enc.encrypt_with_iv(b"hello world, 7z!", &[i as u8; 16]).unwrap()
        })
        .collect()
}

#[test]
fn rotating_salts_exhaust_kdf_budget() {
    let n_salts = KEY_CACHE_LEN + 1;
    let s = streams(n_salts);
    let d = SevenZCryptoDecoder::new(NoDecoder, Some("pw"), 1 << 20).unwrap().with_max_cycles_power(MAX);
    let mut failed_at = None;
    for i in 0..1000 {
        let (props, ct) = &s[i % n_salts];
        match d.decode(&SEVENZ_AES_METHOD_ID, props, ct, 16) {
            Ok(out) => assert_eq!(out, b"hello world, 7z!"),
            Err(e) => {
                assert_eq!(e, SevenZReadError::LimitExceeded);
                assert_eq!(d.last_error(), Some(SevenZAesCoderError::LimitExceeded));
                failed_at = Some(i);
                break;
            }
        }
    }
    let at = failed_at.expect("rotating salts must exhaust the KDF budget");
    // Many below-limit derivations must still fit.
    assert!(at >= 2 * KEY_CACHE_LEN, "budget too small: failed after {at} decodes");
}

#[test]
fn shared_salt_never_exhausts_budget() {
    let s = streams(1);
    let d = SevenZCryptoDecoder::new(NoDecoder, Some("pw"), 1 << 20).unwrap().with_max_cycles_power(MAX);
    for _ in 0..1000 {
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, &s[0].0, &s[0].1, 16).unwrap(), b"hello world, 7z!");
    }
}

#[test]
fn salts_within_cache_never_exhaust_budget() {
    let s = streams(KEY_CACHE_LEN);
    let d = SevenZCryptoDecoder::new(NoDecoder, Some("pw"), 1 << 20).unwrap().with_max_cycles_power(MAX);
    for i in 0..1000 {
        let (props, ct) = &s[i % KEY_CACHE_LEN];
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, props, ct, 16).unwrap(), b"hello world, 7z!");
    }
}

#[test]
fn max_cost_derivations_are_capped() {
    let n = 6;
    let s: Vec<_> = (0..n)
        .map(|i| {
            let enc = SevenZAesEncoder::with_params("pw", MAX, &[i as u8 + 1; 4], false).unwrap();
            enc.encrypt_with_iv(b"hello world, 7z!", &[0; 16]).unwrap()
        })
        .collect();
    let d = SevenZCryptoDecoder::new(NoDecoder, Some("pw"), 1 << 20).unwrap().with_max_cycles_power(MAX);
    let ok = s.iter().take_while(|(p, c)| d.decode(&SEVENZ_AES_METHOD_ID, p, c, 16).is_ok()).count();
    assert_eq!(ok as u64, KDF_BUDGET_MAX_COST_DERIVATIONS);
    assert_eq!(d.last_error(), Some(SevenZAesCoderError::LimitExceeded));
}
