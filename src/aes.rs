// SPDX-License-Identifier: MIT OR Apache-2.0
//! AES-128/192/256 block cipher (FIPS-197) with CBC and CTR modes
//! (NIST SP 800-38A).
//!
//! Sources: NIST FIPS PUB 197 "Advanced Encryption Standard" (cipher, key
//! expansion, equivalent inverse cipher, section 5.3.5) and NIST SP 800-38A
//! "Recommendation for Block Cipher Modes of Operation" (CBC section 6.2,
//! CTR section 6.5). The S-box and round tables are computed at compile time
//! from the GF(2^8) definitions in FIPS-197 section 4-5, not copied.
//!
//! Archive formats use AES as follows:
//! - 7z (`7zAES`): AES-256-CBC, no padding, IV from the coder properties.
//! - WinZip AE-1/AE-2: AES-CTR with a 128-bit *little-endian* counter that
//!   starts at 1 and an all-zero nonce ([`AesCtr::winzip`]).
//!
//! # Side-channel caveat
//! This is a table-based ("T-table") implementation. Table lookups are
//! indexed by secret-dependent bytes, so execution time and cache behaviour
//! can leak key material to an attacker who shares the CPU (cache-timing
//! attacks, e.g. Bernstein 2005, Osvik-Shamir-Tromer 2006). That is
//! acceptable for a local archiver decrypting/encrypting files the user owns,
//! but this module must not be used where an adversary can time operations
//! with attacker-chosen inputs (network services, shared hosts). A
//! constant-time bitsliced backend is a planned follow-up.
//!
//! Round keys are overwritten on drop on a best-effort basis (no `unsafe`,
//! so the compiler is not formally prevented from eliding the wipe).
//!
//! No allocation, no panics on any input: length errors are reported as
//! [`AesError`].

/// AES block size in bytes.
pub const AES_BLOCK_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// Key is not 16, 24 or 32 bytes.
    InvalidKeyLength,
    /// IV / counter block is not 16 bytes.
    InvalidIvLength,
    /// Data length is not a multiple of the 16-byte block size (CBC).
    InvalidDataLength,
}

// ---------------------------------------------------------------------------
// Compile-time tables (FIPS-197 sections 4.2 and 5.1.1).

const fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8) (a^254), with 0 mapping to 0.
const fn ginv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e != 0 {
        if e & 1 != 0 {
            result = gmul(result, base);
        }
        base = gmul(base, base);
        e >>= 1;
    }
    if a == 0 { 0 } else { result }
}

const fn make_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let b = ginv(i as u8);
        s[i] = b
            ^ b.rotate_left(1)
            ^ b.rotate_left(2)
            ^ b.rotate_left(3)
            ^ b.rotate_left(4)
            ^ 0x63;
        i += 1;
    }
    s
}

const fn make_inv_sbox(s: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[s[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const SBOX: [u8; 256] = make_sbox();
const INV_SBOX: [u8; 256] = make_inv_sbox(&SBOX);

/// Encryption table: column (2s, s, s, 3s) as a big-endian word.
const fn make_te() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        t[i] = ((gmul(s, 2) as u32) << 24)
            | ((s as u32) << 16)
            | ((s as u32) << 8)
            | (gmul(s, 3) as u32);
        i += 1;
    }
    t
}

/// Decryption table: column (14s', 9s', 13s', 11s') with s' = InvSBox[x].
const fn make_td() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        t[i] = ((gmul(s, 14) as u32) << 24)
            | ((gmul(s, 9) as u32) << 16)
            | ((gmul(s, 13) as u32) << 8)
            | (gmul(s, 11) as u32);
        i += 1;
    }
    t
}

const fn rotated(t: &[u32; 256], r: u32) -> [u32; 256] {
    let mut o = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        o[i] = t[i].rotate_right(r);
        i += 1;
    }
    o
}

const TE0: [u32; 256] = make_te();
const TE1: [u32; 256] = rotated(&TE0, 8);
const TE2: [u32; 256] = rotated(&TE0, 16);
const TE3: [u32; 256] = rotated(&TE0, 24);
const TD0: [u32; 256] = make_td();
const TD1: [u32; 256] = rotated(&TD0, 8);
const TD2: [u32; 256] = rotated(&TD0, 16);
const TD3: [u32; 256] = rotated(&TD0, 24);

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    ((SBOX[(w >> 24) as usize] as u32) << 24)
        | ((SBOX[((w >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX[((w >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX[(w & 0xff) as usize] as u32)
}

#[inline(always)]
fn b(w: u32, shift: u32) -> usize {
    ((w >> shift) & 0xff) as usize
}

// ---------------------------------------------------------------------------
// Block cipher.

const MAX_WORDS: usize = 60; // 4 * (14 + 1)

/// An expanded AES key (128, 192 or 256 bits) ready to encrypt or decrypt
/// single 16-byte blocks.
#[derive(Clone)]
pub struct Aes {
    /// Number of rounds: 10, 12 or 14.
    rounds: usize,
    /// Encryption round keys.
    ek: [u32; MAX_WORDS],
    /// Decryption round keys for the equivalent inverse cipher.
    dk: [u32; MAX_WORDS],
}

impl core::fmt::Debug for Aes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.debug_struct("Aes").field("key_bits", &self.key_bits()).finish()
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        self.ek = [0; MAX_WORDS];
        self.dk = [0; MAX_WORDS];
        std::hint::black_box(&self.ek);
        std::hint::black_box(&self.dk);
    }
}

impl Aes {
    /// Expand a 16-, 24- or 32-byte key (FIPS-197 section 5.2).
    pub fn new(key: &[u8]) -> Result<Self, AesError> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return Err(AesError::InvalidKeyLength),
        };
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut ek = [0u32; MAX_WORDS];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            ek[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in nk..total {
            let mut temp = ek[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ ((RCON[i / nk - 1] as u32) << 24);
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            ek[i] = ek[i - nk] ^ temp;
        }

        // Equivalent inverse cipher key schedule (FIPS-197 section 5.3.5):
        // reverse round order and apply InvMixColumns to rounds 1..Nr-1.
        let mut dk = [0u32; MAX_WORDS];
        for r in 0..=rounds {
            for c in 0..4 {
                let w = ek[4 * (rounds - r) + c];
                dk[4 * r + c] = if r == 0 || r == rounds {
                    w
                } else {
                    // Td tables contain InvSBox, so pre-apply SBox to cancel it.
                    TD0[SBOX[b(w, 24)] as usize]
                        ^ TD1[SBOX[b(w, 16)] as usize]
                        ^ TD2[SBOX[b(w, 8)] as usize]
                        ^ TD3[SBOX[b(w, 0)] as usize]
                };
            }
        }
        Ok(Self { rounds, ek, dk })
    }

    /// Key size in bits (128, 192 or 256).
    pub fn key_bits(&self) -> usize {
        (self.rounds - 6) * 32
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        let k = &self.ek;
        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) ^ k[0];
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]) ^ k[1];
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]) ^ k[2];
        let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]) ^ k[3];
        for r in 1..self.rounds {
            let o = 4 * r;
            let t0 = TE0[b(s0, 24)] ^ TE1[b(s1, 16)] ^ TE2[b(s2, 8)] ^ TE3[b(s3, 0)] ^ k[o];
            let t1 = TE0[b(s1, 24)] ^ TE1[b(s2, 16)] ^ TE2[b(s3, 8)] ^ TE3[b(s0, 0)] ^ k[o + 1];
            let t2 = TE0[b(s2, 24)] ^ TE1[b(s3, 16)] ^ TE2[b(s0, 8)] ^ TE3[b(s1, 0)] ^ k[o + 2];
            let t3 = TE0[b(s3, 24)] ^ TE1[b(s0, 16)] ^ TE2[b(s1, 8)] ^ TE3[b(s2, 0)] ^ k[o + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }
        let o = 4 * self.rounds;
        let last = |a: u32, b1: u32, c: u32, d: u32, rk: u32| -> u32 {
            (((SBOX[b(a, 24)] as u32) << 24)
                | ((SBOX[b(b1, 16)] as u32) << 16)
                | ((SBOX[b(c, 8)] as u32) << 8)
                | (SBOX[b(d, 0)] as u32))
                ^ rk
        };
        let r0 = last(s0, s1, s2, s3, k[o]);
        let r1 = last(s1, s2, s3, s0, k[o + 1]);
        let r2 = last(s2, s3, s0, s1, k[o + 2]);
        let r3 = last(s3, s0, s1, s2, k[o + 3]);
        block[0..4].copy_from_slice(&r0.to_be_bytes());
        block[4..8].copy_from_slice(&r1.to_be_bytes());
        block[8..12].copy_from_slice(&r2.to_be_bytes());
        block[12..16].copy_from_slice(&r3.to_be_bytes());
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        let k = &self.dk;
        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) ^ k[0];
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]) ^ k[1];
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]) ^ k[2];
        let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]) ^ k[3];
        for r in 1..self.rounds {
            let o = 4 * r;
            let t0 = TD0[b(s0, 24)] ^ TD1[b(s3, 16)] ^ TD2[b(s2, 8)] ^ TD3[b(s1, 0)] ^ k[o];
            let t1 = TD0[b(s1, 24)] ^ TD1[b(s0, 16)] ^ TD2[b(s3, 8)] ^ TD3[b(s2, 0)] ^ k[o + 1];
            let t2 = TD0[b(s2, 24)] ^ TD1[b(s1, 16)] ^ TD2[b(s0, 8)] ^ TD3[b(s3, 0)] ^ k[o + 2];
            let t3 = TD0[b(s3, 24)] ^ TD1[b(s2, 16)] ^ TD2[b(s1, 8)] ^ TD3[b(s0, 0)] ^ k[o + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }
        let o = 4 * self.rounds;
        let last = |a: u32, b1: u32, c: u32, d: u32, rk: u32| -> u32 {
            (((INV_SBOX[b(a, 24)] as u32) << 24)
                | ((INV_SBOX[b(b1, 16)] as u32) << 16)
                | ((INV_SBOX[b(c, 8)] as u32) << 8)
                | (INV_SBOX[b(d, 0)] as u32))
                ^ rk
        };
        let r0 = last(s0, s3, s2, s1, k[o]);
        let r1 = last(s1, s0, s3, s2, k[o + 1]);
        let r2 = last(s2, s1, s0, s3, k[o + 2]);
        let r3 = last(s3, s2, s1, s0, k[o + 3]);
        block[0..4].copy_from_slice(&r0.to_be_bytes());
        block[4..8].copy_from_slice(&r1.to_be_bytes());
        block[8..12].copy_from_slice(&r2.to_be_bytes());
        block[12..16].copy_from_slice(&r3.to_be_bytes());
    }
}

fn iv_array(iv: &[u8]) -> Result<[u8; AES_BLOCK_LEN], AesError> {
    iv.try_into().map_err(|_| AesError::InvalidIvLength)
}

// ---------------------------------------------------------------------------
// CBC (SP 800-38A section 6.2). No padding: callers handle format-specific
// padding (7z pads the packed stream to a block multiple).

/// Streaming AES-CBC state. The chaining value carries across calls, so a
/// long stream can be processed in any sequence of block-multiple chunks.
#[derive(Clone, Debug)]
pub struct AesCbc {
    cipher: Aes,
    chain: [u8; AES_BLOCK_LEN],
}

impl AesCbc {
    /// `iv` must be exactly 16 bytes.
    pub fn new(cipher: Aes, iv: &[u8]) -> Result<Self, AesError> {
        Ok(Self { cipher, chain: iv_array(iv)? })
    }

    /// Encrypt `data` in place; its length must be a multiple of 16.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), AesError> {
        if data.len() % AES_BLOCK_LEN != 0 {
            return Err(AesError::InvalidDataLength);
        }
        let (blocks, _) = data.as_chunks_mut::<AES_BLOCK_LEN>();
        for blk in blocks {
            for (x, c) in blk.iter_mut().zip(self.chain.iter()) {
                *x ^= *c;
            }
            self.cipher.encrypt_block(blk);
            self.chain = *blk;
        }
        Ok(())
    }

    /// Decrypt `data` in place; its length must be a multiple of 16.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), AesError> {
        if data.len() % AES_BLOCK_LEN != 0 {
            return Err(AesError::InvalidDataLength);
        }
        let (blocks, _) = data.as_chunks_mut::<AES_BLOCK_LEN>();
        for blk in blocks {
            let next_chain = *blk;
            self.cipher.decrypt_block(blk);
            for (x, c) in blk.iter_mut().zip(self.chain.iter()) {
                *x ^= *c;
            }
            self.chain = next_chain;
        }
        Ok(())
    }

    /// Current chaining value (the IV for the next block).
    pub fn chain(&self) -> [u8; AES_BLOCK_LEN] {
        self.chain
    }
}

/// One-shot CBC encryption in place (`data.len() % 16 == 0`).
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), AesError> {
    AesCbc::new(Aes::new(key)?, iv)?.encrypt(data)
}

/// One-shot CBC decryption in place (`data.len() % 16 == 0`).
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), AesError> {
    AesCbc::new(Aes::new(key)?, iv)?.decrypt(data)
}

// ---------------------------------------------------------------------------
// CTR (SP 800-38A section 6.5, appendix B.1 standard incrementing function
// applied to the whole 128-bit block).

/// Byte order in which the 128-bit counter block is incremented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterOrder {
    /// Big-endian increment (SP 800-38A test vectors, most protocols).
    BigEndian,
    /// Little-endian increment (WinZip AES / Brian Gladman's fileenc).
    LittleEndian,
}

/// Streaming AES-CTR. Encryption and decryption are the same operation.
/// Data may be supplied in chunks of any size; keystream position carries
/// across calls. The counter wraps modulo 2^128.
#[derive(Clone, Debug)]
pub struct AesCtr {
    cipher: Aes,
    counter: [u8; AES_BLOCK_LEN],
    order: CounterOrder,
    keystream: [u8; AES_BLOCK_LEN],
    /// Bytes of `keystream` already used (16 = exhausted).
    used: usize,
}

impl AesCtr {
    /// `initial_counter` is the first counter block (16 bytes).
    pub fn new(cipher: Aes, initial_counter: &[u8], order: CounterOrder) -> Result<Self, AesError> {
        Ok(Self {
            cipher,
            counter: iv_array(initial_counter)?,
            order,
            keystream: [0; AES_BLOCK_LEN],
            used: AES_BLOCK_LEN,
        })
    }

    /// WinZip AE-1/AE-2 mode: little-endian counter starting at 1.
    pub fn winzip(cipher: Aes) -> Self {
        let mut counter = [0u8; AES_BLOCK_LEN];
        counter[0] = 1;
        Self { cipher, counter, order: CounterOrder::LittleEndian, keystream: [0; AES_BLOCK_LEN], used: AES_BLOCK_LEN }
    }

    fn refill(&mut self) {
        self.keystream = self.counter;
        self.cipher.encrypt_block(&mut self.keystream);
        self.used = 0;
        match self.order {
            CounterOrder::BigEndian => {
                for byte in self.counter.iter_mut().rev() {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        break;
                    }
                }
            }
            CounterOrder::LittleEndian => {
                for byte in self.counter.iter_mut() {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        break;
                    }
                }
            }
        }
    }

    /// XOR the keystream into `data` in place.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut rest = data;
        // Finish a partially used keystream block.
        while self.used < AES_BLOCK_LEN && !rest.is_empty() {
            rest[0] ^= self.keystream[self.used];
            self.used += 1;
            rest = &mut rest[1..];
        }
        let (blocks, tail) = rest.as_chunks_mut::<AES_BLOCK_LEN>();
        for chunk in blocks {
            self.refill();
            for (x, k) in chunk.iter_mut().zip(self.keystream.iter()) {
                *x ^= *k;
            }
            self.used = AES_BLOCK_LEN;
        }
        if !tail.is_empty() {
            self.refill();
            for (x, k) in tail.iter_mut().zip(self.keystream.iter()) {
                *x ^= *k;
            }
            self.used = tail.len();
        }
    }

    /// The next counter block that will be encrypted.
    pub fn counter(&self) -> [u8; AES_BLOCK_LEN] {
        self.counter
    }
}

/// One-shot CTR transform in place (encrypt == decrypt).
pub fn aes_ctr_apply(
    key: &[u8],
    initial_counter: &[u8],
    order: CounterOrder,
    data: &mut [u8],
) -> Result<(), AesError> {
    AesCtr::new(Aes::new(key)?, initial_counter, order)?.apply_keystream(data);
    Ok(())
}
