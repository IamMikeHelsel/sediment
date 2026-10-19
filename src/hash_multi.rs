// SPDX-License-Identifier: MIT OR Apache-2.0
//! One streaming interface over every checksum and digest Sediment ships, as
//! selected by the `-scrc<METHOD>` switch of `sediment h`.
//!
//! The algorithms themselves live in their own modules (`crc32`, `crc64_xz`,
//! `hash_md5`, `hash_sha1`, `hash_sha256`, `hash_sha512`, `hash_sha3`,
//! `hash_xxh64`, `hash_blake2sp`); this module only dispatches, renders digests
//! as hex and combines per-file digests into a total.
//!
//! Digest byte order: checksums that are integers (CRC32, CRC64, XXH64) are
//! stored little-endian and printed as an uppercase big-endian hex number, the
//! way archivers print CRCs. Byte-string digests (MD5, SHA family, BLAKE2sp)
//! are printed as lowercase hex in their natural byte order.
//!
//! Totals ("for data" lines): per-file digests are added together as
//! little-endian unsigned integers of the digest length, carries beyond the
//! last byte discarded. For integer checksums this is plain wrapping addition.

use crate::crc32::Crc32;
use crate::crc64_xz::Crc64Xz;
use crate::hash_blake2sp::Blake2sp;
use crate::hash_md5::Md5;
use crate::hash_sha1::Sha1;
use crate::hash_sha256::{Sha224, Sha256};
use crate::hash_sha3::Sha3_256;
use crate::hash_sha512::{Sha384, Sha512};
use crate::hash_xxh64::Xxh64;

/// Largest digest produced by any method (SHA-512).
pub const MAX_DIGEST_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashSelectError {
    /// The method name is not recognised.
    UnknownMethod,
    /// The same method was requested twice.
    Duplicate,
    /// The method list is empty.
    Empty,
}

/// A hash method selectable with `-scrc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashMethod {
    Crc32,
    Crc64,
    Xxh64,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Blake2sp,
}

/// Every method in the order `-scrc*` reports them.
pub const ALL_METHODS: [HashMethod; 11] = [
    HashMethod::Crc32,
    HashMethod::Crc64,
    HashMethod::Xxh64,
    HashMethod::Md5,
    HashMethod::Sha1,
    HashMethod::Sha224,
    HashMethod::Sha256,
    HashMethod::Sha384,
    HashMethod::Sha512,
    HashMethod::Sha3_256,
    HashMethod::Blake2sp,
];

impl HashMethod {
    /// Display name (also the canonical `-scrc` spelling).
    pub fn name(self) -> &'static str {
        match self {
            HashMethod::Crc32 => "CRC32",
            HashMethod::Crc64 => "CRC64",
            HashMethod::Xxh64 => "XXH64",
            HashMethod::Md5 => "MD5",
            HashMethod::Sha1 => "SHA1",
            HashMethod::Sha224 => "SHA224",
            HashMethod::Sha256 => "SHA256",
            HashMethod::Sha384 => "SHA384",
            HashMethod::Sha512 => "SHA512",
            HashMethod::Sha3_256 => "SHA3-256",
            HashMethod::Blake2sp => "BLAKE2sp",
        }
    }

    /// Digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            HashMethod::Crc32 => 4,
            HashMethod::Crc64 | HashMethod::Xxh64 => 8,
            HashMethod::Md5 => 16,
            HashMethod::Sha1 => 20,
            HashMethod::Sha224 => 28,
            HashMethod::Sha256 | HashMethod::Sha3_256 | HashMethod::Blake2sp => 32,
            HashMethod::Sha384 => 48,
            HashMethod::Sha512 => 64,
        }
    }

    /// True for integer checksums printed as a big-endian number.
    pub fn is_numeric(self) -> bool {
        matches!(self, HashMethod::Crc32 | HashMethod::Crc64 | HashMethod::Xxh64)
    }

    /// Parse one method name, case-insensitively. `-`/`_` are ignored, so
    /// `sha3-256`, `SHA3_256` and `sha3256` are equivalent; `SHA-256` and
    /// `SHA256` likewise.
    pub fn parse(name: &str) -> Result<HashMethod, HashSelectError> {
        let mut key = String::new();
        for c in name.chars() {
            if c == '-' || c == '_' {
                continue;
            }
            if !c.is_ascii_alphanumeric() || key.len() >= 16 {
                return Err(HashSelectError::UnknownMethod);
            }
            key.push(c.to_ascii_uppercase());
        }
        Ok(match key.as_str() {
            "CRC32" => HashMethod::Crc32,
            "CRC64" => HashMethod::Crc64,
            "XXH64" => HashMethod::Xxh64,
            "MD5" => HashMethod::Md5,
            "SHA1" => HashMethod::Sha1,
            "SHA224" => HashMethod::Sha224,
            "SHA256" => HashMethod::Sha256,
            "SHA384" => HashMethod::Sha384,
            "SHA512" => HashMethod::Sha512,
            "SHA3256" => HashMethod::Sha3_256,
            "BLAKE2SP" => HashMethod::Blake2sp,
            _ => return Err(HashSelectError::UnknownMethod),
        })
    }
}

/// Build a method list from `-scrc` values. `*` selects every method;
/// otherwise each value may itself be a comma-separated list. An empty
/// `values` slice yields `[CRC32]`, the default. Duplicates are rejected.
pub fn parse_method_list(values: &[&str]) -> Result<Vec<HashMethod>, HashSelectError> {
    if values.is_empty() {
        return Ok(vec![HashMethod::Crc32]);
    }
    let mut out: Vec<HashMethod> = Vec::new();
    let mut all = false;
    for v in values {
        for part in v.split(',') {
            if part == "*" {
                all = true;
                continue;
            }
            if part.is_empty() {
                return Err(HashSelectError::Empty);
            }
            let m = HashMethod::parse(part)?;
            if out.contains(&m) {
                return Err(HashSelectError::Duplicate);
            }
            out.push(m);
        }
    }
    if all {
        return Ok(ALL_METHODS.to_vec());
    }
    if out.is_empty() {
        return Err(HashSelectError::Empty);
    }
    Ok(out)
}

/// A finished digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest {
    method: HashMethod,
    bytes: [u8; MAX_DIGEST_LEN],
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.method.name(), self.to_hex())
    }
}

impl Digest {
    /// The all-zero digest (identity for [`Digest::add`]).
    pub fn zero(method: HashMethod) -> Digest {
        Digest { method, bytes: [0; MAX_DIGEST_LEN] }
    }

    pub fn method(&self) -> HashMethod {
        self.method
    }

    /// Raw digest bytes (little-endian for numeric checksums).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.method.digest_len()]
    }

    /// Add `other` into `self` as little-endian integers (carry discarded).
    /// Digests of different methods are left unchanged and `false` returned.
    pub fn add(&mut self, other: &Digest) -> bool {
        if self.method != other.method {
            return false;
        }
        let mut carry = 0u16;
        for i in 0..self.method.digest_len() {
            let s = self.bytes[i] as u16 + other.bytes[i] as u16 + carry;
            self.bytes[i] = s as u8;
            carry = s >> 8;
        }
        true
    }

    /// Hex rendering: uppercase big-endian number for numeric checksums,
    /// lowercase bytes in order otherwise.
    pub fn to_hex(&self) -> String {
        const UP: &[u8; 16] = b"0123456789ABCDEF";
        const LO: &[u8; 16] = b"0123456789abcdef";
        let b = self.as_bytes();
        let mut s = String::with_capacity(b.len() * 2);
        let push = |s: &mut String, x: u8, t: &[u8; 16]| {
            s.push(t[(x >> 4) as usize] as char);
            s.push(t[(x & 15) as usize] as char);
        };
        if self.method.is_numeric() {
            for &x in b.iter().rev() {
                push(&mut s, x, UP);
            }
        } else {
            for &x in b {
                push(&mut s, x, LO);
            }
        }
        s
    }
}

#[derive(Clone)]
enum State {
    Crc32(Crc32),
    Crc64(Crc64Xz),
    Xxh64(Xxh64),
    Md5(Md5),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha3_256(Sha3_256),
    Blake2sp(Box<Blake2sp>),
}

/// Streaming hasher for one method.
#[derive(Clone)]
pub struct Hasher {
    method: HashMethod,
    state: State,
}

impl Hasher {
    pub fn new(method: HashMethod) -> Hasher {
        let state = match method {
            HashMethod::Crc32 => State::Crc32(Crc32::new()),
            HashMethod::Crc64 => State::Crc64(Crc64Xz::new()),
            HashMethod::Xxh64 => State::Xxh64(Xxh64::new()),
            HashMethod::Md5 => State::Md5(Md5::new()),
            HashMethod::Sha1 => State::Sha1(Sha1::new()),
            HashMethod::Sha224 => State::Sha224(Sha224::new()),
            HashMethod::Sha256 => State::Sha256(Sha256::new()),
            HashMethod::Sha384 => State::Sha384(Sha384::new()),
            HashMethod::Sha512 => State::Sha512(Sha512::new()),
            HashMethod::Sha3_256 => State::Sha3_256(Sha3_256::new()),
            HashMethod::Blake2sp => State::Blake2sp(Box::new(Blake2sp::new())),
        };
        Hasher { method, state }
    }

    pub fn method(&self) -> HashMethod {
        self.method
    }

    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Crc32(h) => h.update(data),
            State::Crc64(h) => h.update(data),
            State::Xxh64(h) => h.update(data),
            State::Md5(h) => h.update(data),
            State::Sha1(h) => h.update(data),
            State::Sha224(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Sha3_256(h) => h.update(data),
            State::Blake2sp(h) => h.update(data),
        }
    }

    pub fn finalize(self) -> Digest {
        let mut d = Digest::zero(self.method);
        let mut put = |b: &[u8]| d.bytes[..b.len()].copy_from_slice(b);
        match self.state {
            State::Crc32(h) => put(&h.finalize().to_le_bytes()),
            State::Crc64(h) => put(&h.value().to_le_bytes()),
            State::Xxh64(h) => put(&h.finalize().to_le_bytes()),
            State::Md5(h) => put(&h.finalize()),
            State::Sha1(h) => put(&h.finalize()),
            State::Sha224(h) => put(&h.finalize()),
            State::Sha256(h) => put(&h.finalize()),
            State::Sha384(h) => put(&h.finalize()),
            State::Sha512(h) => put(&h.finalize()),
            State::Sha3_256(h) => put(&h.finalize()),
            State::Blake2sp(h) => put(&h.finalize()),
        }
        d
    }
}

/// One-shot digest of `data`.
pub fn digest(method: HashMethod, data: &[u8]) -> Digest {
    let mut h = Hasher::new(method);
    h.update(data);
    h.finalize()
}

/// Several hashers fed the same stream.
#[derive(Clone)]
pub struct MultiHasher {
    hashers: Vec<Hasher>,
}

impl MultiHasher {
    pub fn new(methods: &[HashMethod]) -> MultiHasher {
        MultiHasher { hashers: methods.iter().map(|&m| Hasher::new(m)).collect() }
    }

    pub fn update(&mut self, data: &[u8]) {
        for h in &mut self.hashers {
            h.update(data);
        }
    }

    /// Digests in the order the methods were given.
    pub fn finalize(self) -> Vec<Digest> {
        self.hashers.into_iter().map(Hasher::finalize).collect()
    }
}
