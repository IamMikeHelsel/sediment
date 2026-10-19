// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLAKE2s (RFC 7693) and the BLAKE2sp 8-way parallel tree mode.
//!
//! Sources: RFC 7693 "The BLAKE2 Cryptographic Hash and Message
//! Authentication Code" (compression function, IV, sigma schedule, padding,
//! keying) and the BLAKE2 paper "BLAKE2: simpler, smaller, fast as MD5"
//! (Aumasson, Neves, Wilcox-O'Hearn, Winnerlein), section 2.8 / 2.9 (parameter
//! block, tree hashing) and the description of BLAKE2sp: 8 leaves, fanout 8,
//! depth 2, unlimited leaf length, inner length 32; the input is split into
//! 64-byte stripes dealt round-robin to the leaves (stripe `k` goes to leaf
//! `k mod 8`); leaf `i` has node offset `i` and node depth 0; leaf 7 and the
//! root are flagged as last nodes; the root (node depth 1) hashes the eight
//! 32-byte leaf digests in order. When keyed, every leaf absorbs the padded
//! key block first, while the root only records the key length in its
//! parameter block. BLAKE2sp with a 32-byte output and no key is the
//! checksum used by RAR5 and offered by 7-Zip.
//!
//! Verified against Python `hashlib.blake2s` (including tree parameters) and
//! the published BLAKE2sp keyed known-answer tests (`blake2sp-kat.txt`).

/// Maximum (and default) BLAKE2s digest length in bytes.
pub const BLAKE2S_OUT_MAX: usize = 32;
/// Maximum BLAKE2s key length in bytes.
pub const BLAKE2S_KEY_MAX: usize = 32;
/// BLAKE2s block length in bytes.
pub const BLAKE2S_BLOCK: usize = 64;
/// BLAKE2sp digest length in bytes (the only length supported for the tree mode).
pub const BLAKE2SP_OUT: usize = 32;
/// Number of leaves in BLAKE2sp.
pub const BLAKE2SP_LEAVES: usize = 8;

const NODE_OFFSET_LIMIT: u64 = 1 << 48;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Parameter or key validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blake2Error {
    /// Digest length is 0 or greater than 32.
    InvalidDigestLength,
    /// Key longer than 32 bytes.
    KeyTooLong,
    /// Depth is 0 (must be 1..=255).
    InvalidDepth,
    /// Node offset does not fit in 48 bits.
    NodeOffsetTooLarge,
    /// Inner length greater than 32.
    InvalidInnerLength,
}

/// BLAKE2s parameter block (BLAKE2 paper, section 2.8). Defaults describe
/// sequential BLAKE2s-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake2sParams {
    pub digest_length: u8,
    pub fanout: u8,
    pub depth: u8,
    pub leaf_length: u32,
    /// 48-bit node offset.
    pub node_offset: u64,
    pub node_depth: u8,
    pub inner_length: u8,
    pub salt: [u8; 8],
    pub personal: [u8; 8],
    /// Sets the last-node finalization flag (f1).
    pub last_node: bool,
}

impl Default for Blake2sParams {
    fn default() -> Self {
        Self {
            digest_length: BLAKE2S_OUT_MAX as u8,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            salt: [0; 8],
            personal: [0; 8],
            last_node: false,
        }
    }
}

impl Blake2sParams {
    fn validate(&self, key_len: usize) -> Result<(), Blake2Error> {
        if self.digest_length == 0 || self.digest_length as usize > BLAKE2S_OUT_MAX {
            return Err(Blake2Error::InvalidDigestLength);
        }
        if key_len > BLAKE2S_KEY_MAX {
            return Err(Blake2Error::KeyTooLong);
        }
        if self.depth == 0 {
            return Err(Blake2Error::InvalidDepth);
        }
        if self.node_offset >= NODE_OFFSET_LIMIT {
            return Err(Blake2Error::NodeOffsetTooLarge);
        }
        if self.inner_length as usize > BLAKE2S_OUT_MAX {
            return Err(Blake2Error::InvalidInnerLength);
        }
        Ok(())
    }

    fn to_bytes(self, key_len: u8) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0] = self.digest_length;
        p[1] = key_len;
        p[2] = self.fanout;
        p[3] = self.depth;
        p[4..8].copy_from_slice(&self.leaf_length.to_le_bytes());
        p[8..14].copy_from_slice(&self.node_offset.to_le_bytes()[..6]);
        p[14] = self.node_depth;
        p[15] = self.inner_length;
        p[16..24].copy_from_slice(&self.salt);
        p[24..32].copy_from_slice(&self.personal);
        p
    }
}

/// A BLAKE2s digest of 1..=32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake2sDigest {
    bytes: [u8; BLAKE2S_OUT_MAX],
    len: usize,
}

impl Blake2sDigest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn compress(h: &mut [u32; 8], block: &[u8; BLAKE2S_BLOCK], t: u64, f0: u32, f1: u32) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    v[14] ^= f0;
    v[15] ^= f1;
    for s in SIGMA.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Streaming BLAKE2s state (sequential or a single tree node).
#[derive(Clone, Debug)]
pub struct Blake2s {
    h: [u32; 8],
    /// Byte counter, modulo 2^64 (RFC 7693: t is 2w bits).
    t: u64,
    buf: [u8; BLAKE2S_BLOCK],
    /// 0..=64. The last (possibly full) block is kept until finalization.
    buf_len: usize,
    out_len: usize,
    last_node: bool,
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::init(&Blake2sParams::default(), &[])
    }
}

impl Blake2s {
    /// Unkeyed BLAKE2s-256.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keyed (MAC) or unkeyed BLAKE2s with `out_len` bytes of output.
    pub fn new_keyed(key: &[u8], out_len: usize) -> Result<Self, Blake2Error> {
        if out_len == 0 || out_len > BLAKE2S_OUT_MAX {
            return Err(Blake2Error::InvalidDigestLength);
        }
        let params = Blake2sParams { digest_length: out_len as u8, ..Blake2sParams::default() };
        Self::with_params(&params, key)
    }

    /// BLAKE2s with an explicit parameter block and optional key (empty = none).
    pub fn with_params(params: &Blake2sParams, key: &[u8]) -> Result<Self, Blake2Error> {
        params.validate(key.len())?;
        Ok(Self::init(params, key))
    }

    /// Caller must have validated `params` and `key`.
    fn init(params: &Blake2sParams, key: &[u8]) -> Self {
        let mut s = Self::from_params(params, key.len() as u8);
        if !key.is_empty() {
            s.buf[..key.len()].copy_from_slice(key);
            s.buf_len = BLAKE2S_BLOCK;
        }
        s
    }

    /// State whose parameter block records `key_len` without absorbing a key block.
    fn from_params(params: &Blake2sParams, key_len: u8) -> Self {
        let pb = params.to_bytes(key_len);
        let mut h = IV;
        for (i, word) in h.iter_mut().enumerate() {
            *word ^= u32::from_le_bytes([pb[i * 4], pb[i * 4 + 1], pb[i * 4 + 2], pb[i * 4 + 3]]);
        }
        Self {
            h,
            t: 0,
            buf: [0; BLAKE2S_BLOCK],
            buf_len: 0,
            out_len: params.digest_length as usize,
            last_node: params.last_node,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Top up the buffer; only compress it once more input is known to follow.
        let fill = BLAKE2S_BLOCK - self.buf_len;
        if data.len() > fill {
            self.buf[self.buf_len..].copy_from_slice(&data[..fill]);
            data = &data[fill..];
            self.t = self.t.wrapping_add(BLAKE2S_BLOCK as u64);
            let block = self.buf;
            compress(&mut self.h, &block, self.t, 0, 0);
            self.buf_len = 0;
            while data.len() > BLAKE2S_BLOCK {
                let mut block = [0u8; BLAKE2S_BLOCK];
                block.copy_from_slice(&data[..BLAKE2S_BLOCK]);
                self.t = self.t.wrapping_add(BLAKE2S_BLOCK as u64);
                compress(&mut self.h, &block, self.t, 0, 0);
                data = &data[BLAKE2S_BLOCK..];
            }
        }
        self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
        self.buf_len += data.len();
    }

    pub fn finalize(mut self) -> Blake2sDigest {
        self.t = self.t.wrapping_add(self.buf_len as u64);
        let mut block = [0u8; BLAKE2S_BLOCK];
        block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        let f1 = if self.last_node { u32::MAX } else { 0 };
        compress(&mut self.h, &block, self.t, u32::MAX, f1);
        let mut bytes = [0u8; BLAKE2S_OUT_MAX];
        for (i, word) in self.h.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        for b in bytes[self.out_len..].iter_mut() {
            *b = 0;
        }
        Blake2sDigest { bytes, len: self.out_len }
    }
}

/// One-shot unkeyed BLAKE2s-256.
pub fn blake2s_256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s::new();
    h.update(data);
    h.finalize().bytes
}

/// One-shot BLAKE2s with optional key (empty = unkeyed) and `out_len` bytes.
pub fn blake2s(data: &[u8], key: &[u8], out_len: usize) -> Result<Blake2sDigest, Blake2Error> {
    let mut h = Blake2s::new_keyed(key, out_len)?;
    h.update(data);
    Ok(h.finalize())
}

fn sp_params(node_offset: u64, node_depth: u8, last_node: bool) -> Blake2sParams {
    Blake2sParams {
        digest_length: BLAKE2SP_OUT as u8,
        fanout: BLAKE2SP_LEAVES as u8,
        depth: 2,
        leaf_length: 0,
        node_offset,
        node_depth,
        inner_length: BLAKE2SP_OUT as u8,
        last_node,
        ..Blake2sParams::default()
    }
}

/// Streaming BLAKE2sp state (32-byte output).
#[derive(Clone, Debug)]
pub struct Blake2sp {
    leaves: [Blake2s; BLAKE2SP_LEAVES],
    root: Blake2s,
    /// Stream position modulo 8 * 64 (selects the receiving leaf).
    pos: usize,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::init(&[])
    }
}

impl Blake2sp {
    /// Unkeyed BLAKE2sp (the RAR5 / 7-Zip checksum).
    pub fn new() -> Self {
        Self::default()
    }

    /// Keyed BLAKE2sp. `key` must be at most 32 bytes; empty means unkeyed.
    pub fn new_keyed(key: &[u8]) -> Result<Self, Blake2Error> {
        if key.len() > BLAKE2S_KEY_MAX {
            return Err(Blake2Error::KeyTooLong);
        }
        Ok(Self::init(key))
    }

    fn init(key: &[u8]) -> Self {
        let leaves = core::array::from_fn(|i| {
            Blake2s::init(&sp_params(i as u64, 0, i == BLAKE2SP_LEAVES - 1), key)
        });
        // The root carries the key length in its parameter block but never
        // absorbs the key block.
        let root = Blake2s::from_params(&sp_params(0, 1, true), key.len() as u8);
        Self { leaves, root, pos: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        const SPAN: usize = BLAKE2S_BLOCK * BLAKE2SP_LEAVES;
        while !data.is_empty() {
            let leaf = self.pos / BLAKE2S_BLOCK;
            let take = (BLAKE2S_BLOCK - self.pos % BLAKE2S_BLOCK).min(data.len());
            self.leaves[leaf].update(&data[..take]);
            self.pos = (self.pos + take) % SPAN;
            data = &data[take..];
        }
    }

    pub fn finalize(self) -> [u8; BLAKE2SP_OUT] {
        let mut root = self.root;
        for leaf in self.leaves {
            root.update(leaf.finalize().as_bytes());
        }
        root.finalize().bytes
    }
}

/// One-shot unkeyed BLAKE2sp.
pub fn blake2sp(data: &[u8]) -> [u8; BLAKE2SP_OUT] {
    let mut h = Blake2sp::new();
    h.update(data);
    h.finalize()
}

/// One-shot keyed BLAKE2sp.
pub fn blake2sp_keyed(data: &[u8], key: &[u8]) -> Result<[u8; BLAKE2SP_OUT], Blake2Error> {
    let mut h = Blake2sp::new_keyed(key)?;
    h.update(data);
    Ok(h.finalize())
}
