// SPDX-License-Identifier: MIT OR Apache-2.0
//! PPMd variant H (PPMd7) with the 7z range coder: 7z method `03 04 01`.
//!
//! Sources: Dmitry Shkarin's public description of PPM with information
//! inheritance and SEE (PPMd var.H, "PPM: one step to practicality", DCC 2002),
//! the 7z format documentation (coder id 030401, 5-byte properties: order byte
//! then little-endian u32 model memory size) and the public LZMA range coder
//! description (lzma-specification), whose carry-propagating coder 7z uses for
//! PPMd. No 7-Zip source was consulted.
//!
//! The model is emulated on a byte heap of exactly the configured memory size
//! so that out-of-memory restarts happen at the same points as in other
//! implementations; this is what makes streams interoperable.
//!
//! Hostile input never panics: every heap access is bounds-checked and a
//! corrupted model state or range-coder state turns into
//! [`Ppmd7Error::CorruptData`].

use core::cell::Cell;

pub const PPMD7_MIN_ORDER: u32 = 2;
pub const PPMD7_MAX_ORDER: u32 = 64;
pub const PPMD7_MIN_MEM_SIZE: u32 = 1 << 11;
pub const PPMD7_MAX_MEM_SIZE: u32 = 0xFFFF_FFFF - 12 * 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ppmd7Error {
    /// Properties or packed stream ended early.
    UnexpectedEof,
    /// Properties out of the PPMd7 range.
    InvalidProperties,
    /// Model memory or output size larger than the caller limit.
    LimitExceeded,
    /// The model heap or output buffer could not be reserved.
    Allocation,
    /// The packed stream is not a valid PPMd7 stream.
    CorruptData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ppmd7Properties {
    pub order: u8,
    pub memory_size: u32,
}

impl Ppmd7Properties {
    pub fn to_bytes(&self) -> [u8; 5] {
        let m = self.memory_size.to_le_bytes();
        [self.order, m[0], m[1], m[2], m[3]]
    }

    fn validate(&self) -> Result<(), Ppmd7Error> {
        let o = self.order as u32;
        if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&o)
            || self.memory_size < PPMD7_MIN_MEM_SIZE
            || self.memory_size > PPMD7_MAX_MEM_SIZE
        {
            return Err(Ppmd7Error::InvalidProperties);
        }
        Ok(())
    }
}

/// Parses the 5-byte 7z PPMd coder properties.
pub fn parse_properties(bytes: &[u8]) -> Result<Ppmd7Properties, Ppmd7Error> {
    if bytes.len() < 5 {
        return Err(Ppmd7Error::UnexpectedEof);
    }
    if bytes.len() > 5 {
        return Err(Ppmd7Error::InvalidProperties);
    }
    let p = Ppmd7Properties {
        order: bytes[0],
        memory_size: u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
    };
    p.validate()?;
    Ok(p)
}

/// Decodes exactly `output_size` bytes from a 7z PPMd packed stream.
///
/// `max_memory` bounds the model heap (`props.memory_size`). An end marker
/// before `output_size` bytes, a truncated stream or an inconsistent stream is
/// an error.
pub fn decode(
    props: Ppmd7Properties,
    input: &[u8],
    output_size: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd7Error> {
    decode_inner(props, input, Some(output_size), output_size, max_memory)
}

/// Decodes a 7z PPMd stream terminated by an end marker (symbol -1).
/// Output beyond `max_output` bytes is [`Ppmd7Error::LimitExceeded`].
pub fn decode_to_end_marker(
    props: Ppmd7Properties,
    input: &[u8],
    max_output: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd7Error> {
    decode_inner(props, input, None, max_output, max_memory)
}

fn decode_inner(
    props: Ppmd7Properties,
    input: &[u8],
    exact: Option<usize>,
    max_output: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd7Error> {
    props.validate()?;
    if props.memory_size as u64 > max_memory {
        return Err(Ppmd7Error::LimitExceeded);
    }
    let mut out = Vec::new();
    let reserve = match exact {
        Some(n) => n,
        None => max_output.min(1 << 20),
    };
    out.try_reserve(reserve).map_err(|_| Ppmd7Error::Allocation)?;
    let mut model = Model::new(props.memory_size, props.order as u32)?;
    let mut rc = RangeDecoder::new(input);
    if !rc.init() {
        return Err(if rc.overrun > 0 { Ppmd7Error::UnexpectedEof } else { Ppmd7Error::CorruptData });
    }
    loop {
        if let Some(n) = exact {
            if out.len() == n {
                break;
            }
        }
        let sym = model.decode_symbol(&mut rc);
        if model.fault.get() || rc.fault {
            return Err(Ppmd7Error::CorruptData);
        }
        if rc.overrun > 4 {
            return Err(Ppmd7Error::UnexpectedEof);
        }
        if sym < 0 {
            if sym == -1 && exact.is_none() {
                break;
            }
            return Err(if rc.overrun > 0 { Ppmd7Error::UnexpectedEof } else { Ppmd7Error::CorruptData });
        }
        if out.len() >= max_output {
            return Err(Ppmd7Error::LimitExceeded);
        }
        out.push(sym as u8);
    }
    if rc.overrun > 0 {
        return Err(Ppmd7Error::UnexpectedEof);
    }
    if rc.code != 0 {
        return Err(Ppmd7Error::CorruptData);
    }
    Ok(out)
}

/// Encodes `input` as a 7z PPMd packed stream (no end marker unless
/// `end_marker`). The stream decodes with the matching properties.
pub fn encode(
    props: Ppmd7Properties,
    input: &[u8],
    end_marker: bool,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd7Error> {
    props.validate()?;
    if props.memory_size as u64 > max_memory {
        return Err(Ppmd7Error::LimitExceeded);
    }
    let mut model = Model::new(props.memory_size, props.order as u32)?;
    let mut rc = RangeEncoder::new();
    rc.out
        .try_reserve(input.len() / 2 + 16)
        .map_err(|_| Ppmd7Error::Allocation)?;
    for &b in input {
        model.encode_symbol(&mut rc, b as i32);
        if model.fault.get() {
            return Err(Ppmd7Error::CorruptData);
        }
    }
    if end_marker {
        model.encode_symbol(&mut rc, -1);
    }
    rc.flush();
    if rc.alloc_failed {
        return Err(Ppmd7Error::Allocation);
    }
    Ok(rc.out)
}

// ---------------------------------------------------------------------------
// Range coder (LZMA style, carry propagation through a cache byte).

const K_TOP: u32 = 1 << 24;
const BIN_SCALE: u32 = 1 << 14;

struct RangeDecoder<'a> {
    range: u32,
    code: u32,
    input: &'a [u8],
    pos: usize,
    overrun: usize,
    fault: bool,
}

impl<'a> RangeDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        RangeDecoder { range: 0xFFFF_FFFF, code: 0, input, pos: 0, overrun: 0, fault: false }
    }

    fn read(&mut self) -> u32 {
        match self.input.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b as u32
            }
            None => {
                self.overrun += 1;
                0
            }
        }
    }

    fn init(&mut self) -> bool {
        self.code = 0;
        self.range = 0xFFFF_FFFF;
        if self.read() != 0 {
            return false;
        }
        for _ in 0..4 {
            self.code = (self.code << 8) | self.read();
        }
        self.overrun == 0 && self.code < 0xFFFF_FFFF
    }

    fn normalize(&mut self) {
        if self.range < K_TOP {
            self.code = (self.code << 8) | self.read();
            self.range <<= 8;
            if self.range < K_TOP {
                self.code = (self.code << 8) | self.read();
                self.range <<= 8;
            }
        }
    }

    fn threshold(&mut self, total: u32) -> u32 {
        if total == 0 {
            self.fault = true;
            return u32::MAX;
        }
        self.range /= total;
        if self.range == 0 {
            self.fault = true;
            return u32::MAX;
        }
        self.code / self.range
    }

    fn decode(&mut self, start: u32, size: u32) {
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    fn decode_bit(&mut self, size0: u32) -> u32 {
        let bound = (self.range >> 14).wrapping_mul(size0);
        let bit = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            1
        };
        self.normalize();
        bit
    }
}

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
    alloc_failed: bool,
}

impl RangeEncoder {
    fn new() -> Self {
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, cache: 0, cache_size: 1, out: Vec::new(), alloc_failed: false }
    }

    fn put(&mut self, b: u8) {
        if self.out.len() == self.out.capacity() && self.out.try_reserve(self.out.len().max(64)).is_err() {
            self.alloc_failed = true;
            return;
        }
        self.out.push(b);
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.put(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low as u32) >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = ((self.low as u32) << 8) as u64;
    }

    fn normalize(&mut self) {
        while self.range < K_TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn encode(&mut self, start: u32, size: u32, total: u32) {
        self.range /= total;
        self.low += start as u64 * self.range as u64;
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    fn encode_bit0(&mut self, size0: u32) {
        self.range = (self.range >> 14).wrapping_mul(size0);
        self.normalize();
    }

    fn encode_bit1(&mut self, size0: u32) {
        let bound = (self.range >> 14).wrapping_mul(size0);
        self.low += bound as u64;
        self.range = self.range.wrapping_sub(bound);
        self.normalize();
    }

    fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}

// ---------------------------------------------------------------------------
// Model.

const UNIT_SIZE: u32 = 12;
const MAX_FREQ: u32 = 124;
const PERIOD_BITS: u32 = 7;
const INT_BITS: u32 = 7;
const N_INDEXES: usize = 38;
const MAX_O: usize = PPMD7_MAX_ORDER as usize;

const INIT_BIN_ESC: [u16; 8] = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    fn update(&mut self) {
        if (self.shift as u32) < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_shl(1);
                self.count = (3u32 << self.shift) as u8;
                self.shift += 1;
            }
        }
    }
}

/// SEE context selector: `None` is the dummy context used at order 0.
type SeeRef = Option<(usize, usize)>;

fn get_mean(prob: u32) -> u32 {
    (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS
}

struct Tables {
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
}

impl Tables {
    fn new() -> Tables {
        let mut t = Tables {
            indx2units: [0; N_INDEXES],
            units2indx: [0; 128],
            ns2indx: [0; 256],
            ns2bsindx: [0; 256],
            hb2flag: [0; 256],
        };
        let mut k = 0usize;
        for i in 0..N_INDEXES {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                t.units2indx[k] = i as u8;
                k += 1;
            }
            t.indx2units[i] = k as u8;
        }
        t.ns2bsindx[0] = 0;
        t.ns2bsindx[1] = 2;
        for v in &mut t.ns2bsindx[2..11] {
            *v = 4;
        }
        for v in &mut t.ns2bsindx[11..] {
            *v = 6;
        }
        let mut i = 0usize;
        while i < 3 {
            t.ns2indx[i] = i as u8;
            i += 1;
        }
        let (mut m, mut k) = (i, 1usize);
        while i < 256 {
            t.ns2indx[i] = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
            i += 1;
        }
        for v in &mut t.hb2flag[0x40..] {
            *v = 8;
        }
        t
    }
}

struct Model {
    mem: Vec<u8>,
    fault: Cell<bool>,
    size: u32,
    align: u32,

    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,

    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; N_INDEXES],

    t: Tables,
    see: [[See; 16]; 25],
    dummy_see: See,
    bin_summ: [[u16; 64]; 128],
}

impl Model {
    fn new(size: u32, max_order: u32) -> Result<Model, Ppmd7Error> {
        let align = 4 - (size & 3);
        // One extra unit after the heap holds the free-list head during glue.
        let total = align as usize + size as usize + UNIT_SIZE as usize;
        let mut mem = Vec::new();
        mem.try_reserve_exact(total).map_err(|_| Ppmd7Error::Allocation)?;
        mem.resize(total, 0);
        let mut m = Model {
            mem,
            fault: Cell::new(false),
            size,
            align,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; N_INDEXES],
            t: Tables::new(),
            see: [[See::default(); 16]; 25],
            dummy_see: See { summ: 0, shift: PERIOD_BITS as u8, count: 64 },
            bin_summ: [[0; 64]; 128],
        };
        m.restart_model();
        Ok(m)
    }

    // -- raw heap access -------------------------------------------------

    fn bad(&self) {
        self.fault.set(true);
    }

    fn rd8(&self, o: u32) -> u32 {
        match self.mem.get(o as usize) {
            Some(&b) => b as u32,
            None => {
                self.bad();
                0
            }
        }
    }

    fn wr8(&mut self, o: u32, v: u32) {
        match self.mem.get_mut(o as usize) {
            Some(b) => *b = v as u8,
            None => self.fault.set(true),
        }
    }

    fn rd16(&self, o: u32) -> u32 {
        let o = o as usize;
        match self.mem.get(o..o.wrapping_add(2)) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]) as u32,
            None => {
                self.bad();
                0
            }
        }
    }

    fn wr16(&mut self, o: u32, v: u32) {
        let o = o as usize;
        match self.mem.get_mut(o..o.wrapping_add(2)) {
            Some(s) => s.copy_from_slice(&(v as u16).to_le_bytes()),
            None => self.fault.set(true),
        }
    }

    fn rd32(&self, o: u32) -> u32 {
        let o = o as usize;
        match self.mem.get(o..o.wrapping_add(4)) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => {
                self.bad();
                0
            }
        }
    }

    fn wr32(&mut self, o: u32, v: u32) {
        let o = o as usize;
        match self.mem.get_mut(o..o.wrapping_add(4)) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.fault.set(true),
        }
    }

    fn copy_units(&mut self, dst: u32, src: u32, bytes: u32) {
        let (d, s, n) = (dst as usize, src as usize, bytes as usize);
        if s.checked_add(n).is_some_and(|e| e <= self.mem.len())
            && d.checked_add(n).is_some_and(|e| e <= self.mem.len())
        {
            self.mem.copy_within(s..s + n, d);
        } else {
            self.bad();
        }
    }

    // -- record views ----------------------------------------------------
    // State (6 bytes): symbol, freq, successor u32 (as two u16 halves).
    // Context (12 bytes): num_stats u16, summ_freq u16, stats u32, suffix u32;
    // a one-symbol context keeps its state in place of summ_freq+stats.

    fn sym(&self, s: u32) -> u32 {
        self.rd8(s)
    }
    fn freq(&self, s: u32) -> u32 {
        self.rd8(s + 1)
    }
    fn set_freq(&mut self, s: u32, v: u32) {
        self.wr8(s + 1, v)
    }
    fn succ(&self, s: u32) -> u32 {
        self.rd32(s + 2)
    }
    fn set_succ(&mut self, s: u32, v: u32) {
        self.wr32(s + 2, v)
    }
    fn num_stats(&self, c: u32) -> u32 {
        self.rd16(c)
    }
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.wr16(c, v)
    }
    fn summ_freq(&self, c: u32) -> u32 {
        self.rd16(c + 2)
    }
    fn set_summ_freq(&mut self, c: u32, v: u32) {
        self.wr16(c + 2, v)
    }
    fn stats(&self, c: u32) -> u32 {
        self.rd32(c + 4)
    }
    fn set_stats(&mut self, c: u32, v: u32) {
        self.wr32(c + 4, v)
    }
    fn suffix(&self, c: u32) -> u32 {
        self.rd32(c + 8)
    }
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.wr32(c + 8, v)
    }
    fn one_state(c: u32) -> u32 {
        c + 2
    }

    fn read_state(&self, s: u32) -> [u8; 6] {
        let s = s as usize;
        match self.mem.get(s..s.wrapping_add(6)) {
            Some(v) => [v[0], v[1], v[2], v[3], v[4], v[5]],
            None => {
                self.bad();
                [0; 6]
            }
        }
    }

    fn write_state(&mut self, s: u32, v: [u8; 6]) {
        let s = s as usize;
        match self.mem.get_mut(s..s.wrapping_add(6)) {
            Some(d) => d.copy_from_slice(&v),
            None => self.fault.set(true),
        }
    }

    fn swap_states(&mut self, a: u32, b: u32) {
        let va = self.read_state(a);
        let vb = self.read_state(b);
        self.write_state(a, vb);
        self.write_state(b, va);
    }

    /// Finds the state with `symbol` in a multi-symbol context.
    fn find_state(&self, c: u32, symbol: u32) -> u32 {
        let mut s = self.stats(c);
        for _ in 0..256 {
            if self.sym(s) == symbol {
                return s;
            }
            s = s.wrapping_add(6);
        }
        self.bad();
        self.stats(c)
    }

    // -- sub-allocator -------------------------------------------------------

    fn i2u(&self, indx: usize) -> u32 {
        self.t.indx2units[indx] as u32
    }

    fn u2i(&self, nu: u32) -> usize {
        match self.t.units2indx.get((nu as usize).wrapping_sub(1)) {
            Some(&v) => v as usize,
            None => {
                self.bad();
                0
            }
        }
    }

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head = self.free_list[indx];
        self.wr32(node, head);
        self.free_list[indx] = node;
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.rd32(node);
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr = ptr + self.i2u(new_indx) * UNIT_SIZE;
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + k * UNIT_SIZE, (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        // Free nodes during glue: stamp u16 (0 = free), nu u16, next u32, prev u32.
        let head = self.align + self.size;
        let mut n = head;
        self.glue_count = 255;
        for i in 0..N_INDEXES {
            let nu = self.i2u(i);
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            let mut guard = 0u64;
            while next != 0 {
                let node = next;
                self.wr32(node + 4, n);
                self.wr32(n + 8, next);
                n = next;
                next = self.rd32(node);
                self.wr16(node, 0);
                self.wr16(node + 2, nu);
                guard += 1;
                if guard > self.mem.len() as u64 || self.fault.get() {
                    self.bad();
                    return;
                }
            }
        }
        self.wr16(head, 1);
        self.wr32(head + 4, n);
        self.wr32(n + 8, head);
        if self.lo_unit != self.hi_unit {
            self.wr16(self.lo_unit, 1);
        }

        let limit = self.mem.len() as u64;
        let mut steps = 0u64;
        while n != head {
            let node = n;
            let mut nu = self.rd16(node + 2);
            loop {
                let node2 = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
                nu += self.rd16(node2 + 2);
                if self.rd16(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                let prev = self.rd32(node2 + 8);
                let next = self.rd32(node2 + 4);
                self.wr32(prev + 4, next);
                self.wr32(next + 8, prev);
                self.wr16(node + 2, nu);
                steps += 1;
                if steps > limit || self.fault.get() {
                    self.bad();
                    return;
                }
            }
            n = self.rd32(node + 4);
            steps += 1;
            if steps > limit || self.fault.get() {
                self.bad();
                return;
            }
        }

        n = self.rd32(head + 4);
        while n != head {
            let mut node = n;
            let next = self.rd32(node + 4);
            let mut nu = self.rd16(node + 2);
            while nu > 128 {
                self.insert_node(node, N_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
            n = next;
            steps += 1;
            if steps > 2 * limit || self.fault.get() {
                self.bad();
                return;
            }
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == N_INDEXES {
                let num_bytes = self.i2u(indx) * UNIT_SIZE;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if self.units_start - self.text > num_bytes {
                    self.units_start -= num_bytes;
                    self.units_start
                } else {
                    0
                };
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let r = self.remove_node(i);
        self.split_block(r, i, indx);
        r
    }

    fn alloc_units(&mut self, indx: usize) -> u32 {
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let num_bytes = self.i2u(indx) * UNIT_SIZE;
        if num_bytes <= self.hi_unit - self.lo_unit {
            let r = self.lo_unit;
            self.lo_unit += num_bytes;
            return r;
        }
        self.alloc_units_rare(indx)
    }

    fn alloc_context(&mut self) -> u32 {
        if self.hi_unit != self.lo_unit {
            self.hi_unit -= UNIT_SIZE;
            self.hi_unit
        } else if self.free_list[0] != 0 {
            self.remove_node(0)
        } else {
            self.alloc_units_rare(0)
        }
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1] != 0 {
            let ptr = self.remove_node(i1);
            self.copy_units(ptr, old_ptr, new_nu * UNIT_SIZE);
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    // -- model ---------------------------------------------------------------

    fn restart_model(&mut self) {
        self.free_list = [0; N_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.size;
        self.lo_unit = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.units_start = self.lo_unit;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        self.min_context = mc;
        self.max_context = mc;
        self.set_suffix(mc, 0);
        self.set_num_stats(mc, 256);
        self.set_summ_freq(mc, 256 + 1);
        self.found_state = self.lo_unit;
        self.set_stats(mc, self.lo_unit);
        let base = self.lo_unit;
        self.lo_unit += 128 * UNIT_SIZE;
        for i in 0..256u32 {
            let s = base + i * 6;
            self.write_state(s, [i as u8, 1, 0, 0, 0, 0]);
        }
        for i in 0..128 {
            for k in 0..8 {
                let val = (BIN_SCALE - INIT_BIN_ESC[k] as u32 / (i as u32 + 2)) as u16;
                for m in (0..64).step_by(8) {
                    self.bin_summ[i][k + m] = val;
                }
            }
        }
        for (i, row) in self.see.iter_mut().enumerate() {
            for s in row.iter_mut() {
                s.shift = (PERIOD_BITS - 4) as u8;
                s.summ = ((5 * i as u32 + 10) << s.shift) as u16;
                s.count = 4;
            }
        }
    }

    fn create_successors(&mut self, skip: bool) -> u32 {
        let mut c = self.min_context;
        let up_branch = self.succ(self.found_state);
        let fsym = self.sym(self.found_state);
        let mut ps = [0u32; MAX_O + 1];
        let mut num_ps = 0usize;
        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }
        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = if self.num_stats(c) != 1 { self.find_state(c, fsym) } else { Self::one_state(c) };
            let successor = self.succ(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return c;
                }
                break;
            }
            if num_ps >= ps.len() || self.fault.get() {
                self.bad();
                return 0;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        let up_sym = self.rd8(up_branch);
        let up_succ = up_branch.wrapping_add(1);
        let up_freq = if self.num_stats(c) == 1 {
            self.freq(Self::one_state(c))
        } else {
            let s = self.find_state(c, up_sym);
            let cf = self.freq(s).wrapping_sub(1);
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            1 + if 2 * cf <= s0 {
                (5 * cf > s0) as u32
            } else {
                match (2 * cf + 3 * s0).wrapping_sub(1).checked_div(2 * s0) {
                    Some(v) => v,
                    None => {
                        self.bad();
                        0
                    }
                }
            }
        };
        let up = {
            let s = up_succ.to_le_bytes();
            [up_sym as u8, up_freq as u8, s[0], s[1], s[2], s[3]]
        };
        while num_ps != 0 {
            let c1 = self.alloc_context();
            if c1 == 0 {
                return 0;
            }
            self.set_num_stats(c1, 1);
            self.write_state(Self::one_state(c1), up);
            self.set_suffix(c1, c);
            num_ps -= 1;
            self.set_succ(ps[num_ps], c1);
            c = c1;
        }
        c
    }

    fn update_model(&mut self) {
        let fs = self.found_state;
        let fsym = self.sym(fs);
        let ffreq = self.freq(fs);
        let mut f_successor = self.succ(fs);

        if ffreq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 1 {
                let s = Self::one_state(c);
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s) + 1);
                }
            } else {
                let mut s = self.stats(c);
                if self.sym(s) != fsym {
                    s = self.find_state(c, fsym);
                    if self.freq(s) >= self.freq(s - 6) {
                        self.swap_states(s, s - 6);
                        s -= 6;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 2);
                    self.set_summ_freq(c, self.summ_freq(c) + 2);
                }
            }
        }

        if self.order_fall == 0 {
            let c = self.create_successors(true);
            self.min_context = c;
            self.max_context = c;
            if c == 0 {
                self.restart_model();
                return;
            }
            self.set_succ(self.found_state, c);
            return;
        }

        self.wr8(self.text, fsym);
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }

        if f_successor != 0 {
            if f_successor <= successor {
                let cs = self.create_successors(false);
                if cs == 0 {
                    self.restart_model();
                    return;
                }
                f_successor = cs;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.text -= 1;
                }
            }
        } else {
            self.set_succ(self.found_state, successor);
            f_successor = self.min_context;
        }

        let ns = self.num_stats(self.min_context);
        let s0 = self
            .summ_freq(self.min_context)
            .wrapping_sub(ns)
            .wrapping_sub(ffreq - 1);

        let mut c = self.max_context;
        let mut guard = 0;
        while c != self.min_context {
            let ns1 = self.num_stats(c);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restart_model();
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.copy_units(ptr, old_ptr, old_nu * UNIT_SIZE);
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                let sf = self.summ_freq(c);
                let add = (2 * ns1 < ns) as u32 + 2 * ((4 * ns1 <= ns) as u32 & (sf <= 8 * ns1) as u32);
                self.set_summ_freq(c, sf + add);
            } else {
                let s = self.alloc_units(0);
                if s == 0 {
                    self.restart_model();
                    return;
                }
                let st = self.read_state(Self::one_state(c));
                self.write_state(s, st);
                self.set_stats(c, s);
                let mut f = self.freq(s);
                if f < MAX_FREQ / 4 - 1 {
                    f <<= 1;
                } else {
                    f = MAX_FREQ - 4;
                }
                self.set_freq(s, f);
                self.set_summ_freq(c, f + self.init_esc + (ns > 3) as u32);
            }
            let sfc = self.summ_freq(c);
            let mut cf = 2 * ffreq * (sfc + 6);
            let sf = s0.wrapping_add(sfc);
            if cf < 6 * sf {
                cf = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                self.set_summ_freq(c, sfc + 3);
            } else {
                cf = 4 + (cf >= 9 * sf) as u32 + (cf >= 12 * sf) as u32 + (cf >= 15 * sf) as u32;
                self.set_summ_freq(c, sfc + cf);
            }
            let s = self.stats(c) + ns1 * 6;
            let sb = successor.to_le_bytes();
            self.write_state(s, [fsym as u8, cf as u8, sb[0], sb[1], sb[2], sb[3]]);
            self.set_num_stats(c, ns1 + 1);
            c = self.suffix(c);
            guard += 1;
            if guard > MAX_O + 1 || self.fault.get() {
                self.bad();
                return;
            }
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;
        // Move the found state to the front.
        if s != stats {
            let tmp = self.read_state(s);
            let n = (s.wrapping_sub(stats)) / 6;
            if n > 256 {
                self.bad();
                return;
            }
            self.copy_units(stats + 6, stats, n * 6);
            self.write_state(stats, tmp);
            s = stats;
        }
        let mut esc_freq = self.summ_freq(mc).wrapping_sub(self.freq(s));
        let adder = (self.order_fall != 0) as u32;
        let f = (self.freq(s) + 4 + adder) >> 1;
        self.set_freq(s, f);
        let mut sum_freq = f;

        let num_stats = self.num_stats(mc);
        if !(2..=256).contains(&num_stats) {
            self.bad();
            return;
        }
        let mut i = num_stats - 1;
        while i > 0 {
            s += 6;
            esc_freq = esc_freq.wrapping_sub(self.freq(s));
            let f = (self.freq(s) + adder) >> 1;
            self.set_freq(s, f);
            sum_freq += f;
            if f > self.freq(s - 6) {
                let tmp = self.read_state(s);
                let mut s1 = s;
                loop {
                    let prev = self.read_state(s1 - 6);
                    self.write_state(s1, prev);
                    s1 -= 6;
                    if s1 == stats || tmp[1] as u32 <= self.freq(s1 - 6) {
                        break;
                    }
                }
                self.write_state(s1, tmp);
            }
            i -= 1;
        }

        if self.freq(s) == 0 {
            let mut removed = 0;
            loop {
                removed += 1;
                s -= 6;
                if self.freq(s) != 0 || s <= stats {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(removed);
            let new_ns = num_stats - removed;
            self.set_num_stats(mc, new_ns);
            if new_ns == 1 {
                let mut tmp = self.read_state(stats);
                loop {
                    tmp[1] -= tmp[1] >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                let idx = self.u2i((num_stats + 1) >> 1);
                self.insert_node(stats, idx);
                self.found_state = Self::one_state(mc);
                self.write_state(self.found_state, tmp);
                return;
            }
            let n0 = (num_stats + 1) >> 1;
            let n1 = (new_ns + 1) >> 1;
            if n0 != n1 {
                let p = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, p);
            }
        }
        self.set_summ_freq(mc, sum_freq + esc_freq - (esc_freq >> 1));
        self.found_state = self.stats(mc);
    }

    fn next_context(&mut self) {
        let c = self.succ(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s = self.found_state;
        self.set_freq(s, self.freq(s) + 4);
        let mc = self.min_context;
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        if self.freq(s) > self.freq(s - 6) {
            self.swap_states(s, s - 6);
            s -= 6;
            self.found_state = s;
            if self.freq(s) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let mc = self.min_context;
        let fs = self.found_state;
        self.prev_success = (2 * self.freq(fs) > self.summ_freq(mc)) as u32;
        self.run_length += self.prev_success as i32;
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        let f = self.freq(fs) + 4;
        self.set_freq(fs, f);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let fs = self.found_state;
        let f = self.freq(fs);
        self.set_freq(fs, f + (f < 128) as u32);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let fs = self.found_state;
        let mc = self.min_context;
        let f = self.freq(fs) + 4;
        self.set_freq(fs, f);
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    fn bin_summ_index(&mut self) -> (usize, usize) {
        let mc = self.min_context;
        let s = Self::one_state(mc);
        let freq = self.freq(s);
        let suffix_ns = self.num_stats(self.suffix(mc));
        self.hi_bits_flag = self.t.hb2flag[self.sym(self.found_state) as usize] as u32;
        let i = (freq as usize).wrapping_sub(1);
        let j = self.prev_success
            + self.t.ns2bsindx[(suffix_ns as usize).wrapping_sub(1) & 0xFF] as u32
            + self.hi_bits_flag
            + 2 * self.t.hb2flag[self.sym(s) as usize] as u32
            + ((self.run_length >> 26) & 0x20) as u32;
        if i >= 128 || j >= 64 {
            self.bad();
            return (0, 0);
        }
        (i, j as usize)
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 256 {
            let non_masked = ns.wrapping_sub(num_masked);
            let row = self.t.ns2indx[(non_masked as usize).wrapping_sub(1) & 0xFF] as usize;
            let suffix_ns = self.num_stats(self.suffix(mc));
            let col = (non_masked < suffix_ns.wrapping_sub(ns)) as u32
                + 2 * (self.summ_freq(mc) < 11 * ns) as u32
                + 4 * (num_masked > non_masked) as u32
                + self.hi_bits_flag;
            let col = col as usize;
            if row >= 25 || col >= 16 {
                self.bad();
                return (None, 1);
            }
            let see = &mut self.see[row][col];
            let r = (see.summ >> see.shift) as u32;
            see.summ = see.summ.wrapping_sub(r as u16);
            (Some((row, col)), r + (r == 0) as u32)
        } else {
            (None, 1)
        }
    }

    fn see_mut(&mut self, r: SeeRef) -> &mut See {
        match r {
            Some((a, b)) => &mut self.see[a][b],
            None => &mut self.dummy_see,
        }
    }

    fn decode_symbol(&mut self, rc: &mut RangeDecoder) -> i32 {
        let mut char_mask = [0xFFu8; 256];
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 1 {
            let mut s = self.stats(mc);
            let summ = self.summ_freq(mc);
            let count = rc.threshold(summ);
            let mut hi_cnt = self.freq(s);
            if count < hi_cnt {
                rc.decode(0, hi_cnt);
                self.found_state = s;
                let sym = self.sym(s);
                self.update1_0();
                return sym as i32;
            }
            self.prev_success = 0;
            if !(2..=256).contains(&ns) {
                self.bad();
                return -2;
            }
            for _ in 1..ns {
                s += 6;
                let f = self.freq(s);
                hi_cnt += f;
                if hi_cnt > count {
                    rc.decode(hi_cnt - f, f);
                    self.found_state = s;
                    let sym = self.sym(s);
                    self.update1();
                    return sym as i32;
                }
            }
            if count >= summ {
                return -2;
            }
            self.hi_bits_flag = self.t.hb2flag[self.sym(self.found_state) as usize] as u32;
            rc.decode(hi_cnt, summ - hi_cnt);
            let stats = self.stats(mc);
            for k in 0..ns {
                char_mask[self.sym(stats + k * 6) as usize] = 0;
            }
        } else {
            let (i, j) = self.bin_summ_index();
            let prob = self.bin_summ[i][j] as u32;
            if rc.decode_bit(prob) == 0 {
                self.bin_summ[i][j] = (prob + (1 << INT_BITS) - get_mean(prob)) as u16;
                self.found_state = Self::one_state(mc);
                let sym = self.sym(self.found_state);
                self.update_bin();
                return sym as i32;
            }
            let p = prob - get_mean(prob);
            self.bin_summ[i][j] = p as u16;
            self.init_esc = EXP_ESCAPE[(p >> 10) as usize & 15] as u32;
            char_mask[self.sym(Self::one_state(mc)) as usize] = 0;
            self.prev_success = 0;
        }
        let mut ps = [0u32; 256];
        loop {
            let num_masked = self.num_stats(self.min_context);
            let mut guard = 0;
            loop {
                self.order_fall += 1;
                let suffix = self.suffix(self.min_context);
                if suffix == 0 {
                    return -1;
                }
                self.min_context = suffix;
                guard += 1;
                if guard > MAX_O + 2 || self.fault.get() {
                    self.bad();
                    return -2;
                }
                if self.num_stats(self.min_context) != num_masked {
                    break;
                }
            }
            let mc = self.min_context;
            let ns = self.num_stats(mc);
            if ns > 256 || ns < num_masked {
                self.bad();
                return -2;
            }
            let num = (ns - num_masked) as usize;
            let mut hi_cnt = 0u32;
            let mut n = 0usize;
            let mut s = self.stats(mc);
            for _ in 0..ns {
                if char_mask[self.sym(s) as usize] != 0 {
                    if n >= num {
                        self.bad();
                        return -2;
                    }
                    hi_cnt += self.freq(s);
                    ps[n] = s;
                    n += 1;
                }
                s += 6;
            }
            if n != num {
                self.bad();
                return -2;
            }
            let (see, esc) = self.make_esc_freq(num_masked);
            let freq_sum = esc + hi_cnt;
            let count = rc.threshold(freq_sum);
            if count < hi_cnt {
                let mut acc = 0u32;
                let mut k = 0usize;
                loop {
                    acc += self.freq(ps[k]);
                    if acc > count || k + 1 >= n {
                        break;
                    }
                    k += 1;
                }
                let s = ps[k];
                let f = self.freq(s);
                rc.decode(acc - f, f);
                self.see_mut(see).update();
                self.found_state = s;
                let sym = self.sym(s);
                self.update2();
                return sym as i32;
            }
            if count >= freq_sum {
                return -2;
            }
            rc.decode(hi_cnt, freq_sum - hi_cnt);
            let sm = self.see_mut(see);
            sm.summ = sm.summ.wrapping_add(freq_sum as u16);
            for &p in &ps[..n] {
                char_mask[self.sym(p) as usize] = 0;
            }
        }
    }

    fn encode_symbol(&mut self, rc: &mut RangeEncoder, symbol: i32) {
        let mut char_mask = [0xFFu8; 256];
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 1 {
            let mut s = self.stats(mc);
            let summ = self.summ_freq(mc);
            if self.sym(s) as i32 == symbol {
                rc.encode(0, self.freq(s), summ);
                self.found_state = s;
                self.update1_0();
                return;
            }
            self.prev_success = 0;
            let mut sum = self.freq(s);
            for _ in 1..ns {
                s += 6;
                if self.sym(s) as i32 == symbol {
                    rc.encode(sum, self.freq(s), summ);
                    self.found_state = s;
                    self.update1();
                    return;
                }
                sum += self.freq(s);
            }
            self.hi_bits_flag = self.t.hb2flag[self.sym(self.found_state) as usize] as u32;
            let stats = self.stats(mc);
            for k in 0..ns {
                char_mask[self.sym(stats + k * 6) as usize] = 0;
            }
            rc.encode(sum, summ - sum, summ);
        } else {
            let (i, j) = self.bin_summ_index();
            let prob = self.bin_summ[i][j] as u32;
            let s = Self::one_state(mc);
            if self.sym(s) as i32 == symbol {
                rc.encode_bit0(prob);
                self.bin_summ[i][j] = (prob + (1 << INT_BITS) - get_mean(prob)) as u16;
                self.found_state = s;
                self.update_bin();
                return;
            }
            rc.encode_bit1(prob);
            let p = prob - get_mean(prob);
            self.bin_summ[i][j] = p as u16;
            self.init_esc = EXP_ESCAPE[(p >> 10) as usize & 15] as u32;
            char_mask[self.sym(s) as usize] = 0;
            self.prev_success = 0;
        }
        loop {
            let num_masked = self.num_stats(self.min_context);
            let mut guard = 0;
            loop {
                self.order_fall += 1;
                let suffix = self.suffix(self.min_context);
                if suffix == 0 {
                    return; // end marker
                }
                self.min_context = suffix;
                guard += 1;
                if guard > MAX_O + 2 || self.fault.get() {
                    self.bad();
                    return;
                }
                if self.num_stats(self.min_context) != num_masked {
                    break;
                }
            }
            let (see, esc) = self.make_esc_freq(num_masked);
            let mc = self.min_context;
            let ns = self.num_stats(mc);
            let mut s = self.stats(mc);
            let mut sum = 0u32;
            let mut found = None;
            let mut low = 0;
            for _ in 0..ns.min(256) {
                let cur = self.sym(s);
                if char_mask[cur as usize] != 0 {
                    if cur as i32 == symbol {
                        found = Some(s);
                        low = sum;
                    }
                    sum += self.freq(s);
                    char_mask[cur as usize] = 0;
                }
                s += 6;
            }
            if let Some(s1) = found {
                rc.encode(low, self.freq(s1), sum + esc);
                self.see_mut(see).update();
                self.found_state = s1;
                self.update2();
                return;
            }
            rc.encode(sum, esc, sum + esc);
            let sm = self.see_mut(see);
            sm.summ = sm.summ.wrapping_add((sum + esc) as u16);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        let t = Tables::new();
        assert_eq!(t.indx2units[0], 1);
        assert_eq!(t.indx2units[4], 6);
        assert_eq!(t.indx2units[11], 24);
        assert_eq!(t.indx2units[37], 128);
        assert_eq!(t.ns2indx[255], 24);
        assert_eq!(t.units2indx[127], 37);
    }
}
