// SPDX-License-Identifier: MIT OR Apache-2.0
//! PPMd variant I revision 1 (PPMd8), as used by ZIP compression method 98.
//!
//! Sources: Dmitry Shkarin's public PPMd var.I description (PPM with
//! information inheritance, SEE, and the "restart"/"cut-off" model
//! restoration methods), the PKWARE APPNOTE (section 5.10: method 98, 2-byte
//! parameter header: bits 0-3 order-1, bits 4-11 memory size in MB minus 1,
//! bits 12-15 restoration method) and the public description of the
//! carry-less range coder by D. Subbotin that PPMd var.I uses. No 7-Zip source
//! was consulted.
//!
//! Like [`crate::ppmd7`], the model runs on an emulated byte heap of exactly
//! the configured size so that memory-exhaustion handling matches other
//! implementations bit for bit. Corrupt input yields
//! [`Ppmd8Error::CorruptData`]; nothing panics.

use core::cell::Cell;

pub const PPMD8_MIN_ORDER: u32 = 2;
pub const PPMD8_MAX_ORDER: u32 = 16;
pub const PPMD8_MIN_MEM_MB: u32 = 1;
pub const PPMD8_MAX_MEM_MB: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ppmd8Error {
    /// Header or packed stream ended early.
    UnexpectedEof,
    /// Parameters outside the PPMd8 range.
    InvalidProperties,
    /// Valid but unsupported parameters (restoration method "freeze").
    UnsupportedProperties,
    /// Model memory or output size larger than the caller limit.
    LimitExceeded,
    /// The model heap or output buffer could not be reserved.
    Allocation,
    /// The packed stream is not a valid PPMd8 stream.
    CorruptData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMethod {
    /// Restart the model from scratch when memory runs out.
    Restart,
    /// Prune the context tree ("cut off") when memory runs out.
    CutOff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ppmd8Properties {
    pub order: u8,
    /// Model memory in MiB (1..=256).
    pub memory_mb: u16,
    pub restore: RestoreMethod,
}

impl Ppmd8Properties {
    /// Memory size in bytes.
    pub fn memory_size(&self) -> u32 {
        (self.memory_mb as u32) << 20
    }

    /// The 2-byte little-endian ZIP parameter word.
    pub fn zip_header(&self) -> [u8; 2] {
        let r = match self.restore {
            RestoreMethod::Restart => 0u16,
            RestoreMethod::CutOff => 1,
        };
        let v = (self.order as u16 - 1) | ((self.memory_mb - 1) << 4) | (r << 12);
        v.to_le_bytes()
    }

    fn validate(&self) -> Result<(), Ppmd8Error> {
        let o = self.order as u32;
        let m = self.memory_mb as u32;
        if !(PPMD8_MIN_ORDER..=PPMD8_MAX_ORDER).contains(&o) || !(PPMD8_MIN_MEM_MB..=PPMD8_MAX_MEM_MB).contains(&m) {
            return Err(Ppmd8Error::InvalidProperties);
        }
        Ok(())
    }
}

/// Parses the 2-byte ZIP method-98 parameter header.
pub fn parse_zip_header(bytes: &[u8]) -> Result<Ppmd8Properties, Ppmd8Error> {
    if bytes.len() < 2 {
        return Err(Ppmd8Error::UnexpectedEof);
    }
    let v = u16::from_le_bytes([bytes[0], bytes[1]]);
    let order = (v & 0xF) as u8 + 1;
    let memory_mb = ((v >> 4) & 0xFF) + 1;
    let restore = match v >> 12 {
        0 => RestoreMethod::Restart,
        1 => RestoreMethod::CutOff,
        2 => return Err(Ppmd8Error::UnsupportedProperties),
        _ => return Err(Ppmd8Error::InvalidProperties),
    };
    let p = Ppmd8Properties { order, memory_mb, restore };
    p.validate()?;
    Ok(p)
}

/// Decodes a ZIP method-98 entry payload (2-byte header + range-coded data)
/// into exactly `output_size` bytes. An end marker directly after the data is
/// accepted (and consumed) but not required.
pub fn decode_zip(data: &[u8], output_size: usize, max_memory: u64) -> Result<Vec<u8>, Ppmd8Error> {
    let props = parse_zip_header(data)?;
    decode(props, &data[2..], output_size, max_memory)
}

/// Decodes `output_size` bytes from a raw PPMd8 stream (no ZIP header).
pub fn decode(
    props: Ppmd8Properties,
    input: &[u8],
    output_size: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd8Error> {
    decode_inner(props, input, Some(output_size), output_size, max_memory)
}

/// Decodes a raw PPMd8 stream up to its end marker.
pub fn decode_to_end_marker(
    props: Ppmd8Properties,
    input: &[u8],
    max_output: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd8Error> {
    decode_inner(props, input, None, max_output, max_memory)
}

fn decode_inner(
    props: Ppmd8Properties,
    input: &[u8],
    exact: Option<usize>,
    max_output: usize,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd8Error> {
    props.validate()?;
    if props.memory_size() as u64 > max_memory {
        return Err(Ppmd8Error::LimitExceeded);
    }
    let mut out = Vec::new();
    let reserve = match exact {
        Some(n) => n,
        None => max_output.min(1 << 20),
    };
    out.try_reserve(reserve).map_err(|_| Ppmd8Error::Allocation)?;
    let mut model = Model::new(props)?;
    let mut rc = RangeDecoder::new(input);
    if !rc.init() {
        return Err(if rc.overrun > 0 { Ppmd8Error::UnexpectedEof } else { Ppmd8Error::CorruptData });
    }
    loop {
        if let Some(n) = exact
            && out.len() == n
        {
            break;
        }
        let sym = model.decode_symbol(&mut rc);
        if model.fault.get() || rc.fault {
            return Err(Ppmd8Error::CorruptData);
        }
        if rc.overrun > 4 {
            return Err(Ppmd8Error::UnexpectedEof);
        }
        if sym < 0 {
            if sym == -1 && exact.is_none() {
                break;
            }
            return Err(if rc.overrun > 0 { Ppmd8Error::UnexpectedEof } else { Ppmd8Error::CorruptData });
        }
        if out.len() >= max_output {
            return Err(Ppmd8Error::LimitExceeded);
        }
        out.push(sym as u8);
    }
    if exact.is_some() && rc.pos < input.len() {
        // Writers (7-Zip, WinZip) append an end marker; accept exactly that.
        let sym = model.decode_symbol(&mut rc);
        if sym != -1 || model.fault.get() || rc.fault {
            return Err(Ppmd8Error::CorruptData);
        }
    }
    if rc.overrun > 0 {
        return Err(Ppmd8Error::UnexpectedEof);
    }
    Ok(out)
}

/// Encodes `input` as a ZIP method-98 payload: header, data and end marker.
pub fn encode_zip(props: Ppmd8Properties, input: &[u8], max_memory: u64) -> Result<Vec<u8>, Ppmd8Error> {
    props.validate()?;
    let body = encode(props, input, true, max_memory)?;
    let mut out = Vec::new();
    out.try_reserve_exact(body.len() + 2).map_err(|_| Ppmd8Error::Allocation)?;
    out.extend_from_slice(&props.zip_header());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Encodes `input` as a raw PPMd8 stream, optionally followed by an end marker.
pub fn encode(
    props: Ppmd8Properties,
    input: &[u8],
    end_marker: bool,
    max_memory: u64,
) -> Result<Vec<u8>, Ppmd8Error> {
    props.validate()?;
    if props.memory_size() as u64 > max_memory {
        return Err(Ppmd8Error::LimitExceeded);
    }
    let mut model = Model::new(props)?;
    let mut rc = RangeEncoder::new();
    rc.out
        .try_reserve(input.len() / 2 + 16)
        .map_err(|_| Ppmd8Error::Allocation)?;
    for &b in input {
        model.encode_symbol(&mut rc, b as i32);
        if model.fault.get() || rc.fault {
            return Err(Ppmd8Error::CorruptData);
        }
    }
    if end_marker {
        model.encode_symbol(&mut rc, -1);
    }
    rc.flush();
    if rc.alloc_failed {
        return Err(Ppmd8Error::Allocation);
    }
    if model.fault.get() || rc.fault {
        return Err(Ppmd8Error::CorruptData);
    }
    Ok(rc.out)
}

// ---------------------------------------------------------------------------
// Carry-less range coder.

const K_TOP: u32 = 1 << 24;
const K_BOT: u32 = 1 << 15;
const BIN_SCALE: u32 = 1 << 14;

struct RangeDecoder<'a> {
    low: u32,
    range: u32,
    /// Code value relative to `low`.
    code: u32,
    input: &'a [u8],
    pos: usize,
    overrun: usize,
    fault: bool,
}

impl<'a> RangeDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        RangeDecoder { low: 0, range: 0xFFFF_FFFF, code: 0, input, pos: 0, overrun: 0, fault: false }
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
        for _ in 0..4 {
            self.code = (self.code << 8) | self.read();
        }
        self.overrun == 0 && self.code < 0xFFFF_FFFF
    }

    fn normalize(&mut self) {
        let mut guard = 0;
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP {
                if self.range >= K_BOT {
                    break;
                }
                self.range = self.low.wrapping_neg() & (K_BOT - 1);
            }
            self.code = (self.code << 8) | self.read();
            self.range <<= 8;
            self.low <<= 8;
            guard += 1;
            if guard > 8 {
                self.fault = true;
                break;
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
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }
}

struct RangeEncoder {
    low: u32,
    range: u32,
    out: Vec<u8>,
    alloc_failed: bool,
    fault: bool,
}

impl RangeEncoder {
    fn new() -> Self {
        RangeEncoder { low: 0, range: 0xFFFF_FFFF, out: Vec::new(), alloc_failed: false, fault: false }
    }

    fn put(&mut self, b: u8) {
        if self.out.len() == self.out.capacity() && self.out.try_reserve(self.out.len().max(64)).is_err() {
            self.alloc_failed = true;
            return;
        }
        self.out.push(b);
    }

    fn normalize(&mut self) {
        let mut guard = 0;
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP {
                if self.range >= K_BOT {
                    break;
                }
                self.range = self.low.wrapping_neg() & (K_BOT - 1);
            }
            self.put((self.low >> 24) as u8);
            self.range <<= 8;
            self.low <<= 8;
            guard += 1;
            if guard > 8 {
                self.fault = true;
                break;
            }
        }
    }

    fn encode(&mut self, start: u32, size: u32, total: u32) {
        if total == 0 {
            self.fault = true;
            return;
        }
        self.range /= total;
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    fn flush(&mut self) {
        for _ in 0..4 {
            self.put((self.low >> 24) as u8);
            self.low <<= 8;
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
const MAX_O: usize = PPMD8_MAX_ORDER as usize;
const EMPTY_NODE: u32 = 0xFFFF_FFFF;

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

type SeeRef = Option<(usize, usize)>;

fn get_mean(prob: u32) -> u32 {
    (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS
}

struct Tables {
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 260],
    ns2bsindx: [u8; 256],
}

impl Tables {
    fn new() -> Tables {
        let mut t = Tables { indx2units: [0; N_INDEXES], units2indx: [0; 128], ns2indx: [0; 260], ns2bsindx: [0; 256] };
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
        while i < 5 {
            t.ns2indx[i] = i as u8;
            i += 1;
        }
        let (mut m, mut k) = (i, 1usize);
        while i < 260 {
            t.ns2indx[i] = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
            i += 1;
        }
        t
    }
}

/// A place that holds a free-list link: a list head or a node's `next` field.
#[derive(Clone, Copy)]
enum Link {
    Head(usize),
    Node(u32),
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
    restore: RestoreMethod,
    run_length: i32,
    init_rl: i32,

    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; N_INDEXES],
    stamps: [u32; N_INDEXES],

    t: Tables,
    see: [[See; 32]; 24],
    dummy_see: See,
    bin_summ: [[u16; 64]; 25],
}

impl Model {
    fn new(props: Ppmd8Properties) -> Result<Model, Ppmd8Error> {
        let size = props.memory_size();
        let align = 4 - (size & 3);
        let total = align as usize + size as usize + UNIT_SIZE as usize;
        let mut mem = Vec::new();
        mem.try_reserve_exact(total).map_err(|_| Ppmd8Error::Allocation)?;
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
            max_order: props.order as u32,
            restore: props.restore,
            run_length: 0,
            init_rl: 0,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; N_INDEXES],
            stamps: [0; N_INDEXES],
            t: Tables::new(),
            see: [[See::default(); 32]; 24],
            dummy_see: See { summ: 0, shift: PERIOD_BITS as u8, count: 64 },
            bin_summ: [[0; 64]; 25],
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

    fn copy_bytes(&mut self, dst: u32, src: u32, bytes: u32) {
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
    // State (6 bytes): symbol, freq, successor u32.
    // Context (12 bytes): num_stats u8 (count - 1), flags u8, summ_freq u16,
    // stats u32, suffix u32; one-symbol contexts store their state at +2.
    // Free node (12 bytes): stamp u32, next u32, nu u32.

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
        self.rd8(c)
    }
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.wr8(c, v)
    }
    fn flags(&self, c: u32) -> u32 {
        self.rd8(c + 1)
    }
    fn set_flags(&mut self, c: u32, v: u32) {
        self.wr8(c + 1, v)
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

    fn hi(sym: u32) -> u32 {
        (sym >= 0x40) as u32
    }

    // -- sub-allocator -------------------------------------------------------

    fn i2u(&self, indx: usize) -> u32 {
        match self.t.indx2units.get(indx) {
            Some(&v) => v as u32,
            None => {
                self.bad();
                1
            }
        }
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
        if indx >= N_INDEXES {
            self.bad();
            return;
        }
        self.wr32(node, EMPTY_NODE);
        self.wr32(node + 4, self.free_list[indx]);
        self.wr32(node + 8, self.i2u(indx));
        self.free_list[indx] = node;
        self.stamps[indx] = self.stamps[indx].wrapping_add(1);
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.rd32(node + 4);
        self.stamps[indx] = self.stamps[indx].wrapping_sub(1);
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

    fn get_link(&self, l: Link) -> u32 {
        match l {
            Link::Head(i) => self.free_list[i],
            Link::Node(n) => self.rd32(n + 4),
        }
    }

    fn set_link(&mut self, l: Link, v: u32) {
        match l {
            Link::Head(i) => self.free_list[i] = v,
            Link::Node(n) => self.wr32(n + 4, v),
        }
    }

    fn glue_free_blocks(&mut self) {
        self.glue_count = 1 << 13;
        self.stamps = [0; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.wr32(self.lo_unit, 0);
        }
        // Collect all free blocks into one list (in list order), merging each
        // with the free blocks that physically follow it.
        let mut head = 0u32;
        let mut prev: Option<u32> = None;
        let limit = self.mem.len() as u64;
        let mut steps = 0u64;
        for i in 0..N_INDEXES {
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node = next;
                if self.rd32(node + 8) != 0 {
                    match prev {
                        None => head = next,
                        Some(p) => self.wr32(p + 4, next),
                    }
                    prev = Some(node);
                    loop {
                        let nu = self.rd32(node + 8);
                        let node2 = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
                        if self.rd32(node2) != EMPTY_NODE {
                            break;
                        }
                        let nu2 = self.rd32(node2 + 8);
                        self.wr32(node + 8, nu.wrapping_add(nu2));
                        self.wr32(node2 + 8, 0);
                        steps += 1;
                        if nu2 == 0 || steps > limit || self.fault.get() {
                            self.bad();
                            return;
                        }
                    }
                }
                next = self.rd32(node + 4);
                steps += 1;
                if steps > limit || self.fault.get() {
                    self.bad();
                    return;
                }
            }
        }
        match prev {
            None => head = 0,
            Some(p) => self.wr32(p + 4, 0),
        }

        while head != 0 {
            let mut node = head;
            head = self.rd32(node + 4);
            let mut nu = self.rd32(node + 8);
            if nu == 0 {
                continue;
            }
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
            self.copy_bytes(ptr, old_ptr, new_nu * UNIT_SIZE);
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let i = self.u2i(nu);
        self.insert_node(ptr, i);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start += UNIT_SIZE;
        }
    }

    fn move_units_up(&mut self, old_ptr: u32, nu: u32) -> u32 {
        let indx = self.u2i(nu);
        if old_ptr > self.units_start.wrapping_add(16 * 1024) || old_ptr > self.free_list[indx] {
            return old_ptr;
        }
        let ptr = self.remove_node(indx);
        self.copy_bytes(ptr, old_ptr, nu * UNIT_SIZE);
        if old_ptr != self.units_start {
            self.insert_node(old_ptr, indx);
        } else {
            self.units_start += self.i2u(indx) * UNIT_SIZE;
        }
        ptr
    }

    fn expand_text_area(&mut self) {
        let mut count = [0u32; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.wr32(self.lo_unit, 0);
        }
        let mut node = self.units_start;
        let mut guard = 0u64;
        while self.rd32(node) == EMPTY_NODE {
            let nu = self.rd32(node + 8);
            self.wr32(node, 0);
            let i = self.u2i(nu);
            count[i] += 1;
            node = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
            guard += 1;
            if nu == 0 || guard > self.mem.len() as u64 || self.fault.get() {
                self.bad();
                return;
            }
        }
        self.units_start = node;

        for (i, cnt) in count.iter_mut().enumerate() {
            let mut link = Link::Head(i);
            let mut guard = 0u64;
            while *cnt != 0 {
                let mut node = self.get_link(link);
                while self.rd32(node) == 0 {
                    let nx = self.rd32(node + 4);
                    self.set_link(link, nx);
                    node = nx;
                    self.stamps[i] = self.stamps[i].wrapping_sub(1);
                    *cnt -= 1;
                    if *cnt == 0 {
                        break;
                    }
                    guard += 1;
                    if guard > self.mem.len() as u64 || self.fault.get() {
                        self.bad();
                        return;
                    }
                }
                link = Link::Node(node);
                guard += 1;
                if guard > self.mem.len() as u64 || self.fault.get() {
                    self.bad();
                    return;
                }
            }
        }
    }

    fn get_used_memory(&self) -> u32 {
        let mut v: u32 = 0;
        for i in 0..N_INDEXES {
            v = v.wrapping_add(self.stamps[i].wrapping_mul(self.i2u(i)));
        }
        self.size
            .wrapping_sub(self.hi_unit - self.lo_unit)
            .wrapping_sub(self.units_start - self.text)
            .wrapping_sub(v.wrapping_mul(UNIT_SIZE))
    }

    // -- model ---------------------------------------------------------------

    fn restart_model(&mut self) {
        self.free_list = [0; N_INDEXES];
        self.stamps = [0; N_INDEXES];
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
        self.set_num_stats(mc, 255);
        self.set_flags(mc, 0);
        self.set_summ_freq(mc, 256 + 1);
        self.found_state = self.lo_unit;
        self.set_stats(mc, self.lo_unit);
        let base = self.lo_unit;
        self.lo_unit += 128 * UNIT_SIZE;
        for i in 0..256u32 {
            self.write_state(base + i * 6, [i as u8, 1, 0, 0, 0, 0]);
        }

        let mut i = 0usize;
        for m in 0..25 {
            while self.t.ns2indx[i] as usize == m {
                i += 1;
            }
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = (BIN_SCALE - esc as u32 / (i as u32 + 1)) as u16;
                for r in (0..64).step_by(8) {
                    self.bin_summ[m][k + r] = val;
                }
            }
        }
        let mut i = 0usize;
        for m in 0..24 {
            while self.t.ns2indx[i + 3] as usize == m + 3 {
                i += 1;
            }
            for s in self.see[m].iter_mut() {
                s.shift = (PERIOD_BITS - 4) as u8;
                s.summ = ((2 * i as u32 + 5) << s.shift) as u16;
                s.count = 7;
            }
        }
    }

    fn refresh(&mut self, ctx: u32, old_nu: u32, scale: u32) {
        let mut i = self.num_stats(ctx);
        let s0 = self.shrink_units(self.stats(ctx), old_nu, (i + 2) >> 1);
        self.set_stats(ctx, s0);
        let mut s = s0;
        let mut flags = (self.flags(ctx) & (0x10 + 0x04 * scale)) + 0x08 * Self::hi(self.sym(s));
        let mut esc_freq = self.summ_freq(ctx).wrapping_sub(self.freq(s));
        let f = (self.freq(s) + scale) >> scale;
        self.set_freq(s, f);
        let mut sum_freq = f;
        while i > 0 {
            s += 6;
            esc_freq = esc_freq.wrapping_sub(self.freq(s));
            let f = (self.freq(s) + scale) >> scale;
            self.set_freq(s, f);
            sum_freq += f;
            flags |= 0x08 * Self::hi(self.sym(s));
            i -= 1;
        }
        self.set_summ_freq(ctx, sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale));
        self.set_flags(ctx, flags);
    }

    fn cut_off(&mut self, ctx: u32, order: u32) -> u32 {
        if self.fault.get() {
            return 0;
        }
        let ns = self.num_stats(ctx);
        if ns == 0 {
            let s = Self::one_state(ctx);
            if self.succ(s) >= self.units_start {
                let v = if order < self.max_order { self.cut_off(self.succ(s), order + 1) } else { 0 };
                self.set_succ(s, v);
                if v != 0 || order <= 9 {
                    return ctx;
                }
            }
            self.special_free_unit(ctx);
            return 0;
        }
        let tmp = (ns + 2) >> 1;
        let st = self.move_units_up(self.stats(ctx), tmp);
        self.set_stats(ctx, st);
        let mut i = ns as i32;
        let mut k = ns as i32;
        while k >= 0 {
            let s = st + k as u32 * 6;
            if self.succ(s) < self.units_start {
                let s2 = st + i as u32 * 6;
                i -= 1;
                self.set_succ(s, 0);
                self.swap_states(s, s2);
            } else if order < self.max_order {
                let v = self.cut_off(self.succ(s), order + 1);
                self.set_succ(s, v);
            } else {
                self.set_succ(s, 0);
            }
            k -= 1;
        }
        if i != ns as i32 && order != 0 {
            self.set_num_stats(ctx, i as u32 & 0xFF);
            let s = st;
            if i < 0 {
                self.free_units(s, tmp);
                self.special_free_unit(ctx);
                return 0;
            }
            if i == 0 {
                let fl = (self.flags(ctx) & 0x10) + 0x08 * Self::hi(self.sym(s));
                self.set_flags(ctx, fl);
                let mut v = self.read_state(s);
                self.free_units(s, tmp);
                v[1] = ((v[1] as u32 + 11) >> 3) as u8;
                self.write_state(Self::one_state(ctx), v);
            } else {
                let scale = (self.summ_freq(ctx) > 16 * i as u32) as u32;
                self.refresh(ctx, tmp, scale);
            }
        }
        ctx
    }

    fn restore_model(&mut self, c1: u32) {
        self.text = self.align;
        let mut c = self.max_context;
        let mut guard = 0;
        while c != c1 {
            let ns = self.num_stats(c).wrapping_sub(1) & 0xFF;
            self.set_num_stats(c, ns);
            if ns == 0 {
                let s = self.stats(c);
                let fl = (self.flags(c) & 0x10) + 0x08 * Self::hi(self.sym(s));
                self.set_flags(c, fl);
                let mut v = self.read_state(s);
                self.special_free_unit(s);
                v[1] = ((v[1] as u32 + 11) >> 3) as u8;
                self.write_state(Self::one_state(c), v);
            } else {
                self.refresh(c, (ns + 3) >> 1, 0);
            }
            c = self.suffix(c);
            guard += 1;
            if guard > MAX_O + 2 || self.fault.get() {
                self.bad();
                return;
            }
        }
        while c != self.min_context {
            let ns = self.num_stats(c);
            if ns == 0 {
                let s = Self::one_state(c);
                let f = self.freq(s);
                self.set_freq(s, f - (f >> 1));
            } else {
                let sf = self.summ_freq(c) + 4;
                self.set_summ_freq(c, sf);
                if sf > 128 + 4 * ns {
                    self.refresh(c, (ns + 2) >> 1, 1);
                }
            }
            c = self.suffix(c);
            guard += 1;
            if guard > 2 * MAX_O + 4 || self.fault.get() {
                self.bad();
                return;
            }
        }
        if self.restore == RestoreMethod::Restart || self.get_used_memory() < (self.size >> 1) {
            self.restart_model();
        } else {
            let mut guard = 0;
            while self.suffix(self.max_context) != 0 {
                self.max_context = self.suffix(self.max_context);
                guard += 1;
                if guard > MAX_O + 2 {
                    self.bad();
                    return;
                }
            }
            let mut rounds = 0;
            loop {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                rounds += 1;
                if self.fault.get() || rounds > 64 {
                    if rounds > 64 {
                        self.bad();
                    }
                    return;
                }
                if self.get_used_memory() <= 3 * (self.size >> 2) {
                    break;
                }
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
    }

    fn create_successors(&mut self, skip: bool, s1: u32, mut c: u32) -> u32 {
        let fs = self.found_state;
        let fsym = self.sym(fs);
        let up_branch = self.succ(fs);
        let mut ps = [0u32; MAX_O + 1];
        let mut num_ps = 0usize;
        let mut s1 = s1;
        if !skip {
            ps[num_ps] = fs;
            num_ps += 1;
        }
        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s;
            if s1 != 0 {
                s = s1;
                s1 = 0;
            } else if self.num_stats(c) != 0 {
                s = self.find_state(c, fsym);
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 1);
                    self.set_summ_freq(c, self.summ_freq(c) + 1);
                }
            } else {
                s = Self::one_state(c);
                let suffix_bin = (self.num_stats(self.suffix(c)) == 0) as u32;
                let f = self.freq(s);
                self.set_freq(s, f + (suffix_bin & (f < 24) as u32));
            }
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
        let flags = 0x10 * Self::hi(fsym) + 0x08 * Self::hi(up_sym);
        let up_freq = if self.num_stats(c) == 0 {
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
                match (cf + 2 * s0).wrapping_sub(3).checked_div(s0) {
                    Some(v) => v,
                    None => {
                        self.bad();
                        0
                    }
                }
            }
        };
        let up = {
            let b = up_succ.to_le_bytes();
            [up_sym as u8, up_freq as u8, b[0], b[1], b[2], b[3]]
        };
        while num_ps != 0 {
            let c1 = self.alloc_context();
            if c1 == 0 {
                return 0;
            }
            self.set_num_stats(c1, 0);
            self.set_flags(c1, flags);
            self.write_state(Self::one_state(c1), up);
            self.set_suffix(c1, c);
            num_ps -= 1;
            self.set_succ(ps[num_ps], c1);
            c = c1;
        }
        c
    }

    fn reduce_order(&mut self, s1: u32, mut c: u32) -> u32 {
        let c1 = c;
        let up_branch = self.text;
        let fsym = self.sym(self.found_state);
        self.set_succ(self.found_state, up_branch);
        self.order_fall += 1;
        let mut s1 = s1;
        let mut s;
        let mut guard = 0;
        loop {
            if s1 != 0 {
                c = self.suffix(c);
                s = s1;
                s1 = 0;
            } else {
                if self.suffix(c) == 0 {
                    return c;
                }
                c = self.suffix(c);
                if self.num_stats(c) != 0 {
                    s = self.find_state(c, fsym);
                    if self.freq(s) < MAX_FREQ - 9 {
                        self.set_freq(s, self.freq(s) + 2);
                        self.set_summ_freq(c, self.summ_freq(c) + 2);
                    }
                } else {
                    s = Self::one_state(c);
                    let f = self.freq(s);
                    self.set_freq(s, f + (f < 32) as u32);
                }
            }
            if self.succ(s) != 0 {
                break;
            }
            self.set_succ(s, up_branch);
            self.order_fall += 1;
            guard += 1;
            if guard > MAX_O + 2 || self.fault.get() {
                self.bad();
                return 0;
            }
        }
        if self.succ(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, 0, c);
            self.set_succ(s, successor);
            self.found_state = s2;
        }
        if self.order_fall == 1 && c1 == self.max_context {
            let v = self.succ(s);
            self.set_succ(self.found_state, v);
            self.text -= 1;
        }
        self.succ(s)
    }

    fn update_model(&mut self) {
        let fs = self.found_state;
        let fsym = self.sym(fs);
        let ffreq = self.freq(fs);
        let mut f_successor = self.succ(fs);
        let mut s = 0u32;

        if ffreq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 0 {
                s = Self::one_state(c);
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s) + 1);
                }
            } else {
                s = self.stats(c);
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

        let max_ctx = self.max_context;
        if self.order_fall == 0 && f_successor != 0 {
            let cs = self.create_successors(true, s, self.min_context);
            if cs == 0 {
                self.set_succ(self.found_state, 0);
                self.restore_model(max_ctx);
            } else {
                self.set_succ(self.found_state, cs);
                self.max_context = cs;
            }
            return;
        }

        self.wr8(self.text, fsym);
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restore_model(max_ctx);
            return;
        }

        if f_successor == 0 {
            let cs = self.reduce_order(s, self.min_context);
            if cs == 0 {
                self.restore_model(max_ctx);
                return;
            }
            f_successor = cs;
        } else if f_successor < self.units_start {
            let cs = self.create_successors(false, s, self.min_context);
            if cs == 0 {
                self.restore_model(max_ctx);
                return;
            }
            f_successor = cs;
        }

        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            successor = f_successor;
            if self.max_context != self.min_context {
                self.text -= 1;
            }
        }

        let ns = self.num_stats(self.min_context);
        let s0 = self
            .summ_freq(self.min_context)
            .wrapping_sub(ns)
            .wrapping_sub(ffreq);
        let flag = 0x08 * Self::hi(fsym);

        let mut c = self.max_context;
        let mut guard = 0;
        while c != self.min_context {
            let ns1 = self.num_stats(c);
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restore_model(c);
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.copy_bytes(ptr, old_ptr, old_nu * UNIT_SIZE);
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                let sf = self.summ_freq(c);
                self.set_summ_freq(c, sf + (3 * ns1 + 1 < ns) as u32);
            } else {
                let p = self.alloc_units(0);
                if p == 0 {
                    self.restore_model(c);
                    return;
                }
                let st = self.read_state(Self::one_state(c));
                self.write_state(p, st);
                self.set_stats(c, p);
                let mut f = self.freq(p);
                if f < MAX_FREQ / 4 - 1 {
                    f <<= 1;
                } else {
                    f = MAX_FREQ - 4;
                }
                self.set_freq(p, f);
                self.set_summ_freq(c, f + self.init_esc + (ns > 2) as u32);
            }
            let sfc = self.summ_freq(c);
            let mut cf = 2 * ffreq * (sfc + 6);
            let sf = s0.wrapping_add(sfc);
            if cf < 6 * sf {
                cf = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                self.set_summ_freq(c, sfc + 4);
            } else {
                cf = 4 + (cf > 9 * sf) as u32 + (cf > 12 * sf) as u32 + (cf > 15 * sf) as u32;
                self.set_summ_freq(c, sfc + cf);
            }
            let p = self.stats(c) + (ns1 + 1) * 6;
            let b = successor.to_le_bytes();
            self.write_state(p, [fsym as u8, cf as u8, b[0], b[1], b[2], b[3]]);
            self.set_flags(c, self.flags(c) | flag);
            self.set_num_stats(c, ns1 + 1);
            c = self.suffix(c);
            guard += 1;
            if guard > MAX_O + 2 || self.fault.get() {
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
        if s != stats {
            let tmp = self.read_state(s);
            let n = s.wrapping_sub(stats) / 6;
            if n > 256 {
                self.bad();
                return;
            }
            self.copy_bytes(stats + 6, stats, n * 6);
            self.write_state(stats, tmp);
            s = stats;
        }
        let mut esc_freq = self.summ_freq(mc).wrapping_sub(self.freq(s));
        let adder = (self.order_fall != 0) as u32;
        let f = (self.freq(s) + 4 + adder) >> 1;
        self.set_freq(s, f);
        let mut sum_freq = f;

        let num_stats = self.num_stats(mc);
        if num_stats == 0 {
            self.bad();
            return;
        }
        let mut i = num_stats;
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
            if new_ns == 0 {
                let mut tmp = self.read_state(stats);
                let mut f = match (2 * tmp[1] as u32 + esc_freq).wrapping_sub(1).checked_div(esc_freq) {
                    Some(v) => v,
                    None => {
                        self.bad();
                        1
                    }
                };
                if f > MAX_FREQ / 3 {
                    f = MAX_FREQ / 3;
                }
                tmp[1] = f as u8;
                let idx = self.u2i((num_stats + 2) >> 1);
                self.insert_node(stats, idx);
                let fl = (self.flags(mc) & 0x10) + 0x08 * Self::hi(tmp[0] as u32);
                self.set_flags(mc, fl);
                self.found_state = Self::one_state(mc);
                self.write_state(self.found_state, tmp);
                return;
            }
            let n0 = (num_stats + 2) >> 1;
            let n1 = (new_ns + 2) >> 1;
            if n0 != n1 {
                let p = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, p);
            }
            let st = self.stats(mc);
            let mut fl = self.flags(mc) & !0x08;
            for k in 0..=new_ns {
                fl |= 0x08 * Self::hi(self.sym(st + k * 6));
            }
            self.set_flags(mc, fl);
        }
        self.set_summ_freq(mc, sum_freq + esc_freq - (esc_freq >> 1));
        self.set_flags(mc, self.flags(mc) | 0x04);
        self.found_state = self.stats(mc);
    }

    fn next_context(&mut self) {
        let c = self.succ(self.found_state);
        if self.order_fall == 0 && c >= self.units_start {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
            self.min_context = self.max_context;
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
        self.prev_success = (2 * self.freq(fs) >= self.summ_freq(mc)) as u32;
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
        self.set_freq(fs, f + (f < 196) as u32);
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let fs = self.found_state;
        let mc = self.min_context;
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        let f = self.freq(fs) + 4;
        self.set_freq(fs, f);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
        self.min_context = self.max_context;
    }

    fn bin_summ_index(&self) -> (usize, usize) {
        let mc = self.min_context;
        let s = Self::one_state(mc);
        let freq = self.freq(s) as usize;
        let i = match self.t.ns2indx.get(freq.wrapping_sub(1)) {
            Some(&v) => v as usize,
            None => {
                self.bad();
                0
            }
        };
        let suffix_ns = self.num_stats(self.suffix(mc)) as usize;
        let j = self.t.ns2bsindx[suffix_ns & 0xFF] as u32
            + self.prev_success
            + self.flags(mc)
            + ((self.run_length >> 26) & 0x20) as u32;
        if i >= 25 || j >= 64 {
            self.bad();
            return (0, 0);
        }
        (i, j as usize)
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 0xFF {
            let row = (self.t.ns2indx[(ns as usize + 2).min(259)] as usize).wrapping_sub(3);
            let suffix_ns = self.num_stats(self.suffix(mc));
            let col = (self.summ_freq(mc) > 11 * (ns + 1)) as u32
                + 2 * (2 * ns < suffix_ns + num_masked) as u32
                + self.flags(mc);
            let col = col as usize;
            if row >= 24 || col >= 32 {
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
        if ns != 0 {
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
            for _ in 0..ns {
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
            rc.decode(hi_cnt, summ - hi_cnt);
            let stats = self.stats(mc);
            for k in 0..=ns {
                char_mask[self.sym(stats + k * 6) as usize] = 0;
            }
        } else {
            let (i, j) = self.bin_summ_index();
            let prob = self.bin_summ[i][j] as u32;
            rc.range >>= 14;
            if rc.range == 0 {
                rc.fault = true;
                return -2;
            }
            if rc.code / rc.range < prob {
                rc.decode(0, prob);
                self.bin_summ[i][j] = (prob + (1 << INT_BITS) - get_mean(prob)) as u16;
                self.found_state = Self::one_state(mc);
                let sym = self.sym(self.found_state);
                self.update_bin();
                return sym as i32;
            }
            rc.decode(prob, BIN_SCALE - prob);
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
            if ns < num_masked {
                self.bad();
                return -2;
            }
            let num = (ns - num_masked) as usize;
            let mut hi_cnt = 0u32;
            let mut n = 0usize;
            let mut s = self.stats(mc);
            for _ in 0..=ns {
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
        if ns != 0 {
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
            for _ in 0..ns {
                s += 6;
                if self.sym(s) as i32 == symbol {
                    rc.encode(sum, self.freq(s), summ);
                    self.found_state = s;
                    self.update1();
                    return;
                }
                sum += self.freq(s);
            }
            let stats = self.stats(mc);
            for k in 0..=ns {
                char_mask[self.sym(stats + k * 6) as usize] = 0;
            }
            rc.encode(sum, summ.wrapping_sub(sum), summ);
        } else {
            let (i, j) = self.bin_summ_index();
            let prob = self.bin_summ[i][j] as u32;
            let s = Self::one_state(mc);
            rc.range >>= 14;
            if self.sym(s) as i32 == symbol {
                rc.range = rc.range.wrapping_mul(prob);
                rc.normalize();
                self.bin_summ[i][j] = (prob + (1 << INT_BITS) - get_mean(prob)) as u16;
                self.found_state = s;
                self.update_bin();
                return;
            }
            rc.low = rc.low.wrapping_add(prob.wrapping_mul(rc.range));
            rc.range = rc.range.wrapping_mul(BIN_SCALE - prob);
            rc.normalize();
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
            for _ in 0..=ns {
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
        assert_eq!(t.ns2indx[3], 3);
        assert_eq!(t.ns2indx[256], 26);
        assert_eq!(t.ns2indx[195], 24);
        assert_eq!(t.indx2units[37], 128);
    }

    #[test]
    fn header_roundtrip() {
        let p = Ppmd8Properties { order: 8, memory_mb: 24, restore: RestoreMethod::CutOff };
        assert_eq!(parse_zip_header(&p.zip_header()).unwrap(), p);
    }
}
