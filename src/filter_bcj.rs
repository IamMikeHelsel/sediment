// SPDX-License-Identifier: MIT OR Apache-2.0

//! Branch/call/jump (BCJ) converter filters for executable code.
//!
//! Implements the "simple" branch converters used by the .xz format and by
//! 7z archives: x86, PowerPC, IA-64, ARM, ARM-Thumb, SPARC, ARM64 and RISC-V.
//! Each converter rewrites relative branch targets into absolute ones when
//! encoding (so repeated calls to the same function produce identical bytes)
//! and back again when decoding. Sizes never change.
//!
//! Sources: the .xz file format specification (filter IDs 0x04..0x0B,
//! Filter Properties = optional 32-bit little-endian start offset that must be
//! a multiple of the filter's alignment), the 7z format documentation
//! (method IDs 03 03 xx xx and 0A/0B), the instruction set manuals for the
//! respective architectures (encodings of x86 CALL/JMP rel32, ARM BL, Thumb-2
//! BL pairs, PowerPC `bl`, SPARC `call`, IA-64 bundle templates and IP-relative
//! branches, ARM64 BL/ADRP, RISC-V JAL/AUIPC), and the public-domain XZ Utils
//! documentation of the conversion rules. No 7-Zip source was used.
//! Outputs are verified differentially against liblzma (Python `lzma` and the
//! `xz` tool) by the fixtures in `tests/fixtures/filters/`.
//!
//! Low-level API: [`BcjCoder::convert`] converts a buffer in place and returns
//! how many leading bytes are final. The caller must present the remaining
//! bytes again (followed by more data) on the next call; at end of input the
//! unconverted tail is passed through unchanged. [`BcjStream`] wraps this for
//! chunked input, and [`bcj_encode`]/[`bcj_decode`] are one-shot helpers.
//! All position arithmetic wraps modulo 2^32, as in the reference format.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcjError {
    /// Start offset is not a multiple of the architecture's alignment.
    UnalignedStartOffset,
    /// Filter properties have an invalid length.
    InvalidProperties,
    /// Unknown filter or method identifier.
    UnsupportedFilter,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcjArch {
    X86,
    PowerPc,
    Ia64,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
    RiscV,
}

impl BcjArch {
    /// All supported architectures.
    pub const ALL: [BcjArch; 8] = [
        BcjArch::X86,
        BcjArch::PowerPc,
        BcjArch::Ia64,
        BcjArch::Arm,
        BcjArch::ArmThumb,
        BcjArch::Sparc,
        BcjArch::Arm64,
        BcjArch::RiscV,
    ];

    /// Required alignment of the start offset (and instruction alignment).
    pub fn alignment(self) -> u32 {
        match self {
            BcjArch::X86 => 1,
            BcjArch::ArmThumb | BcjArch::RiscV => 2,
            BcjArch::PowerPc | BcjArch::Arm | BcjArch::Sparc | BcjArch::Arm64 => 4,
            BcjArch::Ia64 => 16,
        }
    }

    /// Maximum number of trailing bytes a single `convert` call may leave
    /// unprocessed.
    pub fn max_lookahead(self) -> usize {
        match self {
            BcjArch::X86 => 4,
            BcjArch::PowerPc | BcjArch::Arm | BcjArch::ArmThumb | BcjArch::Sparc | BcjArch::Arm64 => 3,
            BcjArch::Ia64 => 15,
            BcjArch::RiscV => 7,
        }
    }

    /// .xz filter ID (xz file format spec, section 5.3).
    pub fn xz_filter_id(self) -> u64 {
        match self {
            BcjArch::X86 => 0x04,
            BcjArch::PowerPc => 0x05,
            BcjArch::Ia64 => 0x06,
            BcjArch::Arm => 0x07,
            BcjArch::ArmThumb => 0x08,
            BcjArch::Sparc => 0x09,
            BcjArch::Arm64 => 0x0A,
            BcjArch::RiscV => 0x0B,
        }
    }

    pub fn from_xz_filter_id(id: u64) -> Result<BcjArch, BcjError> {
        BcjArch::ALL
            .iter()
            .copied()
            .find(|a| a.xz_filter_id() == id)
            .ok_or(BcjError::UnsupportedFilter)
    }

    /// 7z coder method ID (big-endian method ID bytes as an integer).
    pub fn sevenz_method_id(self) -> u64 {
        match self {
            BcjArch::X86 => 0x0303_0103,
            BcjArch::PowerPc => 0x0303_0205,
            BcjArch::Ia64 => 0x0303_0401,
            BcjArch::Arm => 0x0303_0501,
            BcjArch::ArmThumb => 0x0303_0701,
            BcjArch::Sparc => 0x0303_0805,
            BcjArch::Arm64 => 0x0A,
            BcjArch::RiscV => 0x0B,
        }
    }

    pub fn from_sevenz_method_id(id: u64) -> Result<BcjArch, BcjError> {
        BcjArch::ALL
            .iter()
            .copied()
            .find(|a| a.sevenz_method_id() == id)
            .ok_or(BcjError::UnsupportedFilter)
    }
}

/// Parse BCJ filter properties (xz Filter Properties or 7z coder properties):
/// empty means start offset 0; four bytes are a little-endian start offset
/// that must be a multiple of the architecture's alignment.
pub fn parse_bcj_properties(arch: BcjArch, props: &[u8]) -> Result<u32, BcjError> {
    let offset = match props.len() {
        0 => 0,
        4 => u32::from_le_bytes([props[0], props[1], props[2], props[3]]),
        _ => return Err(BcjError::InvalidProperties),
    };
    check_start_offset(arch, offset)?;
    Ok(offset)
}

fn check_start_offset(arch: BcjArch, start_offset: u32) -> Result<(), BcjError> {
    if !start_offset.is_multiple_of(arch.alignment()) {
        return Err(BcjError::UnalignedStartOffset);
    }
    Ok(())
}

/// Persistent x86 converter state (tracks recent E8/E9 candidates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86State {
    prev_mask: u32,
    prev_pos: u32,
}

impl X86State {
    pub fn new(start_offset: u32) -> X86State {
        X86State {
            prev_mask: 0,
            prev_pos: start_offset.wrapping_sub(5),
        }
    }
}

/// In-place branch converter for one architecture and direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcjCoder {
    arch: BcjArch,
    encoding: bool,
    pos: u32,
    x86: X86State,
}

impl BcjCoder {
    pub fn new(arch: BcjArch, start_offset: u32, encoding: bool) -> Result<BcjCoder, BcjError> {
        check_start_offset(arch, start_offset)?;
        Ok(BcjCoder {
            arch,
            encoding,
            pos: start_offset,
            x86: X86State::new(start_offset),
        })
    }

    pub fn arch(&self) -> BcjArch {
        self.arch
    }

    pub fn is_encoder(&self) -> bool {
        self.encoding
    }

    /// Stream position (start offset plus bytes finalized so far, mod 2^32).
    pub fn position(&self) -> u32 {
        self.pos
    }

    /// Convert `buf` in place. Returns the number of leading bytes that are
    /// final; the remaining (at most `arch.max_lookahead()`) bytes must be
    /// presented again at the start of the next call, or passed through
    /// unchanged at end of input.
    pub fn convert(&mut self, buf: &mut [u8]) -> usize {
        let done = match self.arch {
            BcjArch::X86 => x86_convert(buf, self.pos, &mut self.x86, self.encoding),
            BcjArch::PowerPc => powerpc_convert(buf, self.pos, self.encoding),
            BcjArch::Ia64 => ia64_convert(buf, self.pos, self.encoding),
            BcjArch::Arm => arm_convert(buf, self.pos, self.encoding),
            BcjArch::ArmThumb => armthumb_convert(buf, self.pos, self.encoding),
            BcjArch::Sparc => sparc_convert(buf, self.pos, self.encoding),
            BcjArch::Arm64 => arm64_convert(buf, self.pos, self.encoding),
            BcjArch::RiscV => {
                if self.encoding {
                    riscv_encode(buf, self.pos)
                } else {
                    riscv_decode(buf, self.pos)
                }
            }
        };
        let done = done.min(buf.len());
        self.pos = self.pos.wrapping_add(done as u32);
        done
    }
}

/// Chunked BCJ filter: feed input with [`BcjStream::update`], then call
/// [`BcjStream::finish`]. The output is identical regardless of chunking.
#[derive(Debug, Clone)]
pub struct BcjStream {
    coder: BcjCoder,
    pending: [u8; 16],
    pending_len: usize,
    produced: usize,
    max_output: usize,
}

impl BcjStream {
    pub fn new(arch: BcjArch, start_offset: u32, encoding: bool, max_output: usize) -> Result<BcjStream, BcjError> {
        Ok(BcjStream {
            coder: BcjCoder::new(arch, start_offset, encoding)?,
            pending: [0; 16],
            pending_len: 0,
            produced: 0,
            max_output,
        })
    }

    /// Total bytes appended to output so far.
    pub fn total_out(&self) -> usize {
        self.produced
    }

    /// Filter `input`, appending finalized bytes to `out`.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), BcjError> {
        if input.is_empty() {
            return Ok(());
        }
        let total = self
            .pending_len
            .checked_add(input.len())
            .ok_or(BcjError::LimitExceeded)?;
        if self.produced.checked_add(total).is_none_or(|t| t > self.max_output) {
            // Only bytes that will eventually be output count; the total
            // stream length is produced + pending + input.
            return Err(BcjError::LimitExceeded);
        }
        out.try_reserve(total).map_err(|_| BcjError::Allocation)?;
        let start = out.len();
        out.extend_from_slice(&self.pending[..self.pending_len]);
        out.extend_from_slice(input);
        let done = self.coder.convert(&mut out[start..]);
        let rest = total - done;
        // The converters never leave more than max_lookahead (<= 15) bytes.
        debug_assert!(rest <= self.coder.arch.max_lookahead());
        let rest = rest.min(self.pending.len());
        let tail_start = out.len() - rest;
        self.pending[..rest].copy_from_slice(&out[tail_start..]);
        self.pending_len = rest;
        out.truncate(tail_start);
        self.produced += tail_start - start;
        Ok(())
    }

    /// Flush the unconvertible tail unchanged.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), BcjError> {
        let n = self.pending_len;
        out.try_reserve(n).map_err(|_| BcjError::Allocation)?;
        out.extend_from_slice(&self.pending[..n]);
        self.pending_len = 0;
        self.produced += n;
        Ok(())
    }
}

fn one_shot(arch: BcjArch, start_offset: u32, input: &[u8], max_output: usize, encoding: bool) -> Result<Vec<u8>, BcjError> {
    let mut coder = BcjCoder::new(arch, start_offset, encoding)?;
    if input.len() > max_output {
        return Err(BcjError::LimitExceeded);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(input.len()).map_err(|_| BcjError::Allocation)?;
    out.extend_from_slice(input);
    coder.convert(&mut out);
    Ok(out)
}

/// Apply the encoder (relative to absolute) to a complete buffer.
pub fn bcj_encode(arch: BcjArch, start_offset: u32, input: &[u8], max_output: usize) -> Result<Vec<u8>, BcjError> {
    one_shot(arch, start_offset, input, max_output, true)
}

/// Apply the decoder (absolute to relative) to a complete buffer.
pub fn bcj_decode(arch: BcjArch, start_offset: u32, input: &[u8], max_output: usize) -> Result<Vec<u8>, BcjError> {
    one_shot(arch, start_offset, input, max_output, false)
}

/// Convert a complete buffer in place.
pub fn bcj_convert_in_place(arch: BcjArch, start_offset: u32, buf: &mut [u8], encoding: bool) -> Result<(), BcjError> {
    let mut coder = BcjCoder::new(arch, start_offset, encoding)?;
    coder.convert(buf);
    Ok(())
}

#[inline]
fn read32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[inline]
fn write32le(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn read32be(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[inline]
fn write32be(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn x86_ms_byte(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

/// x86: E8 (CALL rel32) and E9 (JMP rel32) whose 32-bit operand's most
/// significant byte is 0x00 or 0xFF. A small history mask of recent E8/E9
/// bytes suppresses conversions that are likely to be false positives.
pub fn x86_convert(buf: &mut [u8], now_pos: u32, state: &mut X86State, encoding: bool) -> usize {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

    let size = buf.len();
    if size < 5 {
        return 0;
    }
    let mut prev_mask = state.prev_mask;
    let mut prev_pos = state.prev_pos;
    if now_pos.wrapping_sub(prev_pos) > 5 {
        prev_pos = now_pos.wrapping_sub(5);
    }

    let limit = size - 5;
    let mut i = 0usize;
    while i <= limit {
        let b = buf[i];
        if b != 0xE8 && b != 0xE9 {
            i += 1;
            continue;
        }
        let here = now_pos.wrapping_add(i as u32);
        let offset = here.wrapping_sub(prev_pos);
        prev_pos = here;
        if offset > 5 {
            prev_mask = 0;
        } else {
            for _ in 0..offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }

        let b4 = buf[i + 4];
        if x86_ms_byte(b4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
            let mut src = (b4 as u32) << 24 | (buf[i + 3] as u32) << 16 | (buf[i + 2] as u32) << 8 | buf[i + 1] as u32;
            let mut dest;
            loop {
                let pc = here.wrapping_add(5);
                dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) };
                if prev_mask == 0 {
                    break;
                }
                let idx = BIT_NUMBER[(prev_mask >> 1) as usize & 7];
                let probe = (dest >> (24 - idx * 8)) as u8;
                if !x86_ms_byte(probe) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - idx * 8)) - 1);
            }
            let top = ((dest >> 24) & 1).wrapping_sub(1);
            buf[i + 4] = !(top as u8);
            buf[i + 3] = (dest >> 16) as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 1] = dest as u8;
            i += 5;
            prev_mask = 0;
        } else {
            i += 1;
            prev_mask |= 1;
            if x86_ms_byte(b4) {
                prev_mask |= 0x10;
            }
        }
    }

    state.prev_mask = prev_mask;
    state.prev_pos = prev_pos;
    i
}

/// PowerPC (big-endian): `bl` = opcode 18 with AA=0, LK=1.
pub fn powerpc_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if (buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1 {
            let src = read32be(buf, i) & 0x03FF_FFFC;
            let pc = now_pos.wrapping_add(i as u32);
            let dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) };
            write32be(buf, i, 0x4800_0000 | (dest & 0x03FF_FFFC) | 1);
        }
        i += 4;
    }
    i
}

/// IA-64: 128-bit bundles; IP-relative branch slots selected by template.
pub fn ia64_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    const BRANCH_TABLE: [u32; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
    ];
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        let mask = BRANCH_TABLE[(buf[i] & 0x1F) as usize];
        let mut bit_pos = 5u32;
        for slot in 0..3 {
            if (mask >> slot) & 1 != 0 {
                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 7;
                let mut instruction: u64 = 0;
                for j in 0..6 {
                    instruction |= (buf[i + j + byte_pos] as u64) << (8 * j);
                }
                let mut norm = instruction >> bit_res;
                if ((norm >> 37) & 0xF) == 0x5 && ((norm >> 9) & 0x7) == 0 {
                    let mut src = ((norm >> 13) & 0xF_FFFF) as u32;
                    src |= (((norm >> 36) & 1) as u32) << 20;
                    src <<= 4;
                    let pc = now_pos.wrapping_add(i as u32);
                    let mut dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) };
                    dest >>= 4;
                    norm &= !(0x8F_FFFFu64 << 13);
                    norm |= ((dest & 0xF_FFFF) as u64) << 13;
                    norm |= ((dest & 0x10_0000) as u64) << (36 - 20);
                    instruction &= (1u64 << bit_res) - 1;
                    instruction |= norm << bit_res;
                    for j in 0..6 {
                        buf[i + j + byte_pos] = (instruction >> (8 * j)) as u8;
                    }
                }
            }
            bit_pos += 41;
        }
        i += 16;
    }
    i
}

/// ARM (little-endian): BL with condition AL (top byte 0xEB).
pub fn arm_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i + 3] == 0xEB {
            let src = ((buf[i + 2] as u32) << 16 | (buf[i + 1] as u32) << 8 | buf[i] as u32) << 2;
            let pc = now_pos.wrapping_add(i as u32).wrapping_add(8);
            let dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) } >> 2;
            buf[i + 2] = (dest >> 16) as u8;
            buf[i + 1] = (dest >> 8) as u8;
            buf[i] = dest as u8;
        }
        i += 4;
    }
    i
}

/// ARM-Thumb (little-endian): 32-bit BL as two 16-bit halves (F000/F800).
pub fn armthumb_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if (buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8 {
            let src = (((buf[i + 1] as u32) & 7) << 19
                | (buf[i] as u32) << 11
                | ((buf[i + 3] as u32) & 7) << 8
                | buf[i + 2] as u32)
                << 1;
            let pc = now_pos.wrapping_add(i as u32).wrapping_add(4);
            let dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) } >> 1;
            buf[i + 1] = 0xF0 | ((dest >> 19) & 7) as u8;
            buf[i] = (dest >> 11) as u8;
            buf[i + 3] = 0xF8 | ((dest >> 8) & 7) as u8;
            buf[i + 2] = dest as u8;
            i += 4;
        } else {
            i += 2;
        }
    }
    i
}

/// SPARC (big-endian): `call` with a displacement that fits in 23 bits.
pub fn sparc_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if (buf[i] == 0x40 && (buf[i + 1] & 0xC0) == 0x00) || (buf[i] == 0x7F && (buf[i + 1] & 0xC0) == 0xC0) {
            let src = read32be(buf, i) << 2;
            let pc = now_pos.wrapping_add(i as u32);
            let mut dest = if encoding { src.wrapping_add(pc) } else { src.wrapping_sub(pc) } >> 2;
            dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3FFF_FFFF) | (dest & 0x3F_FFFF) | 0x4000_0000;
            write32be(buf, i, dest);
        }
        i += 4;
    }
    i
}

/// ARM64 (little-endian): BL (26-bit word offset) and ADRP (only when the
/// page offset is within +-512 MiB, i.e. bits 20..18 of the 21-bit immediate
/// are a sign extension of bit 17).
pub fn arm64_convert(buf: &mut [u8], now_pos: u32, encoding: bool) -> usize {
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        let mut instr = read32le(buf, i);
        let pc = now_pos.wrapping_add(i as u32);
        if (instr >> 26) == 0x25 {
            let mut p = pc >> 2;
            if !encoding {
                p = 0u32.wrapping_sub(p);
            }
            instr = 0x9400_0000 | (instr.wrapping_add(p) & 0x03FF_FFFF);
            write32le(buf, i, instr);
        } else if (instr & 0x9F00_0000) == 0x9000_0000 {
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
            if (src.wrapping_add(0x0002_0000) & 0x001C_0000) == 0 {
                let mut p = pc >> 12;
                if !encoding {
                    p = 0u32.wrapping_sub(p);
                }
                let dest = src.wrapping_add(p);
                instr &= 0x9000_001F;
                instr |= (dest & 3) << 29;
                instr |= (dest & 0x0003_FFFC) << 3;
                instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
                write32le(buf, i, instr);
            }
        }
        i += 4;
    }
    i
}

/// RISC-V encoder. Converts JAL with rd = x1/x5, and AUIPC+(I/S-type) pairs
/// whose second instruction uses AUIPC's rd as rs1. A converted pair is
/// stored as a marker AUIPC with rd = x2 carrying the second instruction's
/// low 20 bits, followed by the big-endian absolute address. Genuine AUIPC
/// x0/x2 instructions that would look like a marker are escaped by swapping
/// fields so the decoder's AUIPC-pair path restores them.
fn riscv_encode(buf: &mut [u8], now_pos: u32) -> usize {
    let len = buf.len();
    if len < 8 {
        return 0;
    }
    let last = len - 8;
    let mut i = 0usize;
    while i <= last {
        let b0 = buf[i] as u32;
        if b0 == 0xEF {
            let b1 = buf[i + 1] as u32;
            if (b1 & 0x0D) != 0 {
                i += 2;
                continue;
            }
            let b2 = buf[i + 2] as u32;
            let b3 = buf[i + 3] as u32;
            let pc = now_pos.wrapping_add(i as u32);
            let mut addr = ((b1 & 0xF0) << 8)
                | ((b2 & 0x0F) << 16)
                | ((b2 & 0x10) << 7)
                | ((b2 & 0xE0) >> 4)
                | ((b3 & 0x7F) << 4)
                | ((b3 & 0x80) << 13);
            addr = addr.wrapping_add(pc);
            buf[i + 1] = ((b1 & 0x0F) | ((addr >> 13) & 0xF0)) as u8;
            buf[i + 2] = (addr >> 9) as u8;
            buf[i + 3] = (addr >> 1) as u8;
            i += 4;
        } else if (b0 & 0x7F) == 0x17 {
            let mut inst = read32le(buf, i);
            let inst2;
            if inst & 0xE80 != 0 {
                // rd is neither x0 nor x2: candidate real pair.
                inst2 = read32le(buf, i + 4);
                if ((inst << 8) ^ inst2.wrapping_sub(3)) & 0xF_8003 != 0 {
                    i += 6;
                    continue;
                }
                let mut addr = (inst & 0xFFFF_F000).wrapping_add(((inst2 as i32) >> 20) as u32);
                addr = addr.wrapping_add(now_pos.wrapping_add(i as u32));
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                write32le(buf, i, inst);
                write32be(buf, i + 4, addr);
            } else {
                // rd is x0 or x2: escape if the decoder would see a marker.
                let fake_rs1 = inst >> 27;
                if (inst.wrapping_sub(0x3117) << 18) >= (fake_rs1 & 0x1D) {
                    i += 4;
                    continue;
                }
                inst2 = read32le(buf, i + 4);
                let new_inst = 0x17 | (fake_rs1 << 7) | (inst2 & 0xFFFF_F000);
                let new_inst2 = (inst >> 12) | (inst2 << 20);
                write32le(buf, i, new_inst);
                write32le(buf, i + 4, new_inst2);
            }
            i += 8;
        } else {
            i += 2;
        }
    }
    i
}

/// RISC-V decoder (inverse of [`riscv_encode`]).
fn riscv_decode(buf: &mut [u8], now_pos: u32) -> usize {
    let len = buf.len();
    if len < 8 {
        return 0;
    }
    let last = len - 8;
    let mut i = 0usize;
    while i <= last {
        let b0 = buf[i] as u32;
        if b0 == 0xEF {
            let b1 = buf[i + 1] as u32;
            if (b1 & 0x0D) != 0 {
                i += 2;
                continue;
            }
            let b2 = buf[i + 2] as u32;
            let b3 = buf[i + 3] as u32;
            let pc = now_pos.wrapping_add(i as u32);
            let mut addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
            addr = addr.wrapping_sub(pc);
            buf[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
            buf[i + 2] = (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
            buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
            i += 4;
        } else if (b0 & 0x7F) == 0x17 {
            let mut inst = read32le(buf, i);
            let mut inst2;
            if inst & 0xE80 != 0 {
                // Escaped genuine AUIPC x0/x2: undo the field swap.
                inst2 = read32le(buf, i + 4);
                if ((inst << 8) ^ inst2.wrapping_sub(3)) & 0xF_8003 != 0 {
                    i += 6;
                    continue;
                }
                let addr = (inst & 0xFFFF_F000).wrapping_add(inst2 >> 20);
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                inst2 = addr;
            } else {
                let inst2_rs1 = inst >> 27;
                if (inst.wrapping_sub(0x3117) << 18) >= (inst2_rs1 & 0x1D) {
                    i += 4;
                    continue;
                }
                let addr = read32be(buf, i + 4).wrapping_sub(now_pos.wrapping_add(i as u32));
                inst2 = (inst >> 12) | (addr << 20);
                inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
            }
            write32le(buf, i, inst);
            write32le(buf, i + 4, inst2);
            i += 8;
        } else {
            i += 2;
        }
    }
    i
}
