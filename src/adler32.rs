// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone)]
pub struct Adler32 {
    s1: u32,
    s2: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32 {
    pub fn new() -> Self {
        Self { s1: 1, s2: 0 }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let len = bytes.len();
        let mut i = 0;
        while i < len {
            let end = (i + 3800).min(len);
            while i < end {
                self.s1 = (self.s1 + bytes[i] as u32) % 65521;
                self.s2 = (self.s2 + self.s1) % 65521;
                i += 1;
            }
        }
    }

    pub fn value(&self) -> u32 {
        (self.s2 << 16) | self.s1
    }
}

pub fn adler32(bytes: &[u8]) -> u32 {
    let mut adler = Adler32::new();
    adler.update(bytes);
    adler.value()
}