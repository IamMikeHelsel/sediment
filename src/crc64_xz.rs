// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone)]
pub struct Crc64Xz {
    crc: u64,
}

impl Default for Crc64Xz {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64Xz {
    pub fn new() -> Self {
        Self { crc: 0xFFFFFFFFFFFFFFFF }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.crc;
        for &byte in bytes {
            crc ^= byte as u64;
            for _ in 0..8 {
                if crc & 1 == 1 {
                    crc = (crc >> 1) ^ 0xC96C5795D7870F42;
                } else {
                    crc >>= 1;
                }
            }
        }
        self.crc = crc;
    }

    pub fn value(&self) -> u64 {
        self.crc ^ 0xFFFFFFFFFFFFFFFF
    }
}

pub fn crc64_xz(bytes: &[u8]) -> u64 {
    let mut crc = Crc64Xz::new();
    crc.update(bytes);
    crc.value()
}