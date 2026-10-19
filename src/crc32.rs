// SPDX-License-Identifier: MIT OR Apache-2.0
#[derive(Clone, Debug)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self { state: 0xFFFFFFFF }
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // Convert byte to u32 and XOR into the low 8 bits of the accumulator
            let mut crc = self.state ^ (byte as u32);
            
            // Process 8 bits for this byte
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
            
            self.state = crc;
        }
    }

    pub fn finalize(self) -> u32 {
        self.state ^ 0xFFFFFFFF
    }
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finalize()
}