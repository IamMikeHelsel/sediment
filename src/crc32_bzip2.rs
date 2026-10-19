// SPDX-License-Identifier: MIT OR Apache-2.0

/// CRC-32/BZIP2 checksum implementation.
///
/// This implements the CRC-32 variant used by bzip2 blocks.
/// Polynomial: 0x04C11DB7 (MSB-first, non-reflected)
/// Initial: 0xFFFFFFFF
/// Final XOR: 0xFFFFFFFF
#[derive(Debug, Clone)]
pub struct Crc32Bzip2 {
    crc: u32,
}

impl Default for Crc32Bzip2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32Bzip2 {
    /// Creates a new CRC-32/BZIP2 instance with the initial value.
    pub fn new() -> Self {
        Self {
            crc: 0xFFFFFFFF,
        }
    }

    /// Updates the CRC with the given bytes.
    ///
    /// Each byte is processed in its ordinary bit order (MSB first),
    /// starting from the high end of the register.
    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // XOR input byte into high 8 bits of CRC register
            self.crc ^= (byte as u32) << 24;
            
            // Process 8 bits
            for _ in 0..8 {
                // Test MSB (bit 31) BEFORE shifting
                let msb = (self.crc >> 31) & 1;
                
                // Shift left by 1
                self.crc <<= 1;
                
                // If MSB was set, XOR with polynomial
                if msb == 1 {
                    self.crc ^= 0x04C11DB7;
                }
            }
        }
    }

    /// Returns the final CRC value.
    ///
    /// This applies the final XOR with 0xFFFFFFFF and returns the result.
    /// Repeated calls return the same value.
    pub fn value(&self) -> u32 {
        self.crc ^ 0xFFFFFFFF
    }
}

/// Computes the CRC-32/BZIP2 checksum of the given bytes.
///
/// This is a convenience function that creates a new instance,
/// updates it with the bytes, and returns the final value.
pub fn crc32_bzip2(bytes: &[u8]) -> u32 {
    let mut crc = Crc32Bzip2::new();
    crc.update(bytes);
    crc.value()
}