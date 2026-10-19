// SPDX-License-Identifier: MIT OR Apache-2.0
//! CRC-16/ARC (a.k.a. CRC-16/IBM, LHA's CRC): reflected polynomial 0x8005
//! (0xA001 in reflected form), initial value 0, no final XOR. Check value
//! for "123456789" is 0xBB3D (the standard CRC catalogue entry).

const fn make_table() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xA001 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u16; 256] = make_table();

/// Continue a CRC-16/ARC over `bytes` from `crc` (start with 0).
pub fn crc16_arc_update(crc: u16, bytes: &[u8]) -> u16 {
    let mut c = crc;
    for &b in bytes {
        c = (c >> 8) ^ TABLE[usize::from((c ^ u16::from(b)) as u8)];
    }
    c
}

/// CRC-16/ARC of `bytes`.
pub fn crc16_arc(bytes: &[u8]) -> u16 {
    crc16_arc_update(0, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value() {
        assert_eq!(crc16_arc(b"123456789"), 0xBB3D);
        assert_eq!(crc16_arc(b""), 0);
        assert_eq!(crc16_arc_update(crc16_arc(b"1234"), b"56789"), 0xBB3D);
    }
}
