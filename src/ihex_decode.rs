use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub address: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexImage {
    pub segments: Vec<Segment>,
    pub start_segment: Option<(u16, u16)>,
    pub start_linear: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IhexError {
    MissingColon,
    BadHex,
    BadLength,
    BadChecksum,
    BadRecordType,
    BadRecord,
    MissingEof,
    DataAfterEof,
    Overlap,
    AddressOverflow,
    LimitExceeded,
}

impl fmt::Display for IhexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IhexError::MissingColon => write!(f, "MissingColon"),
            IhexError::BadHex => write!(f, "BadHex"),
            IhexError::BadLength => write!(f, "BadLength"),
            IhexError::BadChecksum => write!(f, "BadChecksum"),
            IhexError::BadRecordType => write!(f, "BadRecordType"),
            IhexError::BadRecord => write!(f, "BadRecord"),
            IhexError::MissingEof => write!(f, "MissingEof"),
            IhexError::DataAfterEof => write!(f, "DataAfterEof"),
            IhexError::Overlap => write!(f, "Overlap"),
            IhexError::AddressOverflow => write!(f, "AddressOverflow"),
            IhexError::LimitExceeded => write!(f, "LimitExceeded"),
        }
    }
}

pub fn decode_ihex(input: &[u8], max_output: usize) -> Result<HexImage, IhexError> {
    let s = std::str::from_utf8(input).map_err(|_| IhexError::BadHex)?;
    let lines: Vec<&str> = s.lines().collect();

    let mut base: u64 = 0;
    let mut start_segment: Option<(u16, u16)> = None;
    let mut start_linear: Option<u32> = None;
    let mut eof_seen = false;
    let mut data_records: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut total_data_bytes: usize = 0;

    for line_raw in &lines {
        let mut line = *line_raw;
        // Remove one trailing \r
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        // Remove trailing spaces/tabs
        let line = line.trim_end_matches(|c: char| c == ' ' || c == '\t');

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // If EOF already seen, any further non-empty line is DataAfterEof
        if eof_seen {
            return Err(IhexError::DataAfterEof);
        }

        // First byte must be ':'
        let bytes = line.as_bytes();
        if bytes.is_empty() || bytes[0] != b':' {
            return Err(IhexError::MissingColon);
        }

        // Rest must be even number of hex digits
        let hex_str = &line[1..];
        if hex_str.len() % 2 != 0 {
            return Err(IhexError::BadHex);
        }

        let mut decoded: Vec<u8> = Vec::with_capacity(hex_str.len() / 2);
        for i in (0..hex_str.len()).step_by(2) {
            let hi = hex_char_to_nibble(hex_str.as_bytes()[i])?;
            let lo = hex_char_to_nibble(hex_str.as_bytes()[i + 1])?;
            decoded.push((hi << 4) | lo);
        }

        // b.len() < 5 or b.len() != b[0] as usize + 5
        let b_len = decoded.len();
        if b_len < 5 || b_len != decoded[0] as usize + 5 {
            return Err(IhexError::BadLength);
        }

        // Checksum: wrapping u8 sum of all bytes must be 0
        let checksum: u8 = decoded.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if checksum != 0 {
            return Err(IhexError::BadChecksum);
        }

        let record_type = decoded[3];
        if record_type > 5 {
            return Err(IhexError::BadRecordType);
        }

        let offset: u16 = u16::from_be_bytes([decoded[1], decoded[2]]);
        let data = &decoded[4..b_len - 1];

        match record_type {
            0 => {
                // Data record
                let address = base + offset as u64;
                if address + data.len() as u64 > (1u64 << 32) {
                    return Err(IhexError::AddressOverflow);
                }
                if total_data_bytes + data.len() > max_output {
                    return Err(IhexError::LimitExceeded);
                }
                total_data_bytes += data.len();
                if !data.is_empty() {
                    data_records.push((address, data.to_vec()));
                }
            }
            1 => {
                // EOF
                if data.len() != 0 {
                    return Err(IhexError::BadRecord);
                }
                eof_seen = true;
            }
            2 => {
                // Extended segment address
                if data.len() != 2 {
                    return Err(IhexError::BadRecord);
                }
                let seg_addr = u16::from_be_bytes([data[0], data[1]]);
                base = (seg_addr as u64) << 4;
            }
            4 => {
                // Extended linear address
                if data.len() != 2 {
                    return Err(IhexError::BadRecord);
                }
                let lin_addr = u16::from_be_bytes([data[0], data[1]]);
                base = (lin_addr as u64) << 16;
            }
            3 => {
                // Start segment address
                if data.len() != 4 {
                    return Err(IhexError::BadRecord);
                }
                let cs = u16::from_be_bytes([data[0], data[1]]);
                let ip = u16::from_be_bytes([data[2], data[3]]);
                start_segment = Some((cs, ip));
            }
            5 => {
                // Start linear address
                if data.len() != 4 {
                    return Err(IhexError::BadRecord);
                }
                let eip = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                start_linear = Some(eip);
            }
            _ => {
                // Should not reach here since we checked record_type > 5 above
                return Err(IhexError::BadRecordType);
            }
        }
    }

    if !eof_seen {
        return Err(IhexError::MissingEof);
    }

    // Sort data records by address
    data_records.sort_by_key(|(addr, _)| *addr);

    // Merge into contiguous segments
    let mut segments: Vec<Segment> = Vec::new();
    for (addr, data) in data_records {
        let addr_u32 = addr as u32;
        if segments.is_empty() {
            segments.push(Segment {
                address: addr_u32,
                data,
            });
        } else {
            let last = segments.last_mut().unwrap();
            let last_end = last.address as u64 + last.data.len() as u64;
            if addr == last_end {
                // Extend the last segment
                last.data.extend_from_slice(&data);
            } else if addr > last_end {
                // New segment
                segments.push(Segment {
                    address: addr_u32,
                    data,
                });
            } else {
                // Overlap
                return Err(IhexError::Overlap);
            }
        }
    }

    Ok(HexImage {
        segments,
        start_segment,
        start_linear,
    })
}

fn hex_char_to_nibble(c: u8) -> Result<u8, IhexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(IhexError::BadHex),
    }
}
