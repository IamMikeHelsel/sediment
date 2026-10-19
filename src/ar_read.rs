use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArEntry {
    pub name: Vec<u8>,
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub data_offset: usize,
    pub data_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArError {
    BadMagic,
    Truncated,
    BadHeader,
    BadNumber,
    BadName,
    TooManyEntries,
}

impl fmt::Display for ArError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArError::BadMagic => write!(f, "BadMagic"),
            ArError::Truncated => write!(f, "Truncated"),
            ArError::BadHeader => write!(f, "BadHeader"),
            ArError::BadNumber => write!(f, "BadNumber"),
            ArError::BadName => write!(f, "BadName"),
            ArError::TooManyEntries => write!(f, "TooManyEntries"),
        }
    }
}

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER_SIZE: usize = 60;
const FMAG: [u8; 2] = [b'`', b'\n'];

fn trim_end_spaces(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && s[end - 1] == b' ' {
        end -= 1;
    }
    &s[..end]
}

fn parse_decimal_unsigned(s: &[u8]) -> Result<u64, ArError> {
    let trimmed = trim_end_spaces(s);
    if trimmed.is_empty() {
        return Ok(0);
    }
    if !trimmed.iter().all(|b| b.is_ascii_digit()) {
        return Err(ArError::BadNumber);
    }
    let val = u64::from_str_radix(
        &String::from_utf8_lossy(trimmed),
        10,
    )
    .map_err(|_| ArError::BadNumber)?;
    Ok(val)
}

fn parse_octal_unsigned(s: &[u8]) -> Result<u32, ArError> {
    let trimmed = trim_end_spaces(s);
    if trimmed.is_empty() {
        return Ok(0);
    }
    if !trimmed.iter().all(|b| b.is_ascii_digit()) {
        return Err(ArError::BadNumber);
    }
    let val = u32::from_str_radix(
        &String::from_utf8_lossy(trimmed),
        8,
    )
    .map_err(|_| ArError::BadNumber)?;
    Ok(val)
}

fn parse_decimal_usize(s: &[u8]) -> Result<usize, ArError> {
    let trimmed = trim_end_spaces(s);
    if trimmed.is_empty() {
        return Err(ArError::BadNumber);
    }
    if !trimmed.iter().all(|b| b.is_ascii_digit()) {
        return Err(ArError::BadNumber);
    }
    let val = usize::from_str_radix(
        &String::from_utf8_lossy(trimmed),
        10,
    )
    .map_err(|_| ArError::BadNumber)?;
    Ok(val)
}

pub fn read_ar(input: &[u8], max_entries: usize) -> Result<Vec<ArEntry>, ArError> {
    if input.len() < MAGIC.len() || &input[..MAGIC.len()] != MAGIC {
        return Err(ArError::BadMagic);
    }

    let mut entries: Vec<ArEntry> = Vec::new();
    let mut pos: usize = MAGIC.len();
    let mut long_name_table: Option<Vec<u8>> = None;

    while pos < input.len() {
        // Check if we have enough bytes for a header
        if pos + HEADER_SIZE > input.len() {
            return Err(ArError::Truncated);
        }

        let header = &input[pos..pos + HEADER_SIZE];

        // Check fmag
        if header[58..60] != FMAG {
            return Err(ArError::BadHeader);
        }

        // Parse numeric fields
        let mtime = parse_decimal_unsigned(&header[16..28])?;
        let uid = parse_decimal_unsigned(&header[28..34])? as u32;
        let gid = parse_decimal_unsigned(&header[34..40])? as u32;
        let mode = parse_octal_unsigned(&header[40..48])?;
        let size = parse_decimal_usize(&header[48..58])?;

        // Check if data fits
        let data_end = pos.checked_add(HEADER_SIZE).and_then(|v| v.checked_add(size)).ok_or(ArError::Truncated)?;
        if data_end > input.len() {
            return Err(ArError::Truncated);
        }

        // Parse name
        let name_raw = &header[0..16];
        let name_trimmed = trim_end_spaces(name_raw);

        let mut skip_member = false;

        if name_trimmed == b"/" || name_trimmed == b"/SYM64/" {
            // GNU symbol table or global symbol table - skip
            skip_member = true;
        } else if name_trimmed == b"//" {
            // GNU long name table - remember data, skip member
            let table_data = &input[pos + HEADER_SIZE..pos + HEADER_SIZE + size];
            long_name_table = Some(table_data.to_vec());
            skip_member = true;
        } else if name_trimmed.starts_with(b"/") && name_trimmed.len() > 1 {
            // GNU long name reference
            let offset_str = &name_trimmed[1..];
            if offset_str.iter().all(|b| b.is_ascii_digit()) {
                let offset = usize::from_str_radix(
                    &String::from_utf8_lossy(offset_str),
                    10,
                )
                .map_err(|_| ArError::BadName)?;

                let table = long_name_table.as_ref().ok_or(ArError::BadName)?;
                if offset >= table.len() {
                    return Err(ArError::BadName);
                }

                let table_slice = &table[offset..];
                if let Some(newline_pos) = table_slice.iter().position(|&b| b == b'\n') {
                    let name_bytes = &table_slice[..newline_pos];
                    let mut name_vec = name_bytes.to_vec();
                    // Remove trailing '/' if present
                    if name_vec.last() == Some(&b'/') {
                        name_vec.pop();
                    }
                    if name_vec.is_empty() {
                        return Err(ArError::BadName);
                    }

                    if entries.len() >= max_entries {
                        return Err(ArError::TooManyEntries);
                    }

                    entries.push(ArEntry {
                        name: name_vec,
                        mtime,
                        uid,
                        gid,
                        mode,
                        data_offset: pos + HEADER_SIZE,
                        data_len: size,
                    });
                } else {
                    return Err(ArError::BadName);
                }
            } else {
                return Err(ArError::BadName);
            }
        } else if name_trimmed.starts_with(b"#1/") && name_trimmed.len() > 3 {
            // BSD long name
            let len_str = &name_trimmed[3..];
            if len_str.iter().all(|b| b.is_ascii_digit()) {
                let name_len = usize::from_str_radix(
                    &String::from_utf8_lossy(len_str),
                    10,
                )
                .map_err(|_| ArError::BadName)?;

                if name_len > size {
                    return Err(ArError::BadName);
                }

                let name_data = &input[pos + HEADER_SIZE..pos + HEADER_SIZE + name_len];
                // Remove trailing NUL bytes
                let mut name_vec = name_data.to_vec();
                while name_vec.last() == Some(&b'\0') {
                    name_vec.pop();
                }
                if name_vec.is_empty() {
                    return Err(ArError::BadName);
                }

                // Adjust data offset and length
                let adjusted_data_offset = pos + HEADER_SIZE + name_len;
                let adjusted_data_len = size - name_len;

                if entries.len() >= max_entries {
                    return Err(ArError::TooManyEntries);
                }

                entries.push(ArEntry {
                    name: name_vec,
                    mtime,
                    uid,
                    gid,
                    mode,
                    data_offset: adjusted_data_offset,
                    data_len: adjusted_data_len,
                });
            } else {
                return Err(ArError::BadName);
            }
        } else if name_trimmed.starts_with(b"/") || name_trimmed.starts_with(b"#1/") {
            return Err(ArError::BadName);
        } else {
            // Short name - remove trailing '/' if present (GNU style)
            let mut name_vec = name_trimmed.to_vec();
            if name_vec.last() == Some(&b'/') {
                name_vec.pop();
            }
            if name_vec.is_empty() {
                return Err(ArError::BadName);
            }

            if entries.len() >= max_entries {
                return Err(ArError::TooManyEntries);
            }

            entries.push(ArEntry {
                name: name_vec,
                mtime,
                uid,
                gid,
                mode,
                data_offset: pos + HEADER_SIZE,
                data_len: size,
            });
        }

        // Move to next header, accounting for padding
        let mut next_pos = pos.checked_add(HEADER_SIZE).and_then(|v| v.checked_add(size)).ok_or(ArError::Truncated)?;
        if size % 2 != 0 && next_pos < input.len() {
            next_pos += 1; // Skip padding byte
        }
        pos = next_pos;
    }

    Ok(entries)
}
