// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertiesError {
    UnexpectedEof,
    InvalidProperties,
    UnsupportedProperties,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaProperties {
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
    pub dictionary_size: u32,
}

pub fn parse_properties(bytes: &[u8], max_dictionary_bytes: u64) -> Result<LzmaProperties, PropertiesError> {
    if bytes.len() < 5 {
        return Err(PropertiesError::UnexpectedEof);
    }

    let prop_byte = bytes[0];
    if prop_byte >= 225 {
        return Err(PropertiesError::InvalidProperties);
    }

    let val = prop_byte as u32;
    let lc = (val % 9) as u8;
    let rem = val / 9;
    let lp = (rem % 5) as u8;
    let pb = (rem / 5) as u8;

    if (lc as u32) + (lp as u32) > 4 {
        return Err(PropertiesError::UnsupportedProperties);
    }

    let raw_dict = u32::from_le_bytes([
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
    ]);

    let normalized_dict = if raw_dict < 4096 { 4096 } else { raw_dict };

    if (normalized_dict as u64) > max_dictionary_bytes {
        return Err(PropertiesError::LimitExceeded);
    }

    Ok(LzmaProperties {
        lc,
        lp,
        pb,
        dictionary_size: normalized_dict,
    })
}