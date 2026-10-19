// SPDX-License-Identifier: MIT OR Apache-2.0

/// Errors that can occur when interpreting length or distance codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// The symbol is not a valid length symbol (257..=285).
    InvalidLengthSymbol,
    /// The symbol is not a valid distance symbol (0..=29).
    InvalidDistanceSymbol,
}

/// The length code bases as specified in RFC 1951.
/// Index 0 corresponds to symbol 257, index 28 corresponds to symbol 285.
const LENGTH_BASES: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258,
];

/// The length code additional bits as specified in RFC 1951.
/// Index 0 corresponds to symbol 257, index 28 corresponds to symbol 285.
const LENGTH_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// The distance code bases as specified in RFC 1951.
/// Index 0 corresponds to symbol 0, index 29 corresponds to symbol 29.
const DISTANCE_BASES: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// The distance code additional bits as specified in RFC 1951.
/// Index 0 corresponds to symbol 0, index 29 corresponds to symbol 29.
const DISTANCE_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// Returns the base value and number of additional bits for a length symbol.
///
/// Valid length symbols are 257..=285. Symbol 256 is the end-of-block marker and
/// is not a length symbol. Symbols 286 and 287 are invalid.
///
/// # Errors
///
/// Returns `CodeError::InvalidLengthSymbol` if the symbol is not in the range 257..=285.
pub fn length_spec(symbol: u16) -> Result<(u16, u8), CodeError> {
    if symbol < 257 || symbol > 285 {
        return Err(CodeError::InvalidLengthSymbol);
    }
    let idx = (symbol - 257) as usize;
    Ok((LENGTH_BASES[idx], LENGTH_BITS[idx]))
}

/// Returns the base value and number of additional bits for a distance symbol.
///
/// Valid distance symbols are 0..=29.
///
/// # Errors
///
/// Returns `CodeError::InvalidDistanceSymbol` if the symbol is not in the range 0..=29.
pub fn distance_spec(symbol: u16) -> Result<(u16, u8), CodeError> {
    if symbol > 29 {
        return Err(CodeError::InvalidDistanceSymbol);
    }
    let idx = symbol as usize;
    Ok((DISTANCE_BASES[idx], DISTANCE_BITS[idx]))
}