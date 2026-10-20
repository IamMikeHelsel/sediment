// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-stream `.lzma` (LZMA-alone) and `.lzma86` files as one-member
//! archives, plus tar inside them (`.tar.lzma`, `.tlz`, `.tar.lzma86`).
//!
//! Formats (public descriptions only):
//! - `.lzma`: the 13-byte LZMA-alone header from the LZMA SDK
//!   `lzma-specification` (properties byte, little-endian 32-bit dictionary
//!   size, little-endian 64-bit uncompressed size where all-ones means
//!   "unknown, stream ends with an end marker") followed by the LZMA stream.
//!   Decoding is delegated to [`crate::lzma_decode::decode_lzma_alone`].
//! - `.lzma86`: the LZMA SDK `Lzma86` layout: one filter byte (0 = none,
//!   1 = x86 BCJ applied before compression) followed by the same 13-byte
//!   header and stream. The x86 filter is undone with
//!   [`crate::filter_bcj`] starting at offset 0.
//!
//! `.lzma86` has no magic bytes, so it is only recognised by file name;
//! `.lzma` is recognised by `archive_detect`'s header heuristic or by name.

use std::borrow::Cow;

use crate::archive_open::{StreamReader, TarReader};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::filter_bcj::{BcjArch, BcjError, bcj_decode};
use crate::lzma_decode::{LzmaError, decode_lzma_alone};

/// Largest dictionary accepted (same cap as the xz/7z readers).
pub const MAX_DICTIONARY: u64 = 1 << 32;

/// `.lzma86` filter byte values.
pub const LZMA86_FILTER_NONE: u8 = 0;
pub const LZMA86_FILTER_X86: u8 = 1;

impl From<LzmaError> for ReaderError {
    fn from(e: LzmaError) -> Self {
        match e {
            LzmaError::UnexpectedEof => ReaderError::Truncated,
            LzmaError::LimitExceeded => ReaderError::LimitExceeded,
            LzmaError::Allocation => ReaderError::Allocation,
            LzmaError::InvalidProperties | LzmaError::InvalidData | LzmaError::TrailingData => ReaderError::Invalid,
        }
    }
}

fn bcj_error(e: BcjError) -> ReaderError {
    match e {
        BcjError::LimitExceeded => ReaderError::LimitExceeded,
        BcjError::Allocation => ReaderError::Allocation,
        BcjError::UnalignedStartOffset | BcjError::InvalidProperties | BcjError::UnsupportedFilter => {
            ReaderError::Invalid
        }
    }
}

/// Which single-stream LZMA flavour a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzmaKind {
    Alone,
    Lzma86,
}

fn ends_with_ci(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn base_name(name: &[u8]) -> &[u8] {
    name.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(name)
}

/// Suffixes naming a tar inside an LZMA stream, with their kind.
const TAR_SUFFIXES: [(&[u8], LzmaKind); 4] = [
    (b".tar.lzma86", LzmaKind::Lzma86),
    (b".tar.lzma", LzmaKind::Alone),
    (b".tlz", LzmaKind::Alone),
    (b".tlzma", LzmaKind::Alone),
];

/// Plain suffixes, longest first.
const STREAM_SUFFIXES: [(&[u8], LzmaKind); 3] =
    [(b".lzma86", LzmaKind::Lzma86), (b".lzma", LzmaKind::Alone), (b".86", LzmaKind::Lzma86)];

/// The kind implied by the archive file name, if any.
pub fn kind_from_name(archive_name: &[u8]) -> Option<LzmaKind> {
    let base = base_name(archive_name);
    TAR_SUFFIXES
        .iter()
        .chain(STREAM_SUFFIXES.iter())
        .find(|(s, _)| ends_with_ci(base, s))
        .map(|&(_, k)| k)
}

/// Member name and "is a tar" for an LZMA single-stream file:
/// `x.tar.lzma`/`x.tlz` -> `x.tar` (tar), `notes.txt.lzma` -> `notes.txt`.
pub fn lzma_member_name(archive_name: &[u8]) -> (Vec<u8>, bool) {
    let base = base_name(archive_name);
    for (s, _) in TAR_SUFFIXES {
        if ends_with_ci(base, s) {
            let mut v = base[..base.len() - s.len()].to_vec();
            v.extend_from_slice(b".tar");
            return (v, true);
        }
    }
    for (s, _) in STREAM_SUFFIXES {
        if ends_with_ci(base, s) {
            let v = base[..base.len() - s.len()].to_vec();
            let is_tar = ends_with_ci(&v, b".tar");
            return (v, is_tar);
        }
    }
    if base.is_empty() || base == b"." || base == b".." {
        return (b"data".to_vec(), false);
    }
    (base.to_vec(), false)
}

/// Decode a complete `.lzma` file.
pub fn decode_lzma(input: &[u8], max_output: usize) -> Result<Vec<u8>, ReaderError> {
    Ok(decode_lzma_alone(input, MAX_DICTIONARY, max_output)?)
}

/// Decode a complete `.lzma86` file (filter byte + LZMA-alone stream).
pub fn decode_lzma86(input: &[u8], max_output: usize) -> Result<Vec<u8>, ReaderError> {
    let (&flag, rest) = input.split_first().ok_or(ReaderError::Truncated)?;
    if flag > LZMA86_FILTER_X86 {
        return Err(ReaderError::Invalid);
    }
    let data = decode_lzma_alone(rest, MAX_DICTIONARY, max_output)?;
    if flag == LZMA86_FILTER_NONE {
        return Ok(data);
    }
    bcj_decode(BcjArch::X86, 0, &data, max_output).map_err(bcj_error)
}

/// Decode either flavour.
pub fn decode(kind: LzmaKind, input: &[u8], max_output: usize) -> Result<Vec<u8>, ReaderError> {
    match kind {
        LzmaKind::Alone => decode_lzma(input, max_output),
        LzmaKind::Lzma86 => decode_lzma86(input, max_output),
    }
}

/// Open an LZMA single-stream file as an archive (tar when the name says so
/// or the member name ends in `.tar`).
pub fn open_lzma<'a>(
    bytes: &[u8],
    archive_name: &[u8],
    kind: LzmaKind,
    limits: ReaderLimits,
) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    let max = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
    let data = decode(kind, bytes, max)?;
    let (member, is_tar) = lzma_member_name(archive_name);
    if is_tar {
        return Ok(Box::new(TarReader::new(Cow::Owned(data), limits)?));
    }
    if data.len() as u64 > limits.max_entry_size {
        return Err(ReaderError::LimitExceeded);
    }
    let format = match kind {
        LzmaKind::Alone => ArchiveFormat::Lzma,
        LzmaKind::Lzma86 => ArchiveFormat::Lzma86,
    };
    let crc = crate::crc32::crc32(&data);
    Ok(Box::new(StreamReader::new(format, member, data, None, Some(crc))))
}

/// The hook `archive_open::open_named` calls for inputs that matched no
/// primary magic: `Some` when the name or the header says LZMA. A name of
/// `.lzma86` wins over the header heuristic. `looks_alone` is the
/// `archive_detect` LZMA-alone verdict.
pub fn try_open<'a>(
    bytes: &[u8],
    archive_name: &[u8],
    looks_alone: bool,
    limits: ReaderLimits,
) -> Option<Result<Box<dyn ArchiveReader + 'a>, ReaderError>> {
    let kind = match kind_from_name(archive_name) {
        Some(k) => k,
        None if looks_alone => LzmaKind::Alone,
        None => return None,
    };
    Some(open_lzma(bytes, archive_name, kind, limits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(lzma_member_name(b"a/b.tar.lzma"), (b"b.tar".to_vec(), true));
        assert_eq!(lzma_member_name(b"b.tlz"), (b"b.tar".to_vec(), true));
        assert_eq!(lzma_member_name(b"p.bin.lzma86"), (b"p.bin".to_vec(), false));
        assert_eq!(lzma_member_name(b"p.bin.lzma"), (b"p.bin".to_vec(), false));
        assert_eq!(kind_from_name(b"x.LZMA86"), Some(LzmaKind::Lzma86));
        assert_eq!(kind_from_name(b"x.tlz"), Some(LzmaKind::Alone));
        assert_eq!(kind_from_name(b"x.gz"), None);
    }

    #[test]
    fn malformed_is_err() {
        assert!(decode_lzma86(&[], 100).is_err());
        assert!(decode_lzma86(&[2; 20], 100).is_err());
        assert!(decode_lzma(&[0x5d, 0, 0, 1, 0], 100).is_err());
        let mut junk = vec![0x5d, 0, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        junk.extend_from_slice(&[0xAA; 64]);
        assert!(decode_lzma(&junk, 1 << 20).is_err());
    }
}
