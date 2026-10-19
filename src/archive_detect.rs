// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive / compression format detection from leading bytes.
//!
//! Signatures from public specs: PKWARE APPNOTE (local header `PK\3\4`,
//! empty-archive EOCD `PK\5\6`, spanning marker `PK\7\8`), RFC 1952 (gzip
//! `1F 8B`), bzip2 (`BZh` + block-size digit `1`..`9`), the xz file format
//! (`FD 37 7A 58 5A 00`), the 7z format doc (`37 7A BC AF 27 1C`), POSIX ustar
//! (`ustar` at offset 257) and the header checksum, and the LZMA SDK
//! description of the `.lzma` ("LZMA-alone") header: properties byte
//! `(pb*5+lp)*9+lc` < 225, 32-bit LE dictionary size, 64-bit LE uncompressed
//! size (all ones = unknown). Unix formats: cpio(5) (ASCII magics
//! `070701`, `070702`, `070707`; binary magic 070707 as a 16-bit word in
//! either byte order), ar(5) (`!<arch>\n`), the RPM lead (`ED AB EE DB`) and
//! the xar header (`xar!`).

use crate::tar_read::header_checksum_valid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    SevenZip,
    /// ustar magic at offset 257 with a valid header checksum.
    Tar,
    /// No ustar magic (v7 or damaged magic) but the first header checksum is
    /// valid.
    TarHeuristic,
    LzmaAlone,
    /// cpio: ASCII magic `070701`/`070702`/`070707`, or the binary magic
    /// with a well-formed first header.
    Cpio,
    /// Unix ar (`!<arch>\n`), including Debian packages.
    Ar,
    /// RPM lead magic `ED AB EE DB`.
    Rpm,
    /// xar magic `xar!`.
    Xar,
    Unknown,
}

fn looks_like_lzma_alone(b: &[u8]) -> bool {
    if b.len() < 13 || b[0] >= 225 {
        return false;
    }
    let dict = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
    // Encoders write 2^n or 2^n + 2^(n-1); accept those from 4 KiB upward.
    let dict_ok = dict >= 4096 && {
        let hi = 31 - dict.leading_zeros();
        let rest = dict - (1u32 << hi);
        rest == 0 || rest == 1u32 << (hi - 1)
    };
    if !dict_ok {
        return false;
    }
    let usize_ = u64::from_le_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]);
    // Unknown size, or a plausible one (< 256 TiB).
    usize_ == u64::MAX || usize_ < (1u64 << 48)
}

/// Detect the format of `bytes` from its leading bytes.
pub fn detect_format(bytes: &[u8]) -> ArchiveFormat {
    let tar_valid = header_checksum_valid(bytes);
    if tar_valid && &bytes[257..262] == b"ustar" {
        return ArchiveFormat::Tar;
    }
    if bytes.len() >= 4 && bytes[0] == b'P' && bytes[1] == b'K' {
        match (bytes[2], bytes[3]) {
            (3, 4) | (5, 6) | (7, 8) => return ArchiveFormat::Zip,
            _ => {}
        }
    }
    if bytes.len() >= 6 && bytes[..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
        return ArchiveFormat::SevenZip;
    }
    if bytes.len() >= 6 && bytes[..6] == [0xfd, b'7', b'z', b'X', b'Z', 0] {
        return ArchiveFormat::Xz;
    }
    if bytes.len() >= 4 && &bytes[..3] == b"BZh" && (b'1'..=b'9').contains(&bytes[3]) {
        return ArchiveFormat::Bzip2;
    }
    if bytes.len() >= 3 && bytes[0] == 0x1f && bytes[1] == 0x8b && bytes[2] == 8 {
        return ArchiveFormat::Gzip;
    }
    if bytes.starts_with(crate::ar_archive::AR_MAGIC) {
        return ArchiveFormat::Ar;
    }
    if bytes.starts_with(&crate::rpm_archive::LEAD_MAGIC) {
        return ArchiveFormat::Rpm;
    }
    if bytes.starts_with(crate::xar_archive::XAR_MAGIC) {
        return ArchiveFormat::Xar;
    }
    if bytes.len() >= 6 && matches!(&bytes[..6], b"070701" | b"070702" | b"070707") {
        return ArchiveFormat::Cpio;
    }
    if tar_valid {
        return ArchiveFormat::TarHeuristic;
    }
    if crate::cpio_archive::looks_like_cpio(bytes) {
        return ArchiveFormat::Cpio;
    }
    if looks_like_lzma_alone(bytes) {
        return ArchiveFormat::LzmaAlone;
    }
    ArchiveFormat::Unknown
}
