// SPDX-License-Identifier: MIT OR Apache-2.0
//! A single compressed stream (gzip, bzip2, xz, zstd) that is not named as
//! a tar or cpio archive becomes one entry, so its decoder must stop at
//! `min(max_entry_size, max_total_size)` instead of decoding up to the
//! total limit first (decompression-bomb guard).
//!
//! Each bomb decodes to 64 KiB but has a corrupted integrity check at its
//! very end. A decoder capped at the 4 KiB entry limit stops before reaching
//! that check and reports `LimitExceeded`; a decoder that runs to the total
//! limit decodes everything and reports `CrcMismatch` instead.
use sediment_engine::archive_open::open_named;
use sediment_engine::archive_open_ext::open_named_ext;
use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::bzip2_encode::encode_bzip2;
use sediment_engine::gzip_encode::encode_gzip;
use sediment_engine::xz_encode::{XzOptions, encode_xz};

const PLAIN: usize = 64 * 1024;

fn limits() -> ReaderLimits {
    ReaderLimits { max_entry_size: 4096, ..ReaderLimits::default() }
}

fn gzip_bomb() -> Vec<u8> {
    let mut g = encode_gzip(&vec![0u8; PLAIN], 1 << 20, 1 << 10).unwrap();
    let t = g.len() - 8;
    g[t] ^= 0xFF; // CRC-32 trailer
    g
}

fn bzip2_bomb() -> Vec<u8> {
    let mut b = encode_bzip2(&vec![0u8; PLAIN], 9, 1 << 20).unwrap();
    // The combined stream CRC is the 32 bits just before the final padding.
    let n = b.len();
    b[n - 2] ^= 0xFF;
    b
}

fn xz_bomb() -> Vec<u8> {
    let x = encode_xz(&vec![0u8; PLAIN], &XzOptions::preset(1).unwrap()).unwrap();
    let mut x = x;
    // Corrupt the stream footer's backward size: only reached after the
    // whole block is decoded.
    let n = x.len();
    x[n - 8] ^= 0xFF;
    x
}

fn zstd_bomb() -> Vec<u8> {
    // Frame: checksum flag, 64 KiB window, one last RLE block of 64 KiB
    // zeros, then a wrong content checksum.
    let mut z = vec![0x28, 0xB5, 0x2F, 0xFD, 0x04, 0x30];
    let bh: u32 = ((PLAIN as u32) << 3) | (1 << 1) | 1;
    z.extend_from_slice(&bh.to_le_bytes()[..3]);
    z.push(0x00);
    z.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    z
}

#[test]
fn bombs_fail_with_their_check_when_decoded_fully() {
    // Sanity: with default limits each fixture decodes fully and fails its
    // integrity check, so the capped result below is meaningful.
    let d = ReaderLimits::default();
    assert!(open_named(&gzip_bomb(), b"bomb.bin.gz", d).is_err());
    assert!(open_named(&bzip2_bomb(), b"bomb.bin.bz2", d).is_err());
    assert!(open_named(&xz_bomb(), b"bomb.bin.xz", d).is_err());
    assert_eq!(open_named_ext(&zstd_bomb(), b"bomb.bin.zst", d).err(), Some(ReaderError::CrcMismatch));
}

#[test]
fn single_stream_decoding_stops_at_entry_limit() {
    let l = limits();
    assert_eq!(open_named(&gzip_bomb(), b"bomb.bin.gz", l).err(), Some(ReaderError::LimitExceeded), "gzip");
    assert_eq!(open_named(&bzip2_bomb(), b"bomb.bin.bz2", l).err(), Some(ReaderError::LimitExceeded), "bzip2");
    assert_eq!(open_named(&xz_bomb(), b"bomb.bin.xz", l).err(), Some(ReaderError::LimitExceeded), "xz");
    assert_eq!(open_named_ext(&gzip_bomb(), b"bomb.bin.gz", l).err(), Some(ReaderError::LimitExceeded), "gzip ext");
    assert_eq!(open_named_ext(&zstd_bomb(), b"bomb.bin.zst", l).err(), Some(ReaderError::LimitExceeded), "zstd");
}

#[test]
fn tar_named_streams_still_use_total_limit() {
    // A .tar.gz may be larger than one entry: it is decoded to the total
    // limit and then fails its check rather than the entry limit.
    let l = limits();
    assert_ne!(open_named(&gzip_bomb(), b"bomb.tar.gz", l).err(), Some(ReaderError::LimitExceeded));
    assert_ne!(open_named_ext(&zstd_bomb(), b"bomb.tar.zst", l).err(), Some(ReaderError::LimitExceeded));
}
