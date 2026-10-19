// SPDX-License-Identifier: MIT OR Apache-2.0
mod zip_ext_common;

use sediment_engine::zip_descriptor::*;
use zip_ext_common::*;

fn layout(signature: bool, zip64: bool) -> DescriptorLayout {
    DescriptorLayout { signature, zip64 }
}

#[test]
fn layouts_and_lengths() {
    assert_eq!(layout(false, false).len(), 12);
    assert_eq!(layout(true, false).len(), 16);
    assert_eq!(layout(false, true).len(), 20);
    assert_eq!(layout(true, true).len(), 24);
}

#[test]
fn parse_each_layout() {
    let mut b = vec![0xaa; 3];
    put32(&mut b, DESCRIPTOR_SIGNATURE);
    put32(&mut b, 0x1234_5678);
    put64(&mut b, 0x1_0000_0001);
    put64(&mut b, 0x2_0000_0002);
    let d = parse_descriptor(&b, 3, layout(true, true)).unwrap();
    assert_eq!((d.crc32, d.compressed_size, d.uncompressed_size, d.end), (0x1234_5678, 0x1_0000_0001, 0x2_0000_0002, 27));
    let d = parse_descriptor(&b, 7, layout(false, false)).unwrap();
    assert_eq!((d.crc32, d.compressed_size, d.uncompressed_size), (0x1234_5678, 1, 1));
    assert_eq!(parse_descriptor(&b, 7, layout(true, false)).unwrap_err(), DescriptorError::Invalid);
    assert_eq!(parse_descriptor(&b, 10, layout(true, true)).unwrap_err(), DescriptorError::Truncated);
    assert_eq!(parse_descriptor(&b, usize::MAX, layout(false, false)).unwrap_err(), DescriptorError::Truncated);
}

#[test]
fn match_resolves_signature_valued_crc() {
    // Unsigned 32-bit descriptor whose CRC equals the signature value.
    let mut b = Vec::new();
    put32(&mut b, DESCRIPTOR_SIGNATURE);
    put32(&mut b, 10);
    put32(&mut b, 20);
    b.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 0, 0]); // next local header
    let exp = ExpectedDescriptor { crc32: DESCRIPTOR_SIGNATURE, compressed_size: 10, uncompressed_size: 20 };
    let d = match_descriptor(&b, 0, Some(false), exp).unwrap();
    assert!(!d.layout.signature);
    assert_eq!(d.end, 12);
    let d = match_descriptor(&b, 0, None, exp).unwrap();
    assert!(!d.layout.signature);
}

#[test]
fn match_prefers_hinted_width_and_falls_back() {
    let mut b = Vec::new();
    put32(&mut b, DESCRIPTOR_SIGNATURE);
    put32(&mut b, 7);
    put64(&mut b, 2);
    put64(&mut b, 0);
    let exp = ExpectedDescriptor { crc32: 7, compressed_size: 2, uncompressed_size: 0 };
    let d = match_descriptor(&b, 0, Some(true), exp).unwrap();
    assert_eq!(d.layout, layout(true, true));
    // Without a hint the wider layout is tried first.
    assert_eq!(match_descriptor(&b, 0, None, exp).unwrap().layout, layout(true, true));
    let wrong = ExpectedDescriptor { crc32: 8, ..exp };
    assert_eq!(match_descriptor(&b, 0, None, wrong).unwrap_err(), DescriptorError::Mismatch);
    assert_eq!(match_descriptor(&b[..5], 0, None, exp).unwrap_err(), DescriptorError::Truncated);
}

#[test]
fn python_streamed_descriptors_parse() {
    let bytes = fixture("stream_desc64.zip");
    let at = bytes.windows(4).position(|w| w == DESCRIPTOR_SIGNATURE.to_le_bytes()).unwrap();
    let d = parse_descriptor(&bytes, at, layout(true, true)).unwrap();
    assert_eq!(d.uncompressed_size, 300);
    assert_eq!(d.compressed_size, 143);
}
