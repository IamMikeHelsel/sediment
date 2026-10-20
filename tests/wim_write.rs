// SPDX-License-Identifier: MIT OR Apache-2.0
//! WIM writer + XPRESS Huffman encoder: round trips through the in-tree
//! readers (wim_read, xpress_huffman). Externally verified with
//! `wimlib-imagex verify` / `apply` (see the module docs).

use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::wim_read::{WimArchive, WimLimits, header_flag};
use sediment_engine::wim_write::{WimWriteCompression, WimWriteError, WimWriteLimits, WimWriteOptions, create_wim};
use sediment_engine::xpress_huffman::decompress;
use sediment_engine::xpress_huffman_encode::{MAX_BLOCK, compress};

fn lcg(seed: u32, n: usize) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

#[test]
fn xpress_roundtrip_many_shapes() {
    for n in [1usize, 2, 3, 4, 15, 16, 17, 18, 19, 31, 32, 33, 100, 4095, 32768, MAX_BLOCK] {
        for shape in 0..4 {
            let data: Vec<u8> = match shape {
                0 => lcg(n as u32, n),
                1 => vec![b'z'; n],
                2 => lcg(7, n).iter().map(|b| b % 4).collect(),
                _ => (0..n).map(|i| (i / 300) as u8).collect(),
            };
            let c = compress(&data).unwrap();
            assert_eq!(decompress(&c, n, n).unwrap(), data, "n={n} shape={shape}");
        }
    }
}

fn e<'a>(name: &'a str, kind: EntryKind, data: &'a [u8]) -> ArchiveEntry<'a> {
    ArchiveEntry { name: name.as_bytes(), kind, data, mtime: 0, mode: 0o644, link_target: b"" }
}

#[test]
fn wim_multi_chunk_and_dedup() {
    let a = lcg(1, 200_000);
    let mut b = b"text ".repeat(20_000);
    b.extend_from_slice(&a[..1000]);
    let es = [e("dir/a", EntryKind::File, &a), e("b", EntryKind::File, &b), e("c", EntryKind::File, &b), e("dir", EntryKind::Directory, b"")];
    for comp in [WimWriteCompression::Xpress, WimWriteCompression::None] {
        let w = create_wim(&es, &WimWriteOptions { compression: comp, image_name: "t<&>".into() }, WimWriteLimits::default()).unwrap();
        let ar = WimArchive::open(&w, WimLimits::default()).unwrap();
        assert_eq!(ar.image_count(), 1);
        assert_eq!(ar.header().flags & header_flag::COMPRESS_XPRESS != 0, comp == WimWriteCompression::Xpress);
        assert_eq!(ar.lookup_table().len(), 3);
        assert_eq!(ar.lookup_table().iter().filter(|l| l.ref_count == 2).count(), 1);
        for x in &es[..3] {
            let i = ar.entries().iter().position(|y| y.path.as_bytes() == x.name).unwrap();
            assert_eq!(ar.read_entry(i, 1 << 30).unwrap(), x.data);
        }
        assert!(ar.xml(1 << 20).unwrap().contains("<NAME>t&lt;&amp;&gt;</NAME>"));
    }
}

#[test]
fn wim_bad_names() {
    let o = WimWriteOptions::default();
    let l = WimWriteLimits::default();
    let bad = [0xFFu8, 0xFE];
    let ent = ArchiveEntry { name: &bad, kind: EntryKind::File, data: b"", mtime: 0, mode: 0, link_target: b"" };
    assert_eq!(create_wim(&[ent], &o, l), Err(WimWriteError::InvalidName));
    assert_eq!(create_wim(&[e("a/./b", EntryKind::File, b"")], &o, l), Err(WimWriteError::InvalidName));
}
