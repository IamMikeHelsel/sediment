// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Imaging (WIM) archive writing: one image, uncompressed or
//! XPRESS Huffman, with SHA-1 stream de-duplication. The inverse of
//! [`crate::wim_read`].
//!
//! Spec sources: Microsoft "Windows Imaging File Format (WIM)" white paper
//! (WIMHEADER_V1_PACKED, RESHDR_DISK_SHORT, offset table entries, the
//! metadata resource with SECURITYBLOCK_DISK and DIRENTRY, chunked
//! compressed resources with a chunk offset table), [MS-XCA] for XPRESS
//! Huffman chunks (see [`crate::xpress_huffman_encode`]), [MS-FSCC]
//! 2.1.2.4 for symbolic-link reparse buffers and FIPS 180-4 for SHA-1.
//!
//! Layout: header, file streams (each distinct content stored once,
//! keyed by SHA-1), the metadata resource (an empty security block, the
//! root directory entry and one entry list per directory), the offset
//! (lookup) table and the UTF-16LE XML data. No integrity table, no boot
//! image. Compressed resources use 32 KiB chunks; a chunk that does not
//! shrink is stored raw, and a resource that does not shrink is stored
//! uncompressed. The lookup table and XML data are always uncompressed.

use std::collections::{BTreeMap, HashMap};

use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::hash_sha1::sha1;
use crate::wim_read::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, HEADER_SIZE, IO_REPARSE_TAG_SYMLINK, WIM_MAGIC,
    header_flag, resource_flag,
};
use crate::xpress_huffman_encode::{self, XpressEncodeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimWriteError {
    /// An entry name is not valid UTF-8, has an empty, `.`, `..` or
    /// backslash-containing component, or is too long for a WIM name.
    InvalidName,
    /// Two entries have the same path, or a file is used as a directory.
    Duplicate,
    /// The output would exceed [`WimWriteLimits::max_output`].
    LimitExceeded,
    /// Memory allocation failed.
    Allocation,
}

type R<T> = Result<T, WimWriteError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimWriteCompression {
    None,
    Xpress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimWriteOptions {
    pub compression: WimWriteCompression,
    /// Image name stored in the XML data.
    pub image_name: String,
}

impl Default for WimWriteOptions {
    fn default() -> Self {
        WimWriteOptions { compression: WimWriteCompression::Xpress, image_name: "Sediment".into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimWriteLimits {
    /// Largest output file.
    pub max_output: u64,
}

impl Default for WimWriteLimits {
    fn default() -> Self {
        WimWriteLimits { max_output: 1 << 40 }
    }
}

/// WIM chunk size for compressed resources.
pub const CHUNK_SIZE: usize = 32768;
const VERSION: u32 = 0x0001_0D00;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const DENTRY_FIXED: usize = 102;
const LOOKUP_ENTRY_SIZE: usize = 50;
const ZERO_HASH: [u8; 20] = [0; 20];

/// Unix seconds to FILETIME (100 ns since 1601), clamped at 0.
fn filetime(unix: i64) -> u64 {
    let secs = i128::from(unix) + 11_644_473_600;
    if secs <= 0 { 0 } else { u64::try_from(secs * 10_000_000).unwrap_or(u64::MAX) }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn push_res(out: &mut Vec<u8>, r: &Res) {
    out.extend_from_slice(&r.size.to_le_bytes()[..7]);
    out.push(r.flags);
    out.extend_from_slice(&r.offset.to_le_bytes());
    out.extend_from_slice(&r.original_size.to_le_bytes());
}

#[derive(Debug, Clone, Copy, Default)]
struct Res {
    size: u64,
    flags: u8,
    offset: u64,
    original_size: u64,
}

fn map_xp(e: XpressEncodeError) -> WimWriteError {
    match e {
        XpressEncodeError::Allocation => WimWriteError::Allocation,
        XpressEncodeError::TooLarge => WimWriteError::LimitExceeded,
    }
}

/// Append `data` as one resource at the end of `out`.
fn write_resource(out: &mut Vec<u8>, data: &[u8], comp: WimWriteCompression, limit: u64, flags: u8) -> R<Res> {
    let offset = out.len() as u64;
    let orig = data.len() as u64;
    let grow = |out: &mut Vec<u8>, n: usize| -> R<()> {
        if (out.len() as u64).saturating_add(n as u64) > limit {
            return Err(WimWriteError::LimitExceeded);
        }
        out.try_reserve(n).map_err(|_| WimWriteError::Allocation)
    };
    if comp == WimWriteCompression::Xpress && !data.is_empty() {
        let n_chunks = data.len().div_ceil(CHUNK_SIZE);
        let entry = if orig > u64::from(u32::MAX) { 8 } else { 4 };
        let mut table = Vec::new();
        table.try_reserve((n_chunks - 1) * entry).map_err(|_| WimWriteError::Allocation)?;
        let mut body: Vec<u8> = Vec::new();
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            if i > 0 {
                let pos = body.len() as u64;
                if entry == 4 {
                    table.extend_from_slice(&(pos as u32).to_le_bytes());
                } else {
                    table.extend_from_slice(&pos.to_le_bytes());
                }
            }
            let c = xpress_huffman_encode::compress(chunk).map_err(map_xp)?;
            body.try_reserve(chunk.len()).map_err(|_| WimWriteError::Allocation)?;
            if c.len() < chunk.len() {
                body.extend_from_slice(&c);
            } else {
                body.extend_from_slice(chunk);
            }
            if body.len() as u64 > orig {
                break; // will not shrink; store uncompressed below
            }
        }
        let total = table.len() + body.len();
        if (total as u64) < orig {
            grow(out, total)?;
            out.extend_from_slice(&table);
            out.extend_from_slice(&body);
            return Ok(Res { size: total as u64, flags: flags | resource_flag::COMPRESSED, offset, original_size: orig });
        }
    }
    grow(out, data.len())?;
    out.extend_from_slice(data);
    Ok(Res { size: orig, flags, offset, original_size: orig })
}

/// A node of the image tree; index 0 is the root.
struct Node {
    name: String,
    attributes: u32,
    time: u64,
    hash: [u8; 20],
    reparse: bool,
    children: BTreeMap<String, usize>,
    explicit: bool,
}

fn dentry_len(name: &str) -> usize {
    let n = name.encode_utf16().count() * 2;
    (DENTRY_FIXED + if n > 0 { n + 2 } else { 0 }).next_multiple_of(8)
}

fn push_dentry(md: &mut Vec<u8>, n: &Node, subdir: u64) {
    let start = md.len();
    let name = utf16(&n.name);
    let len = dentry_len(&n.name);
    md.extend_from_slice(&(len as u64).to_le_bytes());
    md.extend_from_slice(&n.attributes.to_le_bytes());
    md.extend_from_slice(&(-1i32).to_le_bytes()); // no security descriptor
    md.extend_from_slice(&subdir.to_le_bytes());
    md.extend_from_slice(&[0u8; 16]); // unused
    for _ in 0..3 {
        md.extend_from_slice(&n.time.to_le_bytes());
    }
    md.extend_from_slice(&n.hash);
    md.extend_from_slice(&0u32.to_le_bytes());
    if n.reparse {
        md.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        md.extend_from_slice(&[0u8; 4]);
    } else {
        md.extend_from_slice(&0u64.to_le_bytes()); // hard link group: none
    }
    md.extend_from_slice(&0u16.to_le_bytes()); // named streams
    md.extend_from_slice(&0u16.to_le_bytes()); // short name
    md.extend_from_slice(&(name.len() as u16).to_le_bytes());
    md.extend_from_slice(&name);
    if !name.is_empty() {
        md.extend_from_slice(&[0, 0]);
    }
    md.resize(start + len, 0);
}

/// Symbolic-link reparse data (without the 8-byte tag/length header).
fn symlink_reparse(target: &str) -> Vec<u8> {
    let name = utf16(&target.replace('/', "\\"));
    let l = name.len() as u16;
    let mut d = Vec::with_capacity(12 + name.len() * 2);
    for v in [0u16, l, l, l] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    let relative = !target.starts_with('/');
    d.extend_from_slice(&u32::from(relative).to_le_bytes());
    d.extend_from_slice(&name);
    d.extend_from_slice(&name);
    d
}

/// Build a single-image WIM from `entries` (names `/`-separated, no
/// trailing slash). Missing parent directories are created.
pub fn create_wim(entries: &[ArchiveEntry<'_>], options: &WimWriteOptions, limits: WimWriteLimits) -> R<Vec<u8>> {
    let mut nodes: Vec<Node> = Vec::new();
    nodes.try_reserve(entries.len() + 1).map_err(|_| WimWriteError::Allocation)?;
    let now = entries.iter().map(|e| e.mtime).max().unwrap_or(0);
    nodes.push(Node {
        name: String::new(),
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        time: filetime(now),
        hash: ZERO_HASH,
        reparse: false,
        children: BTreeMap::new(),
        explicit: true,
    });
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(HEADER_SIZE).map_err(|_| WimWriteError::Allocation)?;
    out.resize(HEADER_SIZE, 0);
    // hash -> (resource, ref count), in first-use order.
    let mut streams: Vec<([u8; 20], Res, u32)> = Vec::new();
    let mut by_hash: HashMap<[u8; 20], usize> = HashMap::new();
    let (mut dir_count, mut file_count, mut total_bytes) = (0u64, 0u64, 0u64);
    for e in entries {
        let path = std::str::from_utf8(e.name).map_err(|_| WimWriteError::InvalidName)?;
        let comps: Vec<&str> = path.split('/').collect();
        if comps.iter().any(|c| c.is_empty() || *c == "." || *c == ".." || c.contains(['\\', '\0'])) {
            return Err(WimWriteError::InvalidName);
        }
        if comps.iter().any(|c| c.encode_utf16().count() * 2 > usize::from(u16::MAX) - 2) {
            return Err(WimWriteError::InvalidName);
        }
        let mut cur = 0usize;
        for (k, c) in comps.iter().enumerate() {
            let last = k + 1 == comps.len();
            if let Some(&child) = nodes[cur].children.get(*c) {
                if last {
                    let n = &mut nodes[child];
                    if n.explicit || e.kind != EntryKind::Directory {
                        return Err(WimWriteError::Duplicate);
                    }
                    n.explicit = true;
                    n.time = filetime(e.mtime);
                } else if nodes[child].attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                    return Err(WimWriteError::Duplicate);
                }
                cur = child;
                continue;
            }
            let idx = nodes.len();
            let mut node = Node {
                name: (*c).to_string(),
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                time: filetime(e.mtime),
                hash: ZERO_HASH,
                reparse: false,
                children: BTreeMap::new(),
                explicit: last,
            };
            if last {
                let data: Vec<u8>;
                let stream: &[u8] = match e.kind {
                    EntryKind::Directory => &[],
                    EntryKind::File => {
                        node.attributes = FILE_ATTRIBUTE_NORMAL;
                        e.data
                    }
                    EntryKind::Symlink => {
                        node.attributes = FILE_ATTRIBUTE_REPARSE_POINT;
                        node.reparse = true;
                        let t = std::str::from_utf8(e.link_target).map_err(|_| WimWriteError::InvalidName)?;
                        if t.is_empty() || t.len() > 16000 {
                            return Err(WimWriteError::InvalidName);
                        }
                        data = symlink_reparse(t);
                        &data
                    }
                };
                if e.kind == EntryKind::Directory {
                    dir_count += 1;
                } else {
                    file_count += 1;
                    total_bytes = total_bytes.saturating_add(stream.len() as u64);
                }
                if !stream.is_empty() {
                    let h = sha1(stream);
                    node.hash = h;
                    if let Some(&i) = by_hash.get(&h) {
                        streams[i].2 += 1;
                    } else {
                        let r = write_resource(&mut out, stream, options.compression, limits.max_output, 0)?;
                        by_hash.insert(h, streams.len());
                        streams.push((h, r, 1));
                    }
                }
            } else {
                dir_count += 1;
            }
            nodes.try_reserve(1).map_err(|_| WimWriteError::Allocation)?;
            nodes.push(node);
            nodes[cur].children.insert((*c).to_string(), idx);
            cur = idx;
        }
    }

    // Metadata resource: security block, root dentry + end marker, then one
    // child list per directory (breadth first).
    let mut order = vec![0usize];
    let mut i = 0;
    while i < order.len() {
        let d = order[i];
        order.extend(nodes[d].children.values().copied().filter(|&c| nodes[c].attributes & FILE_ATTRIBUTE_DIRECTORY != 0));
        i += 1;
    }
    let root_off = 8usize;
    let mut list_off = HashMap::new();
    let mut pos = root_off + dentry_len("") + 8;
    for &d in &order {
        list_off.insert(d, pos as u64);
        pos += nodes[d].children.keys().map(|n| dentry_len(n)).sum::<usize>() + 8;
    }
    let mut md: Vec<u8> = Vec::new();
    md.try_reserve(pos).map_err(|_| WimWriteError::Allocation)?;
    md.extend_from_slice(&8u32.to_le_bytes()); // security block total length
    md.extend_from_slice(&0u32.to_le_bytes()); // no descriptors
    push_dentry(&mut md, &nodes[0], list_off[&0]);
    md.extend_from_slice(&[0u8; 8]);
    for &d in &order {
        for &c in nodes[d].children.values() {
            let sub = list_off.get(&c).copied().unwrap_or(0);
            push_dentry(&mut md, &nodes[c], sub);
        }
        md.extend_from_slice(&[0u8; 8]);
    }
    debug_assert_eq!(md.len(), pos);
    let md_hash = sha1(&md);
    let md_res = write_resource(&mut out, &md, options.compression, limits.max_output, resource_flag::METADATA)?;

    // Lookup table: metadata first, then streams.
    let mut table = Vec::new();
    table.try_reserve((streams.len() + 1) * LOOKUP_ENTRY_SIZE).map_err(|_| WimWriteError::Allocation)?;
    for (h, r, refs) in std::iter::once((md_hash, md_res, 1)).chain(streams.iter().copied()) {
        push_res(&mut table, &r);
        table.extend_from_slice(&1u16.to_le_bytes());
        table.extend_from_slice(&refs.to_le_bytes());
        table.extend_from_slice(&h);
    }
    let lt_res = write_resource(&mut out, &table, WimWriteCompression::None, limits.max_output, 0)?;

    let xml_off = out.len() as u64;
    let t = nodes[0].time;
    let esc = options.image_name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let xml = format!(
        "<WIM><TOTALBYTES>{xml_off}</TOTALBYTES><IMAGE INDEX=\"1\"><DIRCOUNT>{dir_count}</DIRCOUNT>\
         <FILECOUNT>{file_count}</FILECOUNT><TOTALBYTES>{total_bytes}</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES>\
         <CREATIONTIME><HIGHPART>0x{:08X}</HIGHPART><LOWPART>0x{:08X}</LOWPART></CREATIONTIME>\
         <LASTMODIFICATIONTIME><HIGHPART>0x{:08X}</HIGHPART><LOWPART>0x{:08X}</LOWPART></LASTMODIFICATIONTIME>\
         <NAME>{esc}</NAME></IMAGE></WIM>",
        t >> 32,
        t & 0xFFFF_FFFF,
        t >> 32,
        t & 0xFFFF_FFFF
    );
    let mut xml_bytes = vec![0xFF, 0xFE];
    xml_bytes.extend_from_slice(&utf16(&xml));
    let xml_res = write_resource(&mut out, &xml_bytes, WimWriteCompression::None, limits.max_output, 0)?;

    // Header.
    let mut h = Vec::with_capacity(HEADER_SIZE);
    h.extend_from_slice(&WIM_MAGIC);
    h.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    h.extend_from_slice(&VERSION.to_le_bytes());
    let (flags, chunk) = match options.compression {
        WimWriteCompression::None => (0u32, 0u32),
        WimWriteCompression::Xpress => (header_flag::COMPRESSION | header_flag::COMPRESS_XPRESS, CHUNK_SIZE as u32),
    };
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&chunk.to_le_bytes());
    // Deterministic GUID derived from the content.
    let mut g = sha1(&[&table[..], &md_hash[..]].concat());
    g[6] = (g[6] & 0x0F) | 0x50;
    g[8] = (g[8] & 0x3F) | 0x80;
    h.extend_from_slice(&g[..16]);
    h.extend_from_slice(&1u16.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    push_res(&mut h, &lt_res);
    push_res(&mut h, &xml_res);
    push_res(&mut h, &Res::default()); // boot metadata
    h.extend_from_slice(&0u32.to_le_bytes()); // boot index
    push_res(&mut h, &Res::default()); // integrity table
    h.resize(HEADER_SIZE, 0);
    out[..HEADER_SIZE].copy_from_slice(&h);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wim_read::{WimArchive, WimLimits};

    fn entry<'a>(name: &'a str, kind: EntryKind, data: &'a [u8], link: &'a [u8]) -> ArchiveEntry<'a> {
        ArchiveEntry { name: name.as_bytes(), kind, data, mtime: 1_700_000_000, mode: 0o644, link_target: link }
    }

    #[test]
    fn roundtrip_both_modes() {
        let big: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
        let text = b"hello sediment\n".repeat(50);
        let es = [
            entry("a.txt", EntryKind::File, &text, b""),
            entry("copy.txt", EntryKind::File, &text, b""),
            entry("bin/big.bin", EntryKind::File, &big, b""),
            entry("empty", EntryKind::File, b"", b""),
            entry("deep/x/y/z.txt", EntryKind::File, b"nested\n", b""),
            entry("emptydir", EntryKind::Directory, b"", b""),
            entry("link", EntryKind::Symlink, b"", b"a.txt"),
            entry("caf\u{e9}.txt", EntryKind::File, b"unicode", b""),
        ];
        for comp in [WimWriteCompression::None, WimWriteCompression::Xpress] {
            let opts = WimWriteOptions { compression: comp, ..Default::default() };
            let w = create_wim(&es, &opts, WimWriteLimits::default()).unwrap();
            let a = WimArchive::open(&w, WimLimits::default()).unwrap();
            // a.txt and copy.txt share one stream.
            assert_eq!(a.lookup_table().len(), 1 + 5);
            for e in &es {
                let name = std::str::from_utf8(e.name).unwrap();
                let i = a.entries().iter().position(|x| x.path == name).unwrap();
                if e.kind == EntryKind::File {
                    assert_eq!(a.read_entry(i, 1 << 30).unwrap(), e.data, "{name}");
                }
            }
            for d in ["bin", "deep", "deep/x", "deep/x/y", "emptydir"] {
                assert!(a.entries().iter().any(|x| x.path == d && x.is_dir()));
            }
            let li = a.entries().iter().position(|x| x.path == "link").unwrap();
            let rp = a.read_entry(li, 1 << 20).unwrap();
            assert_eq!(crate::wim_read::symlink_target(&rp).unwrap(), ("a.txt".to_string(), true));
            assert!(a.xml(1 << 20).unwrap().contains("<NAME>Sediment</NAME>"));
            if comp == WimWriteCompression::Xpress {
                assert!(w.len() < 20_000);
            }
        }
    }

    #[test]
    fn rejects_bad_input() {
        let o = WimWriteOptions::default();
        let l = WimWriteLimits::default();
        for bad in ["", "a//b", "../x", "a\\b"] {
            assert_eq!(create_wim(&[entry(bad, EntryKind::File, b"x", b"")], &o, l), Err(WimWriteError::InvalidName));
        }
        let dup = [entry("a", EntryKind::File, b"x", b""), entry("a", EntryKind::File, b"y", b"")];
        assert_eq!(create_wim(&dup, &o, l), Err(WimWriteError::Duplicate));
        let under_file = [entry("a", EntryKind::File, b"x", b""), entry("a/b", EntryKind::File, b"y", b"")];
        assert_eq!(create_wim(&under_file, &o, l), Err(WimWriteError::Duplicate));
        let data = vec![1u8; 5000];
        let small = WimWriteLimits { max_output: 1000 };
        let opts = WimWriteOptions { compression: WimWriteCompression::None, ..Default::default() };
        assert_eq!(create_wim(&[entry("a", EntryKind::File, &data, b"")], &opts, small), Err(WimWriteError::LimitExceeded));
        // Empty input still yields a valid image with just the root.
        let w = create_wim(&[], &o, l).unwrap();
        assert!(WimArchive::open(&w, WimLimits::default()).unwrap().entries().is_empty());
    }
}
