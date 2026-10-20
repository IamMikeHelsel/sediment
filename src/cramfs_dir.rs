// SPDX-License-Identifier: MIT OR Apache-2.0
//! cramfs (LE/BE, optional 512-byte boot pad) superblock + CRC, directory tree listing and file read.

use crate::crc32::crc32;
use crate::zlib_wrapper::decode_zlib;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CramError {
    Truncated,
    BadMagic,
    BadSignature,
    BadCrc,
    UnsupportedFlags,
    BadInode,
    BadDirectory,
    Decompress,
    Loop,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CramInode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub gid: u8,
    pub namelen: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CramSuper {
    pub endian: Endian,
    pub offset: usize,
    pub size: u32,
    pub flags: u32,
    pub crc: u32,
    pub edition: u32,
    pub blocks: u32,
    pub files: u32,
    pub name: [u8; 16],
    pub root: CramInode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CramKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CramEntry {
    pub path: String,
    pub kind: CramKind,
    pub inode: CramInode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CramLimits {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for CramLimits {
    fn default() -> Self {
        Self {
            max_entries: 65536,
            max_depth: 64,
        }
    }
}

pub const MAGIC: u32 = 0x28cd_3d45;

fn rd32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parse a 12-byte inode at `at` in `img` using the given endianness.
pub fn parse_inode(img: &[u8], at: usize, e: Endian) -> Result<CramInode, CramError> {
    if img.len() < at + 12 {
        return Err(CramError::Truncated);
    }
    let w0 = if e == Endian::Little { rd32le(img, at) } else { rd32be(img, at) };
    let w1 = if e == Endian::Little { rd32le(img, at + 4) } else { rd32be(img, at + 4) };
    let w2 = if e == Endian::Little { rd32le(img, at + 8) } else { rd32be(img, at + 8) };
    let (mode, uid, size, gid, namelen, offset) = if e == Endian::Little {
        ((w0 & 0xffff) as u16, (w0 >> 16) as u16, w1 & 0xffffff, (w1 >> 24) as u8, w2 & 0x3f, w2 >> 6)
    } else {
        ((w0 >> 16) as u16, (w0 & 0xffff) as u16, w1 >> 8, (w1 & 0xff) as u8, w2 >> 26, w2 & 0x3ffffff)
    };
    Ok(CramInode { mode, uid, size, gid, namelen, offset })
}

/// Parse the cramfs superblock.
pub fn parse_super(img: &[u8]) -> Result<CramSuper, CramError> {
    let (off, endian) = find_magic(img)?;
    if img.len() < off + 76 {
        return Err(CramError::Truncated);
    }

    // signature at offset 16
    if &img[off + 16..off + 32] != b"Compressed ROMFS" {
        return Err(CramError::BadSignature);
    }

    let size = if endian == Endian::Little { rd32le(img, off + 4) } else { rd32be(img, off + 4) };
    let flags = if endian == Endian::Little { rd32le(img, off + 8) } else { rd32be(img, off + 8) };

    // Check unsupported flags: 0x800 (EXT_BLOCK_POINTERS) and any bits beyond 0x7FF
    if flags & !0x7FF != 0 {
        return Err(CramError::UnsupportedFlags);
    }

    if flags & 1 != 0 {
        // FSID_VERSION_2: size is image end from byte 0
        if size > img.len() as u32 || size < off as u32 + 76 {
            return Err(CramError::Truncated);
        }
    }

    let crc = if endian == Endian::Little { rd32le(img, off + 32) } else { rd32be(img, off + 32) };
    // CRC covers img[off..size] when FSID_VERSION_2, else img[off..img.len()]
    let check_end = if flags & 1 != 0 { size as usize } else { img.len() };
    if check_end > img.len() { return Err(CramError::Truncated); }

    let mut tmp = img[off..check_end].to_vec();
    tmp[32..36].fill(0);
    if crc32(&tmp) != crc {
        return Err(CramError::BadCrc);
    }

    let edition = if endian == Endian::Little { rd32le(img, off + 36) } else { rd32be(img, off + 36) };
    let blocks = if endian == Endian::Little { rd32le(img, off + 40) } else { rd32be(img, off + 40) };
    let files = if endian == Endian::Little { rd32le(img, off + 44) } else { rd32be(img, off + 44) };

    let mut name = [0u8; 16];
    name.copy_from_slice(&img[off + 48..off + 64]);

    let root = parse_inode(img, off + 64, endian)?;

    Ok(CramSuper { endian, offset: off, size, flags, crc, edition, blocks, files, name, root })
}

/// Find magic at offset 0 or 512. Returns (offset, Endian).
fn find_magic(img: &[u8]) -> Result<(usize, Endian), CramError> {
    if img.len() >= 4 {
        let m0 = rd32le(img, 0);
        if m0 == MAGIC {
            return Ok((0, Endian::Little));
        }
        if m0 == MAGIC.swap_bytes() {
            return Ok((0, Endian::Big));
        }
    }
    if img.len() >= 516 {
        let m512 = rd32le(img, 512);
        if m512 == MAGIC {
            return Ok((512, Endian::Little));
        }
        if m512 == MAGIC.swap_bytes() {
            return Ok((512, Endian::Big));
        }
    }
    if img.len() < 76 {
        Err(CramError::Truncated)
    } else {
        Err(CramError::BadMagic)
    }
}

/// Walk a directory listing, collecting entries.
fn walk_dir(
    img: &[u8],
    s: &CramSuper,
    list_off: usize,
    list_size: u32,
    parent_path: &str,
    stack_depth: usize,
    limits: &CramLimits,
    entries: &mut Vec<CramEntry>,
    walk_path: &mut Vec<u32>, // track inode offsets on current walk path for loop detection
) -> Result<(), CramError> {
    let list_end = list_off + list_size as usize;
    if list_off > img.len() {
        return Err(CramError::Truncated);
    }
    let actual_end = if list_end > img.len() { img.len() } else { list_end };
    let mut pos = list_off;

    while pos < actual_end {
        if pos + 12 > actual_end {
            return Err(CramError::Truncated);
        }
        let child = parse_inode(img, pos, s.endian)?;
        let name_bytes_len = (child.namelen as usize) * 4;
        let name_start = pos + 12;
        let name_end = name_start + name_bytes_len;
        if name_end > actual_end {
            return Err(CramError::Truncated);
        }

        let name_raw = &img[name_start..name_end];
        let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(name_bytes_len);
        let name = String::from_utf8_lossy(&name_raw[..name_len]).into_owned();

        if name.is_empty() || name == "." || name == ".." {
            pos = name_end;
            continue;
        }
        if name.contains('/') {
            return Err(CramError::BadDirectory);
        }

        let kind = match child.mode & 0o170000 {
            0o100000 => CramKind::File,
            0o040000 => CramKind::Dir,
            0o120000 => CramKind::Symlink,
            _ => CramKind::Other,
        };

        let path = if parent_path.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", parent_path, name)
        };

        if entries.len() >= limits.max_entries {
            return Err(CramError::LimitExceeded);
        }
        entries.push(CramEntry { path: path.clone(), kind, inode: child });

        // Pre-order: push dir children right after pushing the dir itself
        if kind == CramKind::Dir && child.size > 0 {
            let child_list_off = (child.offset as usize) * 4;
            // Loop detection: check if this offset is already on the walk path
            if walk_path.contains(&child.offset) {
                return Err(CramError::Loop);
            }
            if stack_depth + 1 >= limits.max_depth {
                return Err(CramError::LimitExceeded);
            }
            walk_path.push(child.offset);
            walk_dir(img, s, child_list_off, child.size, &path, stack_depth + 1, limits, entries, walk_path)?;
            walk_path.pop();
        }
        pos = name_end;
    }
    Ok(())
}

/// List the cramfs tree.
pub fn list_cramfs(img: &[u8], limits: &CramLimits) -> Result<(CramSuper, Vec<CramEntry>), CramError> {
    let s = parse_super(img)?;
    let root = s.root;
    if (root.mode & 0o170000) != 0o040000 {
        return Err(CramError::BadInode);
    }
    let mut entries: Vec<CramEntry> = Vec::with_capacity(limits.max_entries);
    let root_list_off = (root.offset as usize) * 4;
    let mut walk_path = vec![root.offset]; // root is on the walk path
    walk_dir(img, &s, root_list_off, root.size, "", 1, limits, &mut entries, &mut walk_path)?;
    Ok((s, entries))
}

/// Read file/symlink data from a cramfs image.
pub fn read_data(
    img: &[u8],
    s: &CramSuper,
    entry: &CramEntry,
    max_output: usize,
) -> Result<Vec<u8>, CramError> {
    let mode = entry.inode.mode & 0o170000;
    if mode != 0o100000 && mode != 0o120000 {
        return Err(CramError::BadInode);
    }
    let size = entry.inode.size;
    if size > max_output as u32 {
        return Err(CramError::LimitExceeded);
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let inode_off = (entry.inode.offset as usize) * 4;
    let n_blocks = ((size as usize) + 4095) / 4096;
    let ptr_end = inode_off + n_blocks * 4;
    if ptr_end > img.len() {
        return Err(CramError::Truncated);
    }
    let mut output = Vec::with_capacity(size as usize);
    let mut block_start = ptr_end;
    for i in 0..n_blocks {
        let ptr_off = inode_off + i * 4;
        let block_end = if s.endian == Endian::Little {
            rd32le(img, ptr_off) as usize
        } else {
            rd32be(img, ptr_off) as usize
        };
        let remaining = size as usize - i * 4096;
        let want = if remaining < 4096 { remaining } else { 4096 };
        if block_end == block_start {
            output.extend_from_slice(&[0u8; 4096][..want]);
        } else {
            if block_end < block_start || block_end > img.len() {
                return Err(CramError::BadInode);
            }
            let data = &img[block_start..block_end];
            let decompressed = match decode_zlib(data, want, 256) {
                Ok(d) => d,
                Err(_) => return Err(CramError::Decompress),
            };
            if decompressed.len() != want {
                return Err(CramError::Decompress);
            }
            output.extend_from_slice(&decompressed);
        }
        block_start = block_end;
    }
    Ok(output)
}
