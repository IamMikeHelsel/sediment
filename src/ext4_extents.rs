//! ext4 extent tree (index/leaf nodes, uninit extents): logical->physical map and file read.
//! All integers little-endian. std only, no unsafe, never panic, checked arithmetic.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentError { Truncated, BadMagic, BadHeader, TooDeep, LimitExceeded }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentHeader { pub entries: u16, pub max: u16, pub depth: u16, pub generation: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent { pub logical: u32, pub len: u16, pub physical: u64, pub uninit: bool }
pub const MAX_DEPTH: u16 = 5;

fn le_u16(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
fn le_u32(b: &[u8], off: usize) -> u32 { u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]) }

pub fn parse_header(node: &[u8]) -> Result<ExtentHeader, ExtentError> {
    if node.len() < 12 { return Err(ExtentError::Truncated); }
    let magic = le_u16(node, 0);
    if magic != 0xF30A { return Err(ExtentError::BadMagic); }
    let entries = le_u16(node, 2);
    let max = le_u16(node, 4);
    let depth = le_u16(node, 6);
    let generation = le_u32(node, 8);
    if entries > max { return Err(ExtentError::BadHeader); }
    if 12u32 + 12 * max as u32 > node.len() as u32 { return Err(ExtentError::BadHeader); }
    if depth > MAX_DEPTH { return Err(ExtentError::TooDeep); }
    Ok(ExtentHeader { entries, max, depth, generation })
}

fn parse_extent_entry(node: &[u8], off: usize) -> Result<Extent, ExtentError> {
    let logical = le_u32(node, off);
    let len = le_u16(node, off + 4);
    let ee_start_hi = le_u16(node, off + 6);
    let ee_start_lo = le_u32(node, off + 8);
    if len == 0 { return Err(ExtentError::BadHeader); }
    let uninit = len > 32768;
    let actual_len = if uninit { len - 32768 } else { len };
    let physical = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);
    Ok(Extent { logical, len: actual_len, physical, uninit })
}

pub fn parse_extents(img: &[u8], block_size: u32, i_block: &[u8; 60], max_extents: usize) -> Result<Vec<Extent>, ExtentError> {
    let h = parse_header(i_block)?;
    let mut result: Vec<Extent> = Vec::with_capacity(max_extents);
    // stack holds (node_data, expected_depth)
    // push children in reverse so they pop in ascending order
    let mut stack: Vec<(&[u8], u16)> = vec![(i_block, h.depth)];
    while let Some((node, depth)) = stack.pop() {
        let hdr = parse_header(node)?;
        if hdr.depth != depth { return Err(ExtentError::BadHeader); }
        if hdr.depth == 0 {
            // leaf: collect extents
            for i in 0..hdr.entries {
                let off = 12 + (i as usize) * 12;
                let e = parse_extent_entry(node, off)?;
                // check overlap with previous
                if let Some(prev) = result.last() {
                    let prev_end = u64::from(prev.logical) + u64::from(prev.len);
                    let cur_start = u64::from(e.logical);
                    if cur_start < prev_end { return Err(ExtentError::BadHeader); }
                }
                if result.len() >= max_extents { return Err(ExtentError::LimitExceeded); }
                result.push(e);
            }
        } else {
            // index node: push children in reverse order
            for i in (0..hdr.entries).rev() {
                let off = 12 + (i as usize) * 12;
                let ei_block = le_u32(node, off);
                let ei_leaf_lo = le_u32(node, off + 4);
                let ei_leaf_hi = le_u16(node, off + 8);
                let child_block = (u64::from(ei_leaf_hi) << 32) | u64::from(ei_leaf_lo);
                let child_start = child_block.checked_mul(block_size as u64)
                    .ok_or(ExtentError::Truncated)?;
                let child_end = child_start.checked_add(block_size as u64)
                    .ok_or(ExtentError::Truncated)?;
                if child_end > img.len() as u64 { return Err(ExtentError::Truncated); }
                let child_node = &img[child_start as usize..child_end as usize];
                stack.push((child_node, depth - 1));
            }
        }
    }
    Ok(result)
}

pub fn map_logical(extents: &[Extent], logical: u32) -> Option<u64> {
    for e in extents {
        if !e.uninit {
            let start = e.logical;
            let end = start + u32::from(e.len);
            if logical >= start && logical < end {
                return Some(e.physical + (logical - start) as u64);
            }
        }
    }
    None
}

pub fn read_extent_file(img: &[u8], block_size: u32, i_block: &[u8; 60], size: u64, max_output: usize) -> Result<Vec<u8>, ExtentError> {
    if size > max_output as u64 { return Err(ExtentError::LimitExceeded); }
    let extents = parse_extents(img, block_size, i_block, 65536)?;
    let mut output = vec![0u8; size as usize];
    for e in &extents {
        if e.uninit { continue; }
        for k in 0..u32::from(e.len) {
            let file_offset = (u64::from(e.logical) + k as u64) * block_size as u64;
            if file_offset >= size { break; }
            let src_start = (e.physical + k as u64) * block_size as u64;
            let remaining = size - file_offset;
            let copy_len = if remaining < block_size as u64 { remaining } else { block_size as u64 };
            let src_end = src_start + copy_len;
            if src_end > img.len() as u64 { return Err(ExtentError::Truncated); }
            output[file_offset as usize..(file_offset + copy_len) as usize]
                .copy_from_slice(&img[src_start as usize..src_end as usize]);
        }
    }
    Ok(output)
}
