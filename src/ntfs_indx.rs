// SPDX-License-Identifier: MIT OR Apache-2.0
//! NTFS $INDEX_ROOT / INDX index-node parsing with USA fixups.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndxError { Truncated, BadMagic, BadFixup, BadHeader, BadEntry, LimitExceeded }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub mft_record: u64,
    pub mft_seq: u16,
    pub parent_record: u64,
    pub namespace: u8,
    pub is_dir: bool,
    pub name: String,
    pub subnode_vcn: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexNode {
    pub vcn: Option<u64>,
    pub has_children: bool,
    pub entries: Vec<IndexEntry>,
    pub end_subnode_vcn: Option<u64>,
}

/// Apply USA fixups in-place. `magic` must match the first 4 bytes.
pub fn apply_fixups(record: &mut [u8], magic: &[u8; 4]) -> Result<(), IndxError> {
    if record.len() < 8 { return Err(IndxError::Truncated); }
    if &record[0..4] != magic { return Err(IndxError::BadMagic); }
    let usa_ofs = u16::from_le_bytes([record[4], record[5]]) as usize;
    let usa_count = u16::from_le_bytes([record[6], record[7]]) as usize;
    if usa_count < 2 { return Err(IndxError::BadFixup); }
    if (usa_count - 1) * 512 != record.len() { return Err(IndxError::BadFixup); }
    if usa_ofs + 2 * usa_count > record.len() { return Err(IndxError::BadFixup); }
    let usn = u16::from_le_bytes([record[usa_ofs], record[usa_ofs + 1]]);
    for i in 1..usa_count {
        let off = i * 512 - 2;
        let trailer = u16::from_le_bytes([record[off], record[off + 1]]);
        if trailer != usn { return Err(IndxError::BadFixup); }
        let fix_off = usa_ofs + 2 * i;
        let fix = [record[fix_off], record[fix_off + 1]];
        record[off] = fix[0];
        record[off + 1] = fix[1];
    }
    Ok(())
}

/// Parse an INDX index-allocation block (fixups applied internally).
pub fn parse_index_block(block: &[u8], max_entries: usize) -> Result<IndexNode, IndxError> {
    if block.len() < 40 { return Err(IndxError::Truncated); }
    let mut copy = block.to_vec();
    apply_fixups(&mut copy, b"INDX")?;
    let vcn = Some(u64::from_le_bytes([copy[16], copy[17], copy[18], copy[19],
                                        copy[20], copy[21], copy[22], copy[23]]));
    parse_index_header(&copy, 24, vcn, max_entries)
}

/// Parse an $INDEX_ROOT resident attribute value.
pub fn parse_index_root(value: &[u8], max_entries: usize) -> Result<IndexNode, IndxError> {
    if value.len() < 32 { return Err(IndxError::Truncated); }
    let attr_type = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    if attr_type != 0x30 { return Err(IndxError::BadHeader); }
    parse_index_header(value, 16, None, max_entries)
}

/// Walk index entries inside `buf` starting at header offset `h`.
fn parse_index_header(buf: &[u8], h: usize, vcn: Option<u64>, max_entries: usize) -> Result<IndexNode, IndxError> {
    if h + 16 > buf.len() { return Err(IndxError::BadHeader); }
    let entries_offset = u32::from_le_bytes([buf[h], buf[h+1], buf[h+2], buf[h+3]]) as usize;
    let index_length = u32::from_le_bytes([buf[h+4], buf[h+5], buf[h+6], buf[h+7]]) as usize;
    let flags = buf[h + 12];
    if entries_offset < 16 || entries_offset > index_length || h + index_length > buf.len() {
        return Err(IndxError::BadHeader);
    }
    let has_children = flags & 1 != 0;
    let mut entries: Vec<IndexEntry> = Vec::new();
    let mut p = h + entries_offset;
    let end = h + index_length;
    loop {
        // Entry header (16 bytes): ref(8) + length(2) + key_length(2) + flags(2) + key...
        if p + 16 > end { return Err(IndxError::BadEntry); }
        let file_ref = u64::from_le_bytes([buf[p], buf[p+1], buf[p+2], buf[p+3],
                                            buf[p+4], buf[p+5], buf[p+6], buf[p+7]]);
        let length = u16::from_le_bytes([buf[p+8], buf[p+9]]) as usize;
        let key_length = u16::from_le_bytes([buf[p+10], buf[p+11]]) as usize;
        let entry_flags = u16::from_le_bytes([buf[p+12], buf[p+13]]);
        if length < 16 || length % 8 != 0 || p + length > end { return Err(IndxError::BadEntry); }
        let has_subnode = entry_flags & 1 != 0;
        let is_end = entry_flags & 2 != 0;
        if has_subnode && length < 24 { return Err(IndxError::BadEntry); }
        if is_end {
            let end_subnode_vcn = if has_subnode {
                Some(u64::from_le_bytes([buf[p+length-8], buf[p+length-7], buf[p+length-6], buf[p+length-5],
                                         buf[p+length-4], buf[p+length-3], buf[p+length-2], buf[p+length-1]]))
            } else { None };
            return Ok(IndexNode { vcn, has_children, entries, end_subnode_vcn });
        }
        // KEY is FILE_NAME at p+16
        let kl = key_length;
        let subnode_len = if has_subnode { 8 } else { 0 };
        if kl < 66 || kl > length - 16 - subnode_len { return Err(IndxError::BadEntry); }
        let key = &buf[p+16..p+16+kl];
        // FILE_NAME key layout:
        //   parent_ref(FILE_REFERENCE) at key[0..8] — low 48 bits = record number
        //   is_dir at key[56..60] & 0x1000_0000
        //   name_len(u8) at key[64], namespace(u8) at key[65], name at key[66..]
        let name_len = key[64] as usize;
        let namespace = key[65];
        let name_start = 66;
        if name_start + 2 * name_len > kl { return Err(IndxError::BadEntry); }
        let name_bytes = &key[name_start..name_start + 2 * name_len];
        let u16s: Vec<u16> = name_bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let name = match String::from_utf16(&u16s) {
            Ok(n) => n,
            Err(_) => return Err(IndxError::BadEntry),
        };
        let parent_ref = u64::from_le_bytes([key[0], key[1], key[2], key[3],
                                              key[4], key[5], key[6], key[7]]);
        let parent_record = parent_ref & 0xFFFF_FFFF_FFFF;
        let is_dir = u32::from_le_bytes([key[56], key[57], key[58], key[59]]) & 0x1000_0000 != 0;
        let subnode_vcn = if has_subnode {
            Some(u64::from_le_bytes([buf[p+length-8], buf[p+length-7], buf[p+length-6], buf[p+length-5],
                                     buf[p+length-4], buf[p+length-3], buf[p+length-2], buf[p+length-1]]))
        } else { None };
        if entries.len() == max_entries { return Err(IndxError::LimitExceeded); }
        entries.push(IndexEntry {
            mft_record: file_ref & 0xFFFF_FFFF_FFFF,
            mft_seq: (file_ref >> 48) as u16,
            parent_record,
            namespace,
            is_dir,
            name,
            subnode_vcn,
        });
        p += length;
    }
}
