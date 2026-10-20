//! ISO-9660 Joliet: SVD discovery and UCS-2 directory tree listing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JolietError { Truncated, NoJoliet, BadRecord, BadName, Unsupported, LoopDetected, LimitExceeded }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JolietLimits { pub max_depth: usize, pub max_entries: usize }

impl Default for JolietLimits {
    fn default() -> Self { Self { max_depth: 64, max_entries: 1_000_000 } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JolietRoot { pub level: u8, pub extent: u32, pub size: u32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JolietEntry { pub path: String, pub is_dir: bool, pub extent: u32, pub size: u32 }

/// Find the Joliet Supplementary Volume Descriptor (first one wins).
pub fn joliet_root(image: &[u8]) -> Result<JolietRoot, JolietError> {
    const SEC: usize = 2048;
    let mut scanned: bool = false;
    for n in 16u32..64 {
        let start = n.checked_mul(SEC as u32).ok_or(JolietError::Truncated)? as usize;
        if start + SEC > image.len() {
            if !scanned { return Err(JolietError::Truncated); }
            return Err(JolietError::NoJoliet);
        }
        let d = &image[start..start + SEC];
        scanned = true;
        if d[1..6] != *b"CD001" {
            if d[0] == 255 { return Err(JolietError::NoJoliet); }
            continue;
        }
        if d[0] != 2 { continue; }
        if d[88] != 0x25 || d[89] != 0x2F { continue; }
        let esc = d[90];
        let level = match esc { 0x40 => 1, 0x43 => 2, 0x45 => 3, _ => continue };
        let lbs = u16::from_le_bytes([d[128], d[129]]);
        if lbs != 2048 { return Err(JolietError::BadRecord); }
        let extent = u32::from_le_bytes([d[158], d[159], d[160], d[161]]);
        let size = u32::from_le_bytes([d[166], d[167], d[168], d[169]]);
        return Ok(JolietRoot { level, extent, size });
    }
    Err(JolietError::NoJoliet)
}

/// Walk the Joliet directory tree (preorder), respecting *limits*.
pub fn list_joliet(image: &[u8], root: JolietRoot, limits: &JolietLimits) -> Result<Vec<JolietEntry>, JolietError> {
    let mut entries: Vec<JolietEntry> = Vec::new();
    let mut path_stack: Vec<(String, u32)> = Vec::new();
    path_stack.push((String::new(), root.extent));
    walk_dir(image, root, &mut entries, &mut path_stack, 0, limits)?;
    Ok(entries)
}

fn walk_dir(
    image: &[u8],
    dir_root: JolietRoot,
    entries: &mut Vec<JolietEntry>,
    path_stack: &mut Vec<(String, u32)>,
    depth: usize,
    limits: &JolietLimits,
) -> Result<(), JolietError> {
    let off = (dir_root.extent as usize).checked_mul(2048).ok_or(JolietError::Truncated)?;
    let size = dir_root.size as usize;
    let end = off.checked_add(size).ok_or(JolietError::Truncated)?;
    if end > image.len() { return Err(JolietError::Truncated); }
    let dir = &image[off..end];

    let mut pos: usize = 0;
    while pos < dir.len() {
        let len = dir[pos] as usize;
        if len == 0 {
            let next = (pos + 2048) & !(2048 - 1);
            pos = if next > dir.len() { dir.len() } else { next };
            continue;
        }
        if len < 34 || pos + len > dir.len() { return Err(JolietError::BadRecord); }
        let r = &dir[pos..pos + len];
        pos += len;

        let nl = r[32] as usize;
        if 33 + nl > len { return Err(JolietError::BadRecord); }

        // self / parent
        if nl == 1 && (r[33] == 0x00 || r[33] == 0x01) { continue; }

        // multi-extent
        if r[25] & 0x80 != 0 { return Err(JolietError::Unsupported); }

        // name must be even length (UCS-2 pair)
        if nl % 2 != 0 { return Err(JolietError::BadName); }

        // decode UCS-2 BE
        let raw_name = &r[33..33 + nl];
        let mut name_buf = String::with_capacity(nl / 2);
        for chunk in raw_name.chunks_exact(2) {
            let cp = u16::from_be_bytes([chunk[0], chunk[1]]);
            if (0xD800..=0xDFFF).contains(&cp) { return Err(JolietError::BadName); }
            name_buf.push(char::from_u32(cp as u32).unwrap());
        }

        // strip version separator (;N)
        let name = {
            if let Some(semi) = name_buf.rfind(';') {
                let after = &name_buf[semi + 1..];
                if after.bytes().all(|b| b.is_ascii_digit()) { &name_buf[..semi] }
                else { &name_buf }
            } else { &name_buf }
        };

        // reject empty, `.`, `..`, containing `/` or NUL
        if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
            return Err(JolietError::BadName);
        }

        // entry limit
        if entries.len() == limits.max_entries { return Err(JolietError::LimitExceeded); }

        let extent = u32::from_le_bytes([r[2], r[3], r[4], r[5]]);
        let size = u32::from_le_bytes([r[10], r[11], r[12], r[13]]);
        let is_dir = r[25] & 2 != 0;

        let parent_path = &path_stack.last().unwrap().0;
        let path = if parent_path.is_empty() { name.to_string() }
            else { format!("{}/{}", parent_path, name) };

        entries.push(JolietEntry { path: path.clone(), is_dir, extent, size });

        if is_dir {
            let child_depth = depth + 1;
            if child_depth > limits.max_depth { return Err(JolietError::LimitExceeded); }
            // loop detection
            for (_, stack_extent) in path_stack.iter() {
                if *stack_extent == extent { return Err(JolietError::LoopDetected); }
            }
            path_stack.push((path, extent));
            walk_dir(image, JolietRoot { level: 0, extent, size }, entries, path_stack, child_depth, limits)?;
            path_stack.pop();
        }
    }
    Ok(())
}
