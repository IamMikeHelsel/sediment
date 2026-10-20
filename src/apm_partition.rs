//! Apple Partition Map (APM) — Driver Descriptor Map `ER` + partition entries `PM`.
//! Spec: Apple "Inside Macintosh: Devices", SCSI Manager chapter (DDM `ER`, PM entries).
use std::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApmError { Truncated, BadSignature, BadBlockSize, BadEntry, TooManyPartitions }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApmDriver { pub block: u32, pub size: u16, pub kind: u16 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApmPartition {
    pub index: u32, pub map_entries: u32, pub start_block: u32, pub block_count: u32,
    pub name: String, pub kind: String,
    pub data_start: u32, pub data_count: u32, pub status: u32,
    pub byte_offset: u64, pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApmMap {
    pub block_size: u32, pub block_count: u32, pub sector_size: u32,
    pub drivers: Vec<ApmDriver>, pub partitions: Vec<ApmPartition>,
}

fn latin1_slice(s: &[u8]) -> String {
    s.iter().map(|&b| b as u32).map(|c| char::from_u32(c).unwrap_or('\u{FFFD}'))
        .take_while(|&c| c != '\0').collect()
}

fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
}

fn read_u16_be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off+1]])
}

/// Check if `disk` looks like an Apple Partition Map image.
pub fn is_apm(disk: &[u8]) -> bool {
    disk.len() >= 514 && disk[..2] == *b"ER" && disk[512..514] == *b"PM"
}

/// Parse the APM from `disk`, returning at most `max_partitions` partitions.
pub fn read_apm(disk: &[u8], max_partitions: usize) -> Result<ApmMap, ApmError> {
    // Step 1: basic checks
    if disk.len() < 512 { return Err(ApmError::Truncated); }
    if disk[..2] != *b"ER" { return Err(ApmError::BadSignature); }

    // Step 2: read DDM
    let block_size = read_u16_be(disk, 2) as u32;
    if ![512, 1024, 2048, 4096].contains(&block_size) { return Err(ApmError::BadBlockSize); }
    let block_count = read_u32_be(disk, 4);

    let driver_count = read_u16_be(disk, 16) as usize;
    if driver_count > 61 { return Err(ApmError::BadEntry); }

    let mut drivers = Vec::with_capacity(driver_count);
    for i in 0..driver_count {
        let off = 18 + i * 8;
        if off + 8 > disk.len() { return Err(ApmError::Truncated); }
        drivers.push(ApmDriver {
            block: read_u32_be(disk, off),
            size: read_u16_be(disk, off + 4),
            kind: read_u16_be(disk, off + 6),
        });
    }

    // Step 3: determine sector_size (stride)
    let sector_size = if disk.len() >= 514 && disk[512..514] == *b"PM" { 512u32 } else { block_size };
    let ss = sector_size as usize;

    // Step 4: read entry 0 to get map_entries count, then validate
    let entry0_off = (0usize + 1) * ss;
    if entry0_off + 512 > disk.len() { return Err(ApmError::Truncated); }
    if &disk[entry0_off..entry0_off + 2] != b"PM" { return Err(ApmError::BadSignature); }

    let n = read_u32_be(disk, entry0_off + 4);
    if n == 0 { return Err(ApmError::BadEntry); }
    if n as usize > max_partitions { return Err(ApmError::TooManyPartitions); }

    // Check that all entries fit (u64 math)
    let needed = (u64::from(n) + 1) * u64::from(sector_size);
    if needed > disk.len() as u64 { return Err(ApmError::Truncated); }

    // Step 5: read all n entries
    let mut partitions = Vec::with_capacity(n as usize);
    for i in 0..n {
        let off = ((i as usize) + 1) * ss;
        if off + 512 > disk.len() { return Err(ApmError::Truncated); }
        if &disk[off..off + 2] != b"PM" { return Err(ApmError::BadSignature); }

        let map_entries = read_u32_be(disk, off + 4);
        if map_entries != n { return Err(ApmError::BadEntry); }

        let start_block = read_u32_be(disk, off + 8);
        let block_count = read_u32_be(disk, off + 12);
        let name = latin1_slice(&disk[off + 16..off + 48]);
        let kind = latin1_slice(&disk[off + 48..off + 80]);
        let data_start = read_u32_be(disk, off + 80);
        let data_count = read_u32_be(disk, off + 84);
        let status = read_u32_be(disk, off + 88);

        let byte_offset = u64::from(start_block) * u64::from(sector_size);
        let byte_len = u64::from(block_count) * u64::from(sector_size);

        partitions.push(ApmPartition {
            index: i + 1,
            map_entries: n,
            start_block,
            block_count,
            name,
            kind,
            data_start,
            data_count,
            status,
            byte_offset,
            byte_len,
        });
    }

    Ok(ApmMap { block_size, block_count, sector_size, drivers, partitions })
}
