use crate::crc32::crc32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartError {
    Truncated,
    BadSignature,
    BadEntry,
    ChainTooLong,
    TooManyPartitions,
    BadSectorSize,
    BadGptHeader,
    BadHeaderCrc,
    BadEntriesCrc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    pub number: u32,
    pub kind: u8,
    pub bootable: bool,
    pub logical: bool,
    pub first_lba: u64,
    pub sector_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartition {
    pub index: u32,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptTable {
    pub disk_guid: [u8; 16],
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub partitions: Vec<GptPartition>,
}

pub const MAX_EBR_CHAIN: usize = 128;

// ── helpers ──────────────────────────────────────────────────────────────

fn le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
fn le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// Read one MBR/EBR entry from a 16-byte slice starting at `off` relative to `sector`.
/// Returns `None` if the entry is empty (kind == 0).
fn read_entry(sector: &[u8], off: usize) -> Option<(u8, u8, u32, u32)> {
    let status = sector[off];
    let kind = sector[off + 4];
    if kind == 0 {
        return None;
    }
    let start_lba = u32::from_le_bytes(sector[off + 8..off + 12].try_into().unwrap());
    let sector_count = u32::from_le_bytes(sector[off + 12..off + 16].try_into().unwrap());
    Some((status, kind, start_lba, sector_count))
}

// ── MBR ──────────────────────────────────────────────────────────────────

pub fn read_mbr(disk: &[u8], max_partitions: usize) -> Result<Vec<MbrPartition>, PartError> {
    // 1. Sector 0 must be at least 512 bytes
    if disk.len() < 512 {
        return Err(PartError::Truncated);
    }

    // Check signature
    if disk[510] != 0x55 || disk[511] != 0xAA {
        return Err(PartError::BadSignature);
    }

    let mut result: Vec<MbrPartition> = Vec::new();

    // 2. Read primary entries (slots 0..3)
    for slot in 0..4 {
        let off = 446 + slot * 16;
        let sector = &disk[0..512];
        if let Some((status, kind, start_lba, sector_count)) = read_entry(sector, off) {
            if status != 0x00 && status != 0x80 {
                return Err(PartError::BadEntry);
            }
            let p = MbrPartition {
                number: (slot + 1) as u32,
                kind,
                bootable: status == 0x80,
                logical: false,
                first_lba: start_lba as u64,
                sector_count: sector_count as u64,
            };
            if result.len() >= max_partitions {
                return Err(PartError::TooManyPartitions);
            }
            result.push(p);
        }
    }

    // 3. Find extended container (first primary entry with kind 0x05, 0x0F, or 0x85)
    let mut extended_start: Option<u64> = None;
    for slot in 0..4 {
        let off = 446 + slot * 16;
        let sector = &disk[0..512];
        if let Some((_, kind, start_lba, _)) = read_entry(sector, off) {
            if kind == 0x05 || kind == 0x0F || kind == 0x85 {
                extended_start = Some(start_lba as u64);
                break;
            }
        }
    }

    // 4. Walk EBR chain if extended exists
    if let Some(e) = extended_start {
        let mut chain_count: usize = 0;
        let mut current_ebr_lba: u64 = e;
        let mut logical_number: u32 = 5;

        loop {
            // Check chain length
            if chain_count >= MAX_EBR_CHAIN {
                return Err(PartError::ChainTooLong);
            }
            chain_count += 1;

            let sector_off = current_ebr_lba * 512;
            if sector_off + 512 > disk.len() as u64 {
                return Err(PartError::Truncated);
            }

            let sector = &disk[sector_off as usize..sector_off as usize + 512];

            // Check EBR signature
            if sector[510] != 0x55 || sector[511] != 0xAA {
                return Err(PartError::BadSignature);
            }

            // Entry 0 (off=446): logical partition
            if let Some((status, kind, start_lba, sector_count)) = read_entry(sector, 446) {
                if status != 0x00 && status != 0x80 {
                    return Err(PartError::BadEntry);
                }
                let logical_first_lba = current_ebr_lba + start_lba as u64;
                let p = MbrPartition {
                    number: logical_number,
                    kind,
                    bootable: status == 0x80,
                    logical: true,
                    first_lba: logical_first_lba,
                    sector_count: sector_count as u64,
                };
                logical_number += 1;
                if result.len() >= max_partitions {
                    return Err(PartError::TooManyPartitions);
                }
                result.push(p);
            }

            // Entry 1 (off=462): next EBR or end of chain
            if let Some((status, kind, start_lba, _)) = read_entry(sector, 462) {
                if status != 0x00 && status != 0x80 {
                    return Err(PartError::BadEntry);
                }
                // kind must be an extended type
                if kind != 0x05 && kind != 0x0F && kind != 0x85 {
                    return Err(PartError::BadEntry);
                }
                // Next EBR is at E + start_lba (relative to the extended container)
                current_ebr_lba = e + start_lba as u64;
                continue;
            }

            // Entry 1 is empty => chain ends
            break;
        }
    }

    Ok(result)
}

// ── GPT ──────────────────────────────────────────────────────────────────

pub fn read_gpt(disk: &[u8], sector_size: usize, max_partitions: usize) -> Result<GptTable, PartError> {
    // 1. sector_size must be 512 or 4096
    if sector_size != 512 && sector_size != 4096 {
        return Err(PartError::BadSectorSize);
    }

    // 2. Need at least 2 sectors
    if disk.len() < 2 * sector_size {
        return Err(PartError::Truncated);
    }

    // 3. Header at LBA 1
    let h_off = sector_size; // LBA 1 starts at byte sector_size
    if h_off + 512 > disk.len() {
        return Err(PartError::Truncated);
    }

    // Check signature
    if &disk[h_off..h_off + 8] != b"EFI PART" {
        return Err(PartError::BadSignature);
    }

    // 4. header_size
    let header_size = le_u32(&disk[h_off..], 12) as usize;
    if header_size < 92 || header_size > sector_size {
        return Err(PartError::BadGptHeader);
    }

    // 5. Header CRC: CRC32 of h[0..header_size] with crc field (bytes 16..20) zeroed
    {
        let mut tmp = disk[h_off..h_off + header_size].to_vec();
        tmp[16..20].fill(0);
        let expected = le_u32(&disk[h_off..], 16);
        let actual = crc32(&tmp);
        if actual != expected {
            return Err(PartError::BadHeaderCrc);
        }
    }

    // 6. my_lba must be 1; entry_size >= 128 and multiple of 8
    let my_lba = le_u64(&disk[h_off..], 24);
    if my_lba != 1 {
        return Err(PartError::BadGptHeader);
    }

    let entry_size = le_u32(&disk[h_off..], 84) as usize;
    if entry_size < 128 || entry_size % 8 != 0 {
        return Err(PartError::BadGptHeader);
    }

    // 7. Entry array location
    let entries_lba = le_u64(&disk[h_off..], 72);
    let entry_count = le_u32(&disk[h_off..], 80) as usize;

    // Check that the entry array fits in disk (checked arithmetic, overflow counts as out of range)
    let start_byte = entries_lba.checked_mul(sector_size as u64);
    let end_byte = start_byte.and_then(|s| s.checked_add((entry_count as u64) * (entry_size as u64)));

    let entry_end = match end_byte {
        Some(e) => e,
        None => return Err(PartError::Truncated),
    };

    if entry_end as usize > disk.len() {
        return Err(PartError::Truncated);
    }

    // 8. Entry array CRC
    let entry_start = entries_lba as usize * sector_size;
    let entry_end_byte = entry_start + entry_count * entry_size;
    let entries_data = &disk[entry_start..entry_end_byte];
    let expected_entries_crc = le_u32(&disk[h_off..], 88);
    let actual_entries_crc = crc32(entries_data);
    if actual_entries_crc != expected_entries_crc {
        return Err(PartError::BadEntriesCrc);
    }

    // 9. Read header fields
    let first_usable_lba = le_u64(&disk[h_off..], 40);
    let last_usable_lba = le_u64(&disk[h_off..], 48);
    let disk_guid = disk[h_off + 56..h_off + 72].try_into().unwrap();

    // 10. Parse entries
    let mut partitions = Vec::new();
    let mut used_count: usize = 0;

    for i in 0..entry_count {
        let entry_off = i * entry_size;
        let entry = &entries_data[entry_off..entry_off + entry_size];

        // Check type GUID (all zero = unused)
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }

        used_count += 1;
        if used_count > max_partitions {
            return Err(PartError::TooManyPartitions);
        }

        let type_guid = entry[0..16].try_into().unwrap();
        let unique_guid = entry[16..32].try_into().unwrap();
        let first_lba = le_u64(entry, 32);
        let last_lba = le_u64(entry, 40);

        if first_lba > last_lba {
            return Err(PartError::BadEntry);
        }

        let attributes = le_u64(entry, 48);

        // Name: UTF-16LE units from offset 56, up to first 0 unit
        let name_units: Vec<u16> = entry[56..128]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&v| v != 0)
            .collect();

        let name = String::from_utf16_lossy(&name_units);

        let p = GptPartition {
            index: i as u32 + 1,
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
            name,
        };

        partitions.push(p);
    }

    Ok(GptTable {
        disk_guid,
        first_usable_lba,
        last_usable_lba,
        partitions,
    })
}
