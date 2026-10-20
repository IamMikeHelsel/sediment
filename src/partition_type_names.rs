/// Partition type display info (7-Zip File System / extension).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartTypeInfo {
    pub name: String,
    pub ext: &'static str,
}

/// Format a 16-byte on-disk (UEFI mixed-endian) GUID as uppercase hex.
///
/// Layout: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
///   Data1 = bytes 0..4 as LE u32 (8 digits)
///   Data2 = bytes 4..6 as LE u16 (4 digits)
///   Data3 = bytes 6..8 as LE u16 (4 digits)
///   bytes 8..10 (4 digits), bytes 10..16 (12 digits).
pub fn format_guid(raw: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

/// GPT partition type lookup.
///
/// Returns `(name, ext)` from the 7-Zip table; on miss the name is the
/// formatted GUID and ext is `"img"`.
pub fn gpt_type(raw: &[u8; 16]) -> PartTypeInfo {
    let g = format_guid(raw);
    match g.as_str() {
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => PartTypeInfo { name: "APFS".into(), ext: "apfs" },
        "21686148-6449-6E6F-744E-656564454649" => PartTypeInfo { name: "BIOS Boot".into(), ext: "img" },
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => PartTypeInfo { name: "EFI System".into(), ext: "img" },
        "83BD6B9D-7F41-11DC-BE0B-001560B84F0F" => PartTypeInfo { name: "FreeBSD Boot".into(), ext: "img" },
        "516E7CB4-6ECF-11D6-8FF8-00022D09712B" => PartTypeInfo { name: "FreeBSD Data".into(), ext: "img" },
        "516E7CB5-6ECF-11D6-8FF8-00022D09712B" => PartTypeInfo { name: "FreeBSD Swap".into(), ext: "img" },
        "516E7CB6-6ECF-11D6-8FF8-00022D09712B" => PartTypeInfo { name: "FreeBSD UFS".into(), ext: "ufs" },
        "516E7CB8-6ECF-11D6-8FF8-00022D09712B" => PartTypeInfo { name: "FreeBSD Vinum".into(), ext: "img" },
        "48465300-0000-11AA-AA11-00306543ECAC" => PartTypeInfo { name: "HFS+".into(), ext: "hfsx" },
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => PartTypeInfo { name: "Linux Data".into(), ext: "img" },
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => PartTypeInfo { name: "Linux Swap".into(), ext: "img" },
        "69DAD710-2CE4-4E3C-B16C-21A1D49ABED3" => PartTypeInfo { name: "Linux root (ARM)".into(), ext: "img" },
        "B921B045-1DF0-41C3-AF44-4C6F280D3FAE" => PartTypeInfo { name: "Linux root (ARM64)".into(), ext: "img" },
        "993D8D3D-F80E-4225-855A-9DAF8ED7EA97" => PartTypeInfo { name: "Linux root (IA-64)".into(), ext: "img" },
        "44479540-F297-41B2-9AF7-D131D5F0458A" => PartTypeInfo { name: "Linux root (x86)".into(), ext: "img" },
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => PartTypeInfo { name: "Linux root (x86-64)".into(), ext: "img" },
        "024DEE41-33E7-11D3-9D69-0008C781F39F" => PartTypeInfo { name: "MBR".into(), ext: "img" },
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => PartTypeInfo { name: "Windows BDP".into(), ext: "img" },
        "AF9B60A0-1431-4F62-BC68-3311714A69AD" => PartTypeInfo { name: "Windows LDM Data".into(), ext: "img" },
        "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3" => PartTypeInfo { name: "Windows LDM Metadata".into(), ext: "img" },
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => PartTypeInfo { name: "Windows MSR".into(), ext: "img" },
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => PartTypeInfo { name: "Windows Recovery".into(), ext: "img" },
        _ => PartTypeInfo { name: g, ext: "img" },
    }
}

/// MBR partition type byte lookup.
///
/// Returns `(name, ext)` from the 7-Zip table; on miss the name is the
/// decimal string of the byte and ext is `"img"`.
pub fn mbr_type(t: u8) -> PartTypeInfo {
    match t {
        0x01 => PartTypeInfo { name: "FAT12".into(), ext: "fat" },
        0x04 => PartTypeInfo { name: "FAT16 DOS 3.0+".into(), ext: "fat" },
        0x05 => PartTypeInfo { name: "Extended".into(), ext: "img" },
        0x06 => PartTypeInfo { name: "FAT16 DOS 3.31+".into(), ext: "fat" },
        0x0B => PartTypeInfo { name: "FAT32".into(), ext: "fat" },
        0x0C => PartTypeInfo { name: "FAT32-LBA".into(), ext: "fat" },
        0x0E => PartTypeInfo { name: "FAT16-LBA".into(), ext: "fat" },
        0x0F => PartTypeInfo { name: "Extended-LBA".into(), ext: "img" },
        0x11 => PartTypeInfo { name: "FAT12-Hidden".into(), ext: "fat" },
        0x14 => PartTypeInfo { name: "FAT16-Hidden < 32 MB".into(), ext: "fat" },
        0x16 => PartTypeInfo { name: "FAT16-Hidden >= 32 MB".into(), ext: "fat" },
        0x1B => PartTypeInfo { name: "FAT32-Hidden".into(), ext: "fat" },
        0x1C => PartTypeInfo { name: "FAT32-LBA-Hidden".into(), ext: "fat" },
        0x1E => PartTypeInfo { name: "FAT16-LBA-WIN95-Hidden".into(), ext: "fat" },
        0x27 => PartTypeInfo { name: "NTFS-WinRE".into(), ext: "ntfs" },
        0x82 => PartTypeInfo { name: "Solaris x86 / Linux swap".into(), ext: "img" },
        0x83 => PartTypeInfo { name: "Linux".into(), ext: "img" },
        0x8E => PartTypeInfo { name: "Linux LVM".into(), ext: "lvm" },
        0xA5 => PartTypeInfo { name: "BSD slice".into(), ext: "img" },
        0xBE => PartTypeInfo { name: "Solaris 8 boot".into(), ext: "img" },
        0xBF => PartTypeInfo { name: "New Solaris x86".into(), ext: "img" },
        0xC2 => PartTypeInfo { name: "Linux-Hidden".into(), ext: "img" },
        0xC3 => PartTypeInfo { name: "Linux swap-Hidden".into(), ext: "img" },
        0xEE => PartTypeInfo { name: "GPT".into(), ext: "img" },
        _ => PartTypeInfo { name: t.to_string(), ext: "img" },
    }
}
