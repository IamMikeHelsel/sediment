use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::iso_eltorito::{
    BootImage, Media, Platform, ToritoError, boot_image_data, find_boot_record, parse_catalog, read_eltorito,
};

// gen/iso_eltorito.py: xorriso 1.5.6 -as mkisofs; oracle = `xorriso -report_el_torito plain` (*.report.txt).
const BIOS: &[u8] = include_bytes!("iso_eltorito_fixtures/bios.iso.gz");
const BIOS_EFI: &[u8] = include_bytes!("iso_eltorito_fixtures/bios_efi.iso.gz");
const FLOPPY: &[u8] = include_bytes!("iso_eltorito_fixtures/floppy.iso.gz");
const PLAIN: &[u8] = include_bytes!("iso_eltorito_fixtures/plain.iso.gz");

fn iso(gz: &[u8]) -> Vec<u8> {
    decode_gzip(gz, 4 << 20, 1 << 16).unwrap()
}

fn no_emul(platform: Platform, sector_count: u16, load_rba: u32) -> BootImage {
    BootImage { platform, bootable: true, media: Media::NoEmulation, load_segment: 0, system_type: 0, sector_count, load_rba }
}

const CAT: usize = 33 * 2048;

#[test]
fn boot_record_locates_catalog() {
    assert_eq!(find_boot_record(&iso(BIOS)).unwrap(), 33);
    assert_eq!(find_boot_record(&iso(BIOS_EFI)).unwrap(), 33);
    assert_eq!(find_boot_record(&iso(PLAIN)).unwrap_err(), ToritoError::NoBootRecord);
    assert_eq!(find_boot_record(&iso(BIOS)[..17 * 2048 + 100]).unwrap_err(), ToritoError::Truncated);
    assert_eq!(find_boot_record(&[0u8; 40 * 2048]).unwrap_err(), ToritoError::NoBootRecord);
}

#[test]
fn bios_catalog() {
    let c = read_eltorito(&iso(BIOS), 16).unwrap();
    assert_eq!(c.catalog_lba, 33);
    assert_eq!(c.platform, Platform::X86);
    assert_eq!(c.images, [no_emul(Platform::X86, 4, 34)]);
}

#[test]
fn bios_plus_efi_section() {
    let c = read_eltorito(&iso(BIOS_EFI), 16).unwrap();
    assert_eq!(c.images, [no_emul(Platform::X86, 4, 34), no_emul(Platform::Efi, 128, 35)]);
}

#[test]
fn floppy_emulation() {
    let c = read_eltorito(&iso(FLOPPY), 16).unwrap();
    assert_eq!(c.images.len(), 1);
    let b = c.images[0];
    assert_eq!((b.media, b.sector_count, b.load_rba, b.bootable), (Media::Floppy144, 1, 34, true));
    assert_eq!(b.byte_len(), 1_474_560);
}

#[test]
fn boot_image_bytes_match_sources() {
    let a = iso(BIOS_EFI);
    let c = read_eltorito(&a, 16).unwrap();
    let boot: Vec<u8> = (0..2048u32).map(|i| ((i * 5 + 1) & 255) as u8).collect();
    let efi: Vec<u8> = (0..65536u32).map(|i| ((i * 11 + 7) & 255) as u8).collect();
    assert_eq!(boot_image_data(&a, &c.images[0], 1 << 20).unwrap(), boot);
    assert_eq!(boot_image_data(&a, &c.images[1], 1 << 20).unwrap(), efi);
    assert_eq!(boot_image_data(&a, &c.images[1], 65535).unwrap_err(), ToritoError::LimitExceeded);
    let f = iso(FLOPPY);
    let c = read_eltorito(&f, 16).unwrap();
    let d = boot_image_data(&f, &c.images[0], 2 << 20).unwrap();
    assert_eq!(d.len(), 1_474_560);
    assert!(d[..4096].iter().enumerate().all(|(i, &b)| b == ((i * 3) & 255) as u8));
    assert!(d[4096..].iter().all(|&b| b == 0));
    let far = BootImage { load_rba: 1 << 20, ..c.images[0] };
    assert_eq!(boot_image_data(&f, &far, 2 << 20).unwrap_err(), ToritoError::Truncated);
}

#[test]
fn validation_entry_errors() {
    let mut a = iso(BIOS);
    a[CAT + 4] ^= 1;
    assert_eq!(parse_catalog(&a, 33, 16).unwrap_err(), ToritoError::BadChecksum);
    let mut a = iso(BIOS);
    a[CAT + 30] = 0;
    assert_eq!(parse_catalog(&a, 33, 16).unwrap_err(), ToritoError::BadCatalog);
    let mut a = iso(BIOS);
    a[CAT] = 2;
    assert_eq!(parse_catalog(&a, 33, 16).unwrap_err(), ToritoError::BadCatalog);
    let a = iso(BIOS);
    assert_eq!(parse_catalog(&a[..CAT + 40], 33, 16).unwrap_err(), ToritoError::Truncated);
    assert_eq!(parse_catalog(&a, u32::MAX, 16).unwrap_err(), ToritoError::Truncated);
}

#[test]
fn entry_errors_and_limits() {
    let mut a = iso(BIOS);
    a[CAT + 32] = 0x77;
    assert_eq!(parse_catalog(&a, 33, 16).unwrap_err(), ToritoError::BadEntry);
    let a = iso(BIOS_EFI);
    assert_eq!(parse_catalog(&a, 33, 1).unwrap_err(), ToritoError::LimitExceeded);
    let mut a = iso(BIOS_EFI);
    assert_eq!(a[CAT + 64], 0x91);
    a[CAT + 64] = 0x90; // "more headers follow", but the next slot is empty
    assert_eq!(parse_catalog(&a, 33, 16).unwrap_err(), ToritoError::BadEntry);
}

fn entry(out: &mut Vec<u8>, b: [u8; 12]) {
    out.extend_from_slice(&b);
    out.extend_from_slice(&[0; 20]);
}

#[test]
fn synthetic_catalog_with_extension_and_two_sections() {
    let mut cat = vec![1u8, 2, 0, 0];
    cat.extend_from_slice(b"SEDIMENT TEST CATALOG\0\0\0");
    cat.extend_from_slice(&[0, 0, 0x55, 0xAA]);
    let sum = cat.chunks(2).fold(0u16, |s, w| s.wrapping_add(u16::from_le_bytes([w[0], w[1]])));
    cat[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
    entry(&mut cat, [0x00, 4, 0xC0, 0x07, 6, 0, 1, 0, 9, 0, 0, 0]); // not bootable, hard disk
    entry(&mut cat, [0x90, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // header: PowerPC, 1 entry
    entry(&mut cat, [0x88, 0x20 | 2, 0, 0, 0, 0, 1, 0, 10, 0, 0, 0]); // 1.44M floppy, extension follows
    entry(&mut cat, [0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // extension record (skipped)
    entry(&mut cat, [0x91, 0xEF, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // final header: EFI, 1 entry
    entry(&mut cat, [0x88, 0, 0, 0, 0, 0, 8, 0, 11, 0, 0, 0]);
    let mut img = vec![0u8; 2048];
    img.extend_from_slice(&cat);
    img.resize(16 * 2048, 0);
    let c = parse_catalog(&img, 1, 16).unwrap();
    assert_eq!(c.platform, Platform::Mac);
    assert_eq!(&c.id[..21], b"SEDIMENT TEST CATALOG");
    assert_eq!(c.images.len(), 3);
    assert_eq!(c.images[0], BootImage { platform: Platform::Mac, bootable: false, media: Media::HardDisk, load_segment: 0x7C0,
        system_type: 6, sector_count: 1, load_rba: 9 });
    assert_eq!((c.images[1].platform, c.images[1].media, c.images[1].load_rba), (Platform::PowerPc, Media::Floppy144, 10));
    assert_eq!(c.images[2], no_emul(Platform::Efi, 8, 11));
}

#[test]
fn hostile_catalog_never_panics() {
    let base = iso(BIOS_EFI);
    let mut a = base.clone();
    for i in CAT..CAT + 256 {
        for x in [0x01u8, 0x80, 0xff] {
            a[i] ^= x;
            if let Ok(c) = parse_catalog(&a, 33, 64) {
                for b in &c.images {
                    let _ = boot_image_data(&a, b, 4 << 20);
                }
            }
            a[i] = base[i];
        }
    }
    let _ = read_eltorito(&a[..CAT + 2048], 64);
}
