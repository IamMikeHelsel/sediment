use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::reader_ihex::open_ihex;

const THREE: &[u8] = include_bytes!("reader_ihex_fixtures/three.hex");
const ADJACENT: &[u8] = include_bytes!("reader_ihex_fixtures/adjacent.hex");
const EOF_ONLY: &[u8] = include_bytes!("reader_ihex_fixtures/eof_only.hex");
const BADSUM: &[u8] = include_bytes!("reader_ihex_fixtures/badsum.hex");

fn lim() -> ReaderLimits {
    ReaderLimits::default()
}

fn names(r: &dyn sediment_engine::archive_reader::ArchiveReader) -> Vec<String> {
    r.entries().iter().map(|e| String::from_utf8(e.path.clone()).unwrap()).collect()
}

#[test]
fn three_segments_listed_sorted() {
    let r = open_ihex(THREE.to_vec(), lim()).unwrap();
    assert_eq!(names(&*r), ["00000000.bin", "00000100.bin", "00010000.bin"]);
    let sizes: Vec<u64> = r.entries().iter().map(|e| e.size).collect();
    assert_eq!(sizes, [40, 16, 20]);
    for e in r.entries() {
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.mode, None);
        assert_eq!(e.mtime, None);
    }
}

#[test]
fn three_segments_read_back() {
    let r = open_ihex(THREE.to_vec(), lim()).unwrap();
    let a: Vec<u8> = (0..40u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
    assert_eq!(r.read(0).unwrap(), a);
    assert_eq!(r.read(1).unwrap(), (0xA0u8..0xB0).collect::<Vec<u8>>());
    assert_eq!(r.read(2).unwrap(), b"Sediment ihex test!!".to_vec());
    assert_eq!(r.crc32(0), None);
}

#[test]
fn adjacent_records_are_one_entry() {
    let r = open_ihex(ADJACENT.to_vec(), lim()).unwrap();
    assert_eq!(names(&*r), ["00002000.bin"]);
    let mut want = vec![0x11u8; 8];
    want.extend([0x22u8; 8]);
    assert_eq!(r.read(0).unwrap(), want);
}

#[test]
fn eof_only_is_empty_archive() {
    let r = open_ihex(EOF_ONLY.to_vec(), lim()).unwrap();
    assert!(r.entries().is_empty());
    assert_eq!(r.read(0), Err(ReaderError::OutOfRange));
}

#[test]
fn read_out_of_range() {
    let r = open_ihex(THREE.to_vec(), lim()).unwrap();
    assert_eq!(r.read(3), Err(ReaderError::OutOfRange));
    assert_eq!(r.read(usize::MAX), Err(ReaderError::OutOfRange));
}

#[test]
fn max_entries_limit() {
    let l = ReaderLimits { max_entries: 2, ..lim() };
    assert_eq!(open_ihex(THREE.to_vec(), l).err(), Some(ReaderError::LimitExceeded));
    let l = ReaderLimits { max_entries: 3, ..lim() };
    assert!(open_ihex(THREE.to_vec(), l).is_ok());
}

#[test]
fn max_total_size_limit() {
    let l = ReaderLimits { max_total_size: 75, ..lim() };
    assert_eq!(open_ihex(THREE.to_vec(), l).err(), Some(ReaderError::LimitExceeded));
    let l = ReaderLimits { max_total_size: 76, ..lim() };
    assert_eq!(open_ihex(THREE.to_vec(), l).unwrap().entries().len(), 3);
}

#[test]
fn max_entry_size_checked_on_read() {
    let l = ReaderLimits { max_entry_size: 20, ..lim() };
    let r = open_ihex(THREE.to_vec(), l).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::LimitExceeded));
    assert_eq!(r.read(1).unwrap().len(), 16);
    assert_eq!(r.read(2).unwrap().len(), 20);
}

#[test]
fn malformed_input_is_invalid() {
    assert_eq!(open_ihex(BADSUM.to_vec(), lim()).err(), Some(ReaderError::Invalid));
    assert_eq!(open_ihex(b"hello".to_vec(), lim()).err(), Some(ReaderError::Invalid));
    assert_eq!(open_ihex(Vec::new(), lim()).err(), Some(ReaderError::Invalid));
    let cut = &THREE[..THREE.len() - 12];
    assert_eq!(open_ihex(cut.to_vec(), lim()).err(), Some(ReaderError::Invalid));
}

#[test]
fn every_prefix_is_handled_without_panic() {
    for n in 0..THREE.len() {
        let _ = open_ihex(THREE[..n].to_vec(), lim());
    }
}
