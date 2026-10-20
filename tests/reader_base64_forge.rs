use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::reader_base64::open_base64;

const WRAPPED: &[u8] = include_bytes!("reader_base64_fixtures/wrapped.b64");
const CRLF: &[u8] = include_bytes!("reader_base64_fixtures/crlf.b64");
const UNPADDED: &[u8] = include_bytes!("reader_base64_fixtures/unpadded.b64");
const URLSAFE: &[u8] = include_bytes!("reader_base64_fixtures/urlsafe.b64");

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn lim() -> ReaderLimits {
    ReaderLimits::default()
}

#[test]
fn wrapped_lf_decodes_single_entry() {
    let r = open_base64(WRAPPED.to_vec(), lim()).unwrap();
    assert_eq!(r.entries().len(), 1);
    let e = &r.entries()[0];
    assert_eq!(e.path, b"data.bin".to_vec());
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(e.size, 1000);
    assert_eq!((e.mode, e.mtime), (None, None));
    assert_eq!(r.read(0).unwrap(), payload(1000));
    assert_eq!(r.crc32(0), None);
}

#[test]
fn crlf_wrapped_decodes() {
    let r = open_base64(CRLF.to_vec(), lim()).unwrap();
    assert_eq!(r.read(0).unwrap(), payload(1000));
}

#[test]
fn unpadded_decodes() {
    let r = open_base64(UNPADDED.to_vec(), lim()).unwrap();
    assert_eq!(r.entries()[0].size, 1001);
    assert_eq!(r.read(0).unwrap(), payload(1001));
}

#[test]
fn urlsafe_alphabet_rejected() {
    assert_eq!(open_base64(URLSAFE.to_vec(), lim()).err(), Some(ReaderError::Invalid));
}

#[test]
fn garbage_is_invalid() {
    for bad in [&b"@@@@"[..], b"QUJD=A==", b"QUJDR", b"QUJ=", b"QR==", b"QUI=x", b"QQ==="] {
        assert_eq!(open_base64(bad.to_vec(), lim()).err(), Some(ReaderError::Invalid), "{:?}", bad);
    }
}

#[test]
fn empty_and_whitespace_only_give_empty_entry() {
    for input in [&b""[..], b"\r\n  \t\n"] {
        let r = open_base64(input.to_vec(), lim()).unwrap();
        assert_eq!(r.entries().len(), 1);
        assert_eq!(r.entries()[0].size, 0);
        assert_eq!(r.read(0).unwrap(), Vec::<u8>::new());
    }
}

#[test]
fn read_out_of_range() {
    let r = open_base64(WRAPPED.to_vec(), lim()).unwrap();
    assert_eq!(r.read(1), Err(ReaderError::OutOfRange));
    assert_eq!(r.read(usize::MAX), Err(ReaderError::OutOfRange));
}

#[test]
fn size_limits_apply_at_open() {
    let l = ReaderLimits { max_entry_size: 999, ..lim() };
    assert_eq!(open_base64(WRAPPED.to_vec(), l).err(), Some(ReaderError::LimitExceeded));
    let l = ReaderLimits { max_total_size: 999, ..lim() };
    assert_eq!(open_base64(WRAPPED.to_vec(), l).err(), Some(ReaderError::LimitExceeded));
    let l = ReaderLimits { max_entry_size: 1000, max_total_size: 1000, ..lim() };
    assert_eq!(open_base64(WRAPPED.to_vec(), l).unwrap().read(0).unwrap().len(), 1000);
}

#[test]
fn zero_max_entries_rejected() {
    let l = ReaderLimits { max_entries: 0, ..lim() };
    assert_eq!(open_base64(WRAPPED.to_vec(), l).err(), Some(ReaderError::LimitExceeded));
}

#[test]
fn short_known_vectors() {
    let r = open_base64(b"Zm9vYmFy".to_vec(), lim()).unwrap();
    assert_eq!(r.read(0).unwrap(), b"foobar".to_vec());
    let r = open_base64(b"Zm9vYg\n".to_vec(), lim()).unwrap();
    assert_eq!(r.read(0).unwrap(), b"foob".to_vec());
}

#[test]
fn prefixes_never_panic() {
    for n in 0..WRAPPED.len() {
        let _ = open_base64(WRAPPED[..n].to_vec(), lim());
    }
}
