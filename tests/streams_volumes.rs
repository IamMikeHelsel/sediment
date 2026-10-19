// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for `-si`/`-so` and split volumes, driving the built
//! `sediment` binary through pipes. Fixtures: tests/fixtures/streams_volumes
//! (tests/gen/streams_volumes.py, Python stdlib as the oracle).
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");
static N: AtomicU32 = AtomicU32::new(0);

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/streams_volumes").join(name)
}

fn fx_bytes(name: &str) -> Vec<u8> {
    fs::read(fx(name)).unwrap()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "sediment-sv-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn join(&self, s: &str) -> PathBuf {
        self.0.join(s)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Run the binary with `stdin` piped in and stdout/stderr captured.
fn run_in<S: AsRef<std::ffi::OsStr>>(args: &[S], stdin: &[u8], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut sin = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    // Feed stdin on a thread so a large output cannot deadlock the pipe.
    let feeder = std::thread::spawn(move || {
        let _ = sin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    out
}

fn run<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
    run_in(args, b"", &[])
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn assert_clean_fail(o: &Output, code: i32) {
    assert_eq!(o.status.code(), Some(code), "stderr: {}", text(&o.stderr));
    assert!(!text(&o.stderr).contains("panicked"), "{}", text(&o.stderr));
}

fn pair_concat() -> Vec<u8> {
    let mut v = fx_bytes("hello.txt");
    v.extend_from_slice(&fx_bytes("payload.bin"));
    v
}

fn ok(o: &Output) {
    assert_eq!(o.status.code(), Some(0), "stderr: {}", text(&o.stderr));
}

// ---------------------------------------------------------------------------
// -so / -si extraction
// ---------------------------------------------------------------------------

#[test]
fn so_single_streams_match_oracle() {
    let want = fx_bytes("payload.bin");
    for f in ["payload.bin.gz", "payload.bin.bz2", "payload.bin.xz"] {
        for cmd in ["x", "e"] {
            let o = run(&[cmd.as_ref(), "-so".as_ref(), fx(f).as_os_str()]);
            ok(&o);
            assert_eq!(o.stdout, want, "{f} {cmd}");
        }
    }
}

#[test]
fn so_writes_nothing_to_disk() {
    let t = TempDir::new("nodisk");
    let o = run(&[
        "x".as_ref(),
        "-so".as_ref(),
        format!("-o{}", t.0.display()).as_ref(),
        fx("payload.bin.xz").as_os_str(),
    ]);
    ok(&o);
    assert_eq!(fs::read_dir(&t.0).unwrap().count(), 0);
}

#[test]
fn si_so_pipes_single_streams() {
    let want = fx_bytes("payload.bin");
    for f in ["payload.bin.gz", "payload.bin.bz2", "payload.bin.xz"] {
        let o = run_in(&["x", "-si", "-so"], &fx_bytes(f), &[]);
        ok(&o);
        assert_eq!(o.stdout, want, "{f}");
    }
}

#[test]
fn si_tar_gz_is_detected_as_tar() {
    let whole = fx_bytes("pair.tar.gz.whole");
    let o = run_in(&["l", "-si"], &whole, &[]);
    ok(&o);
    let s = text(&o.stdout);
    assert!(s.contains("\thello.txt\n") && s.contains("\tpayload.bin\n"), "{s}");
    let o = run_in(&["t", "-si"], &whole, &[]);
    ok(&o);
    assert_eq!(text(&o.stdout), "OK\t2\t16015\n");
    let o = run_in(&["x", "-si", "-so"], &whole, &[]);
    ok(&o);
    assert_eq!(o.stdout, pair_concat());
}

#[test]
fn si_extracts_to_directory() {
    let t = TempDir::new("si-dir");
    let o = run_in(&["x".to_string(), "-si".into(), format!("-o{}", t.0.display())], &fx_bytes("pair.tar.gz.whole"), &[]);
    ok(&o);
    assert_eq!(fs::read(t.join("hello.txt")).unwrap(), fx_bytes("hello.txt"));
    assert_eq!(fs::read(t.join("payload.bin")).unwrap(), fx_bytes("payload.bin"));
    // A single gzip stream from stdin is named from its FNAME.
    let t2 = TempDir::new("si-gz");
    let o = run_in(&["x".to_string(), "-si".into(), format!("-o{}", t2.0.display())], &fx_bytes("payload.bin.gz"), &[]);
    ok(&o);
    assert_eq!(fs::read(t2.join("payload.bin")).unwrap(), fx_bytes("payload.bin"));
    // bzip2 has no stored name: the member is called "data".
    let t3 = TempDir::new("si-bz");
    let o = run_in(&["x".to_string(), "-si".into(), format!("-o{}", t3.0.display())], &fx_bytes("payload.bin.bz2"), &[]);
    ok(&o);
    assert_eq!(fs::read(t3.join("data")).unwrap(), fx_bytes("payload.bin"));
}

#[test]
fn si_stdin_limit_is_enforced() {
    let input = fx_bytes("payload.bin.xz");
    let o = run_in(&["x", "-si", "-so"], &input, &[("SEDIMENT_STDIN_LIMIT", "1k")]);
    assert_clean_fail(&o, 2);
    assert!(o.stdout.is_empty());
    assert!(text(&o.stderr).contains("size limit"), "{}", text(&o.stderr));
    // Exactly at the limit is fine.
    let lim = input.len().to_string();
    let o = run_in(&["x", "-si", "-so"], &input, &[("SEDIMENT_STDIN_LIMIT", &lim)]);
    ok(&o);
    // The variable can only lower the limit; bad values are rejected.
    for bad in ["", "0", "abc", "-5"] {
        let o = run_in(&["t", "-si"], &input, &[("SEDIMENT_STDIN_LIMIT", bad)]);
        assert_clean_fail(&o, 2);
    }
    let o = run_in(&["a", "-si", "-so", "-tgz"], &input, &[("SEDIMENT_STDIN_LIMIT", "1k")]);
    assert_clean_fail(&o, 1);
    assert!(o.stdout.is_empty());
}

#[test]
fn si_malformed_input_fails_cleanly() {
    let xz = fx_bytes("payload.bin.xz");
    let gz = fx_bytes("payload.bin.gz");
    let mut corrupt = gz.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0x55;
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"definitely not an archive".to_vec(),
        xz[..xz.len() / 2].to_vec(),
        gz[..gz.len() - 3].to_vec(),
        corrupt,
        b"BZh9".to_vec(),
        vec![0x1f, 0x8b, 8],
    ];
    for c in &cases {
        for args in [&["x", "-si", "-so"][..], &["t", "-si"], &["l", "-si"]] {
            let o = run_in(args, c, &[]);
            assert_clean_fail(&o, 2);
            if args[0] == "x" {
                assert!(o.stdout.is_empty(), "partial output for {args:?}");
            }
        }
    }
}

#[test]
fn stdio_usage_errors() {
    let p = fx("payload.bin.gz");
    let ps = p.to_str().unwrap();
    for args in [
        &["x", "-si", ps][..],
        &["l", "-si", ps],
        &["t", "-zz", ps],
        &["l"],
        &["a", "-so", "-v1k", "o.tar", ps],
        &["a", "-an", "o.tar", ps],
        &["a", "-so", "-an", ps],
        &["a", "-si", "o.tar", ps],
        &["a", "-v0", "o.tar", ps],
        &["a", "-vx", "o.tar", ps],
        &["a", "-tbogus", "-so", "-an", ps],
    ] {
        let o = run(args);
        assert_clean_fail(&o, 2);
    }
}

#[test]
fn so_broken_pipe_exits_quietly() {
    // ~2 MiB of output, far more than a pipe buffer.
    let big = vec![b'z'; 2 << 20];
    let gz = run_in(&["a", "-si", "-so", "-tgz"], &big, &[]);
    ok(&gz);
    let t = TempDir::new("pipe");
    let arc = t.join("big.gz");
    fs::write(&arc, &gz.stdout).unwrap();
    let mut child = Command::new(BIN)
        .args(["x".as_ref(), "-so".as_ref(), arc.as_os_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut so = child.stdout.take().unwrap();
    let mut first = [0u8; 16];
    so.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"zzzzzzzzzzzzzzzz");
    drop(so);
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    assert!(o.stderr.is_empty(), "{}", text(&o.stderr));
}

// ---------------------------------------------------------------------------
// Reading split archives
// ---------------------------------------------------------------------------

#[test]
fn split_tar_gz_reads_transparently() {
    let first = fx("pair.tar.gz.001");
    let o = run(&["l".as_ref(), first.as_os_str()]);
    ok(&o);
    assert!(text(&o.stdout).contains("\tpayload.bin\n"));
    let o = run(&["t".as_ref(), first.as_os_str()]);
    ok(&o);
    assert_eq!(text(&o.stdout), "OK\t2\t16015\n");
    let o = run(&["x".as_ref(), "-so".as_ref(), first.as_os_str()]);
    ok(&o);
    assert_eq!(o.stdout, pair_concat());
    // Concatenating the volumes reproduces the oracle archive.
    let mut cat = Vec::new();
    for i in 1..=6 {
        cat.extend_from_slice(&fx_bytes(&format!("pair.tar.gz.{i:03}")));
    }
    assert_eq!(cat, fx_bytes("pair.tar.gz.whole"));
}

#[test]
fn split_zip_extracts_to_directory() {
    let t = TempDir::new("splitzip");
    let o = run(&["x".as_ref(), format!("-o{}", t.0.display()).as_ref(), fx("pair.zip.001").as_os_str()]);
    ok(&o);
    assert_eq!(fs::read(t.join("hello.txt")).unwrap(), fx_bytes("hello.txt"));
    assert_eq!(fs::read(t.join("payload.bin")).unwrap(), fx_bytes("payload.bin"));
}

#[test]
fn split_with_missing_volume_fails_cleanly() {
    for args in [&["t"][..], &["x", "-so"], &["l"]] {
        let mut a: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        a.push(fx("gap.tar.gz.001").into_os_string());
        let o = run(&a);
        assert_clean_fail(&o, 2);
    }
    // A later volume is not a first volume: it is opened as a plain file.
    let o = run(&["t".as_ref(), fx("pair.tar.gz.002").as_os_str()]);
    assert_clean_fail(&o, 2);
    // Missing first volume.
    let o = run(&["t".as_ref(), fx("nothing.tar.gz.001").as_os_str()]);
    assert_clean_fail(&o, 2);
}

// ---------------------------------------------------------------------------
// Creation: -v, -si, -so
// ---------------------------------------------------------------------------

fn volumes_of(dir: &Path, base: &str) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(&format!("{base}.")).then(|| (n, e.metadata().unwrap().len()))
        })
        .collect();
    v.sort();
    v
}

#[test]
fn create_volumes_and_read_back() {
    let t = TempDir::new("mkvol");
    let src = t.join("src");
    fs::create_dir(&src).unwrap();
    fs::copy(fx("payload.bin"), src.join("payload.bin")).unwrap();
    fs::copy(fx("hello.txt"), src.join("hello.txt")).unwrap();
    for (name, vsize) in [("o.tar", 4096u64), ("o.zip", 3000), ("o.tgz", 1024), ("o.tar.xz", 2048), ("o.tbz2", 5000)] {
        let arc = t.join(name);
        let o = run(&["a".as_ref(), format!("-v{vsize}b").as_ref(), arc.as_os_str(), src.as_os_str()]);
        ok(&o);
        assert!(text(&o.stdout).contains(" volumes "), "{}", text(&o.stdout));
        assert!(!arc.exists(), "unsplit archive left behind");
        let vols = volumes_of(&t.0, name);
        assert!(vols.len() >= 2, "{name}: {vols:?}");
        for (i, (n, len)) in vols.iter().enumerate() {
            assert_eq!(n, &format!("{name}.{:03}", i + 1));
            if i + 1 < vols.len() {
                assert_eq!(*len, vsize, "{n}");
            } else {
                assert!(*len >= 1 && *len <= vsize, "{n}");
            }
        }
        let out = TempDir::new("mkvol-x");
        let first = t.join(&format!("{name}.001"));
        let o = run(&["x".as_ref(), format!("-o{}", out.0.display()).as_ref(), first.as_os_str()]);
        ok(&o);
        assert_eq!(fs::read(out.join("src/payload.bin")).unwrap(), fx_bytes("payload.bin"), "{name}");
        assert_eq!(fs::read(out.join("src/hello.txt")).unwrap(), fx_bytes("hello.txt"), "{name}");
    }
}

#[test]
fn create_volumes_multiple_sizes_and_units() {
    let t = TempDir::new("units");
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 7919 % 251) as u8).collect();
    let arc = t.join("d.tar");
    let o = run_in(&["a".as_ref(), "-v1k".as_ref(), "-v2K".as_ref(), arc.as_os_str()], &[], &[]);
    assert_clean_fail(&o, 2); // missing inputs
    let o = run_in(&["a".as_ref(), "-sid.bin".as_ref(), "-v1k".as_ref(), "-v2K".as_ref(), arc.as_os_str()], &data, &[]);
    ok(&o);
    let vols = volumes_of(&t.0, "d.tar");
    let sizes: Vec<u64> = vols.iter().map(|v| v.1).collect();
    // tar of 5000 bytes is 10240 bytes: 1024, then 2048-byte volumes.
    assert_eq!(sizes, vec![1024, 2048, 2048, 2048, 2048, 1024]);
    let o = run(&["x".as_ref(), "-so".as_ref(), t.join("d.tar.001").as_os_str()]);
    ok(&o);
    assert_eq!(o.stdout, data);
}

#[test]
fn create_volumes_refuses_and_overwrites_existing() {
    let t = TempDir::new("exists");
    let arc = t.join("v.gz");
    let big: Vec<u8> = (0..20000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let o = run_in(&["a".as_ref(), "-si".as_ref(), "-mx0".as_ref(), "-v4k".as_ref(), arc.as_os_str()], &big, &[]);
    ok(&o);
    let n_before = volumes_of(&t.0, "v.gz").len();
    assert!(n_before >= 5);
    // Without -y nothing is touched.
    let o = run_in(&["a".as_ref(), "-si".as_ref(), "-v4k".as_ref(), arc.as_os_str()], b"tiny", &[]);
    assert_clean_fail(&o, 1);
    assert_eq!(volumes_of(&t.0, "v.gz").len(), n_before);
    // With -y the shorter set replaces the old one and the stale tail goes.
    let o = run_in(&["a".as_ref(), "-si".as_ref(), "-y".as_ref(), "-v4k".as_ref(), arc.as_os_str()], b"tiny", &[]);
    ok(&o);
    assert_eq!(volumes_of(&t.0, "v.gz").len(), 1);
    let o = run(&["x".as_ref(), "-so".as_ref(), t.join("v.gz.001").as_os_str()]);
    ok(&o);
    assert_eq!(o.stdout, b"tiny");
    // No temporary files remain.
    assert!(fs::read_dir(&t.0).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains("sediment-tmp")));
}

#[test]
fn si_so_compress_round_trip_all_types() {
    let data = fx_bytes("payload.bin");
    for ty in ["-tgz", "-tbz2", "-txz", "-ttar", "-ttgz", "-ttbz2", "-ttxz", "-tzip"] {
        let z = run_in(&["a", "-si", "-so", ty], &data, &[]);
        ok(&z);
        assert!(!z.stdout.is_empty());
        let back = run_in(&["x", "-si", "-so"], &z.stdout, &[]);
        ok(&back);
        assert_eq!(back.stdout, data, "{ty}");
    }
    // Level 0 gzip and empty input.
    let z = run_in(&["a", "-si", "-so", "-mx0", "-tgz"], b"", &[]);
    ok(&z);
    let back = run_in(&["x", "-si", "-so"], &z.stdout, &[]);
    ok(&back);
    assert!(back.stdout.is_empty());
}

#[test]
fn si_named_member_in_tar_file() {
    let t = TempDir::new("siname");
    let arc = t.join("n.tar");
    let o = run_in(&["a".as_ref(), "-sinotes.txt".as_ref(), arc.as_os_str()], b"note body\n", &[]);
    ok(&o);
    let l = run(&["l".as_ref(), arc.as_os_str()]);
    ok(&l);
    assert!(text(&l.stdout).ends_with("10\t--------\tnotes.txt\n"), "{}", text(&l.stdout));
    // Unsafe -si names are rejected by the container writer.
    let o = run_in(&["a".as_ref(), "-si../x".as_ref(), t.join("bad.tar").as_os_str()], b"x", &[]);
    assert_clean_fail(&o, 1);
    assert!(!t.join("bad.tar").exists());
}

#[test]
fn so_tar_of_tree_round_trips_through_pipe() {
    let t = TempDir::new("tree");
    let src = t.join("tree");
    fs::create_dir_all(src.join("a/b")).unwrap();
    fs::write(src.join("a/b/one.txt"), b"one\n").unwrap();
    fs::write(src.join("two.bin"), fx_bytes("payload.bin")).unwrap();
    fs::create_dir(src.join("empty")).unwrap();
    for (ty, name) in [("-ttar", None), ("-ttgz", None), ("-ttxz", None), ("-ttbz2", None), ("", Some("x.tar.gz"))] {
        let mut args: Vec<std::ffi::OsString> = vec!["a".into(), "-so".into()];
        match name {
            Some(n) => args.push(n.into()),
            None => {
                args.push(ty.into());
                args.push("-an".into());
            }
        }
        args.push(src.clone().into_os_string());
        let tar = run_in(&args, b"", &[]);
        ok(&tar);
        assert!(!t.join("x.tar.gz").exists(), "-so must not write the named archive");
        let out = TempDir::new("tree-x");
        let o = run_in(&["x".to_string(), "-si".into(), format!("-o{}", out.0.display())], &tar.stdout, &[]);
        ok(&o);
        assert_eq!(fs::read(out.join("tree/a/b/one.txt")).unwrap(), b"one\n");
        assert_eq!(fs::read(out.join("tree/two.bin")).unwrap(), fx_bytes("payload.bin"));
        assert!(out.join("tree/empty").is_dir());
    }
}

#[test]
fn single_stream_from_path_with_so_and_volumes() {
    let t = TempDir::new("single");
    let o = run(&["a".as_ref(), "-so".as_ref(), "p.xz".as_ref(), fx("payload.bin").as_os_str()]);
    ok(&o);
    let back = run_in(&["x", "-si", "-so"], &o.stdout, &[]);
    assert_eq!(back.stdout, fx_bytes("payload.bin"));
    let arc = t.join("p.bz2");
    let o = run(&["a".as_ref(), "-v8k".as_ref(), arc.as_os_str(), fx("payload.bin").as_os_str()]);
    ok(&o);
    let x = run(&["x".as_ref(), "-so".as_ref(), t.join("p.bz2.001").as_os_str()]);
    ok(&x);
    assert_eq!(x.stdout, fx_bytes("payload.bin"));
    // Single streams take exactly one regular file.
    let o = run(&["a".as_ref(), "-so".as_ref(), "p.gz".as_ref(), fx("payload.bin").as_os_str(), fx("hello.txt").as_os_str()]);
    assert_clean_fail(&o, 1);
    let o = run(&["a".as_ref(), "-so".as_ref(), "p.gz".as_ref(), t.0.as_os_str()]);
    assert_clean_fail(&o, 1);
}
