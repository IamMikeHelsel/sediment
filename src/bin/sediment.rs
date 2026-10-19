// SPDX-License-Identifier: MIT OR Apache-2.0
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;

use sediment_engine::archive_name::escape_name;
use sediment_engine::zip_index::{parse_entries, ZipLimits};
use sediment_engine::zip_decode::entry_data;

fn err(msg: &'static str, code: i32) -> ! {
    let _ = writeln!(io::stderr().lock(), "sediment: {msg}");
    process::exit(code);
}

fn main() {
    let mut args = std::env::args_os();
    args.next();
    let cmd = args.next();
    if cmd.as_deref() == Some(std::ffi::OsStr::new("--help")) {
        if args.next().is_some() {
            err("too many arguments", 2);
        }
        let mut out = io::stdout().lock();
        if let Err(e) = out.write_all(b"Usage: sediment <list|test> ARCHIVE\n") {
            err("write error", 1);
        }
        if let Err(e) = out.flush() {
            err("flush error", 1);
        }
        return;
    }
    let cmd = match cmd {
        Some(c) => c,
        None => err("missing command", 2),
    };
    if cmd != "list" && cmd != "test" {
        err("unknown command", 2);
    }
    let path = match args.next() {
        Some(p) => p,
        None => err("missing archive path", 2),
    };
    if args.next().is_some() {
        err("too many arguments", 2);
    }
    let p = Path::new(&path);
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(_) => err("cannot access file", 1),
    };
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let mut f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => err("cannot open file", 1),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(_) => err("cannot read file metadata", 1),
    };
    if !m.is_file() || m.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let max = 64 * 1024 * 1024;
    let mut buf = Vec::new();
    if let Err(_) = buf.try_reserve_exact(max + 1) {
        err("allocation failed", 1);
    }
    if let Err(_) = f.take(max as u64 + 1).read_to_end(&mut buf) {
        err("read error", 1);
    }
    if buf.len() > max {
        err("file too large", 1);
    }
    let limits = ZipLimits { max_entries: 10000, max_total_size: 64 * 1024 * 1024 };
    let entries = match parse_entries(&buf, limits) {
        Ok(e) => e,
        Err(_) => err("parse error", 1),
    };
    let mut out = io::stdout().lock();
    if cmd == "list" {
        if let Err(_) = out.write_all(b"SIZE\tCRC32\tNAME\n") {
            err("write error", 1);
        }
        for e in &entries {
            let esc = match escape_name(e.name) {
                Ok(s) => s,
                Err(_) => err("escape error", 1),
            };
            if let Err(_) = writeln!(out, "{}\t{:08x}\t{}", e.size, e.crc32, esc) {
                err("write error", 1);
            }
        }
    } else {
        let count = entries.len();
        let per_entry_blocks = if count > 0 { 100000 / count } else { 100000 };
        let mut total: u64 = 0;
        for e in &entries {
            let data = match entry_data(&buf, e, e.size, per_entry_blocks) {
                Ok(d) => d,
                Err(_) => err("payload error", 1),
            };
            drop(data);
            total = match total.checked_add(e.size as u64) {
                Some(v) => v,
                None => err("overflow", 1),
            };
        }
        if let Err(_) = writeln!(out, "OK\t{count}\t{total}") {
            err("write error", 1);
        }
    }
    if let Err(_) = out.flush() {
        err("flush error", 1);
    }
}
