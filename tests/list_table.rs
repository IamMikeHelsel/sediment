// SPDX-License-Identifier: MIT OR Apache-2.0
//! Default `sediment l` table vs `TZ=UTC 7zz l` output captured on sparky
//! (tests/fixtures/list_table/*.l.txt; archives from tests/gen/list_table.py
//! and tests/fixtures/sevenz_write/lzma2_solid_hc.7z).

use std::path::{Path, PathBuf};
use std::process::Command;

use sediment_engine::cli_slt::{TableRow, format_table_row, format_table_totals, table_attributes};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");

fn fx(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir)
}

fn expected(name: &str) -> String {
    let full = std::fs::read_to_string(fx("list_table").join(format!("{name}.l.txt"))).unwrap();
    let at = full.find("Listing archive:").unwrap();
    full[at..].to_string()
}

fn sediment_l(dir: &str, name: &str, extra: &[&str]) -> (i32, String) {
    let o = Command::new(BIN).arg("l").args(extra).arg(name).current_dir(fx(dir)).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8(o.stdout).expect("listing is UTF-8"))
}

/// Archive-block lines 7-Zip prints that Sediment does not compute (yet).
fn without_unsupported(text: &str, skip: &[&str]) -> String {
    text.lines().filter(|l| !skip.iter().any(|p| l.starts_with(p))).map(|l| format!("{l}\n")).collect()
}

fn rows_only(text: &str) -> String {
    let mut parts = text.split("------------------- ----- ------------ ------------  ------------------------\n");
    parts.nth(1).unwrap().to_string()
}

#[test]
fn zip_matches_7zz() {
    let (code, out) = sediment_l("list_table", "basic.zip", &[]);
    assert_eq!(code, 0);
    assert_eq!(out, expected("basic.zip"));
}

#[test]
fn tar_matches_7zz() {
    let (code, out) = sediment_l("list_table", "basic.tar", &[]);
    assert_eq!(code, 0);
    let want = without_unsupported(&expected("basic.tar"), &["Headers Size = ", "Code Page = ", "Characteristics = "]);
    assert_eq!(out, want);
}

#[test]
fn sevenz_matches_7zz() {
    let (code, out) = sediment_l("sevenz_write", "lzma2_solid_hc.7z", &[]);
    assert_eq!(code, 0);
    assert_eq!(out, expected("lzma2_solid_hc.7z"));
}

#[test]
fn ba_prints_rows_only() {
    for (dir, name) in [("list_table", "basic.zip"), ("list_table", "basic.tar"), ("sevenz_write", "lzma2_solid_hc.7z")] {
        let (code, out) = sediment_l(dir, name, &["-ba"]);
        assert_eq!(code, 0);
        assert_eq!(out, rows_only(&expected(name)), "{name}");
    }
}

#[test]
fn selection_filters_rows_and_totals() {
    let o = Command::new(BIN).args(["l", "basic.zip", "-r", "*.txt"]).current_dir(fx("list_table")).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let out = String::from_utf8(o.stdout).unwrap();
    assert!(out.ends_with("  4 files\n"), "{out}");
    assert!(out.contains("  café.txt\n"), "{out}");
    assert!(!out.contains("  empty\n"), "{out}");
}

#[test]
fn empty_and_unknown_columns() {
    assert_eq!(format_table_totals(&[]), format!("{:19}       {:>12} {:>12}  0 files\n", "", 0, 0));
    let r = TableRow { name: "x".into(), size: 3, ..TableRow::default() };
    assert_eq!(format_table_row(&r), format!("{:19} ..... {:>12} {:>12}  x\n", "", 3, ""));
    assert!(format_table_totals(&[r]).ends_with("3               1 files\n"));
    assert_eq!(table_attributes(0x37), "DRHSA");
}

#[test]
fn frozen_list_unchanged() {
    let o = Command::new(BIN).arg("list").arg("basic.zip").current_dir(fx("list_table")).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.starts_with("SIZE\tCRC32\tNAME\n"), "{s}");
}
