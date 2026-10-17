use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output},
};
use zip::{ZipWriter, write::SimpleFileOptions};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sediment"))
        .args(args)
        .env_remove("SEDIMENT_TRACE")
        .output()
        .expect("run CLI")
}
fn text(path: &Path) -> &str {
    path.to_str().expect("fixture path is Unicode")
}
fn fixture(path: &Path, name: &str, bytes: &[u8]) {
    let mut archive = ZipWriter::new(fs::File::create(path).unwrap());
    archive
        .start_file(
            name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    archive.write_all(bytes).unwrap();
    archive.finish().unwrap();
}

#[test]
fn cli_round_trip_and_json_contract() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("hello world — 測試.txt");
    fs::write(&input, b"archive contract\n").unwrap();
    let archive = root.path().join("result.zip");
    let created = cli(&["--json", "create", text(&archive), text(&input)]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(created["operation"], "create");
    assert_eq!(created["files"], 1);
    let archive_before = fs::read(&archive).unwrap();
    let conflict = cli(&["create", text(&archive), text(&input)]);
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(fs::read(&archive).unwrap(), archive_before);
    let listed = cli(&["list", text(&archive), "--json"]);
    assert!(listed.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["operation"], "list");
    assert_eq!(listed["format"], "ZIP");
    assert_eq!(listed["entries"][0]["name"], "hello world — 測試.txt");
    assert_eq!(listed["total_size"], 17);
    let tested = cli(&["--json", "test", text(&archive)]);
    assert!(tested.status.success());
    let tested: serde_json::Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(tested["files"], 1);
    let destination = root.path().join("new destination");
    let extracted = cli(&["--json", "extract", text(&archive), text(&destination)]);
    assert!(extracted.status.success());
    assert_eq!(
        fs::read(destination.join(input.file_name().unwrap())).unwrap(),
        b"archive contract\n"
    );
    let conflict = cli(&["extract", text(&archive), text(&destination)]);
    assert_eq!(conflict.status.code(), Some(1));
    assert!(conflict.stdout.is_empty());
    assert_eq!(
        fs::read(destination.join(input.file_name().unwrap())).unwrap(),
        b"archive contract\n"
    );
}

#[test]
fn corruption_returns_failure_and_publishes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("corrupt.zip");
    fixture(&path, "payload.txt", b"uniquely identifiable payload");
    let mut data = fs::read(&path).unwrap();
    let offset = data
        .windows(29)
        .position(|window| window == b"uniquely identifiable payload")
        .unwrap();
    data[offset] ^= 0xff;
    fs::write(&path, data).unwrap();
    let tested = cli(&["--json", "test", text(&path)]);
    assert_eq!(tested.status.code(), Some(1));
    assert!(tested.stdout.is_empty());
    let failure: serde_json::Value = serde_json::from_slice(&tested.stderr).unwrap();
    assert!(failure["error"].is_string());
    assert_eq!(failure["cancelled"], false);
    let destination = root.path().join("must-not-exist");
    assert!(
        !cli(&["extract", text(&path), text(&destination)])
            .status
            .success()
    );
    assert!(!destination.exists());
}

#[test]
fn traversal_and_unsupported_inputs_fail_cleanly() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("traversal.zip");
    fixture(&path, "../escaped.txt", b"no escape");
    let destination = root.path().join("out");
    assert_eq!(
        cli(&["extract", text(&path), text(&destination)])
            .status
            .code(),
        Some(1)
    );
    assert!(!destination.exists());
    assert!(!root.path().join("escaped.txt").exists());
    let invalid = root.path().join("unsupported.rar");
    fs::write(&invalid, b"not a supported archive").unwrap();
    let output = cli(&["list", text(&invalid)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn usage_and_version_have_predictable_exit_codes() {
    assert!(cli(&["--help"]).status.success());
    assert!(cli(&["--version"]).status.success());
    assert_eq!(cli(&["extract"]).status.code(), Some(2));
    assert_eq!(cli(&["--unknown-option"]).status.code(), Some(2));
}

#[cfg(not(feature = "gui"))]
#[test]
fn cli_only_no_arguments_explains_gui_requirement() {
    let output = cli(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn trace_is_json_and_does_not_disclose_archive_names() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private-archive-name.zip");
    fixture(&path, "private-member-name.txt", b"synthetic fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_sediment"))
        .args(["--trace", "--json", "test", text(&path)])
        .env_remove("SEDIMENT_TRACE")
        .output()
        .unwrap();
    assert!(output.status.success());
    let trace = String::from_utf8(output.stderr).unwrap();
    assert!(!trace.is_empty());
    assert!(!trace.contains("private-archive-name"));
    assert!(!trace.contains("private-member-name"));
    assert!(!trace.contains(text(root.path())));
    for line in trace.lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(event.is_object());
    }
}

#[test]
fn human_listing_escapes_terminal_control_characters() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control.zip");
    let name = "name\u{1b}[31m\nsecond-line\t.txt";
    fixture(&path, name, b"fixture");
    let output = cli(&["list", text(&path)]);
    assert!(output.status.success());
    let listing = String::from_utf8(output.stdout).unwrap();
    assert!(!listing.contains('\u{1b}'));
    assert!(!listing.contains('\t'));
    assert_eq!(listing.lines().count(), 2, "member newline must be escaped");
    assert!(listing.contains(&name.escape_debug().to_string()));
    let machine = cli(&["--json", "list", text(&path)]);
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["entries"][0]["name"], name);
}

#[test]
fn shortcuts_extract_beside_archive_and_report_output() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("holiday photos.ZIP");
    fixture(&path, "photo.txt", b"picture");
    assert!(cli(&["l", text(&path)]).status.success());
    assert!(cli(&["t", text(&path)]).status.success());
    let output = cli(&["x", text(&path), "--json"]);
    assert!(output.status.success(), "{:?}", output);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let destination = root.path().join("holiday photos");
    assert_eq!(result["destination"], text(&destination));
    assert_eq!(fs::read(destination.join("photo.txt")).unwrap(), b"picture");
    assert_eq!(cli(&["x", text(&path)]).status.code(), Some(1));
    let new_archive = root.path().join("copy.zip");
    let created = cli(&["c", text(&new_archive), text(&destination), "--json"]);
    assert!(created.status.success());
    let result: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(result["output"], text(&new_archive));
}

#[test]
fn default_destination_handles_compound_suffix_and_rejects_ambiguous_names() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("backup.TAR.GZ");
    let gzip = flate2::write::GzEncoder::new(
        fs::File::create(&path).unwrap(),
        flate2::Compression::default(),
    );
    let mut tar = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "file.txt", &b"payload"[..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    assert!(cli(&["x", text(&path)]).status.success());
    assert_eq!(
        fs::read(root.path().join("backup/file.txt")).unwrap(),
        b"payload"
    );
    for name in [".zip", "..zip", "...zip", "no-extension"] {
        let path = root.path().join(name);
        fixture(&path, "file.txt", b"fixture");
        assert_eq!(cli(&["x", text(&path)]).status.code(), Some(1));
    }
}

#[cfg(unix)]
#[test]
fn shell_shortcuts_preserve_arguments_and_system_sed() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("sediment's binary");
    fs::copy(env!("CARGO_BIN_EXE_sediment"), &binary).unwrap();
    let archive = root.path().join("archive with spaces.zip");
    fixture(&archive, "payload.txt", b"fixture");
    for alias in ["sdm", "sed"] {
        let init = Command::new(&binary)
            .args(["shell-init", "--alias", alias])
            .output()
            .unwrap();
        assert!(init.status.success());
        let script = String::from_utf8(init.stdout).unwrap();
        for shell in ["bash", "zsh"] {
            // zsh is the macOS default; Linux CI need only have bash.
            if shell == "zsh" && !cfg!(target_os = "macos") {
                continue;
            }
            let invocation = format!(
                "{script}\n{alias} t \"$1\" --json && printf 'before\\n' | command sed 's/before/after/'"
            );
            let output = Command::new(shell)
                .args(["-c", &invocation, "shortcut-test", text(&archive)])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains("\"files\":1"));
            assert!(stdout.ends_with("after\n"));
        }
    }
    assert_eq!(
        cli(&["shell-init", "--alias", "bad;command"]).status.code(),
        Some(2)
    );
}
