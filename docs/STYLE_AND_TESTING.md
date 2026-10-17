# Style and testing

Use Rust 1.98.1 (matching the CI pin), Rust's formatter and strict Clippy instead of subjective formatting rules. Keep changes focused, preserve unrelated and generated files, and test failure paths whenever changing archive or persistence behavior. These principles follow the local drift STYLE.md and CONTRIBUTING.md conventions; Flutter-specific tooling does not apply here.

Run `./scripts/check.sh` before packaging. It checks formatting, strict Clippy and locked tests for the desktop/default build and the CLI-only build, plus GUI behavior tests with `--features gui-test`. Python benchmark tooling uses only the standard library; authored Python is checked and formatted with Ruff 0.14.8, and shell scripts are checked with ShellCheck 0.11.0 (CI distribution shellcheck-py 0.11.0.1) plus `bash -n` syntax validation. Keep Cargo.lock committed. A lock update requires a fresh dependency audit.

Integration tests in tests/cli.rs execute the actual binary and verify JSON/human command behavior, Unicode paths, corrupted ZIP checksums, path traversal rejection, no-overwrite behavior, exit codes, and CLI-only startup. Use generated synthetic fixtures and independent payload checks; do not assert incidental implementation details. Unit tests belong beside archive logic for adversarial cases inaccessible through a practical CLI fixture.

The non-rendering GUI behavior harness runs in the ordinary check script with `--features gui-test`. Ignored GUI render snapshots are a separate graphics-capable check using `--features gui-test` and their explicit test names. Run them on a machine with the intended graphics backend. A render snapshot is not acceptance of native dialogs, keyboard accessibility, display scaling, Finder launch, signing, or notarization. Manually exercise light/dark/system modes, initial/minimum sizes, long names and errors, busy behavior, cancellation, and the complete create/open/test/extract workflow before a desktop release.

The GitHub workflow defines macOS desktop/default checks and Linux CLI-only checks. Creating this file does not mean hosted CI has run or passed. Record exact failures and distinguish unavailable hosted validation from a failing code test.

## Reproducible performance observations

`scripts/benchmark.py` creates 1,000 small files plus a 16 MiB mixed compressible/pseudorandom file using a fixed seed. It times ZIP and TAR.GZ list/test/extract and ZIP creation, three runs each, including process startup. Extraction and ZIP creation are verified against a SHA-256 payload manifest; ZIP creation also passes Python's independent CRC check. Fixture setup and correctness checks are outside the timed interval. Compression container bytes contain metadata and are not expected to be identical.

```sh
python3 scripts/benchmark.py --binary /tmp/sediment-baseline-0.1.1 --output docs/evidence/performance-before.json
python3 scripts/benchmark.py --binary target/release/sediment --output docs/evidence/performance-after.json --compare docs/evidence/performance-before.json
```

Results are host-specific observations, with warm fixture data, potentially cold executable startup, and ordinary system noise. Compare medians and investigate material changes; no universal timing threshold is invented. Re-run both candidates on the same quiet host when making a performance claim. A faster median does not establish correctness, lower memory use, or a broad production speedup. Preserve the executable hash, workload manifest hash, individual samples, environment, and baseline comparison with the evidence.

Regenerate local dependency notices after lock changes with `python3 scripts/generate-notices.py`; review entries lacking published license files against the separately preserved upstream supplement. The generator does not certify licensing and must not overwrite `docs/UPSTREAM_LICENSES.md`. CI's separate audit job installs cargo-audit 0.22.2 and records JSON; vulnerability findings fail the job, while informational unmaintained warnings remain visible without being promoted to failures. Refresh the advisory database on each run.

## Recorded 0.1.2 measurements

The final desktop and CLI-only release executables both passed all workload payload/hash checks (three timed runs per operation). Desktop measurements below compare against the preserved 0.1.1 binary on this host. Lower timings include caching and scheduling effects; they are not guaranteed speedups.

| Operation | Before median (ms) | Desktop after (ms) | CLI-only after (ms) |
| --- | ---: | ---: | ---: |
| zip_list | 30.9 | 13.7 | 12.5 |
| zip_test | 38.5 | 27.2 | 23.6 |
| zip_extract | 290.9 | 170.2 | 122.3 |
| tar_gz_list | 12.8 | 12.4 | 12.2 |
| tar_gz_test | 19.0 | 18.1 | 16.2 |
| tar_gz_extract | 114.0 | 112.8 | 109.6 |
| zip_create | 183.5 | 170.2 | 174.3 |

Evidence: [before](evidence/performance-before.json), [desktop after](evidence/performance-after.json), [CLI-only after](evidence/performance-cli.json). The CLI-only measurements use a different executable, so their comparison includes linking/startup differences; they do not isolate one optimization.
