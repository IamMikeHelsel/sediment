# Preview validation — 2026-10-15

Host: macOS 27.0.1, Apple Silicon. Rust 1.98.1. Local evidence only.

## Executed

- Core test suite: 12 passing tests covering ZIP/TAR/TAR.GZ round trips, Unicode and empty directories, path traversal, symlinks, duplicate names, overwrite refusal, corrupted ZIP rollback, gzip truncation, root TAR directory handling, and safety-limit boundaries.
- Strict Clippy on all targets and rustfmt checks passed.
- Optimized Apple Silicon executable built.
- Packaged native GUI visually reviewed: empty state and archive contents.
- Native GUI workflow: open sample ZIP, verify it, select extraction parent, extract into a fresh child directory. Recursive diff confirms original file contents and empty directories survive.
- Native GUI creation: select folder, save ZIP, automatically browse created archive. macOS `unzip -t` independently reports every entry OK.
- GUI filtering tested with `hello`: only the matching file remains.
- CLI ZIP creation and integrity verification passed; independent macOS `unzip -t` passed.

## Still open

- Public distribution: Developer ID signing attempt stalled and was terminated; current packaging uses an ad-hoc local signature. Not notarized, not published.
- No Windows/Linux or Intel macOS validation, clean-machine install test, large archive performance study, fuzzing campaign, or full keyboard/VoiceOver acceptance.
- File dialog cancellation, drag/drop, window-size edge cases and cancellation during operations have not been comprehensively validated. Mid-operation cancellation is not implemented.
- This is an original Rust archive manager using third-party codecs, not full WinRAR parity. RAR, 7z, encryption, recovery and split volumes remain unsupported.
- Dependency advisory results and upstream notice qualification are recorded in RELEASE_CHECKLIST.md and UPSTREAM_LICENSES.md.


## 0.1.1 cassette GUI — 2026-10-17

- Palette/layout adapted from local drift cassette design references; no third-party artwork copied.
- 600 × 420 initial window, 560 × 380 minimum, first archive view expands to at least 760 × 540 without shrinking larger user windows.
- Light/dark/System appearance, compact header, fixed status strip, keyboard-accessible operation details, compact ZIP composer.
- Actual egui UI rendered offscreen through egui_kittest/WGPU for light/dark empty and archive states, minimum-size archive, and minimum-size composer. Images in `docs/evidence/cassette-0.1.1/`. These are app renders with representative fixture data, not native desktop captures.
- Native GUI reinspection was blocked by repeated `Sky Computer Use native pipe startup failed` errors. Prior 0.1.0 native workflow evidence does not establish 0.1.1 native acceptance.
- Test-only rendering dependencies added; runtime dependency requirements unchanged. Prior advisory report applies to its recorded lock hash, not the expanded development lockfile.
- Still a local ad-hoc-signed preview; distribution signing/notarization remain open.


## 0.1.2 hardening — 2026-10-17

The shared gate in scripts/check.sh passed with Rust 1.98.1: 26 archive tests, 7 GUI behavior tests, and 7 CLI-only integration cases (6 also run in desktop builds), with strict Clippy, Rustfmt, Ruff and ShellCheck. Ignored GPU rendering and the release 100k-entry UI benchmark were each run explicitly. Test suite repetition across feature combinations is not counted as additional unique coverage.

Cancellation tests exercise real worker operations, temporary-output rollback, already-completed publication, close deferral, and worker panic recovery. A real standalone CLI process was interrupted with SIGINT after its compression phase started: exit130, empty stdout, absent output, no staging residue, and no filenames in structured events. Trace includes the final binary SHA-256.

The archive engine now bounds ZIP metadata parsing before allocation, validates ZIP32/ZIP64 container limits, limits GNU/PAX extension metadata, rejects special/symlink archive sources without blocking, validates creation source identity, and uses buffered I/O. ZIP9 offset detection is explicitly fixed at zero because prepended/SFX archives are unsupported; this avoids scanning payload data to infer an offset. These checks do not establish universal malicious-archive immunity or fuzzing acceptance.

The final performance comparison uses the same generated payload manifest and independent extraction/CRC validation. Timings include process startup and system/cache noise; see performance-before.json and performance-after.json. GUI responsiveness evidence uses an actual release-mode egui harness with100,000 entries; no native display latency claim follows.

Actual native GUI inspection remains blocked by the computer-use native pipe startup failure. Public signing/notarization, native accessibility/dialog/drop acceptance, and clean-machine install remain separate release gates.


Final signing update: Developer ID signing succeeded with hardened runtime. Local signature validation passes. Gatekeeper rejects the artifact as Unnotarized Developer ID; notarization credentials/profile were not available from inspected configuration. See signing-0.1.2.json and the release checklist. No public release was performed.

## 0.1.3 workflow candidate — 2026-10-17

`./scripts/check.sh` passed: 26 core tests, 11 GUI behavior tests, 10 CLI-only integration tests (9 in the GUI build), formatting, strict Clippy, Ruff and ShellCheck. The GUI suite now includes real create→preview→verify→extract workers with Unicode payload readback and preservation of an existing output folder. The explicit GPU render suite also passed; layouts are under `evidence/workflows-0.1.3/`.

Both locked release builds succeeded, including the GUI-free executable. The final CLI passed a real SIGINT test with exit130, no published output or staging residue, and no private fixture paths in diagnostics. Fresh cargo-audit reported zero known vulnerabilities; four maintenance advisories remain. Dependency versions are unchanged from the final 0.1.2 lock except the root package version.

Evidence: `evidence/check-workflows-0.1.3.log`, `evidence/trace-cancellation-0.1.3.json`, `evidence/cargo-audit-0.1.3.json`. The previous performance numbers are observations of 0.1.2, not fresh benchmarks of this candidate.

Native UI inspection again failed before connection with `Sky Computer Use native pipe startup failed`. Native dialogs, clean-download Gatekeeper acceptance and the oldest supported macOS remain open. See USER_JOURNEYS.md for the logical review and remaining native checklist. GitHub integration/publication and hosted CI have not occurred in this checkout.
