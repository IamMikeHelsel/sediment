# sediment frontier candidates (scouted 2026-10-22)

Source of truth: `docs/SYNERGY_WEIGHTS.json` and `docs/RESEARCH_FRONTIER_2026-10.md` in the sibling `ctrl` repo, lane SED (plus cross-domain `XD-02`). Query with `./ctrl synergy rank -c -d rust_systems` there. This page is a rendered copy for readers of this repo.

## What the scout found

- sediment never calls the library extractors that shipped the 2025–2026 zip-slip and PAX advisories (zip CVE-2025-29787, tar-rs CVE-2026-33055/33056, par2cmdline GHSA-j5pc-g362-c5xp), so it avoids them by construction. It has no published, machine-checkable statement of what it rejects.
- The Mac archiver market is saturated and security-marketed (Keka, The Unarchiver, PeaZip 11.x, NanaZip 6). The credible niche is auditable, scriptable extraction (JSON/NDJSON, exit codes, never-overwrite), reproducible creation, and provably safe extraction as a credibility claim.
- Homebrew 5 deprecated non-notarized casks, so distribution now needs the paid Apple Developer program; cosign `sign-blob --bundle` is the one-file way to sign release tarballs.
- Real cross-link to `ctrl`: PAR2 recovery records are Reed–Solomon erasure decoding over GF(2^16). ArkLib (Lean) already has RS codes and a Berlekamp–Welch decoder with correctness theorems; the erasure-decoder correctness and the PAR2 layout would be new. The `ctrl` Reed–Solomon modules are on a branch not present in this checkout.
- Stretch links assessed honestly: response-time analysis and information theory do not give sediment a theorem, only vocabulary.

## Candidates, cheapest first

| id | kind | weeks | payoff | conf | title |
| --- | --- | ---: | ---: | ---: | --- |
| `SED-07` | productionize | 1 | 2 | 0.85 | OpenTelemetry CLI semantic-convention alignment of the JSON trace |
| `SED-09` | explore | 1 | 1 | 0.30 | Cancellation-latency bound as measured evidence (RTA cross-link, assessed as a stretch) |
| `SED-04` | productionize | 2 | 3 | 0.85 | Reproducible ZIP/TAR creation mode (SOURCE_DATE_EPOCH, sorted, normalized) |
| `SED-02` | productionize | 2 | 3 | 0.80 | Archive-hardening regression corpus and named extraction policy |
| `SED-05` | industrialize | 2 | 3 | 0.70 | Notarized Homebrew cask and cargo-dist pipeline with sigstore bundles |
| `SED-08` | explore | 2 | 3 | 0.65 | Kani-proved resource accounting for decompression-bomb limits |
| `SED-11` | productionize | 2 | 2 | 0.60 | Signed archive manifest and verify-against-manifest for auditable extraction |
| `SED-06` | productionize | 3 | 3 | 0.70 | Read-only zstd, xz, 7z and ZIP-AES support under sediment's limit wrappers |
| `SED-01` | explore | 3 | 3 | 0.60 | Lean-checked archive path sanitizer (hax/Aeneas) with Kani harness |
| `SED-10` | industrialize | 3 | 2 | 0.50 | Linux/Windows CLI-first ports with egui GUI as beta |
| `XD-02` | productionize | 5 | 3 | 0.70 | Verified PAR2-style recovery records for sediment |
| `SED-03` | explore | 8 | 4 | 0.55 | Verified GF(2^16) PAR2 recovery-record kernel bridging ctrl Reed-Solomon and ArkLib |

Recommended order from the scout: `SED-02` → `SED-07` → `SED-04` → `SED-01` → `SED-08` → `SED-05` → `SED-03` (only after confirming the `ctrl` Reed–Solomon branch exists) → `SED-06` → `SED-11` → `SED-10`. Skip `SED-09` beyond a paragraph in the docs.

### `SED-07` OpenTelemetry CLI semantic-convention alignment of the JSON trace

- **Why now.** OpenTelemetry now has dedicated 'Semantic conventions for CLI programs' (Release Candidate attributes process.executable.name/process.exit.code/process.pid, Stable error.type) whose privacy posture (do not collect command args by default) matches sediment's no-paths trace, so alignment costs field renames, not architecture.
- **Prior art.** OTel CLI span conventions; Equinix otel-cli v0.4.5 bridges shell output to OTLP; sediment's tracing-subscriber JSON layer with archive_operation span.
- **What we would build.** Emit process.executable.name, process.exit.code, process.pid and a closed-enum error.type (unsafe_path, limit_exceeded, cancelled, destination_exists, format_unsupported, io, changed_during_operation) on the root span; document the NDJSON schema with a version field; keep no exporter in-tree and show the otel-cli pipe recipe.
- **External pull.** Standard: OpenTelemetry semantic conventions (Development status, so early alignment can feed back issues)
- **Evidence.** <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/cli/cli-spans.md> · <https://github.com/packethost/otel-cli> · <https://deploy.equinix.com/labs/otel-cli>

### `SED-09` Cancellation-latency bound as measured evidence (RTA cross-link, assessed as a stretch)

- **Why now.** sediment already records cancellation phases and durations (scripts/trace-smoke.py, docs/evidence/trace-cancellation-0.1.2.json), so a stated bound (time-to-ack <= one 64 KiB read + one fs call + staging cleanup) can be checked against evidence now; but ctrl's ROBO-04 fixed-priority response-time analysis models periodic task sets, which a single cooperative worker is not.
- **Prior art.** ctrl ROBO-04 RTA (Liu-Layland critical instant, per docs/IDEA_PORTFOLIO_AND_SYNERGIES.md); sediment OperationControl + copy_controlled check-per-buffer design.
- **What we would build.** A one-page doc stating the cancellation latency model and a test asserting the measured p99 against it. No theorem is warranted; information-theoretic bomb detection likewise reduces to the existing ratio policy.
- **External pull.** None identified
- **Evidence.** <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/cli/cli-spans.md>

### `SED-04` Reproducible ZIP/TAR creation mode (SOURCE_DATE_EPOCH, sorted, normalized)

- **Why now.** Reproducible-builds practice (SOURCE_DATE_EPOCH, strip-nondeterminism, repro-zipfile/repro-tarfile, Helm 4 reproducible charts) is now expected of release tooling, and sediment's create path still uses wall-clock mtimes and directory-walk order (SimpleFileOptions::default()).
- **Prior art.** repro-zipfile/repro-tarfile (Python), python-stripzip, strip-nondeterminism (Debian), Cargo's own deterministic .crate packaging (no URL); zip2 supports fixed last-modified times and feature-gated compressors.
- **What we would build.** A `--reproducible` flag (and GUI toggle) that sorts entries bytewise, sets mtime from SOURCE_DATE_EPOCH or 1980-01-01, fixes modes to 0644/0755, drops extra fields, forces the UTF-8 flag, uses a fixed deflate level, and a CI test asserting byte-identical output across two hosts; documented as part of the auditability story.
- **External pull.** Standard: reproducible-builds.org SOURCE_DATE_EPOCH convention; release engineers using cargo-dist/GitHub Actions
- **Evidence.** <https://cwiki.apache.org/confluence/spaces/SECURITY/pages/287607354/Reproducible+Builds> · <https://github.com/drivendataorg/repro-tarfile> · <https://pypi.org/project/python-stripzip/0.2.4> · <https://github.com/zip-rs/zip2>

### `SED-02` Archive-hardening regression corpus and named extraction policy

- **Why now.** Between Mar 2025 and Jun 2026 at least six extractor advisories landed across zip (Rust), tar-rs, mholt/archiver (Go), par2cmdline and libarchive; sediment avoids all of them by construction but has no published, machine-checkable statement of what it rejects, and Python 3.14 just made PEP 706's 'data' filter the default, giving a vocabulary to align with.
- **Prior art.** PEP 706 filters (fully_trusted/tar/data); tar-rs and zip2 advisory test cases; sediment's own unit tests (rejects_traversal_without_publishing, rejects_tar_symlinks, rejects_tar_duplicate_paths, safety_limit_boundaries).
- **What we would build.** A fixtures crate/corpus reproducing each 2025-2026 CVE class (symlink-then-file, symlink-then-dir chmod, PAX size disagreement, PAX desync, dangling-symlink destination, zip64 metadata bomb, overlapping-entry bomb) with cargo-fuzz targets for the PAX reader and EOCD preflight, and a documented 'sediment data filter' policy table comparable to PEP 706.
- **External pull.** Community: contributable as regression fixtures to zip-rs/zip2 and alexcrichton/tar-rs; cited by security reviewers evaluating archive tooling
- **Evidence.** <https://github.com/advisories/GHSA-94vh-gphv-8pm8> · <https://github.com/rustsec/advisory-db/blob/main/crates/tar/RUSTSEC-2026-0068.md> · <https://github.com/alexcrichton/tar-rs/security/advisories> · <https://github.com/Parchive/par2cmdline/security/advisories/GHSA-j5pc-g362-c5xp> · <https://www.sentinelone.com/vulnerability-database/cve-2025-3445/> · <https://github.com/python/peps/blob/main/peps/pep-0706.rst>

### `SED-05` Notarized Homebrew cask and cargo-dist pipeline with sigstore bundles

- **Why now.** Homebrew 5.0.0 deprecated non-notarized casks with removal from the main tap by Sep 2026, so the only free Mac distribution channel that matters now requires exactly the Developer ID + notarization gate that sediment's 0.1.3 release notes list as still open; cosign sign-blob --bundle has become the one-file way to sign tarballs.
- **Prior art.** Homebrew Acceptable-Casks policy (Gatekeeper must pass; notability required; OSS without compiled distribution rejected); Foundry's release workflow (sha256 + SBOM + cosign + actions/attest) as a reference; sediment's scripts/package-macos.sh and docs/RELEASE_CHECKLIST.md.
- **What we would build.** A hosted CI job producing Developer-ID-signed, notarized, stapled app and CLI artifacts, cosign bundles and sha256, a homebrew tap (own tap first, since main-tap notability is not yet met), and completion of the native acceptance table in USER_JOURNEYS.md.
- **External pull.** Standard/market: Homebrew cask policy and Apple notarization; blocked on a paid Apple Developer account and a real Mac for native acceptance
- **Evidence.** <https://workbrew.com/blog/homebrew-5-0-0> · <https://flaviocopes.com/macos-open-anyway.md> · <https://github.com/Homebrew/brew/blob/main/docs/Acceptable-Casks.md> · <https://github.com/sigstore/docs/blob/main/content/en/cosign/signing/signing_with_blobs.md>

### `SED-08` Kani-proved resource accounting for decompression-bomb limits

- **Why now.** Kani is now the workhorse of the AWS verify-rust-std program (10/29 challenges resolved, ASE'26 paper) and sediment's budget logic (check_limits, zip_metadata_preflight incl. zip64, SafeZipReader byte budget, drain_padding, MAX_TAR_EXTENSION) is small, integer-only and loop-bounded, which is exactly Kani's sweet spot.
- **Prior art.** verify-rust-std harnesses for numeric primitives/Duration/NonZero; sediment's safety_limit_boundaries unit test; no formal proof of archive budget invariants found.
- **What we would build.** Proof harnesses showing: no arithmetic overflow in check_limits/preflight for all u64 inputs; bytes written by copy_controlled never exceed the announced entry size; cumulative entries/bytes/metadata never exceed MAX_* before an Err; PAX size override is applied consistently (the CVE-2026-33055 class) in sediment's own TAR reader. Run in CI behind a feature.
- **External pull.** Community: verify-rust-std style harnesses are a recognised evidence format; useful collateral for SED-05's security claims
- **Evidence.** <https://github.com/model-checking/kani> · <https://github.com/model-checking/verify-rust-std> · <https://github.com/rustsec/advisory-db/blob/main/crates/tar/RUSTSEC-2026-0068.md>

### `SED-11` Signed archive manifest and verify-against-manifest for auditable extraction

- **Why now.** Supply-chain practice in 2025-2026 moved to sigstore bundles plus attestations next to release archives (Foundry-style sha256 + SBOM + cosign + actions/attest), yet archive tools themselves still verify only internal CRCs; a manifest of entry names/sizes/hashes that a consumer can pin turns sediment's never-overwrite extraction into an auditable step.
- **Prior art.** cosign sign-blob/verify-blob bundles, SLSA provenance via slsa-verifier (search results only), in-toto attestations (no URL); content-addressed stores (Nix NAR, casync; no URL).
- **What we would build.** `sediment manifest archive.zip` emitting canonical JSON (sorted entries, sizes, BLAKE3/SHA-256 per entry, archive hash) and `sediment extract --manifest m.json` refusing on mismatch; signing left to cosign externally to keep the dependency tree small; pairs with SED-04 so manifests are reproducible.
- **External pull.** Standard: sigstore/SLSA ecosystems; release-engineering users
- **Evidence.** <https://github.com/sigstore/docs/blob/main/content/en/cosign/signing/signing_with_blobs.md> · <https://upd.dev/foundry-rs/foundry/src/branch/master/SECURITY.md> · <https://github.com/zip-rs/zip2>

### `SED-06` Read-only zstd, xz, 7z and ZIP-AES support under sediment's limit wrappers

- **Why now.** sevenz-rust2 (pure Rust, Apache-2.0, AES read/write) replaced the unmaintained sevenz-rust, zip2 ships zstd/xz/lzma/aes-crypto feature flags, and 7-Zip 26.02's XZ heap overflow (CVE-2026-14266) shows users want a memory-safe reader for exactly these containers.
- **Prior art.** Keka/The Unarchiver/PeaZip/NanaZip cover these formats via p7zip/7-Zip C++ code; Rust: sevenz-rust2, zesven (2026, docs.rs only), lzma-rs (incomplete .xz), zip2 feature flags. RAR stays excluded by CLEAN_ROOM.md and the unRAR license.
- **What we would build.** Format detection and inspect/verify/extract for tar.zst, tar.xz, 7z (read-only) and AES ZIP entries, each routed through SafeZipReader-style byte budgets, MAX_EXPANDED/MAX_RATIO accounting and the same no-links/no-special policy; plus the dependency notices update.
- **External pull.** Community demand: every 2026 Mac archiver roundup lists 7z/multipart as Archive Utility's gap; Keka has 263 open issues largely on format edge cases
- **Evidence.** <https://github.com/hasenbanck/sevenz-rust2> · <https://github.com/zip-rs/zip2> · <https://github.com/gendx/lzma-rs> · <https://7-zip.org/history.txt> · <https://fedoraproject.org/wiki/Licensing:Unrar>

### `SED-01` Lean-checked archive path sanitizer (hax/Aeneas) with Kani harness

- **Why now.** 2025-2026 produced fresh zip-slip variants in the Rust ecosystem itself (zip CVE-2025-29787 symlink-then-file; tar-rs CVE-2026-33056 chmod via symlink; PAX desync advisories in Mar/May 2026), and hax 0.4 now drives Lean through Charon+Aeneas with on-demand installs, so a Lean theorem about a small pure Rust sanitizer is finally a weeks-scale job rather than a toolchain project.
- **Prior art.** verify-rust-std (AWS) has 29 std challenges, none on std::path; Aeneas has verified crypto (libcrux-class) and a jxl-rs sample; Python PEP 706 'data' filter is the policy benchmark; no Lean-checked archive sanitizer found. sediment's safe_path already exists but uses std::path::Components/PathBuf, which Aeneas/hax do not translate.
- **What we would build.** A pure byte-level sanitize(&[u8]) -> Result<Vec<component>> in sediment, translated to Lean via cargo hax into lean, with theorem: every accepted output is a non-empty list of non-empty, separator-free, non-'..' components (so dest.join(out) stays under dest on a link-free tree); plus a Kani harness over bounded-length names and a proptest differential test against the std-based safe_path.
- **External pull.** Community: zip2/tar-rs maintainers are actively shipping path-safety advisories (GHSA-747h-hw98-c42x informational); a citable verified sanitizer is referenceable by both and by the verify-rust-std effort
- **Evidence.** <https://github.com/advisories/GHSA-94vh-gphv-8pm8> · <https://github.com/rustsec/advisory-db/blob/main/crates/tar/RUSTSEC-2026-0067.md> · <https://github.com/alexcrichton/tar-rs/security/advisories> · <https://github.com/AeneasVerif/aeneas> · <https://github.com/cryspen/hax> · <https://github.com/model-checking/kani> · <https://github.com/model-checking/verify-rust-std>

### `SED-10` Linux/Windows CLI-first ports with egui GUI as beta

- **Why now.** eframe officially supports Web/Linux/Mac/Windows/Android with AccessKit on Windows and macOS, but egui states native look is a non-goal and APIs are still breaking; meanwhile Windows is saturated by free 7-Zip 26.x and NanaZip 6 with hardened MSIX builds, so the credible wedge on other platforms is the JSON/trace CLI, not the GUI.
- **Prior art.** NanaZip (CFG/CET/MSIX, zstd/brotli/lz4), PeaZip 11.4 (Apple Silicon DMG, 7z backend), 7-Zip 26.x; sediment's GUI-free feature set already builds without eframe.
- **What we would build.** Static musl Linux and Windows CLI builds via cargo-dist, Windows-specific path rules (reserved names, ADS already rejected), set_permissions no-op audit on Windows, and a clearly labelled beta GUI; distribution through cargo install and winget/apt later.
- **External pull.** Market: CI/agent users on Linux who want structured archive results; weak against free incumbents on Windows
- **Evidence.** <https://github.com/emilk/egui> · <https://github.com/M2Team/NanaZip> · <https://7-zip.org/history.txt> · <https://github.com/peazip/PeaZip/releases>

### `XD-02` Verified PAR2-style recovery records for sediment

- **Why now.** sediment 0.1.3 lists recovery records as unsupported; pure-Rust PAR2 crates (rust-par2, par2-rs) now exist for interop testing; ArkLib (2026) shows Lean RS verification is tractable, and the lean-zip OOM bug (2025) showed verified codecs with unverified archive layers still fail.
- **Prior art.** Cohen-Wang-Appel (Coq/VST+MathComp) verified a different RS FEC C implementation; Affeldt-Garrigue-Saikawa Coq ECC library; ArkLib Lean RS list decoding for ZK; rust-par2 and par2-rs (unverified). PAR2 spec itself notes Plank's sequential-constant construction is wrong.
- **What we would build.** Lean theorem over GF(2^16) that the PAR2 constant choice (powers of 2 of multiplicative order 65535, recovery exponents) yields an invertible recovery matrix for any erasure pattern with #missing <= #recovery, plus an erasure-decoding kernel extracted via the existing C99 codegen (or Rust port with Kani harness) and wired into sediment's `test`/`extract` with its JSON trace model.
- **External pull.** product gap: sediment README/CLEAN_ROOM.md list recovery records as unsupported; archive-utility users expect PAR2 parity
- **Evidence.** <https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html> · <https://docs.rs/crate/rust-par2/latest> · <https://docs.rs/par2-rs> · <https://www.cs.princeton.edu/~jmc16/docs/FECVerification.pdf> · <https://staff.aist.go.jp/reynald.affeldt/documents/ecc.pdf> · <https://eprint.iacr.org/2026/2056> · <https://kirancodes.me/posts/log-who-watches-the-watchers.html>

### `SED-03` Verified GF(2^16) PAR2 recovery-record kernel bridging ctrl Reed-Solomon and ArkLib

- **Why now.** par2cmdline shipped two repair-path advisories on 2026-06-10 (dangling-symlink write-outside-base and a heap OOB write from block-count wrap), PAR3 is still unreleased after a 'near-final' 2022 spec, the only pure-Rust crate (rust-par2, created 2026-03) cannot create recovery sets, and ArkLib (Lean) now has RS codes, MDS/distance theorems and a Berlekamp-Welch decoder with correctness theorems to import rather than re-prove.
- **Prior art.** Verified-FEC (Coq/VST/MathComp, CAV 2022) proved an RS *erasure* decoder for C; ArkLib (Lean, Apache-2.0) has ReedSolomon.lean (Vandermonde generator, MDS, unique decoding radius, Lagrange interpolation, no sorry seen) and a noncomputable Berlekamp-Welch decoder with decoder_eq_some/not_exists_of_decoder_eq_none; rust-par2 implements GF(2^16) poly 0x1100B with PSHUFB nibble tables (~15 GB/s AVX2) for verify/repair only; par2cmdline-turbo uses ParPar GF16. ctrl's ROBO-04 Barcode decoder (per docs, branch crossover-research-2026-10-19, not present in this checkout) is error-decoding, likely GF(2^8), so only field/polynomial lemmas transfer.
- **What we would build.** (1) A Lean instance of GF(2^16) with PAR2's primitive polynomial and a proof that the PAR2 Vandermonde recovery matrix restricted to any set of surviving blocks is invertible (erasure-decoding correctness), importing ArkLib's RS statements; (2) a pure-Rust PAR2 *create* + repair kernel whose table arithmetic is refined to the Lean field (Kani for the table layer, Aeneas/hax for the polynomial layer) and whose repair path is dangling-symlink-safe by reusing sediment's create_new staging; (3) `sediment create --recovery N%` and `sediment repair`. Reuse ctrl's theorem-to-C99 codegen pattern for the kernel.
- **External pull.** Community: Parchive org and Usenet/long-term-archiving users (par2cmdline 1.4.0 Sep 2026 still active); 'verified recovery records' is a citable artifact for the Renaissance/XTX AI-for-Math tools track named in ctrl/BOUNTIES.md
- **Evidence.** <https://github.com/Parchive/par2cmdline/security/advisories/GHSA-j5pc-g362-c5xp> · <https://github.com/Parchive/par2cmdline/releases> · <https://github.com/Parchive/par3cmdline> · <https://github.com/AusAgentSmith-org/rust-par2> · <https://crates.io/api/v1/crates/rust-par2> · <https://github.com/animetosho/par2cmdline-turbo> · <https://github.com/Verified-zkEVM/ArkLib/blob/main/ArkLib/Data/CodingTheory/ReedSolomon.lean> · <https://github.com/Verified-zkEVM/ArkLib/blob/main/ArkLib/Data/CodingTheory/BerlekampWelch/BerlekampWelch.lean>

