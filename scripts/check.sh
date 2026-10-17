#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ruff check scripts
ruff format --check scripts
shellcheck scripts/*.sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --features gui-test --all-targets -- -D warnings
cargo test --locked --features gui-test
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo test --locked --no-default-features
python3 -m py_compile scripts/benchmark.py
bash -n scripts/check.sh scripts/package-macos.sh
