#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc -Vv
cargo --version
sha256sum Cargo.lock
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
sha256sum Cargo.lock
