#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
command -v wasm-pack
command -v chromedriver
rustc -Vv
sha256sum Cargo.lock
wasm-pack test --headless --chrome -- --locked
sha256sum Cargo.lock
