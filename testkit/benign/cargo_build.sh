#!/usr/bin/env bash
# `cargo build` of one crate of this repository, offline, into DIR/target.
source "$(dirname "$0")/_common.sh"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
[ "$step" = setup ] && exit 0
command -v cargo >/dev/null || { echo "cargo_build: no cargo here, skipped"; exit 0; }
cd "$repo" && cargo build -q --offline -p candor-proto --target-dir "$dir/target"
