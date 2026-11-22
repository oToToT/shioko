#!/bin/sh
# Every check a change must pass. Runs on a developer machine and, through
# tools/ci.sh, inside Linux containers. Needs no network.
set -eu
cd "$(dirname "$0")/.."

# On Linux, test the same static target that gets deployed.
if [ "$(uname -s)" = Linux ]; then
    test_target="--target $(uname -m)-unknown-linux-musl"
else
    test_target=""
fi

echo "== lint"
cargo clippy --locked --all-targets -- -D warnings
# The development builds, which record what the checks of recorded runs
# need (never deployed), must stay clean too.
cargo clippy --locked --all-targets --features keylog,record -- -D warnings

echo "== test"
# shellcheck disable=SC2086
cargo test --locked $test_target

echo "== release build, both deployment targets"
cargo build --release --locked \
    --target x86_64-unknown-linux-musl \
    --target aarch64-unknown-linux-musl

echo "== all checks passed"
