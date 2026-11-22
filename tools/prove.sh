#!/bin/sh
# Checks the proofs in the code with Kani, a bounded model checker for Rust.
# A proof is a function marked #[kani::proof] in a `#[cfg(kani)] mod proofs`;
# Kani checks it for every input within the bounds the proof states.
#
# Needs Kani (development tool only, nothing of it ends up in the binary):
#   cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
# run from outside this directory, which allows no network access to Cargo.
set -eu
cd "$(dirname "$0")/.."

cargo kani --output-format terse
echo "== all proofs passed"
