#!/bin/sh
# Coverage-guided fuzzing of shioko (fuzz/): its parsers, and whole plain
# and TLS connections fed from the fuzzer's bytes. Development only; needs
# a nightly toolchain and cargo-fuzz, outside this directory:
#   rustup toolchain install nightly-2026-08-21
#   cargo install --locked cargo-fuzz --version 0.13.2
#
#   tools/fuzz.sh [SECONDS] [TARGET...]   each target (all by default) for
#                                         SECONDS (default 60)
#
# Each target starts from fuzz/seeds/<target> (tools/fuzz-seeds.py writes
# them) and the corpus it has grown in fuzz/corpus/<target>. A crash, a
# panic, a leak or a hang stops the run; its input goes to
# fuzz/artifacts/<target>/.
set -eu
cd "$(dirname "$0")/../fuzz"
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-08-21}
seconds=${1:-60}
[ $# -gt 0 ] && shift
targets=${*:-$(cargo +"$toolchain" fuzz list)}
cargo +"$toolchain" fuzz build
for target in $targets; do
    echo "== $target, $seconds s"
    mkdir -p "corpus/$target"
    cargo +"$toolchain" fuzz run "$target" "corpus/$target" "seeds/$target" -- \
        -max_total_time="$seconds" -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 2>&1 |
        grep -E '^(#[0-9]+ +DONE|stat::(number_of_executed_units|new_units_added|peak_rss_mb)|==|SUMMARY|thread|panicked|Test unit written)' || true
    if [ -n "$(ls "artifacts/$target" 2> /dev/null)" ]; then
        echo "$target: found a crash; see fuzz/artifacts/$target/"
        exit 1
    fi
done
echo "== no crash in: $targets"
