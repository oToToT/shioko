#!/bin/sh
# Re-create vendor/ from Cargo.lock.
#
# Cargo's lockfile also lists optional and verification-only dependencies of
# libcrux that are never compiled, and an offline build refuses to start unless
# every one of them is present. Crates that are compiled are vendored
# unmodified. Every other crate is reduced to a stub: its upstream Cargo.toml
# and an empty source file, no code.
set -eu
cd "$(dirname "$0")/.."

# .cargo/config.toml points Cargo at vendor/ and forbids network access, so it
# is set aside while the crates are downloaded.
mv .cargo/config.toml .cargo/config.toml.off
trap 'mv .cargo/config.toml.off .cargo/config.toml' EXIT
rm -rf vendor
cargo vendor --locked vendor > /dev/null

used=$(for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin; do
    cargo tree --locked --target "$t" --edges normal,build --prefix none
done | awk '{print $1}' | sort -u)

for dir in vendor/*/; do
    name=$(basename "$dir")
    if printf '%s\n' "$used" | grep -qx "$name"; then
        continue
    fi
    sum=$(sed -n 's/.*"package":"\([0-9a-f]*\)".*/\1/p' "$dir/.cargo-checksum.json")
    lib=$(awk '/^\[lib\]/{f=1;next} /^\[/{f=0} f && /^path *=/{gsub(/"/,"",$3); print $3}' "$dir/Cargo.toml")
    find "$dir" -mindepth 1 ! -name Cargo.toml -delete
    mkdir -p "$dir/$(dirname "${lib:-src/lib.rs}")"
    : > "$dir/${lib:-src/lib.rs}"
    printf '{"files":{},"package":"%s"}' "$sum" > "$dir/.cargo-checksum.json"
done

echo "compiled crates:"
printf '  %s\n' $used | grep -v '^  shioko$'
