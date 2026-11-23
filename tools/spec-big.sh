#!/bin/sh
# Model-checks the specs within larger bounds than tools/spec.sh, which CI
# runs: Handshake.tla with sequence numbers up to 3, two key updates in each
# direction and up to 3 quiet records; Server.tla with four connections from
# three addresses (TUNNELS=2: and two tunnels at a time, much slower). Only
# the model checks, not the broken variants or the tables, and the temporal
# properties once, at the end. Slow, and Server.tla needs GB of memory and
# disk for its states: for a developer machine, not for CI.
#
#   tools/spec-big.sh [Handshake|Server]...   (both by default)
#
# Needs `tlc` on the PATH (the Nix dev shell has it). TLC gets 60% of the
# memory unless JAVA_TOOL_OPTIONS says otherwise.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:--XX:MaxRAMPercentage=60.0}"
tunnels=${TUNNELS:-1}
[ $# -gt 0 ] || set -- Handshake Server
for module in "$@"; do
    dir=$root/target/spec-big/$module
    rm -rf "$dir"
    mkdir -p "$dir"
    cp spec/*.tla "$dir/"
    case $module in
    Handshake)
        sed -e 's/^CONSTANT MaxSeq = .*/CONSTANT MaxSeq = 3/' \
            -e 's/^CONSTANT MaxGen = .*/CONSTANT MaxGen = 2/' \
            -e 's/^CONSTANT MaxQuiet = .*/CONSTANT MaxQuiet = 3/' \
            spec/Handshake.cfg > "$dir/$module.cfg" ;;
    Server)
        # TUNNELS tunnels at a time.
        sed "s/^=====*\$/Tunnels == Cardinality({c \\\\in Conns : conn[c] = \"tunnel\"}) <= $tunnels\\
&/" spec/Server.tla > "$dir/Server.tla"
        sed -e 's/^CONSTANT Conns = .*/CONSTANT Conns = {"c1", "c2", "c3", "c4"}/' \
            -e 's/^CONSTANT Addresses = .*/CONSTANT Addresses = {"a1", "a2", "a3"}/' \
            -e 's/^CONSTRAINT OneTunnel/CONSTRAINT Tunnels/' \
            spec/Server.cfg > "$dir/$module.cfg" ;;
    *)
        echo "no larger bounds for $module" >&2
        exit 2 ;;
    esac
    echo "== $module, larger bounds:"
    grep -E '^CONST|^CONSTRAINT' "$dir/$module.cfg" | sed 's/^/   /'
    started=$(date +%s)
    (cd "$dir" && tlc -workers auto -lncheck final -metadir "$dir/states" -config "$module.cfg" "$module.tla") > "$dir/tlc.log" 2>&1 ||
        { tail -30 "$dir/tlc.log"; echo "$module fails within the larger bounds; see $dir/tlc.log"; exit 1; }
    grep -E 'distinct states found, 0 states left' "$dir/tlc.log" | tail -1 | sed 's/^/   /'
    echo "   passed in $(( $(date +%s) - started )) s"
done
