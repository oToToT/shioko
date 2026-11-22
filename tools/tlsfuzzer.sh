#!/bin/sh
# Runs tlsfuzzer against a real shioko as tests/tlsfuzzer.txt lists, records
# every connection, and has TLC check each recording against
# spec/Handshake.tla (tools/tlstrace.py, spec/HandshakeTrace.tla). Then shows
# that the check can fail, on recordings changed to look like a broken
# server.
#
#   tools/tlsfuzzer.sh SHIOKO TLSFUZZER_DIR [SCRIPT...]
#
# SHIOKO must be built with --features keylog. TLSFUZZER_DIR is a tlsfuzzer
# checkout with tlslite-ng's tlslite linked into it; python3 needs ecdsa and
# cryptography; TLC is `tlc` on the PATH or TLA2TOOLS. Ports 80 and 443 must
# be free. ci/tlsfuzzer.Dockerfile has all of this.
set -eu
cd "$(dirname "$0")/.."
binary=$1
fuzzer=$2
shift 2
certs=$PWD/tests/certs
work=$(mktemp -d)
stop() {
    [ -z "${pid:-}" ] || { kill "$pid" 2> /dev/null || true; wait "$pid" 2> /dev/null || true; }
    rm -rf "$work"
}
trap stop EXIT

# tlsfuzzer's requests carry no Host, so nothing reaches the upstream.
cat > "$work/shioko.conf" <<CONF
[site.test]
upstream = 127.0.0.1:9
cert = $certs/site.test.chain.pem
key = $certs/site.test.key
CONF
SHIOKO_KEYLOG=$work/keylog "$binary" run "$work/shioko.conf" > /dev/null 2> "$work/error.log" &
pid=$!
sleep 1

tools=$PWD/tools
python3 tools/tlsfuzzer-run.py --record "$work/rec" "$fuzzer" 127.0.0.1 443 site.test "$@"
echo "== recorded runs against spec/Handshake.tla"
cd "$work/rec"
python3 "$tools/tlstrace.py" check "$work/keylog" */
if [ -d test-tls13-keyupdate ]; then
    python3 "$tools/tlstrace.py" selftest "$work/keylog" test-tls13-keyupdate
fi
