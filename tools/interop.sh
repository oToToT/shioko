#!/bin/sh
# Talks to a real shioko with OpenSSL and curl, the TLS clients of other
# people, and checks what comes back. Needs openssl, curl and python3 (the
# Nix dev shell has the first two), and ports 80 and 443 free.
#
#   tools/interop.sh [path to a shioko binary]
set -eu
cd "$(dirname "$0")/.."
binary=${1:-target/release/shioko}
[ -x "$binary" ] || cargo build --locked --release
certs=$PWD/tests/certs
work=$(mktemp -d)
stop() {
    for pid in $(cat "$work"/pids 2> /dev/null); do
        kill "$pid" 2> /dev/null || true
        wait "$pid" 2> /dev/null || true
    done
    rm -rf "$work"
}
trap stop EXIT

mkdir "$work/www"
echo "hello from upstream" > "$work/www/index.html"
head -c 300000 /dev/urandom > "$work/www/big.bin"
cat > "$work/shioko.conf" <<CONF
[site.test]
upstream = 127.0.0.1:18080
cert = $certs/site.test.chain.pem
key = $certs/site.test.key

[tls.test]
upstream = 127.0.0.1:18080
cert = $certs/tls.test.chain.pem
key = $certs/tls.test.key

[plain.test]
upstream = 127.0.0.1:18080
CONF
(cd "$work/www" && exec python3 -m http.server 18080 --bind 127.0.0.1 > /dev/null 2>&1) &
echo $! > "$work/pids"
"$binary" check "$work/shioko.conf" > /dev/null
"$binary" run "$work/shioko.conf" > "$work/access.log" 2> "$work/error.log" &
echo $! >> "$work/pids"
sleep 1

failures=0
check() { # description, command...
    what=$1
    shift
    if "$@" > "$work/out" 2>&1; then
        echo "ok    $what"
    else
        echo "FAIL  $what"
        sed 's/^/      /' "$work/out" | head -n 8
        failures=$((failures + 1))
    fi
}
resolve="--resolve site.test:443:127.0.0.1 --resolve tls.test:443:127.0.0.1 --resolve site.test:80:127.0.0.1 --resolve plain.test:80:127.0.0.1"

check "curl: a page over TLS 1.3" sh -c "curl -sS --fail $resolve --cacert $certs/ca.pem https://site.test/ | grep -q 'hello from upstream'"
check "curl: the second site, the SEC1 key" sh -c "curl -sS --fail $resolve --cacert $certs/ca.pem https://tls.test/ | grep -q hello"
check "curl: TLS 1.3, ChaCha20-Poly1305, http/1.1" sh -c "curl -sS -v $resolve --cacert $certs/ca.pem https://site.test/ -o /dev/null > $work/v 2>&1; grep -q 'TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256' $work/v && grep -qE 'ALPN.*accepted.*http/1.1' $work/v"
check "curl: 300 KB arrive intact" sh -c "[ \"\$(curl -sS --fail $resolve --cacert $certs/ca.pem https://site.test/big.bin | shasum)\" = \"\$(shasum < $work/www/big.bin)\" ]"
check "curl: keep-alive, three requests on one connection" sh -c "[ \"\$(curl -sS -v $resolve --cacert $certs/ca.pem https://site.test/ https://site.test/ https://site.test/ -o /dev/null -o /dev/null -o /dev/null 2>&1 | grep -cE 'Re-using|Reusing existing')\" -ge 2 ]"
check "curl: port 80 redirects a TLS site" sh -c "curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' $resolve http://site.test/a | grep -qx '301 https://site.test/a'"
check "curl: port 80 serves a plain site" sh -c "curl -sS --fail $resolve http://plain.test/ | grep -q hello"
check "openssl: the chain verifies, ECDSA P-256 signature, X25519" sh -c "printf 'Q\n' | openssl s_client -connect 127.0.0.1:443 -servername site.test -CAfile $certs/ca.pem > $work/o 2>&1; grep -q 'Verify return code: 0 (ok)' $work/o && grep -qi 'signature type: ecdsa_secp256r1_sha256' $work/o && grep -qiE '(Temp Key|group): X25519' $work/o"
check "openssl: HelloRetryRequest when P-256 is offered first" sh -c "(printf 'GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n'; sleep 1) | openssl s_client -connect 127.0.0.1:443 -servername site.test -CAfile $certs/ca.pem -groups P-256:X25519 -msg 2>&1 > $work/hrr; grep -c ClientHello $work/hrr | grep -qx 2 && grep -q '^HTTP/1.1 200' $work/hrr"
for command in k K; do
    check "openssl: KeyUpdate ($command) between two requests" sh -c "(printf 'GET / HTTP/1.1\r\nHost: site.test\r\n\r\n'; sleep 0.5; printf '$command\n'; sleep 0.5; printf 'GET / HTTP/1.1\r\nHost: site.test\r\n\r\n'; sleep 1) | openssl s_client -connect 127.0.0.1:443 -servername site.test -CAfile $certs/ca.pem 2>&1 | grep -c '^HTTP/1.1 200' | grep -qx 2"
done
check "openssl: TLS 1.2 only gets protocol_version" sh -c "openssl s_client -connect 127.0.0.1:443 -servername site.test -tls1_2 < /dev/null 2>&1 | grep -q 'alert protocol version'"
check "openssl: AES only gets handshake_failure" sh -c "openssl s_client -connect 127.0.0.1:443 -servername site.test -ciphersuites TLS_AES_128_GCM_SHA256 < /dev/null 2>&1 | grep -q 'alert handshake failure'"
check "openssl: an unknown name gets unrecognized_name" sh -c "openssl s_client -connect 127.0.0.1:443 -servername nowhere.test < /dev/null 2>&1 | grep -q 'unrecognized name'"
check "openssl: a plain site gets unrecognized_name on 443" sh -c "openssl s_client -connect 127.0.0.1:443 -servername plain.test < /dev/null 2>&1 | grep -q 'unrecognized name'"
check "openssl: close_notify is sent on close" sh -c "(printf 'GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n'; sleep 1) | openssl s_client -connect 127.0.0.1:443 -servername site.test -CAfile $certs/ca.pem -msg 2>&1 | grep -q 'Alert \[length 0002\], warning close_notify'"
check "the log has one line per request" grep -q 'site.test "GET /" 200' "$work/access.log"
check "the error log names the alerts we sent" grep -q 'tls: sent protocol_version' "$work/error.log"

[ "$failures" -eq 0 ] || { echo "$failures interop checks failed"; exit 1; }
echo "== all interop checks passed"
