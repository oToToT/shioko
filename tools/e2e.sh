#!/bin/sh
# Runs the end-to-end environment of ci/e2e/: shioko (the static release
# build, as deployed) and nginx serving the same sites in front of real
# Vaultwarden and Jellyfin and a test upstream, and Pebble issuing a
# certificate to certbot through shioko's port 80. Then the checks
# (ci/e2e/e2e.py check), the comparison with nginx (parity), and on request
# the soak runs, sampling shioko's memory, threads and file descriptors.
#
#   tools/e2e.sh                  checks and parity
#   tools/e2e.sh soak [MINUTES]   also the soak runs (default 10 minutes each)
#   tools/e2e.sh record [MINUTES] all of it (default 1 minute each) with a
#                                 shioko built with --features record, and
#                                 TLC checks the run against spec/Server.tla
#
# Everything found goes to target/e2e/: checks.json, parity.json,
# soak.json, resources.csv, certbot.log, shioko.log, shioko.record.
set -eu
cd "$(dirname "$0")/.."
mode=${1:-}
minutes=${2:-}
if [ "$mode" = record ]; then
    export SHIOKO_FEATURES=record
    minutes=${minutes:-1}
fi
compose="docker compose -f ci/e2e/compose.yaml --profile run"
out=target/e2e
rm -rf "$out"
mkdir -p "$out"
stop() {
    [ -z "${sampler:-}" ] || kill "$sampler" 2> /dev/null || true
    $compose logs --no-color shioko > "$out/shioko.log" 2>&1 || true
    $compose down -v --remove-orphans > /dev/null 2>&1 || true
}
trap stop EXIT

echo "== starting the environment"
$compose up -d --build setup upstream vaultwarden jellyfin shioko nginx challtestsrv pebble
sleep 3

echo "== certbot, through shioko's port 80"
status=0
$compose run --rm certbot certonly --non-interactive --agree-tos \
    --register-unsafely-without-email --no-verify-ssl \
    --server https://10.88.0.30:14000/dir \
    --webroot -w /var/lib/shioko/acme -d mail.test > "$out/certbot.log" 2>&1 || status=$?
echo "$status" > "$out/certbot.exit"

failed=0
echo "== checks"
$compose run --rm client python3 e2e.py check || failed=1
echo "== parity with nginx"
$compose run --rm client python3 e2e.py parity

if [ "$mode" = soak ] || [ "$mode" = record ]; then
    echo "== soak"
    # shioko is process 1 of its container.
    echo "seconds,rss_kb,threads,fds,cpu_seconds" > "$out/resources.csv"
    (
        start=$(date +%s)
        while :; do
            $compose exec -T shioko sh -c '
                rss=$(sed -n "s/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p" /proc/1/status)
                threads=$(sed -n "s/^Threads:[[:space:]]*//p" /proc/1/status)
                fds=$(ls /proc/1/fd | wc -l)
                ticks=$(cut -d" " -f14,15 /proc/1/stat | tr " " +)
                echo "$rss,$threads,$fds,$(( ($ticks) / $(getconf CLK_TCK) ))"' 2> /dev/null |
                sed "s/^/$(( $(date +%s) - start )),/" >> "$out/resources.csv" || true
            sleep 5
        done
    ) &
    sampler=$!
    $compose run --rm client python3 soak.py "${minutes:-10}" || failed=1
fi

if [ "$mode" = record ]; then
    echo "== the run against spec/Server.tla"
    $compose cp shioko:/tmp/shioko.record "$out/shioko.record"
    docker build --quiet --file ci/e2e/tlc.Dockerfile --tag shioko-e2e-tlc ci/e2e > /dev/null
    tlc="docker run --rm -v $PWD:/src -w /src shioko-e2e-tlc python3 tools/servertrace.py"
    $tlc check "$out/shioko.record" || failed=1
    $tlc selftest "$out/shioko.record" || failed=1
fi

[ "$failed" -eq 0 ] || { echo "end-to-end checks failed; see $out/"; exit 1; }
echo "== end-to-end checks passed; results in $out/"
