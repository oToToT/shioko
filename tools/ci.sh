#!/bin/sh
# Runs every check in Linux containers: the TLA+ specs, the Kani proofs, the
# interop checks and tlsfuzzer with its recorded runs checked by TLC once,
# then tools/check.sh for each architecture we deploy to.
#
#   tools/ci.sh                 specs, proofs, then amd64 and arm64
#   tools/ci.sh linux/arm64     specs, proofs, then one architecture
#
# Only the image setup steps use the network; the checks run without it.
set -eu
cd "$(dirname "$0")/.."

echo "==== specs"
docker build --file ci/spec.Dockerfile --progress plain --tag shioko-ci:spec .

echo "==== proofs"
docker build --file ci/kani.Dockerfile --progress plain --tag shioko-ci:kani .

echo "==== interop with OpenSSL and curl"
docker build --file ci/interop.Dockerfile --progress plain --tag shioko-ci:interop .

echo "==== tlsfuzzer, and its recorded runs checked by TLC"
docker build --file ci/tlsfuzzer.Dockerfile --progress plain --tag shioko-ci:tlsfuzzer .

for platform in ${*:-linux/amd64 linux/arm64}; do
    echo "==== $platform"
    docker build --platform "$platform" --file ci/Dockerfile --progress plain \
        --tag "shioko-ci:$(basename "$platform")" .
done

echo "==== CI passed: specs proofs interop tlsfuzzer ${*:-linux/amd64 linux/arm64}"
