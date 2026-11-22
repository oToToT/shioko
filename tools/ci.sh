#!/bin/sh
# Runs every check in Linux containers: the TLA+ specs, the Kani proofs, the
# interop checks, the systemd unit, and tlsfuzzer with its recorded runs
# checked by TLC once, then tools/check.sh for each architecture we deploy
# to. .github/workflows/ci.yml runs each stage as a job of its own.
#
#   tools/ci.sh             every stage
#   tools/ci.sh STAGE...    only those, of: specs proofs interop unit
#                           tlsfuzzer fuzz linux/amd64 linux/arm64
#
# Only the image setup steps use the network; the checks run without it.
set -eu
cd "$(dirname "$0")/.."
stages=${*:-specs proofs interop unit tlsfuzzer fuzz linux/amd64 linux/arm64}

build() { # DOCKERFILE TAG [docker build options]
    file=$1 tag=$2
    shift 2
    docker build "$@" --file "ci/$file" --progress plain --tag "shioko-ci:$tag" .
}

for stage in $stages; do
    case $stage in
    specs)
        echo "==== specs"
        build spec.Dockerfile spec ;;
    proofs)
        echo "==== proofs"
        build kani.Dockerfile kani ;;
    interop)
        echo "==== interop with OpenSSL and curl"
        build interop.Dockerfile interop ;;
    unit)
        echo "==== the systemd unit"
        build unit.Dockerfile unit ;;
    tlsfuzzer)
        echo "==== tlsfuzzer, and its recorded runs checked by TLC"
        build tlsfuzzer.Dockerfile tlsfuzzer ;;
    fuzz)
        echo "==== a short run of every fuzz target"
        build fuzz.Dockerfile fuzz ;;
    linux/amd64 | linux/arm64)
        echo "==== $stage"
        build Dockerfile "${stage#linux/}" --platform "$stage" ;;
    *)
        echo "unknown stage: $stage" >&2
        exit 2 ;;
    esac
done

echo "==== CI passed: $stages"
