# syntax=docker/dockerfile:1
# Model-checks the TLA+ specs with the same TLC release as the Nix dev shell.
FROM eclipse-temurin:21-jre
ADD --checksum=sha256:936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
    /opt/tla2tools.jar
ENV TLA2TOOLS=/opt/tla2tools.jar
WORKDIR /src
COPY spec spec
COPY tools/spec.sh tools/rfc-sentences.awk tools/
COPY tests/vectors tests/vectors
COPY src src
RUN --network=none tools/spec.sh
