# syntax=docker/dockerfile:1
# Runs tlsfuzzer against shioko and checks every recorded connection against
# spec/Handshake.tla with TLC (tools/tlsfuzzer.sh). Used by tools/ci.sh.
FROM rust:1.95.0-slim AS build
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
# A test build: it writes each handshake's secret to SHIOKO_KEYLOG.
RUN --network=none cargo build --locked --release --features keylog

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git openjdk-21-jre-headless python3 python3-cryptography \
        python3-ecdsa python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --break-system-packages kyber-py==1.2.0
ADD --checksum=sha256:936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
    /opt/tla2tools.jar
ENV TLA2TOOLS=/opt/tla2tools.jar
# tlsfuzzer and tlslite-ng, pinned by commit.
RUN git clone -q https://github.com/tlsfuzzer/tlsfuzzer /opt/tlsfuzzer \
    && git -C /opt/tlsfuzzer checkout -q 51aad6e9ae42f5b045fa9b76129fe0746631784d \
    && git clone -q https://github.com/tlsfuzzer/tlslite-ng /opt/tlslite-ng \
    && git -C /opt/tlslite-ng checkout -q 7e95ea1a86c0d42d8d931ff14134d31f01ce1d76 \
    && ln -s /opt/tlslite-ng/tlslite /opt/tlsfuzzer/tlslite
WORKDIR /src
COPY spec spec
COPY tools tools
COPY tests/certs tests/certs
COPY tests/tlsfuzzer.txt tests/tlsfuzzer.txt
COPY --from=build /src/target/release/shioko /usr/local/bin/shioko
RUN --network=none tools/tlsfuzzer.sh /usr/local/bin/shioko /opt/tlsfuzzer
