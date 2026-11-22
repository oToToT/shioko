# syntax=docker/dockerfile:1
# Builds shioko and talks to it with Debian's OpenSSL and curl.
FROM rust:1.95.0-slim AS build
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
# The crates of Cargo.lock, checked against its checksums; the network is
# used here and nowhere after.
RUN cargo fetch --locked
ENV CARGO_NET_OFFLINE=true
RUN --network=none cargo build --locked --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl curl python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY tools/interop.sh tools/interop.sh
COPY tests/certs tests/certs
COPY --from=build /src/target/release/shioko /usr/local/bin/shioko
RUN --network=none tools/interop.sh /usr/local/bin/shioko
