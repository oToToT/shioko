# syntax=docker/dockerfile:1
# Checks the Kani proofs in the code.
FROM rust:1.95.0-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
# The crates of Cargo.lock, checked against its checksums; the network is
# used here and nowhere after.
RUN cargo fetch --locked
ENV CARGO_NET_OFFLINE=true
RUN --network=none tools/prove.sh
