# syntax=docker/dockerfile:1
# A short run of every fuzz target (tools/fuzz.sh), so that a target that
# no longer builds, or a crash close to the seeds, fails CI. The long runs
# are done locally. Used by tools/ci.sh.
FROM rust:1.95.0-slim
RUN apt-get update && apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly-2026-08-21 --profile minimal \
    && cargo install --locked cargo-fuzz --version 0.13.2
WORKDIR /src
COPY . .
# The crates of fuzz/Cargo.lock; the network is used here and nowhere after.
RUN cd fuzz && cargo +nightly-2026-08-21 fetch --locked
ENV CARGO_NET_OFFLINE=true
RUN --network=none tools/fuzz.sh 20
