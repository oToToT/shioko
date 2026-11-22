# syntax=docker/dockerfile:1
# CI image: builds and tests shioko. Used by tools/ci.sh.
FROM rust:1.95.0-slim

WORKDIR /src

# Install the toolchain, targets and components named in rust-toolchain.toml
# (one of the two steps that use the network).
COPY rust-toolchain.toml .
RUN rustup toolchain install

COPY . .
# The crates of Cargo.lock and shuttle/Cargo.lock (shioko's, and those of
# the schedule tests), checked against their checksums; the network is used
# here and nowhere after.
RUN cargo fetch --locked && cd shuttle && cargo fetch --locked
ENV CARGO_NET_OFFLINE=true
RUN --network=none tools/check.sh
