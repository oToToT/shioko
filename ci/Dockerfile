# syntax=docker/dockerfile:1
# CI image: builds and tests shioko. Used by tools/ci.sh.
FROM rust:1.95.0-slim

WORKDIR /src

# The only step that uses the network: install the toolchain, targets and
# components named in rust-toolchain.toml.
COPY rust-toolchain.toml .
RUN rustup toolchain install

COPY . .
RUN --network=none tools/check.sh
