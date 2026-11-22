# shioko as it is deployed: the static musl release build.
FROM rust:1.95.0-slim AS build
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
RUN --network=none cargo build --locked --release --target "$(uname -m)-unknown-linux-musl" \
    && cp "target/$(uname -m)-unknown-linux-musl/release/shioko" /shioko

FROM debian:trixie-slim
COPY --from=build /shioko /usr/local/bin/shioko
RUN useradd --system shioko && mkdir -p /var/lib/shioko/acme
ENTRYPOINT ["/usr/local/bin/shioko"]
CMD ["run", "/etc/shioko/shioko.conf"]
