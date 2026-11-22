# The end-to-end environment's own containers: certificates, the test
# upstream and the clients. Debian's OpenSSL, curl and Python.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl procps python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /e2e
COPY ci/e2e/*.py ci/e2e/*.sh ./
