# TLC and Python, for checking what the end-to-end run recorded
# (tools/servertrace.py).
FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
    /opt/tla2tools.jar
ENV TLA2TOOLS=/opt/tla2tools.jar
