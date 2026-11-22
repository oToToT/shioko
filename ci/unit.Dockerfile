# syntax=docker/dockerfile:1
# Checks deploy/ with the tools of a real system: the unit must verify
# cleanly and its exposure score stay low, and the certbot hook must let
# shioko read a certificate laid out as certbot lays it out, and nobody
# else, without restarting shioko. Used by tools/ci.sh.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends acl systemd \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system shioko && useradd --system other \
    && printf '#!/bin/sh\n' > /usr/local/bin/shioko && chmod 0755 /usr/local/bin/shioko
COPY deploy/shioko.service /etc/systemd/system/shioko.service
COPY deploy/certbot-deploy-hook /etc/letsencrypt/renewal-hooks/deploy/shioko
RUN --network=none systemd-analyze verify /etc/systemd/system/shioko.service \
    && systemd-analyze security --offline=true --threshold=20 \
        /etc/systemd/system/shioko.service
# certbot's layout and modes, and a systemctl that only says what it was
# asked, which the hook must not ask anything.
RUN --network=none set -eu; \
    mkdir -p /etc/letsencrypt/live/site /etc/letsencrypt/archive/site; \
    chmod 0700 /etc/letsencrypt/live /etc/letsencrypt/archive; \
    echo key > /etc/letsencrypt/archive/site/privkey1.pem; \
    echo cert > /etc/letsencrypt/archive/site/fullchain1.pem; \
    chmod 0600 /etc/letsencrypt/archive/site/*; \
    ln -s ../../archive/site/privkey1.pem /etc/letsencrypt/live/site/privkey.pem; \
    ln -s ../../archive/site/fullchain1.pem /etc/letsencrypt/live/site/fullchain.pem; \
    printf '#!/bin/sh\necho "systemctl $*" > /tmp/systemctl\n' > /usr/local/sbin/systemctl; \
    chmod 0755 /usr/local/sbin/systemctl; \
    RENEWED_LINEAGE=/etc/letsencrypt/live/site /etc/letsencrypt/renewal-hooks/deploy/shioko; \
    test "$(setpriv --reuid shioko --regid shioko --init-groups cat /etc/letsencrypt/live/site/privkey.pem)" = key; \
    test "$(setpriv --reuid shioko --regid shioko --init-groups cat /etc/letsencrypt/live/site/fullchain.pem)" = cert; \
    if setpriv --reuid other --regid other --init-groups cat /etc/letsencrypt/live/site/privkey.pem 2> /dev/null; \
        then echo "another user can read the key"; exit 1; fi; \
    test "$(stat -c %a /etc/letsencrypt/archive/site/privkey1.pem)" != 644; \
    if [ -e /tmp/systemctl ]; then echo "the hook ran $(cat /tmp/systemctl)"; exit 1; fi; \
    echo "certbot hook: shioko reads the certificate and key, others do not, nothing restarted"
