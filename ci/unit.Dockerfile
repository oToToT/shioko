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
# certbot's layout and modes: a certificate shioko serves, renewed once, and
# one it does not serve (a mail server's); and a systemctl that only says
# what it was asked, which the hook must not ask anything.
RUN --network=none set -eu; \
    cd /etc/letsencrypt; \
    mkdir -p live/site archive/site live/mail archive/mail /etc/shioko; \
    chmod 0700 live archive; \
    echo oldkey > archive/site/privkey1.pem; \
    echo key > archive/site/privkey2.pem; \
    echo cert > archive/site/fullchain2.pem; \
    echo mailkey > archive/mail/privkey1.pem; \
    echo mailcert > archive/mail/fullchain1.pem; \
    chmod 0600 archive/site/* archive/mail/*; \
    ln -s ../../archive/site/privkey2.pem live/site/privkey.pem; \
    ln -s ../../archive/site/fullchain2.pem live/site/fullchain.pem; \
    ln -s ../../archive/mail/privkey1.pem live/mail/privkey.pem; \
    ln -s ../../archive/mail/fullchain1.pem live/mail/fullchain.pem; \
    printf '[site.test]\nupstream = 127.0.0.1:8000\ncert = /etc/letsencrypt/live/site/fullchain.pem\nkey  = /etc/letsencrypt/live/site/privkey.pem # ours\n' \
        > /etc/shioko/shioko.conf; \
    printf '#!/bin/sh\necho "systemctl $*" > /tmp/systemctl\n' > /usr/local/sbin/systemctl; \
    chmod 0755 /usr/local/sbin/systemctl; \
    for name in site mail; do \
        RENEWED_LINEAGE=/etc/letsencrypt/live/$name /etc/letsencrypt/renewal-hooks/deploy/shioko; \
    done; \
    as() { user=$1; shift; setpriv --reuid "$user" --regid "$user" --init-groups "$@"; }; \
    test "$(as shioko cat live/site/privkey.pem)" = key; \
    test "$(as shioko cat live/site/fullchain.pem)" = cert; \
    for closed in archive/site/privkey1.pem live/mail/privkey.pem archive/mail/privkey1.pem live/mail/fullchain.pem; do \
        if as shioko cat "$closed" 2> /dev/null; then echo "shioko can read $closed"; exit 1; fi; \
    done; \
    if as shioko ls archive/site > /dev/null 2>&1; then echo "shioko can list the archive"; exit 1; fi; \
    if as other cat live/site/privkey.pem 2> /dev/null; then echo "another user can read the key"; exit 1; fi; \
    test "$(stat -c %a archive/site/privkey2.pem)" != 644; \
    if [ -e /tmp/systemctl ]; then echo "the hook ran $(cat /tmp/systemctl)"; exit 1; fi; \
    echo "certbot hook: shioko reads the certificate and key it serves, not older keys or another certificate; others read nothing; nothing restarted"
