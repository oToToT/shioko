#!/bin/sh
# Makes the test CA and a certificate for every test site, in /certs, for
# both shioko and nginx; and the allowlist file. Runs once, before the rest.
set -eu
cd /certs
[ -f done ] && exit 0
ossl() { openssl "$@" 2> /dev/null; }
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
ossl req -x509 -new -key ca.key -days 3650 -subj "/CN=shioko e2e CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out ca.pem
for name in vault.test media.test chat.test files.test mail.test; do
    ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key"
    ossl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
    printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n' \
        "$name" > "$name.ext"
    ossl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 3650 -extfile "$name.ext" -out "$name.pem"
    cat "$name.pem" ca.pem > "$name.chain.pem"
    rm "$name.csr" "$name.ext"
done
# The vault is open to the inside network only, as the real one is open to
# Cloudflare's ranges only.
printf '# stands in for Cloudflare\n10.88.0.0/24\n' > allowed.txt
chmod 0644 ./*
touch done
