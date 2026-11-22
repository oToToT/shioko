#!/bin/sh
# Makes the certificates and keys under tests/certs/ that the tests use.
# Development-time tool; needs openssl (the Nix dev shell has it). The keys
# are for tests only and are published with the repository.
set -eu
cd "$(dirname "$0")/../tests/certs"
days=36500
ossl() { openssl "$@" 2> /dev/null; }

# A certificate authority, and certificates it signs for the test sites.
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
ossl req -x509 -new -key ca.key -days $days -subj "/CN=shioko test CA" -out ca.pem

leaf() { # name, key file
    ossl req -new -key "$2" -subj "/CN=$1" -out "$1.csr"
    printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' "$1" > "$1.ext"
    ossl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days $days \
        -extfile "$1.ext" -out "$1.leaf.pem"
    cat "$1.leaf.pem" ca.pem > "$1.chain.pem"
    rm -f "$1.csr" "$1.ext" "$1.leaf.pem"
}

# site.test: the key as certbot writes it (PKCS#8).
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out site.test.key
leaf site.test site.test.key
# tls.test: the key in the older SEC1 form, with the curve named.
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out tls.tmp
ossl ec -in tls.tmp -out tls.test.key
rm -f tls.tmp
leaf tls.test tls.test.key
# Keys that must be refused: RSA, another curve, encrypted.
ossl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out p384.key
ossl pkcs8 -topk8 -in site.test.key -passout pass:secret -out encrypted.key
rm -f ca.srl
ls
