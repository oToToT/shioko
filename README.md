# shioko

A minimal TLS-terminating reverse proxy, written to replace nginx on a
handful of small hosts. It routes by hostname to one local HTTP upstream per
site, passes WebSocket upgrades through, and serves ACME tokens on port 80.

Status: ready to deploy. HTTP (port 80) and TLS 1.3 (port 443) are written
and tested, against OpenSSL, curl and tlsfuzzer, and end to end in Docker
with real Vaultwarden, Jellyfin and certbot. `deploy/` has the systemd unit,
the certbot hook and the deployment guide.

## What it is built from

- Rust `std` and nothing else of ours; `unsafe` is forbidden in our code.
- One third-party dependency family, the formally verified crypto library
  libcrux, vendored and pinned in `vendor/`.
- TLA+ specifications of the TLS state machine, the HTTP exchange and the
  threads (`spec/`), checked with TLC.
- A list for each RFC of every sentence that states a requirement, and what
  we do about it (`spec/rfc/*.req`).

## Configuration

One file, one section per site:

```
[vw.example.org]
upstream  = 127.0.0.1:3678
cert      = /etc/letsencrypt/live/vw.example.org/fullchain.pem
key       = /etc/letsencrypt/live/vw.example.org/privkey.pem
websocket = yes
allow     = /etc/shioko/cloudflare.txt
max-body  = 525M
```

The six keys: `upstream` (required), `cert` and `key` (together; without
them the site is plain HTTP), `websocket` (`yes` to let upgrades through),
`allow` (address ranges and files of them), `max-body` (default `1M`).
`shioko check` validates a configuration without starting the server.
`deploy/README.md` is the deployment guide.

### Not in v1

Each would be one new key, with no change to existing configurations:
redirects, path-based routing, per-site timeouts, added response headers,
static files, wildcard hostnames, Unix-socket or HTTPS upstreams, several
upstreams per site.

## Where it does not follow the RFCs

These are deliberate. Each is recorded as a `deviation` against the sentence
it departs from in `spec/rfc/`.

**TLS (RFC 8446)**

- **Only one cipher suite, one key exchange group, one signature scheme.**
  RFC 8446 section 9.1 makes `TLS_AES_128_GCM_SHA256`, key exchange over
  secp256r1 and RSA signatures mandatory to implement. shioko implements
  `TLS_CHACHA20_POLY1305_SHA256`, X25519 and `ecdsa_secp256r1_sha256` only.
  A client that offers none of these cannot connect, and every site needs an
  ECDSA P-256 certificate. Current browsers, curl, OpenSSL and Cloudflare
  all offer what shioko needs.
- TLS 1.3 only; no session resumption, no early data, no client
  certificates.
- The certificate chain is sent as it is in the file and never parsed, so
  nothing the RFC asks of a chain is checked.
- ECDSA nonces are random rather than derived as RFC 6979 recommends, and
  secrets cannot be reliably erased without `unsafe` code.

**HTTP (RFC 9110, RFC 9112)**

- **Absolute-form request targets are refused.** RFC 9112 section 3.2.2
  says a server must accept `GET http://host/path HTTP/1.1`. shioko answers
  400 to anything but an origin-form target (`/path`).
  Browsers and CDNs send origin-form to an origin; accepting the other form
  means choosing between two host names in one request. CONNECT is refused
  for the same reason.
- Request targets may hold characters the URI grammar forbids (`|`, `^`,
  `[`, `{`, ...), because browsers send them unencoded; they are forwarded
  as received.
- `Max-Forwards` is not processed for OPTIONS.
- TRACE is refused with 405 (without the `Allow` field RFC 9110 asks for)
  and `OPTIONS *` with 400, as nginx refuses them. OPTIONS for a path, the
  CORS preflight, is forwarded.
- Header lists with empty elements (`Transfer-Encoding: chunked,`) are
  refused.
- The upstream hop is plain HTTP/1.1, with a new connection per request.
- ACME tokens are served without validators and without evaluating
  conditional requests.

The complete lists are at the end of sections 5 and 6 of `PLAN.md`.

## Checking it

```
nix develop            # TLC, OpenSSL, curl
tools/check.sh         # lint, tests, release builds for both targets
tools/spec.sh          # model-check the specs, check the RFC lists
tools/prove.sh         # Kani proofs
tools/interop.sh       # a real shioko against OpenSSL and curl
tools/ci.sh            # all of the above in Linux containers, and tlsfuzzer
```

`tools/e2e.sh [soak MINUTES]` runs the end-to-end environment of `ci/e2e/`
(needs Docker and network to pull images): shioko as deployed, nginx for
comparison, Vaultwarden, Jellyfin, a test upstream, and Pebble issuing a
certificate to certbot through shioko. Results go to `target/e2e/`.

`tools/ci.sh` also runs every TLS 1.3 script of tlsfuzzer against shioko
(`ci/tlsfuzzer.Dockerfile`, `tools/tlsfuzzer.sh`). The probes expected to
fail are listed in `tests/tlsfuzzer.txt`, each with the reason: mostly
features shioko leaves out on purpose, such as AES, other groups, RSA
certificates, tickets and TLS 1.2. Every connection of that run is recorded,
decrypted by an independent decoder, and checked by TLC against the TLS
spec as a whole behaviour (`tools/tlstrace.py`, `spec/HandshakeTrace.tla`).
