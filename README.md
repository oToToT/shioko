# shioko

A small TLS 1.3 reverse proxy for the most common nginx setup: a few HTTPS
sites, each forwarded to one HTTP service on the same host or network. One
static binary, one configuration file with six keys per site, no
dependencies at run time.

- Terminates TLS 1.3 and picks the certificate by SNI.
- Forwards each hostname to its upstream over HTTP/1.1, with `Host` as the
  client sent it, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` and
  `Via`.
- Passes WebSocket upgrades through.
- Streams request bodies, with a size cap per site.
- Allows a site only from given address ranges (a CDN's, a private
  network's), refusing everyone else during the handshake.
- On port 80, redirects to HTTPS and serves ACME tokens for
  `certbot --webroot`, so certificates renew without an nginx plugin.
- Logs a line per request to journald.

It is written in Rust with `unsafe` forbidden, on top of libcrux, a
formally verified crypto library. The TLS and HTTP state machines and the
threading are specified in TLA+ and model-checked, and the code is tested
against those specs (see "Checking it").

Status: version 0.1, new. It is tested as described below, but has not yet
had much use. There is no warranty (see the licenses).

## Is it for you?

shioko fits if each `server` block of your nginx configuration does no more
than this:

```nginx
server {
    listen 443 ssl;
    server_name app.example.org;
    ssl_certificate     /etc/letsencrypt/live/app.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.org/privkey.pem;
    client_max_body_size 100M;
    allow 10.0.0.0/8;
    deny all;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

That block, plus the usual port 80 server for the redirect and certbot, is
in shioko:

```
[app.example.org]
upstream  = 127.0.0.1:8080
cert      = /etc/letsencrypt/live/app.example.org/fullchain.pem
key       = /etc/letsencrypt/live/app.example.org/privkey.pem
websocket = yes
allow     = 10.0.0.0/8
max-body  = 100M
```

It does not fit if you need any of these, which shioko does not do:

- static files, PHP or FastCGI, gzip;
- `rewrite`, `return`, `try_files`, or several `location` blocks going to
  different places;
- wildcard or regular-expression `server_name`s, or redirects from one name
  to another (`www` to the bare domain); several plain names are fine, one
  section each;
- `add_header`, including `Strict-Transport-Security` (the application has
  to send it), and `auth_basic`;
- HTTPS or Unix-socket upstreams, or several upstreams per site;
- ports other than 80 and 443, or HTTP/2 (clients fall back to HTTP/1.1);
- configuration reload without a restart;
- clients that cannot do TLS 1.3 with ChaCha20-Poly1305 (next section).

### Which clients can connect

shioko offers one choice at each layer of TLS: TLS 1.3, the cipher
`TLS_CHACHA20_POLY1305_SHA256`, key exchange X25519MLKEM768 (post-quantum
hybrid) or X25519, and ECDSA P-256 certificates.

- **Works:** current Chrome, Edge, Firefox and Safari, curl and anything
  else using OpenSSL 1.1.1 or later, Go, Python, Node.js, Java 12 and
  later, and Cloudflare in front of your site.
- **Does not work:** clients that only speak TLS 1.2 or older, such as apps
  on Android 9 and older that use the system's TLS; Java before 12; and
  programs that use Windows' own TLS (Schannel), such as Windows' built-in
  `curl.exe`, PowerShell and many .NET applications, because Windows
  supports ChaCha20-Poly1305 but leaves it off by default. Browsers on
  Windows bring their own TLS and are fine. Older smart TVs, set-top boxes
  and other embedded clients may also fail.
- **Certificates must be ECDSA P-256.** certbot 2.0 and later issues those
  by default; an RSA certificate has to be replaced first (the deployment
  guide shows how).

The deployment guide shows how to find out from your nginx logs whether any
of your clients would be refused, before you switch.

## Getting started

You need Rust ([rustup](https://rustup.rs)). Everything else is vendored,
so after the toolchain is installed the build needs no network. Build on
Linux or macOS, for the architecture of the server (`uname -m` there says
`x86_64` or `aarch64`):

```
git clone https://github.com/oToToT/Shioko.git shioko
cd shioko
rustup toolchain install    # the version pinned in rust-toolchain.toml
cargo build --locked --release --target x86_64-unknown-linux-musl
```

The binary, `target/x86_64-unknown-linux-musl/release/shioko`, is static and
runs on any Linux distribution. Then follow
[`deploy/README.md`](deploy/README.md): it translates your nginx
configuration, installs shioko with its systemd unit and the certbot hook,
switches over with a few seconds of downtime, and says how to go back.

## Configuration

One file, `/etc/shioko/shioko.conf`, with one section per site, named by its
hostname:

| Key | Meaning | If omitted |
|---|---|---|
| `upstream` | `host:port` of the HTTP/1.1 server the site is forwarded to | required |
| `cert` | PEM certificate chain; the site is served over HTTPS and port 80 redirects to it | the site is plain HTTP |
| `key` | PEM private key (ECDSA P-256), required with `cert` | |
| `websocket` | `yes` lets WebSocket upgrades through | upgrade headers are removed |
| `allow` | address ranges, and files with one range per line, that may connect | everyone |
| `max-body` | largest request body, in bytes or with `K`, `M` or `G`, such as `525M`; unlike nginx's, `0` allows no body | `1M`, as in nginx |

`#` starts a comment, to the end of its line. `shioko check` validates the
file without starting the server, and reports the first mistake with its
line number.

Fixed, not configurable: ports 80 and 443 on all IPv4 and IPv6 addresses
(through one dual-stack socket, so IPv6 must be enabled on the host, as it
is by default); ACME tokens from
`/var/lib/shioko/acme/.well-known/acme-challenge` (where
`certbot --webroot -w /var/lib/shioko/acme` puts them), for any hostname; at
most 512 connections; 5 s to connect to an upstream (nginx waits 60 s); as
in nginx, 60 s of silence from an upstream or on a WebSocket, and 75 s for
an idle keep-alive connection. A name that only needs a
certificate, a mail server's for instance, needs no section. An unknown
hostname gets a 404 or, over TLS, an `unrecognized_name` alert.

More examples, and every detail of the behaviour, are in
[`SPEC.md`](SPEC.md): section 3 for the configuration, 5 for TLS, 6 for
HTTP.

## Where it does not follow the RFCs

These are deliberate. Each is recorded as a `deviation` against the sentence
it departs from in `spec/rfc/`.

**TLS (RFC 8446)**

- **Only one cipher suite, two key exchange groups, one signature scheme.**
  RFC 8446 section 9.1 makes `TLS_AES_128_GCM_SHA256`, key exchange over
  secp256r1 and RSA signatures mandatory to implement. shioko implements
  `TLS_CHACHA20_POLY1305_SHA256`, X25519MLKEM768 (the post-quantum hybrid
  of RFC 10024, preferred when offered), X25519 and `ecdsa_secp256r1_sha256`
  only.
- TLS 1.3 only; no session resumption, no early data, no client
  certificates.
- The certificate chain is sent as it is in the file and never parsed, so
  nothing the RFC asks of a chain is checked.
- Secrets cannot be reliably erased without `unsafe` code.

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

The complete lists are at the end of sections 5 and 6 of `SPEC.md`.

## Checking it

```
nix develop            # TLC, OpenSSL, curl
tools/check.sh         # lint, tests, release builds for both targets
tools/spec.sh          # model-check the specs, check the RFC lists
tools/prove.sh         # Kani proofs
tools/interop.sh       # a real shioko against OpenSSL and curl
tools/ci.sh            # all of the above in Linux containers, and tlsfuzzer
tools/ci.sh STAGE...   # some of it: specs proofs interop unit tlsfuzzer
                       # linux/amd64 linux/arm64
```

GitHub Actions (`.github/workflows/ci.yml`) verifies every push to `main` and
every pull request. Each stage of `tools/ci.sh` is a job of its own, with
arm64 on an arm64 runner, and the end-to-end environment below runs twice:
`tools/e2e.sh` and `tools/e2e.sh record`. Their results are kept as artifacts
of the run.

`tools/e2e.sh [soak MINUTES]` runs the end-to-end environment of `ci/e2e/`
(needs Docker and network to pull images): shioko as deployed, nginx for
comparison, Vaultwarden, Jellyfin, a test upstream, and Pebble issuing a
certificate to certbot through shioko. Results go to `target/e2e/`.
`tools/e2e.sh record` does the same with a development build that logs the
steps of its threads, and TLC checks the whole run against `spec/Server.tla`
(`tools/servertrace.py`).

`tools/ci.sh` also runs every TLS 1.3 script of tlsfuzzer against shioko
(`ci/tlsfuzzer.Dockerfile`, `tools/tlsfuzzer.sh`). The probes expected to
fail are listed in `tests/tlsfuzzer.txt`, each with the reason: mostly
features shioko leaves out on purpose, such as AES, other groups, RSA
certificates, tickets and TLS 1.2. Every connection of that run is recorded,
decrypted by an independent decoder, and checked by TLC against the TLS
spec as a whole behaviour (`tools/tlstrace.py`, `spec/HandshakeTrace.tla`).

`SPEC.md` section 8 describes every check in detail.

## License

shioko is licensed under either of the [Apache License, Version
2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.
`vendor/` holds libcrux (Apache-2.0) and the crates it needs, and
`spec/rfc/` the RFC texts; `THIRD-PARTY.md` lists them with their terms.
