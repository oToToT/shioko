# shioko — specification

What shioko does, how it is built, and how it is checked. `README.md` is the
overview and `deploy/README.md` the deployment guide. The requirement lists
in `spec/rfc/` cite the sections of this file by number ("SPEC 5").

## 1. Goals and constraints

- Do what nginx does for the common small setup, a TLS-terminating reverse
  proxy in front of local HTTP services, and nothing else.
- Our own code: Rust `std` only, `unsafe` denied but in the functions
  section 4 lists, about 3,000
  lines excluding tests.
- One third-party dependency family: libcrux (formally verified crypto),
  pinned by version and checksum in `Cargo.lock`.
- Designs of the three state machines are model-checked in TLA+, and the Rust
  state machines are tested against the checked models.
- TLS 1.3 only. A changed configuration needs a restart; renewed
  certificates do not. Development tools (TLC, openssl, curl, fuzzers) are
  allowed; they never end up in the binary.

## 2. Scope

### What it does

| Feature | Typical use |
|---|---|
| TLS termination, certificate chosen by SNI | every HTTPS site |
| Host-based routing to one local HTTP upstream per site | an application listening on `127.0.0.1:PORT` |
| WebSocket / `Upgrade` passthrough | chat, media servers, password vault sync |
| Streamed request bodies, per-site size cap (default 1M) | uploads of hundreds of megabytes |
| CIDR allowlist, IPv4 and IPv6 | a site reachable only through a CDN, or only from a private network |
| `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` to upstream | every proxied site |
| Port 80: 301 to HTTPS for known hosts, 404 otherwise | every host |
| ACME tokens served for any hostname, while the TLS handshake for unknown names is rejected | a certificate for a name that serves nothing, such as a mail server's |
| Access log line per request, error log | journald |

### Beyond a plain nginx proxy

- Port 80 serves `/.well-known/acme-challenge/<token>` from a directory, so
  certbot can use `--webroot` instead of its nginx plugin.

### Left out

Static files, FastCGI/PHP, gzip, HTTPS upstreams, TLS 1.2, session
resumption and tickets, 0-RTT, client certificates, DHE, upstream keepalive,
per-site log files, config reload, HTTP/2.

### Where it behaves differently from nginx

1. **Allowlist is enforced at the TLS ClientHello**, not as an HTTP 403. A
   peer outside the allowlist gets an `access_denied` alert before any crypto
   runs. A request whose `Host` differs from the SNI site gets 421, so the
   allowlist cannot be bypassed by mixing names.
2. **Redirects and ACME tokens on port 80 are not subject to the allowlist.**
   Only plain-HTTP sites enforce it there.
3. **Both ports listen on IPv4 and IPv6**, whatever the sites are.
4. **`X-Forwarded-Proto` is sent to every upstream.**
5. **Request bodies are streamed**, not buffered to disk first.
6. **Clients that only speak TLS 1.2 are refused** with a `protocol_version`
   alert.
7. **Post-quantum hybrid key exchange**: X25519MLKEM768 is preferred
   whenever the client offers a share for it.
8. **Connections beyond a pool's room are closed at once**, not queued: 512
   from inside the allowlists, 512 from everyone else, 64 from one
   address outside them. nginx queues connections beyond its
   `worker_connections` and has no per-address limit unless `limit_conn` is
   set.

## 3. Configuration

One file, `/etc/shioko/shioko.conf` by default (`shioko run [config]`). One
section per site, named by its hostname. Six keys. No global settings.

```
[vault.example.org]
upstream  = 127.0.0.1:3678
cert      = /etc/letsencrypt/live/vault.example.org/fullchain.pem
key       = /etc/letsencrypt/live/vault.example.org/privkey.pem
websocket = yes
allow     = /etc/shioko/cloudflare.txt
max-body  = 525M
```

| Key | Meaning | If omitted |
|---|---|---|
| `upstream` | `host:port` the site is forwarded to, over HTTP. It must be an HTTP/1.1 server. | required |
| `cert` | Path to the PEM certificate chain. The site is served over HTTPS and plain HTTP gets a 301. | The site is served over plain HTTP, no TLS |
| `key` | Path to the PEM private key | required with `cert`, an error without it |
| `websocket` | `yes` lets WebSocket upgrades through | `no`: upgrade headers are stripped |
| `allow` | Who may connect: IP ranges, and/or paths to files with one range per line | everyone |
| `max-body` | Largest request body, e.g. `525M` | `1M` |

Syntax: `[hostname]` headers, `key = value` lines, `#` comments, blank lines.
An unknown key, a repeated key or hostname, `cert` without `key` (or the
reverse), an unreadable file, or a private key that does not match its
certificate is a startup error with a line number.
`shioko check` validates the file without starting the server.

Fixed, not configurable:

- Listens on port 80 and port 443, all addresses, IPv4 and IPv6, through
  one dual-stack socket each (`::`, with IPv4 as mapped addresses).
- ACME tokens are read from `/var/lib/shioko/acme/.well-known/acme-challenge`,
  where `certbot --webroot -w /var/lib/shioko/acme` writes them.
- Forwarding headers, timeouts and limits (section 4), the TLS profile.
- Unknown hostnames get HTTP 404 or a TLS `unrecognized_name` alert.

### Example configurations

A site behind Cloudflare only, taking large uploads. A name that only needs
a certificate (say, for a mail server) needs no entry: ACME tokens are
served for any hostname.

```
[vault.example.org]
upstream  = 127.0.0.1:3678
cert      = /etc/letsencrypt/live/vault.example.org/fullchain.pem
key       = /etc/letsencrypt/live/vault.example.org/privkey.pem
websocket = yes
allow     = /etc/shioko/cloudflare.txt
max-body  = 525M
```

Two WebSocket sites on one host, under different domains:

```
[chat.example.org]
upstream  = 127.0.0.1:8787
cert      = /etc/letsencrypt/live/chat.example.org/fullchain.pem
key       = /etc/letsencrypt/live/chat.example.org/privkey.pem
websocket = yes

[media.example.net]
upstream  = 127.0.0.1:8096
cert      = /etc/letsencrypt/live/media.example.net/fullchain.pem
key       = /etc/letsencrypt/live/media.example.net/privkey.pem
websocket = yes
```

A plain-HTTP site restricted to a private network, with an allowlist
given inline and from a file:

```
[wiki.internal]
upstream = 10.0.0.5:8080
allow    = 10.0.0.0/8 /etc/shioko/office.txt
```

### Not in v1

Each would be one new key, with no change to existing configs: redirects,
path-based routing, per-site timeouts, added response headers, static files,
wildcard hostnames, Unix-socket or HTTPS upstreams, several upstreams.

## 4. Architecture

### Process model

- One process, blocking I/O, one thread per connection. A WebSocket tunnel
  uses a second thread for the other direction; the connection's thread
  waits for it before giving its slot back.
- In a tunnel both threads share the TLS connection. Writing has a lock;
  reading never waits for it, so a client that is slow to read cannot stop
  us reading from it. After a failed write nothing more is sent.
- A thread that stops shuts down both sockets, which is what stops the
  other one. Every blocking read and write has a timeout.
- Two pools of connection slots, 512 each: one for peers inside some site's
  allowlist, one for everyone else, where one address (IPv4, or an IPv6
  /64) may hold at most 64. A flood from outside the allowlists, however
  many addresses it comes from, cannot take the slots of the sites behind
  them. Over TLS, when every site with a certificate has an allowlist, a
  peer outside all of them is turned away at once.
- The accept loop takes a slot before calling `accept`, so when both pools
  are full overload backs up into the kernel queue. Once the connection has
  come, its slot is from its pool; if the pool, or the peer's address, has
  no room, the connection is closed at once (turned away), and the log
  says how many were, at most once a minute. Slots are released by an RAII
  guard on every exit path, including panics.
- The pools are lowered at startup if the open-file limit cannot hold them:
  a connection holds up to two descriptors, and 16 are kept for the rest
  (so two pools of 512 need a limit of 2064; the unit sets 4096).
- `/dev/urandom` is opened once, at startup, and kept open.
- A watcher thread reads the certificate and key files again every minute
  (section 5).
- `unsafe` is denied by a lint, and allowed by name only in `crypto::wipe`,
  which overwrites secrets with volatile writes, and in `signals`, which
  makes the two Linux system calls that wait for SIGTERM (the standard
  library has none). Every `unsafe` block has a `SAFETY:` comment, which
  clippy requires.
- `panic = "unwind"`: a panic ends one connection, not the server. Integer
  overflow checks stay on in release builds.
- SIGTERM and SIGINT (systemd's stop and restart, a terminal's Ctrl-C) stop
  the server gracefully: both are blocked in every thread before any
  starts, and one thread waits for them. From then on nobody is let in,
  the connections waiting for a request and the tunnels are cut at once,
  the requests being served get up to 10 s to finish, and the process
  exits with status 0. If a system call filter forbids waiting for them,
  they are left alone, so they end the server at once, and the log says so.
  No other signal is handled; no privilege code, no
  daemonising. systemd grants the port-binding capability, runs the
  process as an unprivileged user and restarts it. Randomness comes from
  `/dev/urandom` through `std::fs`.
- Parsers never index or unwrap. All untrusted input goes through one
  bounds-checked cursor type. Clippy denies `indexing_slicing`, `unwrap_used`,
  `expect_used` and `panic` outside tests.

### Limits and timeouts (constants, matching nginx defaults where one exists)

| Limit | Value |
|---|---|
| Concurrent connections | 512 from inside some allowlist, 512 from everyone else |
| Connections from one address outside every allowlist (IPv4, IPv6 /64) | 64 |
| TLS handshake deadline | 10 s |
| Request head size / header count | 16 KB / 100 |
| Request head read timeout | 60 s |
| Client keep-alive idle | 75 s |
| Upstream connect timeout | 5 s |
| Upstream read / write idle | 60 s |
| Tunnel idle (no bytes either way) | 60 s |
| Request body | 1M default, per site |
| Requests being served when told to stop | 10 s to finish |

### Source layout

```
src/
  main.rs          CLI (run, check)
  config.rs        parser and validation
  net.rs           CIDR matching, v4-mapped address normalisation
  log.rs           access and error lines, control characters escaped
  pem.rs           base64, PEM, minimal DER walk for the EC private key
  crypto.rs        the only module that touches libcrux
  tls/wire.rs      bounds-checked cursor for TLS encodings
  tls/fsm.rs       pure handshake state machine (mirrors Handshake.tla)
  tls/msgs.rs      ClientHello parsing and checks, our handshake messages
  tls/keys.rs      TLS 1.3 key schedule, transcript hash
  tls/record.rs    record layer: framing, protection, padding
  tls/conn.rs      the connection: handshake driver, reading and writing
                   threads, the three locks
  tls/client.rs    a TLS client for tests, and tls/tests.rs the tests
  stream.rs        the stream trait, the read buffer, CRLF lines
  server.rs        listeners, accept loop, connection cap
  http/parse.rs    request and response heads, fields, chunk sizes, Host
  http/body.rs     copying bodies: stated length, chunked, until close
  http/fsm.rs      pure exchange state machine (mirrors Http.tla)
  http/proxy.rs    serving a connection: routing, ACME tokens, redirects,
                   forwarding, relay, tunnel
  http/own.rs      the responses shioko writes itself, HTTP dates
  http/tests.rs    the proxy against scripted streams
  record.rs        development builds only: the steps checked against
                   Server.tla
spec/              the three specs, their TLC configs, their .broken files
                   (deliberately wrong variants), the table printers, the
                   trace checkers, and the RFCs with their requirement lists
tests/             vectors, transition tables, test certificates, the
                   tlsfuzzer expectations
deploy/            systemd unit, certbot deploy hook, the deployment guide
ci/                the Docker images of the checks, the end-to-end environment
tools/             the scripts that run the checks
patches/           our stand-in for libcrux's CPU detection
```

The proxy logic is written against the `Stream` trait, so it is tested over plain
sockets and runs in production over the TLS stream.

## 5. TLS 1.3 profile

Exactly one choice at each layer:

| Layer | Choice |
|---|---|
| Version | TLS 1.3 (RFC 8446), server only |
| Cipher suite | `TLS_CHACHA20_POLY1305_SHA256` |
| Key exchange | X25519MLKEM768 (RFC 10024) when the client sends a share for it, X25519 otherwise |
| Signature | `ecdsa_secp256r1_sha256` (a site needs an ECDSA P-256 certificate) |
| ALPN | `http/1.1` if the client offers ALPN |

Handshake behaviour:

- ClientHello is refused with the alert the RFC names:

  | ClientHello | Alert |
  |---|---|
  | does not offer TLS 1.3 | `protocol_version` |
  | lacks our cipher suite, X25519 or our signature scheme | `handshake_failure` |
  | lacks `signature_algorithms`, `supported_groups`, `key_share` or `server_name` | `missing_extension` |
  | names a host we have no certificate for | `unrecognized_name` |
  | comes from an address outside the site's allowlist | `access_denied` |
  | offers ALPN without `http/1.1` | `no_application_protocol` |
  | repeats an extension, carries a cookie, or has `pre_shared_key` anywhere but last | `illegal_parameter` |
  | has `pre_shared_key` without `psk_key_exchange_modes` | `missing_extension` |
  | does not parse | `decode_error` |

- HelloRetryRequest is supported, once, for clients that sent no share we
  can use; it asks for X25519 if listed, else X25519MLKEM768.
- An X25519MLKEM768 share must be 1216 bytes, its ML-KEM key must pass the
  check of FIPS 203 section 7.2, and its X25519 part must not give an
  all-zero secret; otherwise `illegal_parameter` (RFC 10024). The shared
  secret is the ML-KEM secret followed by the X25519 one. The second ClientHello
  must repeat the first but for what RFC 8446 section 4.1.2 lets change
  (the key shares, `early_data` dropped, `pre_shared_key`, `padding`), or it
  gets `illegal_parameter`.
- Offered PSKs are ignored and a full handshake follows. Early data is never
  accepted: its records are skipped as RFC 8446 section 4.2.10 requires, up
  to 16 KB, then the connection ends with `unexpected_message`.
- Middlebox compatibility: echo the session id, send one dummy
  ChangeCipherSpec, ignore the client's.
- No NewSessionTicket is ever sent, so there is no resumption.
- Our handshake messages are split into records of at most 2^14 bytes. A
  handshake message from the client may be split over several records, but
  nothing may come between the pieces and each message must end its record.
- A handshake message from the client may be as long as the longest
  ClientHello there can be, 131,396 bytes; a longer one gets `decode_error`.
- An unencrypted alert after our ServerHello and before the client Finished
  ends the connection without an answer: a client that cannot read our
  ServerHello has no keys to encrypt it with (RFC 8446 appendix A.1).
- Records: the version field is ignored; an unknown content type gets
  `unexpected_message`; an unprotected record over 2^14 bytes, or a
  protected one whose content, type and padding exceed 2^14 + 1 bytes, gets
  `record_overflow`; an empty alert or handshake record gets
  `unexpected_message`. A ClientHello whose legacy_version is SSL 3.0 or
  older gets `protocol_version`.
- After the handshake: KeyUpdate from the client is honoured. When it asks
  for ours, we send it together with our next write, as the RFC allows.
- At most 32 records in a row may carry nothing: the client's dummy
  ChangeCipherSpec, a KeyUpdate (also one split over two records), an
  empty application data record. Application data and each step of the
  handshake start the count again; the 33rd gets `unexpected_message`, as
  in OpenSSL and BoringSSL.
- We send `close_notify` whenever we end a connection that can still be
  written to: when the application is done, on every deadline, at the end
  of a tunnel, and when the client's stream ends. (Ending at once, to stop
  a tunnel's other thread, says it only if the write lock is free, so that
  a thread blocked on a slow client cannot delay the shutdown.) When the
  client sends it we answer with ours and close; there is no half-open
  state. Only a failed transport ends silently.
- A read reports an orderly end only after the client's `close_notify`. A
  connection cut off without one, or ended by an alert or an error, is
  reported as an error, so that a cut-off WebSocket does not look closed on
  purpose to the upstream.
- A failure of our own (no randomness, a sequence number running out) is
  logged and answered with `internal_error` where that can still be sent.
- A sequence number that would wrap ends the connection.
- Every alert sent or received is logged with its description, except
  `close_notify`, which is the normal end of every connection; so is an
  alert record that is empty or malformed.
- ECDSA nonces are derived from the private key and the signed content as
  RFC 6979 section 3.2 specifies ("deterministic ECDSA", recommended by RFC
  8446 appendix C.3), so a failing random number generator cannot repeat a
  nonce and give the key away. Every other random value comes from the
  kernel CSPRNG; if reading it fails, the handshake fails.
- Every secret (the key exchange output, the early, handshake and master
  secrets, superseded traffic secrets and keys) is overwritten with
  volatile writes as soon as everything derived from it is computed.
  Copies the compiler made while moving a value are not reached.

Certificates and keys:

- `fullchain.pem` is decoded to DER and sent as opaque bytes; no X.509 parsing.
- `privkey.pem` (PKCS#8 or SEC1) is walked just far enough to extract the
  32-byte scalar.
- Startup check: the public key derived from the private key must appear in
  the leaf certificate bytes, otherwise startup fails.
- The files are read again every minute. A site whose certificate or key
  changed gets the new pair for the handshakes that follow, once it has
  passed the same checks; a pair that does not leaves the one before in
  place, and the log says why. Open connections keep the pair they started
  with.
- Nothing else about the chain is checked: its order, key usage and
  signature algorithms are whatever the certificate file holds.
- The `shioko` user needs read access to the configured paths. For
  Let's Encrypt paths that is read access through ACLs on the `live` and
  `archive` directories, re-asserted by the certbot deploy hook.

Known departures from RFC 8446 (each is listed in `spec/rfc/rfc8446.req`):

- Section 9.1 makes `TLS_AES_128_GCM_SHA256`, key exchange over secp256r1
  and RSA signatures mandatory. We implement none of them (a site needs an
  ECDSA P-256 certificate); see section 10.
- The certificate chain is not parsed, so nothing the RFC asks of it is
  checked: its order, the X.509 version, the key usage, SHA-1 signatures,
  and the client's `signature_algorithms_cert`.
- A ChangeCipherSpec between the pieces of a split handshake message is
  refused, not dropped.
- The RFC has every dummy ChangeCipherSpec dropped and every KeyUpdate
  honoured, however many come; the 33rd record in a row that carries
  nothing is refused (above).
- When a tunnel is ended at once while its other thread is blocked writing
  to the client, no `close_notify` is sent: the record being written can
  neither be finished nor have another put in its middle. Section 6.1 asks
  for `close_notify` before every close.

## 6. HTTP behaviour

- HTTP/1.1 with client keep-alive; HTTP/1.0 clients are answered and closed.
  A higher minor version is treated as 1.1. We always write `HTTP/1.1`.

Requests:

- **Request line.** Empty lines before it are skipped. The target must be in
  origin form (start with `/`) and may hold only visible ASCII characters.
  Absolute-form targets, `*` (even with OPTIONS) and every CONNECT are
  answered with 400, as nginx answers them. TRACE is answered with 405, as
  nginx answers it, once the head has a usable `Host`. A request line over
  8 KB gets 414, a head over 16 KB or 100 fields gets 431. A method over 32
  characters gets 501, but only once the head is read and found to have a
  usable `Host`.
- **The whole head** must arrive within 60 seconds (75 for the next request
  on a kept connection), however slowly it trickles in.
- **Strict head parsing.** Rejected with 400: both `Content-Length` and
  `Transfer-Encoding`, repeated or non-numeric `Content-Length`, a malformed
  `Transfer-Encoding` or one that does not end in `chunked`,
  `Transfer-Encoding` in HTTP/1.0, folded headers, whitespace before the
  colon, control characters in names or values, missing, repeated or
  malformed `Host`, `chunked` with parameters or named twice. A well-formed
  `Transfer-Encoding` that ends in `chunked` but names other codings before
  it (with parameters or not) gets 501, after the `Host` check. A response
  to a HEAD request refused while its head was read has no body either.
- **Line ends** are CRLF everywhere: in heads, chunk-size lines and trailers,
  from clients and from upstreams. A bare CR or LF is an error.
- **Host** is a host name, an IPv4 address or a bracketed IP literal,
  optionally with `:port` (the port may be empty). The name is compared with
  the site's, ignoring case and one trailing dot (`example.org.`), as nginx
  does; an IP literal matches no site and gets 404. The upstream gets `Host`
  as the client sent it.
- **Bodies.** Chunk extensions are ignored (spaces before their `;` and
  non-ASCII in their values included) and trailers are read and dropped, in
  both directions. `Content-Length` may be anything up to 2^64 - 1, with any
  number of leading zeros. `Expect: 100-continue` (read as a list) is
  answered by us, after the allowlist and size checks and once the upstream
  is connected, and is not forwarded. It is ignored in HTTP/1.0 and on
  requests whose body is empty or absent.
- **WebSocket.** On a site with `websocket`, an HTTP/1.1 GET without a body
  whose `Upgrade` list names `websocket` and whose `Connection` names
  `upgrade` is forwarded with its upgrade headers. If the upstream answers
  101 with `Upgrade` naming `websocket` and `Connection` naming `upgrade`,
  the connection becomes an opaque two-way tunnel; any other 101 is
  answered with 502. The 101 we write to the client carries `Connection:
  upgrade` and `Upgrade: websocket`, which every other response loses as
  hop-by-hop fields. Bytes already read from either side go into the tunnel
  first. On other sites, and for any other request (one with `Expect:
  100-continue` included), the upgrade headers are removed like any
  hop-by-hop header.

What the upstream receives:

- One new connection per request. There is no upstream connection reuse, so
  one request cannot contaminate another.
- The head is written by us, never copied: the request line with the target
  as received, then the client's fields without the hop-by-hop ones
  (`Connection` and whatever it names, `Keep-Alive`, `Proxy-Connection`, `TE`,
  `Transfer-Encoding`, `Upgrade`, `Expect`), then ours: `Host` as the client
  sent it, `X-Real-IP` and `X-Forwarded-Proto` (the client's own are
  dropped), `X-Forwarded-For` (ours appended to the client's), `Via` (the
  client's HTTP version and `shioko`, appended), the body length or
  `Transfer-Encoding: chunked`, and `Connection: close`, or for an upgrade
  `Connection: upgrade` and `Upgrade: websocket`.
- The response is read only after the whole request has been sent. If a
  write to the upstream fails, the client gets 502.
- A request whose `Via` shows it has passed through shioko 8 times already
  is in a loop and gets 400.

Responses:

- The upstream's response head is parsed as strictly as a request head and
  written again by us, without hop-by-hop fields and with a `Date` if it had
  none. A head that is malformed, whose length is in doubt (both
  `Content-Length` and `Transfer-Encoding`, or either one malformed), or
  whose status is outside 100 to 599, is answered with 502.
- Response framing (length, chunked, or until-close) is parsed and
  re-emitted; until-close becomes chunked for HTTP/1.1 clients. A chunked
  response is marked as ended only when the upstream's body is known to be
  complete, so a cut-off response looks cut off.
- Interim 1xx responses are passed on to HTTP/1.1 clients and dropped for
  HTTP/1.0 clients.
- Our own responses are 400, 403, 404, 405, 413, 414, 421, 431, 501, 502, 504
  and the port 80 redirect, each with `Date`, `Content-Type: text/plain`,
  `Content-Length`, `Connection: close` and a one-line text body (no body
  for HEAD). Every one of them is followed by closing the connection.
- The request path is never rewritten or normalised; a site has one upstream.
  `Location` and other response fields are passed on as the upstream wrote
  them (nginx's default `proxy_redirect` rewrites some `Location` values).

Startup refuses an upstream on a loopback address at port 80 or 443, which
would be shioko itself.

HTTP listeners, in order:

1. GET or HEAD of `/.well-known/acme-challenge/<token>`, where the token is
   1–128 characters of `[A-Za-z0-9_-]`, returns that file from the ACME
   directory (above), for any hostname, with `Date`, `Content-Type:
   application/octet-stream`, `Content-Length` and `Connection: close`.
   Conditional and range headers are ignored.
2. A request for a site with a `cert` returns 301 to `https://` followed by
   the site's configured name and the request target, with every character
   a URI may not hold percent-encoded, so the location is always a valid
   URI.
3. A request for a site without a `cert` is served like an HTTPS request,
   with the allowlist answered by a 403 and `X-Forwarded-Proto: http`.
4. Everything else returns 404.

Known departures from RFC 9110 and RFC 9112 (each is listed in the `.req`
files under `spec/rfc/`):

- Absolute-form request targets are refused, although a server must accept
  them. Accepting them means deciding between two host names in one request.
- Request targets may hold characters the URI grammar does not allow (`|`,
  `^`, `[`, `]`, `{`, `}`, `` ` ``, `"`, `<`, `>`, `\`), because browsers
  send them unencoded (WHATWG URL standard) and nginx accepts them. They are
  forwarded as received; only the redirect location encodes them.
- `Max-Forwards` is not processed for OPTIONS; like nginx, shioko presents
  itself as the origin.
- TRACE is refused with 405 and `OPTIONS *` with 400, as nginx refuses them:
  a reflected request shows its credentials to whatever page sent it. The
  405 carries no `Allow` field, as nginx's does not, although an origin
  must send one; which methods the upstream allows is not shioko's to know.
- A `Transfer-Encoding` or `Content-Length` list with empty elements is
  refused, although recipients must accept such lists.
- An upgrade request goes upstream with `Connection: upgrade` and without
  `close`, for the sake of WebSocket servers; the connection is closed after
  any answer other than 101 all the same.
- The upstream is not watched for an early error response while a request
  body is being sent, and the client connection is not watched for closing
  while we wait for the upstream.
- The upstream hop is plain HTTP, also for `https` requests, and the
  upstream is required to speak HTTP/1.1 rather than found out to.
- ACME tokens are served without validators and without evaluating
  conditional requests.
- Upstream responses lose their `Upgrade` field unless they are the 101 of
  a tunnel (so a relayed 426 has none), and keep their `Via` unchanged.

## 7. Crypto dependency

Audit of the pinned libcrux release (published on crates.io on 2026-11-19):

| Crate | Lines | Lines with `unsafe` | Role |
|---|---|---|---|
| libcrux-sha2 0.0.10 | 1,554 | 0 | SHA-256 |
| libcrux-chacha20poly1305 0.0.11 | 1,570 | 0 | AEAD |
| libcrux-poly1305 0.0.8 | 658 | 0 | used by the AEAD |
| libcrux-curve25519 0.0.10 | 169 | 0 | X25519 |
| libcrux-p256 0.0.10 | 3,772 | 0 | P-256 |
| libcrux-ecdsa 0.0.10 | 746 | 0 (forbids it) | ECDSA sign, DER signature |
| libcrux-hacl-rs 0.0.7 | 2,489 | 1 | shared HACL\* code (memzero) |
| libcrux-secrets 0.0.8 | 1,673 | 18 | secret-value wrapper types (pointer casts) |
| libcrux-traits 0.0.10 | 2,822 | 4 | API traits (transmutes) |
| libcrux-macros 0.0.4 | 141 | 0 | build-time proc macro |
| libcrux-ml-kem 0.0.12 | 21,035 | 89 | ML-KEM-768; every `unsafe` is in AVX2/NEON code not compiled here, or wraps a call that is a safe function without those features; the crate denies `unsafe` elsewhere |
| libcrux-sha3 0.0.12 | 3,567 | 0 (forbids it) | SHA-3 and SHAKE for ML-KEM |
| libcrux-intrinsics 0.0.10 | 2,523 | 195 | SIMD intrinsics; all of it in its ARM and AVX2 modules, which exist only with the SIMD features, which are off |
| libcrux-platform (ours) | 14 | 0 (forbids it) | stand-in for libcrux's CPU detection (`patches/libcrux-platform`): always "no SIMD"; the real crate needs `libc` and `unsafe` |

Transitive third-party crates: `rand` and `rand_core` (trait definitions only,
default features off), and at build time only `syn`, `quote`, `proc-macro2`,
`unicode-ident`.

Each algorithm crate's README states it is safe Rust compiled from verified
HACL\* code. The whole project is pre-release (all versions below 0.1).

Decisions:

- **HMAC and HKDF are written by us on top of verified SHA-256** (about 60
  lines). `libcrux-hkdf` and `libcrux-hmac` pull in SHA-3, a SIMD intrinsics
  crate with about 190 `unsafe` lines, and `libc`. HMAC and HKDF are plain
  compositions of the hash; any functional bug breaks interoperability with
  every client, and they are covered by RFC 4231, RFC 5869 and Wycheproof
  vectors.
- **ECDSA signing calls the HACL\* function in `libcrux-p256` directly.** The
  `libcrux-ecdsa` wrapper can only create a nonce through its `rand` feature,
  which pulls in `getrandom`, `libc` and more. We derive the nonce
  ourselves by RFC 6979, with our HMAC-SHA256 (checked against the RFC's
  P-256 vectors), and use `libcrux-ecdsa` only for key validation and DER
  encoding.
- **Pinning.** `Cargo.toml` names exact versions, and `Cargo.lock` records
  the SHA-256 checksum of every crate; Cargo downloads them from crates.io
  and refuses one whose checksum differs, and crates.io never lets a
  published version change. The checks download the crates once, with
  `cargo fetch --locked` while their images are set up, and then run with
  networking off. `THIRD-PARTY.md` lists the crates and their licenses.
- **Provenance.** The `src/` of the pinned libcrux crates was compared with
  the upstream repository at the commits recorded in the crates, and is
  byte-identical.
- **Version choice.** The audited release above is the one we pin.
- **Updates** are manual: read the diff of the crates' sources, re-run the
  full test suite, commit the new `Cargo.lock`.
- Only `crypto.rs` imports libcrux.
- **ML-KEM** is called through `mlkem768::portable` only, with
  libcrux-ml-kem's default features off: no SIMD, no `rand`. The SIMD
  dispatch would ask libcrux-platform about the CPU, which needs `libc`;
  `[patch.crates-io]` puts our stand-in in its place, which says no.
  Vectors: Wycheproof's ML-KEM-768 encapsulation (265) and decapsulation
  (201) tests.

What the proofs do not cover: the F\*-to-Rust translation, the thin Rust API
wrappers, `rustc`, and side channels in the compiled binary.

## 8. Verification and testing

### What is checked where

Each tool is used where it is strongest:

| What | Tool | Checks the code itself? |
|---|---|---|
| Threads and locks: the TLS write lock, the connection cap, the two tunnel threads | TLA+ (`Handshake.tla`, `Server.tla`), and TLC on recorded runs of the real server | yes, for the runs recorded: every tlsfuzzer connection against `Handshake.tla`, a whole end-to-end run against `Server.tla` |
| The two state machines (TLS handshake, HTTP exchange) and the framing rules | TLA+, then the Rust function compared with the spec on every input | yes, on every input |
| Parsers: request and status lines, fields, sizes, Host | Kani proofs and unit tests | yes, for every input up to a size |
| Buffers and copying: which bytes go where, where a message ends | tests of the real proxy over scripted streams, every way the reads can fall | yes, for the runs the tests make |
| TLS handshake, records, key updates, alerts | end-to-end tests over loopback sockets with a test client that can misbehave; OpenSSL and curl (`tools/interop.sh`) | yes, for the runs the tests make |
| Key schedule | the two handshake traces of RFC 8448, every intermediate secret | yes, for the traces |
| Crypto primitives | RFC and Wycheproof vectors | yes, for the vectors |
| Every parser, against malformed input | Kani proofs, and mutation tests (hundreds of thousands of corrupted inputs per parser) | yes, for the inputs tried |

The byte-level properties were first modelled in TLA+ as well; that model
checked a description of sequential code rather than the code, so it was
retired and its properties became the tests in `src/http/tests.rs`.

### TLA+ specs (checked with TLC)

Each spec is written to be read: a description of the design in plain
definitions, then the properties TLC checks.

**`Handshake.tla`** — the TLS state machine as a pure function, and a model
of a connection around it: the record keys, a peer that may cause any event
at any time, and two threads sharing the connection.
- Application data is sent or delivered only after the client Finished is
  verified.
- The state machine's idea of the keys is always true; keys never go
  backwards; unencrypted records are refused once we have read keys (except
  the ignored ChangeCipherSpec).
- At most one HelloRetryRequest, ServerHello, flight and alert; records
  leave in handshake order and nothing follows an alert; the records of one
  handshake message of ours follow each other directly.
- No two records are sealed under the same keys and sequence number, and the
  peer can decrypt our records in the order it receives them.
- A requested KeyUpdate is answered before our next application data.
- Records are skipped only as early data we did not accept, and never
  after a record has decrypted.
- Nothing is silently ignored except the four cases the spec lists; a
  closed connection does nothing; under fairness every handshake ends.
- Records that carry nothing are counted, and one too many in a row ends
  the connection; only application data and steps of the handshake start
  the count again (`QuietCapped`, checked with a limit of 2).

**`Http.tla`** — the framing rules and the exchange state machine as pure
functions, with the facts that hold of them for every input:
- A head whose body length could be read in two ways is always rejected.
  Chunked encoding is never used with HTTP/1.0.
- Our own error response always closes the connection; the client is told
  it may keep the connection only if it allowed that and the response is
  delimited; a tunnel opens only on a 101 that answers an allowed upgrade.

**`Server.tla`** — accept loops, the two pools of slots and the two threads
of a tunnel.
- Neither pool ever holds more than its cap, nor one address more than its
  share of the public pool; every slot belongs to exactly one accept loop
  or connection, and a connection's to exactly one pool, on every path
  including panic. (Checked with pools of 2, one connection per address,
  three connections and one tunnel at a time.)
- No tunnel thread outlives its connection; two threads never write to the
  client at once; copying from the client never waits for the write lock.
- Once either tunnel thread's read ends, the whole tunnel ends and the slot
  is free; a thread waiting for the write lock does not wait for ever.
- Once the server is stopping nobody is let in, and the stop always ends
  with the process exiting, also without its deadline: the tunnels are cut
  and the requests being served end.

**Showing the checks can fail.** Each spec has a `.broken` file: a list of
one-place changes to the spec, each with the checks that must then fail.
`tools/spec.sh` applies every one and insists on the failure, and it refuses
a check that no entry makes fail.

### Tying the specs to the RFCs

`spec/rfc/` holds the text of RFC 8446, 9110, 9112 and 10024 and, for each,
a requirement list (`.req`). A script extracts every sentence that contains
MUST, SHALL, REQUIRED, SHOULD or RECOMMENDED, and the list has to account
for each one with a status:

| Status | Meaning | Checked by `tools/spec.sh` |
|---|---|---|
| `row` | a line of a transition table shows the behaviour | the line exists in the table TLC printed |
| `check` | a named check of a spec establishes it | the check is in the `.cfg` |
| `code` | a rule the Rust code must implement | |
| `test` | a Rust test or Kani proof establishes it | the function exists in `src/` |
| `peer` | it binds the other party | |
| `unused` | it is about a feature we do not have | |
| `deviation` | we knowingly do otherwise | |

A sentence that is missing, or still open, fails the check. The statuses
themselves are judgement and are meant to be read; the `deviation` entries
are summarised at the end of sections 5 and 6.

### Tying the specs to the code

1. **Same function, every input.** `tls/fsm.rs` and `http/fsm.rs` hold the
   same pure functions as the specs: `step(state, event) -> (state,
   actions)` and the framing rules. TLC prints each function for every
   input, not only the reachable ones; the tables are kept in
   `tests/vectors/`, a Rust test replays them, and `tools/spec.sh` fails
   when a table no longer matches its spec.
2. **The spec's wire properties, observed on real runs.** The test client
   decrypts every record the real server sends with exactly the keys and
   sequence number the spec says the peer expects next, so a reused nonce,
   a skipped sequence number or a KeyUpdate sent too late fails the test
   (`PeerCanDecrypt`, `NoNonceReuse`, `KeyUpdateAnswered` of
   `Handshake.tla`). `a_websocket_tunnel_over_tls_with_key_updates` does
   this with two threads sharing the connection.
3. **Recorded runs, checked by TLC as whole behaviours.** Every connection
   tlsfuzzer makes goes through a relay that logs its bytes
   (`tools/tlstrace.py`). A test build of shioko (`--features keylog`)
   writes each handshake's shared secret; from it and the handshake on the
   wire, the decoder derives every key itself (from RFC 8446, not from our
   code), decrypts both directions, and checks our CertificateVerify and
   both Finished messages. `spec/HandshakeTrace.tla` then has TLC find, for
   each connection, a behaviour of part 2 of `Handshake.tla` (state
   machine, keys, both threads, the write lock) that reads the client's
   records in order, each only after it arrived, and puts exactly our
   records on the wire: same kind, same alert, same keys and sequence
   number. What cannot be seen from outside (whether a ClientHello can be
   served) is left open and decided by what we sent. A self-test changes
   recorded traces the way nine kinds of broken server would have behaved
   and insists TLC rejects each.
4. **A whole run, checked against `Server.tla`.** A development build
   (`--features record`, never deployed) logs each step of the spec as its
   thread takes it: slots taken and given back, connections accepted,
   tunnels started, each pump's data, end of read, write lock and stop
   (`src/record.rs`). Steps guarded by a lock are logged while it is held,
   so the log is an order the steps could have happened in.
   `tools/e2e.sh record` runs the end-to-end checks and a soak (which fills
   the connection cap) with it, and `tools/servertrace.py` has TLC follow
   the log with `spec/ServerTrace.tla`, checking the cap, the slots, no
   stray thread, one writer and reading never waiting at every step. A
   self-test breaks the log seven ways (a slot given back twice, a tunnel
   ending under a running thread, two writers, ...) and TLC rejects each.
5. **The compiler.** The write half of a TLS connection lives inside the
   lock, so code that writes without holding it does not compile.

### Tests of the proxy over scripted streams

`src/http/tests.rs` runs the real proxy code against a scripted client and
scripted upstreams. A sweep combines 15 kinds of request with 12 kinds of
upstream behaviour, alone and followed by a second request on the same
connection (about 500 conversations), and plays each one with the reads
falling every way that matters: in one piece, byte by byte, split once at
every offset of the client's stream and of the upstream's, and cut off at
every offset by the peer closing or going silent. Each of these properties
is one test, and the requirement lists cite them by name:

| Test | What holds of every run |
|---|---|
| `request_intact` | an upstream receives exactly the client's request, written by us, and nothing of another |
| `head_at_boundary` | a request head is found only where one starts |
| `response_after_request` | the upstream is read only after it has the whole request |
| `refused_never_forwarded` | nothing of a refused request reaches an upstream, and no `100 Continue` is sent for it |
| `continue_in_time` | `100 Continue` is sent exactly to the clients that wait for it, before we wait for the body |
| `no_interim_to_http10` | an HTTP/1.0 client never gets a 1xx |
| `responses_in_order` | responses arrive in request order |
| `one_final_response` | one final response per request, nothing after a closing one |
| `response_intact` | the client receives exactly what its upstream sent |
| `end_only_when_whole` | a response cut off by the upstream is never marked complete |
| `next_request_at_boundary` | a next request is read only after a delimited response |
| `close_honoured` | `Connection: close` from either side ends the connection, and is announced |
| `every_request_answered` | every request read gets a response and a log line |
| `tunnel_rules` | a tunnel carries bytes already read first, in order, and nothing follows it |

**Every bug found gets a test.** A bug found in review, in testing or in
production gets a test named `bug_<what went wrong>` that reproduces the
report, with a comment saying what the bug was. Before the fix counts as
done, the bug is put back once to see the test fail.

`src/server.rs` adds tests over real sockets: a request through a real
upstream, a WebSocket tunnel ended by either side, the connection cap, and
slots coming back after a panic.

### Proofs in the code

Kani is a bounded model checker for Rust: it checks a property for every
input up to a stated size, not for the inputs a test happens to try. It is a
development tool like TLC; nothing of it ends up in the binary. Proofs live
next to the code in `#[cfg(kani)] mod proofs` and `tools/prove.sh` runs
them. In every proof Kani also checks that nothing panics, overflows or
reads out of bounds.

| Proof | For every input of up to |
|---|---|
| a request line that is accepted has a token method and a target in origin form, free of spaces and control characters | 12 bytes |
| a field line that is accepted has a token name directly before the colon and no control character in its value | 12 bytes |
| a status line that is accepted has a status from 100 to 599 | 14 bytes |
| a decimal number is accepted exactly when it is all digits, with the right value | 4 bytes |
| a chunk size never overflows | 18 bytes |
| a Host that is accepted is a plain name (no `/`, `@`, space) | 12 bytes |
| any time is a valid calendar date | all 64-bit times |
| `ct_eq` equals `==` | 4 bytes each |
| reading a TLS vector never leaves its input, however its length lies | 8 bytes |
| a DER element lies within its input | 8 bytes |
| base64 decodes without panicking, to at most 3 bytes per 4 characters | 8 characters |

Kani cannot reasonably check code that runs the hash or the ciphers; those
stay with the test vectors.

### Tests

| Area | Method |
|---|---|
| Crypto facade | RFC and Wycheproof vectors through `crypto.rs` for every primitive |
| Key schedule | RFC 8448 traces (1-RTT and HelloRetryRequest), every intermediate secret |
| TLS interop | OpenSSL `s_client` and curl, two builds of each (Nix, Debian), in `tools/interop.sh`; real Vaultwarden and Jellyfin behind shioko in the end-to-end environment |
| TLS negative | own end-to-end tests of every refusal (`src/tls/tests.rs`); tlsfuzzer, every TLS 1.3 script with every probe, through `tools/tlsfuzzer-profile.py` (which makes its ClientHellos offer our suite, group, scheme and a server name); `tests/tlsfuzzer.txt` lists each probe expected to fail, with the error and why |
| HTTP | unit tests, refusal corpus (`requests_we_refuse_and_why`, `upstream_responses_we_refuse`), the scripted-stream sweep above, real sockets |
| Config | every directive and every startup rule, including each error case |
| Malformed input | mutation tests: ClientHello, records, HTTP heads, chunk sizes, PEM and DER; coverage-guided fuzzing not yet |
| End to end | the Docker environment below |

`tools/check.sh` is the single definition of "all checks" on the code: lint,
tests, and release builds for both deployment targets. `tools/spec.sh` is the
same for the specs and `tools/prove.sh` for the Kani proofs. `tools/ci.sh`
runs all three inside Linux containers, the code checks for `amd64` and
`arm64`, all with networking disabled, along with the interop checks, the
systemd unit and tlsfuzzer. GitHub Actions (`.github/workflows/ci.yml`) runs
each of its stages as a job, and the end-to-end environment twice.

### Docker test environment

The end-to-end environment needs only Docker. `tools/e2e.sh` runs
`ci/e2e/compose.yaml`; results go to `target/e2e/`.

- **shioko**: the static musl release build, as deployed, run as an
  unprivileged user, with an example configuration of each kind of site
  (`ci/e2e/shioko.conf`) and certificates from a test CA.
- **Upstreams**: real Vaultwarden and Jellyfin, and a test server of our own
  (`ci/e2e/upstream.py`: echo, lengths, chunked, until-close, cut-off,
  slow, upload counting, WebSocket echo).
- **Two client networks**: from one the allowlists let clients in, from the
  other they do not.
- **ACME**: Pebble (Let's Encrypt's test server) issues a certificate to
  certbot `--webroot` through shioko's port 80.
- **Checks** (`ci/e2e/e2e.py check`): the TLS profile, both applications
  and their WebSockets, forwarding headers, every kind of response body, a
  525 MB upload and one byte more, port 80, ACME, certbot.
- **Parity** (`e2e.py parity`): an nginx container configured for the same
  sites; the same requests go to both and every difference is listed with
  its explanation, or flagged as unexplained.
- **Soak** (`tools/e2e.sh soak MINUTES`): 500 kept-alive TLS connections,
  more slow clients than the connection cap, 50 long WebSockets, with
  shioko's memory, threads and file descriptors sampled throughout.
- **The unit and the hook** (`ci/unit.Dockerfile`, in `tools/ci.sh`):
  `systemd-analyze verify` and `security` on the unit; the certbot hook run
  on a certbot-like layout, after which shioko can read the key and another
  user cannot.

## 9. Build and deployment

- Pinned toolchain in `rust-toolchain.toml`. Static musl binaries for
  `x86_64` and `aarch64`, built on Linux or macOS with the `rust-lld` that
  ships with Rust; no C toolchain is needed.
- `flake.nix` dev shell provides TLC, openssl and curl.
- systemd unit: dedicated `shioko` user, `CAP_NET_BIND_SERVICE` as the only
  capability, `NoNewPrivileges`, read-only filesystem, address families
  limited to IPv4/IPv6, syscall filter, `Restart=always`,
  `ExecStartPre=shioko check`.
- Certificates: the config points at the certificate files directly. A certbot
  deploy hook re-asserts read access for `shioko`; shioko takes the renewed
  certificate up within a minute, without a restart.
  Renewal configs are switched to `--webroot` with `certbot reconfigure` after
  cutover.
- Logs go to journald; no log files and no logrotate.

`deploy/README.md` is the deployment guide. In outline (direct, no shadow
run):

1. Install binary, unit and config; `shioko check` must pass on the host.
2. Stop nginx, start shioko on 80/443 (a few seconds of downtime).
3. Smoke-test every site from outside.
4. Reconfigure certbot; confirm with its dry run.
5. Rollback is stopping shioko and starting nginx. nginx stays installed but
   disabled until you decide to remove it.

Prerequisites: each host has a valid ECDSA P-256 certificate at cutover, and
port 80 is reachable by the ACME server.

## 10. Risks and limits

- **libcrux is pre-release**, and its wrapper crates contain 23 lines of
  `unsafe` that our own lint does not cover.
- **Side channels** are argued at source level only.
- **The TLS code is new and ours.** It is the largest unverified-by-proof part;
  the mitigations are the spec conformance tests, interop, tlsfuzzer and
  fuzzing.
- **TLA+ checks bounded models, and only of the designs.** TLC explores
  every state, but within bounds: `Handshake.tla` with sequence numbers up
  to 2 and one key update in each direction (`MaxSeq = 2`, `MaxGen = 1`),
  `Server.tla` with a cap of 2 and 3 connections. `Http.tla`'s functions
  are checked on every input of their finite domains. The real server at
  full size is checked against the specs only along the paths recorded
  runs took (tlsfuzzer against `Handshake.tla`, an end-to-end run with 512
  slots against `Server.tla`). Outside the specs altogether: byte-level
  parsing, record framing and reassembly (Kani proofs up to small sizes,
  mutation tests, tlsfuzzer), the cryptography (libcrux, test vectors),
  and the operating system: file descriptors, blocking reads and writes,
  timeouts (tests, the soak run). A bug there is not one TLA+ would catch.
- **Building needs crates.io.** `Cargo.lock`'s checksums make a changed
  crate fail the build, but a build cannot happen while crates.io (or a
  mirror of it) is unreachable, and the crates' build scripts run on the
  machine that builds, as for any Rust project.
- **Thread-per-connection** means slow clients from 8 or more addresses
  (512 at 64 each) can fill the public pool, so sites without an allowlist
  stop answering while they hold it; sites behind an allowlist keep their
  own pool. nginx has the same weakness at a higher number.
- **A full pool turns connections away** rather than queueing them, so a
  burst of more than 512 allowlisted connections at once (from a CDN, say)
  sees the rest closed.
- **Old clients** without TLS 1.3, ChaCha20-Poly1305 or X25519 cannot connect.
  RFC 8446 makes AES-128-GCM and secp256r1 mandatory to implement, so a
  client that offers only those is within its rights. Browsers, curl,
  OpenSSL and Cloudflare all offer ChaCha20-Poly1305 and X25519; older
  Java (before 12) and some embedded clients, such as TV apps, may not.
