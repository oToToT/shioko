# Deploying shioko

How to replace nginx with shioko on one host, and how to go back. Do the
hosts one at a time; each takes about half an hour, with a few seconds of
downtime at the cutover.

What you need on the host: Linux with systemd, certbot, `setfacl` (Debian
and Ubuntu package `acl`), `setpriv` (util-linux), and a valid certificate
for every TLS site. Port 80 must stay reachable from the internet for
certificate renewal. shioko listens on one dual-stack socket per port, so
IPv6 must not be disabled (no `ipv6.disable=1` on the kernel command line)
and `net.ipv6.bindv6only` must be 0, the default; otherwise it serves IPv6
only, or does not start.

Everything below runs as root on the host, except the build.

## 1. Check that your clients can connect

shioko speaks only TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256` and X25519
(see "Which clients can connect" in the main README). To see whether any of
your clients would be refused, let nginx log what each client offers for a
few days. Make sure `ssl_protocols` allows `TLSv1.3` (the default since
nginx 1.23.4), then add to the `http` block

```nginx
log_format shioko_check '$ssl_protocol "$ssl_ciphers" "$ssl_curves" "$http_user_agent"';
```

and to every `server` block that listens on 443, next to any `access_log`
it already has:

```nginx
access_log /var/log/nginx/shioko-check.log shioko_check;
```

Then `nginx -t && systemctl reload nginx`. Later, list the clients that
shioko would refuse:

```
cd /var/log/nginx
grep -v '^TLSv1.3 ' shioko-check.log | sort | uniq -c                    # no TLS 1.3
grep -v 'TLS_CHACHA20_POLY1305_SHA256' shioko-check.log | sort | uniq -c   # no ChaCha20-Poly1305
grep -viE 'x25519|0x001d' shioko-check.log | sort | uniq -c              # no X25519
```

Each line shows the client's user agent. If one you need is there, shioko
is not for that site yet. Remove the two lines from nginx afterwards.

## 2. Check that the certificates are ECDSA P-256

shioko serves only ECDSA P-256 certificates. For each certificate:

```
openssl x509 -in /etc/letsencrypt/live/NAME/fullchain.pem -noout -text | grep -E 'Public Key Algorithm|ASN1 OID'
```

It must say `id-ecPublicKey` and `prime256v1`. If it says
`rsaEncryption`, get a new key while nginx still serves the site:

```
certbot renew --cert-name NAME --key-type ecdsa --elliptic-curve secp256r1 --force-renewal
```

Then make sure the renewal configuration keeps it that way:
`/etc/letsencrypt/renewal/NAME.conf` must have `key_type = ecdsa` (and
`elliptic_curve = secp256r1` if it names a curve). certbot before 2.0
defaults to RSA, so add the lines if they are missing.

A certificate from elsewhere (a commercial CA, Cloudflare's Origin CA) has
to be issued again for an ECDSA P-256 key; Cloudflare's Origin CA offers
one as "ECC".

## 3. Build the binary

On your machine (Linux or macOS), with Rust installed through
[rustup](https://rustup.rs), for the host's architecture: the first build
command if `uname -m` on the host says `x86_64`, the second if it says
`aarch64`.

```
git clone https://github.com/oToToT/Shioko.git shioko
cd shioko
rustup toolchain install    # the version pinned in rust-toolchain.toml
cargo build --locked --release --target x86_64-unknown-linux-musl
cargo build --locked --release --target aarch64-unknown-linux-musl
```

The binary is `target/<target>/release/shioko`: static, no dependencies.
Copy it to the host together with `deploy/shioko.service` and
`deploy/certbot-deploy-hook`, and on the host install it with

```
install -m 0755 -o root -g root shioko /usr/local/bin/shioko
```

(`install` writes a new file, so on SELinux hosts it gets the label of
`/usr/local/bin`; a file moved there with `mv` keeps its old label and
systemd cannot run it.)

## 4. Write the configuration

Read the host's nginx configuration (`nginx -T` prints all of it) and write
one section per `server_name` that serves something into
`/etc/shioko/shioko.conf` (`mkdir -p /etc/shioko` first):

| nginx | shioko |
|---|---|
| `server_name NAME` of a `listen 443 ssl` server | `[NAME]` |
| `server_name NAME1 NAME2` | a section for each name, with the same `cert` and `key` |
| a `listen 80` server that proxies, without TLS | `[NAME]` without `cert` and `key` |
| `proxy_pass http://HOST:PORT` (or `http://HOST:PORT/` in `location /`) | `upstream = HOST:PORT` |
| an `upstream` block with one `server HOST:PORT` | `upstream = HOST:PORT` |
| `ssl_certificate` / `ssl_certificate_key` | `cert` / `key` (the same paths) |
| `proxy_set_header Upgrade $http_upgrade` and `Connection "upgrade"` | `websocket = yes` |
| `allow RANGE; ... deny all;` | `allow = RANGE ...` or `allow = /etc/shioko/FILE` |
| `client_max_body_size 525m` | `max-body = 525M` (units `K`, `M`, `G` in capitals; the default is 1M, as in nginx) |
| `client_max_body_size 0` (no limit) | a large size, such as `max-body = 100G`: in shioko `0` allows no body |
| the port 80 server that redirects to HTTPS | nothing: every TLS site redirects |
| `location /.well-known/acme-challenge/` | nothing: tokens are served for every name |
| `proxy_set_header Host $host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` | nothing: always sent, with `Via: 1.1 shioko` |
| no `proxy_set_header Host` | nginx then sends the upstream's address as `Host`; shioko always sends the name the client asked for, so check that the application accepts it |
| `listen [::]:443`, `http2`, `ssl_protocols`, `ssl_ciphers`, `ssl_session_*`, `ssl_stapling`, `ssl_dhparam`, `include /etc/letsencrypt/options-ssl-nginx.conf` | nothing: both address families always; TLS is fixed; clients use HTTP/1.1 |
| `proxy_http_version 1.1`, `proxy_buffering off`, `proxy_request_buffering off` | nothing: always HTTP/1.1, never buffered |
| `access_log`, `error_log` | nothing: a line per request goes to the journal |
| a `default_server` that refuses unknown names | nothing: unknown names get 404, or the TLS alert `unrecognized_name` |

A name that only needs a certificate (a mail server's, say) needs no
section.

Stop if the nginx configuration has anything else that matters for a site,
because shioko does none of it (see "Is it for you?" in the main README):

- `root`, `try_files`, `rewrite`, `return` other than the HTTPS redirect,
  `error_page`, `gzip`, `proxy_cache`, `sub_filter`;
- several `location` blocks going to different places, a `location` other
  than `/` that proxies, or a `proxy_pass` with a path other than `/`;
- a wildcard (`*.example.org`) or regular-expression `server_name`, or a
  server that redirects one name to another (`www` to the bare domain);
- `proxy_pass` to `https://` or `unix:`, or an `upstream` block with several
  servers;
- `add_header` (shioko adds no response headers, so a
  `Strict-Transport-Security` header has to come from the application),
  `proxy_set_header` for other fields, `proxy_redirect`;
- `real_ip_header`, `set_real_ip_from`, `auth_basic`, `auth_request`,
  `ssl_verify_client`, `limit_req`, `limit_conn`;
- `proxy_read_timeout` or `proxy_send_timeout` above 60 s, for long
  polling or quiet WebSockets: shioko ends a request or a WebSocket that
  is silent for 60 s.

Certificates must be readable outside `/home`, `/root` and `/run/user`,
which the unit hides. Those under `/etc/letsencrypt` are handled by the
certbot hook (section 5); for any other, let the `shioko` group read the
files yourself (`setfacl -m g:shioko:r FILE`).

An example, for a vault reachable only through Cloudflare and a WebSocket
service:

```
[vault.example.org]
upstream  = 127.0.0.1:8000
cert      = /etc/letsencrypt/live/vault.example.org/fullchain.pem
key       = /etc/letsencrypt/live/vault.example.org/privkey.pem
websocket = yes
allow     = /etc/shioko/cloudflare.txt
max-body  = 525M

[chat.example.net]
upstream  = localhost:3000
cert      = /etc/letsencrypt/live/chat.example.net/fullchain.pem
key       = /etc/letsencrypt/live/chat.example.net/privkey.pem
websocket = yes
```

For the Cloudflare allowlist, put Cloudflare's ranges in the file, one per
line (`#` starts a comment):

```
{ curl -sS https://www.cloudflare.com/ips-v4; echo; curl -sS https://www.cloudflare.com/ips-v6; echo; } > /etc/shioko/cloudflare.txt
```

(The `echo`s keep the last range of one list and the first of the next on
separate lines.)

They change rarely; shioko reads the file at startup, so restart it after
changing the file. Behind Cloudflare, `X-Real-IP` is Cloudflare's address
and `X-Forwarded-For` ends with it; the visitor's address comes before it
there, and in the `CF-Connecting-IP` header, which is passed on.

## 5. Install

```
useradd --system --no-create-home --shell /usr/sbin/nologin shioko
mkdir -p /var/lib/shioko/acme
cp shioko.service /etc/systemd/system/shioko.service
cp certbot-deploy-hook /etc/letsencrypt/renewal-hooks/deploy/shioko
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/shioko
systemctl daemon-reload
```

Let shioko read each certificate the configuration names. The hook does it
with ACLs, so nothing else about the files changes; run it once for each:

```
RENEWED_LINEAGE=/etc/letsencrypt/live/NAME /etc/letsencrypt/renewal-hooks/deploy/shioko
```

(It only grants access. After each renewal certbot runs it again, and
shioko, which reads its certificates again every minute, takes the new
one up for new connections without a restart.) Then check the
configuration as the `shioko` user would read it:

```
setpriv --reuid shioko --regid shioko --init-groups /usr/local/bin/shioko check /etc/shioko/shioko.conf
```

It must say `no problems found`. If it cannot read a file, run the hook for
that certificate.

## 6. Cut over

```
systemctl disable --now nginx && systemctl enable --now shioko
systemctl status shioko
```

`journalctl -u shioko` must show `serving N sites on port 80, M of them on
port 443` and no errors. If shioko does not start, go back (section 9) and
read the journal.

## 7. Smoke-test from outside

From another machine, for every site (not with Windows' built-in
`curl.exe`, which cannot connect to shioko: see "Which clients can connect"
in the main README):

```
curl -sSv https://NAME/ -o /dev/null 2>&1 | grep -E 'SSL connection|HTTP/'
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' http://NAME/some/path
```

The first must show TLSv1.3 with `TLS_CHACHA20_POLY1305_SHA256` and the
status the application gives; the second `301 https://NAME/some/path`. Then
use each application as you normally would, including what uses WebSockets
(live updates, sync, media playback).

For a site with `allow`: through the allowed path (Cloudflare, say) it must
work; straight to the host's address it must fail during the handshake
(`curl --resolve NAME:443:HOST_IP https://NAME/` reports an
`access denied` alert).

`journalctl -u shioko -f` shows a line per request:

```
203.0.113.7 vault.example.org "GET /alive" 200 1ms
```

## 8. Switch certbot to webroot

certbot's nginx plugin no longer works once nginx is stopped, and its
standalone mode cannot take port 80 from shioko. See how each certificate
is renewed:

```
grep -H 'authenticator\|installer' /etc/letsencrypt/renewal/*.conf
```

Switch every certificate whose authenticator is `nginx` or `standalone`,
including names that only need a certificate. Leave those renewed through
DNS (`dns-...`) as they are.

```
certbot reconfigure --cert-name NAME --webroot --webroot-path /var/lib/shioko/acme
sed -i '/^installer = nginx$/d' /etc/letsencrypt/renewal/NAME.conf
```

The `sed` removes the nginx installer, if the file still names it, so that
renewals do not try to reload nginx; shioko takes renewed certificates up
by itself. `certbot reconfigure` (certbot 2.3 and later) tries a renewal
first and changes nothing if it fails. With an older certbot, edit
`/etc/letsencrypt/renewal/NAME.conf` by hand: under `[renewalparams]` set
`authenticator = webroot` and `webroot_path = /var/lib/shioko/acme,`, remove
the `installer = nginx` line, and add

```
[[webroot_map]]
NAME = /var/lib/shioko/acme
```

Either way, then confirm:

```
certbot renew --dry-run
```

Every certificate must renew in the dry run. shioko serves the tokens
certbot writes under `/var/lib/shioko/acme/.well-known/acme-challenge/`.

## 9. Going back

```
systemctl disable --now shioko && systemctl enable --now nginx
```

nginx stays installed and configured until you remove it. If certbot was
already switched to webroot, nginx does not serve
`/var/lib/shioko/acme`, so either add to each port 80 server of nginx

```
location /.well-known/acme-challenge/ { root /var/lib/shioko/acme; }
```

or switch certbot back with
`certbot reconfigure --cert-name NAME --nginx`.

## 10. Afterwards

Once the host has run well for a while, remove nginx. First check that
certbot no longer uses its nginx plugin for any certificate; this must
print nothing:

```
grep -l 'installer = nginx\|authenticator = nginx' /etc/letsencrypt/renewal/*.conf
```

Then remove it with the package manager, for example
`apt purge nginx nginx-common` on Debian and Ubuntu (check first that
nothing else depends on it). On a host where nginx serves nothing, the same
check comes first, then just remove nginx.

## Upgrading shioko

Check the new binary against the configuration first, since a restart
stops the old process before the new one checks it:

```
setpriv --reuid shioko --regid shioko --init-groups ./shioko check /etc/shioko/shioko.conf
```

Then copy it over `/usr/local/bin/shioko` and `systemctl restart shioko`.
The same goes for a changed configuration: `shioko check` first, then
restart. A restart lets the requests being served finish, for up to 10 s;
connections waiting for their next request and WebSockets are closed at
once, and clients reconnect.
