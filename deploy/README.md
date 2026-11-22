# Deploying shioko

How to replace nginx with shioko on one host, and how to go back. Do the
hosts one at a time; each takes about half an hour, with a few seconds of
downtime at the cutover.

What you need on the host: systemd, certbot, `setfacl` (Debian and Ubuntu
package `acl`), and a valid certificate for every TLS site. Port 80 must
stay reachable from the internet for certificate renewal.

Everything below runs as root on the host, except the build.

## 1. Check the certificates are ECDSA P-256

shioko serves only ECDSA P-256 certificates. For each certificate:

```
openssl x509 -in /etc/letsencrypt/live/NAME/fullchain.pem -noout -text | grep -A2 'Public Key Algorithm'
```

It must say `id-ecPublicKey` and `prime256v1` (or `P-256`). If it says
`rsaEncryption`, get a new key while nginx still serves the site:

```
certbot renew --cert-name NAME --key-type ecdsa --elliptic-curve secp256r1 --force-renewal
```

Then make sure the renewal configuration keeps it that way:
`/etc/letsencrypt/renewal/NAME.conf` must have `key_type = ecdsa` (and
`elliptic_curve = secp256r1` if it names a curve). certbot before 2.0
defaults to RSA, so add the lines if they are missing.

## 2. Build the binary

On your machine, in the repository, for the host's architecture
(`uname -m` on the host says `x86_64` or `aarch64`):

```
cargo build --locked --release --target x86_64-unknown-linux-musl
cargo build --locked --release --target aarch64-unknown-linux-musl
```

The binary is `target/<target>/release/shioko`: static, no dependencies.
Copy it to the host as `/usr/local/bin/shioko`, mode 0755, owned by root.

## 3. Write the configuration

Read the host's nginx configuration (`nginx -T` prints all of it) and write
one section per `server_name` that serves something into
`/etc/shioko/shioko.conf`:

| nginx | shioko |
|---|---|
| `server_name NAME` of a `listen 443 ssl` server | `[NAME]` |
| `proxy_pass http://127.0.0.1:PORT` | `upstream = 127.0.0.1:PORT` |
| `ssl_certificate` / `ssl_certificate_key` | `cert` / `key` (the same paths) |
| `proxy_set_header Upgrade $http_upgrade` and `Connection "upgrade"` | `websocket = yes` |
| `allow RANGE; ... deny all;` | `allow = RANGE ...` or `allow = /etc/shioko/FILE` |
| `client_max_body_size 525M` | `max-body = 525M` (the default is 1M, as in nginx) |
| the port 80 server that redirects to HTTPS | nothing: every TLS site redirects |
| `location /.well-known/acme-challenge/` | nothing: tokens are served for every name |
| `proxy_set_header Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` | nothing: always sent |

A name that only needs a certificate (a mail server's, say) needs no
section.

Stop if the nginx configuration has anything else that matters: `root`,
`try_files`, `rewrite`, `return` other than the HTTPS redirect, `add_header`,
`real_ip_header`, `auth_basic`, `proxy_pass` to `https://` or to a path,
several `location` blocks going to different places, `gzip`. shioko does
none of these (see "Not in v1" in the main README).

An example, for a vault reachable only through Cloudflare and a WebSocket
service:

```
[vault.example.org]
upstream  = 127.0.0.1:3678
cert      = /etc/letsencrypt/live/vault.example.org/fullchain.pem
key       = /etc/letsencrypt/live/vault.example.org/privkey.pem
websocket = yes
allow     = /etc/shioko/cloudflare.txt
max-body  = 525M

[chat.example.net]
upstream  = 127.0.0.1:8787
cert      = /etc/letsencrypt/live/chat.example.net/fullchain.pem
key       = /etc/letsencrypt/live/chat.example.net/privkey.pem
websocket = yes
```

For the Cloudflare allowlist, put Cloudflare's ranges in the file, one per
line (`#` starts a comment):

```
curl -sS https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6 > /etc/shioko/cloudflare.txt
```

They change rarely; shioko reads the file at startup, so restart it after
changing the file.

## 4. Install

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

(It restarts shioko only if shioko is running, so before the cutover it
only grants access.) Then check the configuration as the `shioko` user
would read it:

```
setpriv --reuid shioko --regid shioko --init-groups /usr/local/bin/shioko check /etc/shioko/shioko.conf
```

It must say `no problems found`. If it cannot read a file, run the hook for
that certificate.

## 5. Cut over

```
systemctl disable --now nginx && systemctl enable --now shioko
systemctl status shioko
```

`journalctl -u shioko` must show `serving N sites on port 80, M of them on
port 443` and no errors. If shioko does not start, go back (section 8) and
read the journal.

## 6. Smoke-test from outside

From another machine, for every site:

```
curl -sSv https://NAME/ -o /dev/null 2>&1 | grep -E 'SSL connection|HTTP/'
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' http://NAME/some/path
```

The first must show TLSv1.3 with `TLS_CHACHA20_POLY1305_SHA256` and the
status the application gives; the second `301 https://NAME/some/path`. Then
use each application as you normally would, including what uses WebSockets
(the Vaultwarden browser extension syncing, Jellyfin playing).

For a site with `allow`: through the allowed path (Cloudflare) it must work;
straight to the host's address it must fail during the handshake
(`curl --resolve NAME:443:HOST_IP https://NAME/` reports an
`access denied` alert).

`journalctl -u shioko -f` shows a line per request:

```
203.0.113.7 vault.example.org "GET /alive" 200 1ms
```

## 7. Switch certbot to webroot

certbot's nginx plugin no longer works once nginx is stopped. For every
certificate on the host, including names that only need a certificate:

```
certbot reconfigure --cert-name NAME --webroot --webroot-path /var/lib/shioko/acme
```

`certbot reconfigure` (certbot 2.3 and later) tries a renewal first and
changes nothing if it fails. With an older certbot, edit
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

## 8. Going back

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

## 9. Afterwards

Once the host has run well for a while, remove nginx:
`apt purge nginx nginx-common` (check first that nothing else depends on
it).

On a host where nginx serves nothing, check that certbot does not use the
nginx plugin there (`grep -l 'installer = nginx\|authenticator = nginx'
/etc/letsencrypt/renewal/*.conf`), then just remove nginx.

## Upgrading shioko

Check the new binary against the configuration first, since a restart
stops the old process before the new one checks it:

```
setpriv --reuid shioko --regid shioko --init-groups ./shioko check /etc/shioko/shioko.conf
```

Then copy it over `/usr/local/bin/shioko` and `systemctl restart shioko`.
The same goes for a changed configuration: `shioko check` first, then
restart. A restart drops open connections, WebSockets included; clients
reconnect.
