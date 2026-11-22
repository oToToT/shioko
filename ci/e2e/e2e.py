"""The end-to-end checks, run in the client container (tools/e2e.sh).

    python3 e2e.py check     everything shioko must do, as seen by a client
    python3 e2e.py parity    the same requests to shioko and to nginx

Writes what it found to /results as well as printing it.
"""

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import time

CA = "/certs/ca.pem"
SHIOKO = {"inside": "10.88.0.2", "outside": "10.89.0.2"}
NGINX = {"inside": "10.88.0.3", "outside": "10.89.0.3"}
ME = {"inside": "10.88.0.10", "outside": "10.89.0.10"}
UPSTREAM, VAULTWARDEN, JELLYFIN = "10.88.0.20", "10.88.0.21", "10.88.0.22"
ACME = "/var/lib/shioko/acme/.well-known/acme-challenge"
MB = 1 << 20


# ------------------------------------------------------------ clients

def connect(server, name=None, side="inside", port=None, timeout=30):
    """A socket to server: TLS for `name` (port 443), plain without one."""
    port = port or (443 if name else 80)
    sock = socket.create_connection((server, port), timeout,
                                    source_address=(ME[side], 0))
    if name is None:
        return sock
    context = ssl.create_default_context(cafile=CA)
    return context.wrap_socket(sock, server_hostname=name)


class Response:
    def __init__(self, status, headers, body, complete=True):
        self.status, self.headers, self.body = status, headers, body
        self.complete = complete

    def header(self, name):
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        return ", ".join(values) if values else None


def exchange(sock, method, path, host, headers=(), body=b"", close=True):
    """Sends one request on sock and reads the response."""
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: " + host]
    lines += ["%s: %s" % h for h in headers]
    if body and not any(k.lower() in ("content-length", "transfer-encoding")
                        for k, _ in headers):
        lines.append("Content-Length: %d" % len(body))
    if close:
        lines.append("Connection: close")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    return read_response(sock, method)


def read_response(sock, method="GET"):
    response = http.client.HTTPResponse(sock, method=method)
    response.begin()
    try:
        data, complete = response.read(), True
    except http.client.IncompleteRead as e:
        data, complete = e.partial, False
    return Response(response.status, response.getheaders(), data, complete)


def request(server, name, method, path, headers=(), body=b"", side="inside",
            port=None, host=None):
    with connect(server, name, side, port) as sock:
        return exchange(sock, method, path, host or name, headers, body)


def pattern(n):
    block = bytes(range(256)) * 4096
    return (block * (n // len(block) + 1))[:n]


# ------------------------------------------------------------ WebSocket

def ws_open(server, name, path="/ws", side="inside"):
    sock = connect(server, name, side)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                  "Sec-WebSocket-Version: 13\r\n\r\n" % (path, name, key)).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        piece = sock.recv(1)
        if not piece:
            break
        head += piece
    status = int(head.split(b" ")[1]) if head else 0
    return sock, status, head.decode(errors="replace")


def ws_send(sock, opcode, payload):
    mask = os.urandom(4)
    head = bytes([128 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([128 | n])
    elif n < 65536:
        head += bytes([128 | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([128 | 127]) + n.to_bytes(8, "big")
    sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def ws_receive(sock):
    def exactly(n):
        data = b""
        while len(data) < n:
            piece = sock.recv(n - len(data))
            if not piece:
                raise EOFError("the WebSocket was cut off")
            data += piece
        return data
    head = exactly(2)
    n = head[1] & 127
    if n == 126:
        n = int.from_bytes(exactly(2), "big")
    elif n == 127:
        n = int.from_bytes(exactly(8), "big")
    return head[0] & 15, exactly(n)


# ------------------------------------------------------------ checks

results = []


def check(what, test):
    """Runs one check; it passes unless it raises or returns a string,
    which says what was wrong."""
    started = time.time()
    try:
        problem = test()
    except Exception as e:  # what went wrong is the finding
        problem = "%s: %s" % (type(e).__name__, e)
    took = time.time() - started
    results.append({"check": what, "ok": not problem, "problem": problem or "",
                    "seconds": round(took, 2)})
    print("%-6s %s%s" % ("ok" if not problem else "FAIL", what,
                         "" if not problem else "\n       " + str(problem)), flush=True)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def tls_alert(name, side="inside"):
    try:
        with connect(SHIOKO[side], name, side) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % name.encode())
            sock.recv(1)
        return None
    except ssl.SSLError as e:
        return e.reason


def wait_for(what, test, seconds=300):
    deadline = time.time() + seconds
    while True:
        try:
            if test():
                return
        except OSError:
            pass
        if time.time() > deadline:
            raise SystemExit("gave up waiting for " + what)
        time.sleep(2)


def checks():
    s = SHIOKO["inside"]
    wait_for("Jellyfin", lambda: request(JELLYFIN, None, "GET", "/health",
                                         port=8096, host="x").status == 200)
    wait_for("Vaultwarden", lambda: request(VAULTWARDEN, None, "GET", "/alive",
                                            port=80, host="x").status == 200)

    # TLS
    def tls_profile():
        for name in ("vault.test", "media.test", "chat.test", "files.test"):
            with connect(s, name) as sock:
                expect(sock.version() == "TLSv1.3", sock.version())
                expect(sock.cipher()[0] == "TLS_CHACHA20_POLY1305_SHA256", sock.cipher())
    check("TLS 1.3 with ChaCha20-Poly1305 for every site, chains verify", tls_profile)
    check("an unknown name gets unrecognized_name",
          lambda: expect(tls_alert("nowhere.test") == "TLSV1_UNRECOGNIZED_NAME",
                         tls_alert("nowhere.test")))
    check("the vault refuses an address outside its allowlist with access_denied",
          lambda: expect(tls_alert("vault.test", "outside") == "TLSV1_ALERT_ACCESS_DENIED",
                         tls_alert("vault.test", "outside")))
    check("other sites take the same address",
          lambda: expect(request(SHIOKO["outside"], "chat.test", "GET", "/bytes?n=10",
                                 side="outside").status == 200, "refused"))

    # Vaultwarden
    def vault():
        expect(request(s, "vault.test", "GET", "/alive").status == 200, "/alive")
        index = request(s, "vault.test", "GET", "/")
        expect(index.status == 200 and b"<html" in index.body.lower(), index.status)
        config = request(s, "vault.test", "GET", "/api/config")
        expect(config.status == 200 and "version" in json.loads(config.body), config.status)
    check("Vaultwarden: the web vault, /alive and /api/config", vault)

    def vault_hub():
        sock, status, head = ws_open(s, "vault.test", "/notifications/anonymous-hub?token=x")
        sock.close()
        direct, direct_status, _ = ws_open_plain(VAULTWARDEN, 80, "vault.test",
                                                 "/notifications/anonymous-hub?token=x")
        direct.close()
        expect(status == direct_status, "through shioko %d, directly %d" % (status, direct_status))
    check("Vaultwarden: its notification WebSocket answers as it does directly", vault_hub)

    # Jellyfin
    def media():
        health = request(s, "media.test", "GET", "/health")
        expect(health.status == 200 and health.body.strip() == b"Healthy", health.body[:80])
        info = request(s, "media.test", "GET", "/System/Info/Public")
        expect(info.status == 200 and "Version" in json.loads(info.body), info.status)
        web = request(s, "media.test", "GET", "/web/")
        expect(web.status in (200, 301, 302), web.status)
    check("Jellyfin: /health, /System/Info/Public, /web/", media)

    def media_socket():
        sock, status, _ = ws_open(s, "media.test", "/socket")
        sock.close()
        direct, direct_status, _ = ws_open_plain(JELLYFIN, 8096, "media.test", "/socket")
        direct.close()
        expect(status == direct_status, "through shioko %d, directly %d" % (status, direct_status))
    check("Jellyfin: its WebSocket answers as it does directly", media_socket)

    # What the upstream receives
    def forwarded():
        echo = request(s, "chat.test", "GET", "/echo",
                       [("X-Forwarded-For", "192.0.2.7"), ("X-Real-IP", "1.1.1.1")]).body.decode()
        for line in ("Host: chat.test", "X-Real-IP: 10.88.0.10",
                     "X-Forwarded-For: 192.0.2.7, 10.88.0.10",
                     "X-Forwarded-Proto: https", "Via: 1.1 shioko", "Connection: close"):
            expect(line in echo, "%r missing from\n%s" % (line, echo))
        expect("1.1.1.1" not in echo, "the client's X-Real-IP was passed on")
    check("the upstream gets Host, X-Real-IP, X-Forwarded-For/-Proto and Via", forwarded)

    def keep_alive():
        with connect(s, "chat.test") as sock:
            for _ in range(3):
                r = exchange(sock, "GET", "/bytes?n=1000", "chat.test", close=False)
                expect(r.status == 200 and r.body == pattern(1000), r.status)
    check("three requests on one connection", keep_alive)

    def bodies():
        for path, n in (("/bytes", 300000), ("/chunked", 100000), ("/close", 50000)):
            r = request(s, "chat.test", "GET", "%s?n=%d" % (path, n))
            expect(r.status == 200 and r.complete and r.body == pattern(n), path)
        r = request(s, "chat.test", "GET", "/close?n=1000")
        expect(r.header("Transfer-Encoding") == "chunked", "an until-close body not re-chunked")
    check("responses with a length, chunked, and until close all arrive intact", bodies)

    check("a response the upstream cuts off is seen as cut off",
          lambda: expect(not request(s, "chat.test", "GET", "/cut?n=100000").complete,
                         "it looked complete"))
    check("a slow upstream (3 s) is waited for",
          lambda: expect(request(s, "chat.test", "GET", "/slow?s=3").status == 200, "no"))

    def websocket():
        sock, status, _ = ws_open(s, "chat.test")
        expect(status == 101, status)
        for size in (5, 200, 70000, 1 * MB):
            message = pattern(size)
            ws_send(sock, 2, message)
            opcode, got = ws_receive(sock)
            expect(opcode == 2 and got == message, "a %d byte message came back wrong" % size)
        ws_send(sock, 9, b"ping")
        expect(ws_receive(sock) == (10, b"ping"), "no pong")
        ws_send(sock, 8, b"\x03\xe8")
        expect(ws_receive(sock)[0] == 8, "no close")
        sock.close()
    check("a WebSocket through chat.test: messages up to 1 MB, ping, close", websocket)

    def no_websocket():
        sock, status, head = ws_open(s, "files.test")
        sock.close()
        expect(status == 502, "%d\n%s" % (status, head))
    check("on a site without websocket, the upgrade is not passed on (502)", no_websocket)

    # Uploads
    def upload(size, chunked=False):
        with connect(s, "files.test", timeout=300) as sock:
            headers = [("Transfer-Encoding", "chunked")] if chunked else \
                [("Content-Length", str(size))]
            sock.sendall(("POST /count HTTP/1.1\r\nHost: files.test\r\n%s\r\n"
                          "Connection: close\r\n\r\n" % "\r\n".join(
                              "%s: %s" % h for h in headers)).encode())
            digest = hashlib.sha256()
            block = pattern(MB)
            sent = 0
            try:
                while sent < size:
                    piece = block[:min(MB, size - sent)]
                    sock.sendall(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
                    digest.update(piece)
                    sent += len(piece)
                if chunked:
                    sock.sendall(b"0\r\n\r\n")
            except OSError:
                pass
            return read_response(sock, "POST"), digest.hexdigest()

    def big_upload():
        size = 525 * MB
        started = time.time()
        r, digest = upload(size)
        expect(r.status == 200, r.status)
        expect(r.body.decode().split() == [str(size), digest], r.body)
        return None if time.time() - started < 600 else "took over 10 minutes"
    check("a 525 MB upload to a site with max-body 525M arrives intact", big_upload)
    check("one byte more gets 413",
          lambda: expect(upload(525 * MB + 1)[0].status == 413, "not 413"))
    check("a chunked upload of 20 MB arrives intact", lambda: expect(
        upload(20 * MB, chunked=True)[0].status == 200, "not 200"))

    # Port 80
    check("port 80 redirects a TLS site, keeping the target", lambda: expect(
        request(s, None, "GET", "/a/b?c=d", host="vault.test").header("Location")
        == "https://vault.test/a/b?c=d", "wrong Location"))
    def wiki():
        echo = request(s, None, "GET", "/echo", host="wiki.internal").body.decode()
        expect("X-Forwarded-Proto: http\r" in echo or "X-Forwarded-Proto: http\n" in echo, echo)
        expect(request(SHIOKO["outside"], None, "GET", "/echo", host="wiki.internal",
                       side="outside").status == 403, "outside was let in")
    check("a plain-HTTP site serves the inside network and refuses the outside", wiki)
    check("an unknown host on port 80 gets 404", lambda: expect(
        request(s, None, "GET", "/", host="nowhere.test").status == 404, "not 404"))

    def acme():
        os.makedirs(ACME, exist_ok=True)
        with open(os.path.join(ACME, "e2e-token_1"), "w") as f:
            f.write("e2e-token_1.thumbprint")
        r = request(s, None, "GET", "/.well-known/acme-challenge/e2e-token_1",
                    host="anything.test")
        expect(r.status == 200 and r.body == b"e2e-token_1.thumbprint", r.status)
    check("ACME tokens are served for any name, from where certbot --webroot writes them", acme)

    def certbot():
        status = open("/results/certbot.exit").read().strip()
        expect(status == "0", "certbot exited with %s; see certbot.log" % status)
    check("certbot gets a certificate for mail.test through shioko (Pebble)", certbot)

    # Our own error responses
    check("a body over max-body is refused before it is read: 413", lambda: expect(
        request(s, "chat.test", "POST", "/count", [("Content-Length", str(2 * MB))]).status
        == 413, "not 413"))


def ws_open_plain(host, port, name, path):
    sock = socket.create_connection((host, port), 10)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                  "Sec-WebSocket-Version: 13\r\n\r\n" % (path, name, key)).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        piece = sock.recv(1)
        if not piece:
            break
        head += piece
    return sock, int(head.split(b" ")[1]) if head else 0, head


# ------------------------------------------------------------ parity

PARITY = [
    # site, method, path, headers, body
    ("vault.test", "GET", "/alive", [], b""),
    ("vault.test", "GET", "/", [], b""),
    ("vault.test", "GET", "/api/config", [], b""),
    ("vault.test", "GET", "/does-not-exist", [], b""),
    ("vault.test", "POST", "/identity/connect/token", [("Content-Type", "application/x-www-form-urlencoded")],
     b"grant_type=password&username=x&password=y"),
    ("media.test", "GET", "/health", [], b""),
    ("media.test", "GET", "/System/Info/Public", [], b""),
    ("media.test", "GET", "/web/", [], b""),
    ("media.test", "HEAD", "/health", [], b""),
    ("chat.test", "GET", "/bytes?n=100000", [], b""),
    ("chat.test", "GET", "/chunked?n=100000", [], b""),
    ("chat.test", "GET", "/close?n=10000", [], b""),
    ("chat.test", "GET", "/status?c=204", [], b""),
    ("chat.test", "GET", "/status?c=304", [], b""),
    ("chat.test", "GET", "/status?c=500", [], b""),
    ("chat.test", "GET", "/missing", [], b""),
    ("chat.test", "HEAD", "/bytes?n=100", [], b""),
    ("chat.test", "POST", "/count", [], pattern(100000)),
    ("chat.test", "POST", "/count", [("Content-Length", str(2 * MB))], b""),
    ("chat.test", "GET", "/a%20b/../c?x=%41", [], b""),
    ("chat.test", "GET", "/[brackets]|pipe^", [], b""),
    ("chat.test", "GET", "http://chat.test/absolute", [], b""),
    ("chat.test", "GET", "/two-lengths", [("Content-Length", "1"), ("Content-Length", "2")], b"x"),
    ("chat.test", "GET", "/te-and-cl", [("Transfer-Encoding", "chunked"), ("Content-Length", "3")], b"0\r\n\r\n"),
    ("chat.test", "OPTIONS", "*", [], b""),
    ("chat.test", "OPTIONS", "/preflight", [("Origin", "https://other.test"),
                                            ("Access-Control-Request-Method", "PUT")], b""),
    ("chat.test", "TRACE", "/", [], b""),
    ("chat.test", "GET", "/echo", [("X-Forwarded-For", "192.0.2.1")], b""),
    ("files.test", "POST", "/count", [], pattern(MB)),
    (None, "GET", "/x?y", [("Host", "vault.test")], b""),
    (None, "GET", "/", [("Host", "nowhere.test")], b""),
    (None, "GET", "/echo", [("Host", "wiki.internal")], b""),
]


def one(server, site, method, path, headers, body):
    host = dict((k.lower(), v) for k, v in headers).get("host", site)
    headers = [(k, v) for k, v in headers if k.lower() != "host"]
    try:
        r = request(server, site, method, path, headers, body, host=host)
    except (ssl.SSLCertVerificationError, ConnectionRefusedError):
        raise  # the environment is broken, not one of the servers
    except Exception as e:
        return {"status": type(e).__name__}
    out = {"status": r.status, "length": len(r.body),
           "sha": hashlib.sha256(r.body).hexdigest()[:12]}
    for name in ("Content-Type", "Location", "Transfer-Encoding"):
        if r.header(name):
            out[name] = r.header(name)
    if path == "/echo":
        out["upstream saw"] = sorted(
            line.split(":")[0] for line in r.body.decode().splitlines()[1:] if ":" in line)
    return out


# Differences that are expected, and why.
EXPLAINED = {
    "vault.test GET /alive": "the body is the current time",
    "chat.test POST /count": "both refuse the body with 413; the error pages differ",
    "chat.test GET http://chat.test/absolute":
        "shioko refuses absolute-form targets (a README deviation); nginx serves them",
    "chat.test GET /two-lengths": "both refuse with 400; the error pages differ",
    "chat.test GET /te-and-cl": "both refuse with 400; the error pages differ",
    "chat.test OPTIONS *": "both refuse it with 400; the error pages differ",
    "chat.test TRACE /": "both refuse it with 405; the error pages differ",
    "chat.test GET /echo": "shioko adds Via and always says Connection: close upstream",
    "port 80 GET /x?y": "both redirect with 301; the bodies differ",
    "port 80 GET /": "both answer 404; the bodies differ",
    "port 80 GET /echo": "shioko adds Via and always says Connection: close upstream",
}


def parity():
    rows = []
    for site, method, path, headers, body in PARITY:
        a = one(SHIOKO["inside"], site, method, path, headers, body)
        b = one(NGINX["inside"], site, method, path, headers, body)
        what = "%s %s %s" % (site or "port 80", method, path)
        same = a == b
        why = "" if same else EXPLAINED.get(what, "NOT EXPLAINED")
        rows.append({"request": what, "same": same, "why": why, "shioko": a, "nginx": b})
        print("%-5s %s%s" % ("same" if same else "DIFF", what, "  (%s)" % why if why else ""))
        if not same:
            for key in sorted(set(a) | set(b)):
                if a.get(key) != b.get(key):
                    print("        %-18s shioko %-30s nginx %s" % (key, a.get(key), b.get(key)))
    with open("/results/parity.json", "w") as f:
        json.dump(rows, f, indent=1)
    print("%d of %d requests answered alike; %d differences not explained" % (
        sum(r["same"] for r in rows), len(rows),
        sum(r["why"] == "NOT EXPLAINED" for r in rows)))


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:
        checks()
        with open("/results/checks.json", "w") as f:
            json.dump(results, f, indent=1)
        failed = [r for r in results if not r["ok"]]
        print("%d of %d checks passed" % (len(results) - len(failed), len(results)))
        sys.exit(1 if failed else 0)
    elif sys.argv[1:] == ["parity"]:
        parity()
    else:
        sys.exit(__doc__)
