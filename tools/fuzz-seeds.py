"""Writes the seed inputs of the fuzz targets to fuzz/seeds/<target>/.

    python3 tools/fuzz-seeds.py

Seeds give the fuzzer a start that already gets past the first checks: a
ClientHello shioko would serve, requests and responses of each framing, a
certificate and a key, a configuration, whole connections. The layout of
each target's input is the one fuzz/src/lib.rs reads: a piece size (0 for
all at once), and for the connection targets the client's part with its
length in two bytes, then what the upstream answers; for tls_session the
client's part is records its harness seals after a real handshake.
"""

import os
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SEEDS = os.path.join(ROOT, "fuzz", "seeds")


def vec(width, data):
    return len(data).to_bytes(width, "big") + data


def extension(kind, data):
    return struct.pack(">H", kind) + vec(2, data)


def client_hello(name=b"site.test", groups=(0x001d, 0x11ec), share=True, alpn=True):
    x25519 = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    extensions = [
        extension(0, vec(2, b"\0" + vec(2, name))),
        extension(43, vec(1, b"\x03\x04")),
        extension(10, vec(2, b"".join(struct.pack(">H", g) for g in groups))),
        extension(13, vec(2, b"\x04\x03\x08\x04")),
        extension(51, vec(2, (b"\x00\x1d" + vec(2, x25519)) if share else b"")),
        extension(45, vec(1, b"\x01")),
    ]
    if alpn:
        extensions.append(extension(16, vec(2, vec(1, b"http/1.1"))))
    body = (b"\x03\x03" + bytes(range(32)) + vec(1, bytes(32)) + vec(2, b"\x13\x03\x13\x01")
            + vec(1, b"\0") + vec(2, b"".join(extensions)))
    return b"\x01" + vec(3, body)


def record(content_type, data):
    return bytes([content_type]) + b"\x03\x01" + vec(2, data)


def sealed(*records):
    """The tls_session target's records: a content type (255 for bytes sent
    as they are), a length, the content; its harness seals them."""
    return b"".join(bytes([t]) + vec(2, content) for t, content in records)


KEY_UPDATE, KEY_UPDATE_REQUESTED = b"\x18\x00\x00\x01\x00", b"\x18\x00\x00\x01\x01"


def connection(piece, client, answer):
    return bytes([piece]) + len(client).to_bytes(2, "big") + client + answer


REQUESTS = [
    b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: site.test\r\nContent-Length: 5\r\n\r\nhello",
    b"POST /up HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    b"GET /a HTTP/1.1\r\nHost: plain.test\r\n\r\nGET /b HTTP/1.1\r\nHost: plain.test:80\r\n\r\n",
    b"PUT /x HTTP/1.1\r\nHost: site.test\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
    b"GET /.well-known/acme-challenge/token HTTP/1.1\r\nHost: any.test\r\n\r\n",
]
RESPONSES = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\nuntil close",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\nframes",
]


def seeds():
    certs = os.path.join(ROOT, "tests", "certs")
    rfc8448 = [bytes.fromhex(line.split("\t")[4]) for line in open(os.path.join(ROOT, "tests", "vectors", "rfc8448.txt"))
               if "\tClientHello\t" in line]
    hellos = [client_hello(), client_hello(share=False), client_hello(groups=(0x11ec,), share=False),
              client_hello(alpn=False), client_hello(name=b"SITE.TEST")] + rfc8448
    out = {
        "client_hello": [h[4:] for h in hellos],
        "http_heads": [b"\0" + r for r in REQUESTS + RESPONSES] + [b"\x03" + REQUESTS[2]],
        "bodies": [b"\0" + b"5\r\nhello\r\n0\r\n\r\n", b"\x02" + b"3;ext=1\r\nabc\r\n0\r\nTrailer: x\r\n\r\n",
                   b"\0\x05hello"],
        "pem": [open(os.path.join(certs, name), "rb").read()
                for name in ("site.test.chain.pem", "site.test.key", "p384.key", "rsa.key")],
        "config": [open(os.path.join(ROOT, "ci", "e2e", "shioko.conf"), "rb").read()],
        "http_connection": [connection(0, r, a) for r in REQUESTS for a in RESPONSES[:2]]
                           + [connection(1, REQUESTS[3], RESPONSES[4])],
        "tls_connection": [connection(0, record(22, h), RESPONSES[0]) for h in hellos[:5]]
                          + [connection(7, record(22, hellos[0]) + record(20, b"\x01"), b"")],
        "tls_session": [
            connection(0, sealed((23, REQUESTS[0])), RESPONSES[0]),
            connection(0, sealed((22, KEY_UPDATE_REQUESTED), (23, REQUESTS[0])), RESPONSES[1]),
            connection(0, sealed((22, KEY_UPDATE), (23, REQUESTS[4][:30]), (23, REQUESTS[4][30:])), RESPONSES[0]),
            connection(0, sealed((21, b"\x01\x00")), b""),
            connection(0, sealed((23, b""), (23, b""), (23, REQUESTS[0])), RESPONSES[2]),
            connection(0, sealed((20, b"\x01"), (23, REQUESTS[0])), RESPONSES[0]),
            connection(3, sealed((23, REQUESTS[2][:40]), (22, KEY_UPDATE), (23, REQUESTS[2][40:])), RESPONSES[3]),
            connection(0, sealed((255, b"\x17\x03\x03\x00\x10" + bytes(16))), b""),
            connection(0, sealed((23, REQUESTS[3]), (23, b"frames up")), RESPONSES[4]),
        ],
    }
    return out


if __name__ == "__main__":
    for target, inputs in seeds().items():
        directory = os.path.join(SEEDS, target)
        os.makedirs(directory, exist_ok=True)
        for old in os.listdir(directory):
            os.remove(os.path.join(directory, old))
        for i, data in enumerate(inputs):
            with open(os.path.join(directory, "seed-%02d" % i), "wb") as f:
                f.write(data)
        print("%s: %d seeds" % (target, len(inputs)))
