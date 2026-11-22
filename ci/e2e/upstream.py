"""The test upstream of the end-to-end environment: an HTTP/1.1 server with
the endpoints the checks need. Python standard library only.

    GET  /echo          the request head we received, as text
    POST /count         reads the body; answers its length and SHA-256
    GET  /bytes?n=N     N bytes (a fixed pattern), with Content-Length
    GET  /chunked?n=N   N bytes, chunked
    GET  /close?n=N     N bytes, delimited by closing the connection
    GET  /cut?n=N       says N bytes, sends half, closes
    GET  /slow?s=S      answers after S seconds
    GET  /status?c=C    an empty response with status C
    GET  /ws            a WebSocket that echoes every message
"""

import base64
import hashlib
import socketserver
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PATTERN = bytes(range(256)) * 4096


def pattern(n):
    out = b""
    while len(out) < n:
        out += PATTERN[:n - len(out)]
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def query(self, name, default):
        values = parse_qs(urlparse(self.path).query).get(name)
        return int(values[0]) if values else default

    def reply(self, code, body=b"", headers=()):
        self.send_response(code)
        for name, value in headers:
            self.send_header(name, value)
        if not any(name.lower() == "content-length" for name, _ in headers):
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/echo":
            head = self.requestline + "\r\n" + str(self.headers)
            self.reply(200, head.encode(), [("Content-Type", "text/plain")])
        elif path == "/bytes":
            self.reply(200, pattern(self.query("n", 1000)))
        elif path == "/chunked":
            n = self.query("n", 1000)
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            body = pattern(n)
            for i in range(0, n, 4096):
                piece = body[i:i + 4096]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/close":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(pattern(self.query("n", 1000)))
            self.close_connection = True
        elif path == "/cut":
            n = self.query("n", 1000)
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            self.wfile.write(pattern(n // 2))
            self.wfile.flush()
            self.close_connection = True
        elif path == "/slow":
            time.sleep(self.query("s", 1))
            self.reply(200, b"slow\n")
        elif path == "/status":
            self.reply(self.query("c", 204))
        elif path == "/ws":
            self.websocket()
        else:
            self.reply(404, b"no such endpoint\n")

    def do_POST(self):
        if urlparse(self.path).path != "/count":
            return self.reply(404, b"no such endpoint\n")
        digest, count = hashlib.sha256(), 0
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b""):
                        pass
                    break
                piece = self.rfile.read(size)
                digest.update(piece)
                count += len(piece)
                self.rfile.readline()
        else:
            left = int(self.headers.get("Content-Length", "0"))
            while left:
                piece = self.rfile.read(min(left, 1 << 20))
                if not piece:
                    break
                digest.update(piece)
                count += len(piece)
                left -= len(piece)
        self.reply(200, ("%d %s\n" % (count, digest.hexdigest())).encode())

    def websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept.decode())
        self.end_headers()
        self.wfile.flush()
        while True:
            frame = read_frame(self.rfile)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 8:
                write_frame(self.wfile, 8, payload)
                return
            write_frame(self.wfile, 10 if opcode == 9 else opcode, payload)
            self.wfile.flush()


def read_frame(stream):
    head = stream.read(2)
    if len(head) < 2:
        return None
    opcode, length = head[0] & 15, head[1] & 127
    if length == 126:
        length = struct.unpack(">H", stream.read(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", stream.read(8))[0]
    mask = stream.read(4) if head[1] & 128 else b"\0\0\0\0"
    data = stream.read(length)
    return opcode, bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def write_frame(stream, opcode, payload):
    head = bytes([128 | opcode])
    if len(payload) < 126:
        head += bytes([len(payload)])
    elif len(payload) < 65536:
        head += bytes([126]) + struct.pack(">H", len(payload))
    else:
        head += bytes([127]) + struct.pack(">Q", len(payload))
    stream.write(head + payload)


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024


if __name__ == "__main__":
    Server(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 8080),
           Handler).serve_forever()
