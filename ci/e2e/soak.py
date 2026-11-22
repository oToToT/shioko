"""Soak runs against shioko, from the client container (tools/e2e.sh soak).

    python3 soak.py MINUTES

1. 500 connections at once, each sending requests on one kept-alive TLS
   connection for MINUTES; every response is checked.
2. Slow clients, 600 from outside and then 600 from inside the
   allowlists: each trickles a request head a byte at a time. From outside,
   one address may hold only 64 connections; from inside, the pool holds
   512. The rest are turned away at once, and so is another request from
   the same side, while a request from the other side is served at once.
   The head deadline (60 s) must end the slow ones, and the server must
   serve normally afterwards.
3. 64 slow uploads from outside, over TLS: each starts a 1 MB body and
   sends a byte every 5 s. A body must keep up 64 KiB a minute, so all must
   be cut after about a minute, while the server serves normally.
4. 50 WebSockets open for MINUTES, a message a second each, every echo
   checked.

Prints the numbers and writes them to /results/soak.json.
"""

import json
import socket
import ssl
import sys
import threading
import time

from e2e import ME, SHIOKO, connect, exchange, pattern, ws_open, ws_receive, ws_send

SERVER = SHIOKO["inside"]
numbers = {}


def many_connections(count, seconds):
    done, failed, latencies = [0], [], []
    lock = threading.Lock()
    stop = time.time() + seconds

    def one(i):
        try:
            with connect(SERVER, "chat.test", timeout=120) as sock:
                n = 0
                while time.time() < stop:
                    size = 1000 + (i * 7919 + n) % 50000
                    started = time.time()
                    r = exchange(sock, "GET", "/bytes?n=%d" % size, "chat.test", close=False)
                    took = time.time() - started
                    if r.status != 200 or r.body != pattern(size):
                        raise AssertionError("a wrong response")
                    n += 1
                    with lock:
                        done[0] += 1
                        latencies.append(took)
                    time.sleep(0.2)
        except Exception as e:
            with lock:
                failed.append("%s: %s" % (type(e).__name__, e))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    latencies.sort()
    numbers["connections"] = {
        "connections": count, "seconds": seconds, "requests": done[0],
        "failed connections": len(failed), "first failures": failed[:5],
        "median ms": round(1000 * latencies[len(latencies) // 2], 1) if latencies else None,
        "p99 ms": round(1000 * latencies[int(len(latencies) * 0.99)], 1) if latencies else None,
    }


def gone(s):
    """The server has closed this connection (we have sent nothing it
    would answer)."""
    s.setblocking(False)
    try:
        closed = s.recv(1) == b""
    except (BlockingIOError, ssl.SSLWantReadError):
        # Nothing to read yet; over TLS this is how it says so.
        closed = False
    except OSError:
        closed = True
    s.setblocking(True)
    return closed


def ordinary(side):
    """How long a plain request from `side` took to be answered, or None if
    it was not."""
    t = time.time()
    try:
        with connect(SHIOKO[side], None, side=side, timeout=30) as sock:
            if exchange(sock, "GET", "/", "nowhere.test").status == 404:
                return round(time.time() - t, 3)
    except (OSError, ValueError):
        pass
    return None


def slow_clients(count, side):
    other = "inside" if side == "outside" else "outside"
    socks = []
    for _ in range(count):
        try:
            s = socket.create_connection((SHIOKO[side], 80), 5, source_address=(ME[side], 0))
            s.sendall(b"G")
            socks.append(s)
        except OSError:
            break
    started = time.time()
    time.sleep(2)
    alive = [s for s in socks if not gone(s)]
    held = len(alive)
    # While they hold their slots: the other side is served at once, the
    # same side is turned away.
    other_took = ordinary(other)
    same_took = ordinary(side)
    # Trickle a byte every 5 s until shioko gives up on them.
    while alive and time.time() - started < 120:
        time.sleep(5)
        still = []
        for s in alive:
            try:
                s.sendall(b"E")
                still.append(s)
            except OSError:
                s.close()
        alive = [s for s in still if not gone(s)]
    ended = time.time() - started
    for s in socks:
        s.close()
    numbers["slow clients from " + side] = {
        "opened": len(socks), "held": held, "turned away": len(socks) - held,
        "still open after 120 s": len(alive), "all ended after s": round(ended, 1),
        "a request from %s meanwhile took s" % other: other_took,
        "a request from %s meanwhile took s" % side: same_took,
        "a request afterwards took s": ordinary(side),
    }


def slow_bodies(count, side="outside"):
    socks = []
    for _ in range(count):
        try:
            s = connect(SHIOKO[side], "chat.test", side=side, timeout=10)
            s.sendall(b"POST /count HTTP/1.1\r\nHost: chat.test\r\nContent-Length: 1000000\r\n\r\nx")
            socks.append(s)
        except OSError:
            break
    started = time.time()
    alive = list(socks)
    meanwhile = None
    while alive and time.time() - started < 150:
        time.sleep(5)
        if meanwhile is None:
            meanwhile = ordinary("inside")
        still = []
        for s in alive:
            try:
                s.sendall(b"x")
                still.append(s)
            except OSError:
                s.close()
        alive = [s for s in still if not gone(s)]
    ended = time.time() - started
    for s in socks:
        s.close()
    numbers["slow bodies from " + side] = {
        "opened": len(socks), "still open after 150 s": len(alive),
        "all ended after s": round(ended, 1),
        "a request from inside meanwhile took s": meanwhile,
    }


def websockets(count, seconds):
    failed, messages = [], [0]
    lock = threading.Lock()
    stop = time.time() + seconds

    def one(i):
        try:
            sock, status, _ = ws_open(SERVER, "chat.test")
            if status != 101:
                raise AssertionError("status %d" % status)
            sock.settimeout(30)
            n = 0
            while time.time() < stop:
                message = pattern(10 + (i + n) % 3000)
                ws_send(sock, 2, message)
                if ws_receive(sock) != (2, message):
                    raise AssertionError("a wrong echo")
                n += 1
                with lock:
                    messages[0] += 1
                time.sleep(1)
            ws_send(sock, 8, b"\x03\xe8")
            ws_receive(sock)
            sock.close()
        except Exception as e:
            with lock:
                failed.append("%s: %s" % (type(e).__name__, e))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    numbers["websockets"] = {"websockets": count, "seconds": seconds,
                             "messages": messages[0], "failed": len(failed),
                             "first failures": failed[:5]}


if __name__ == "__main__":
    minutes = float(sys.argv[1]) if len(sys.argv) > 1 else 10
    for name, run in (("500 connections", lambda: many_connections(500, int(minutes * 60))),
                      ("600 slow clients from outside", lambda: slow_clients(600, "outside")),
                      ("600 slow clients from inside", lambda: slow_clients(600, "inside")),
                      ("64 slow bodies from outside", lambda: slow_bodies(64)),
                      ("50 WebSockets", lambda: websockets(50, int(minutes * 60)))):
        print("== " + name, flush=True)
        run()
        print(json.dumps(numbers, indent=1), flush=True)
    with open("/results/soak.json", "w") as f:
        json.dump(numbers, f, indent=1)
    bad = numbers["connections"]["failed connections"] or numbers["websockets"]["failed"]
    slow = numbers["slow bodies from outside"]
    # Held until the pace ends them, a minute after their heads, not before.
    bad = bad or slow["opened"] != 64 or slow["still open after 150 s"] \
        or not 50 <= slow["all ended after s"] <= 80 or slow["a request from inside meanwhile took s"] is None
    for side, other, cap in (("outside", "inside", 64), ("inside", "outside", 512)):
        slow = numbers["slow clients from " + side]
        meanwhile = slow["a request from %s meanwhile took s" % other]
        bad = bad or slow["held"] != cap or slow["still open after 120 s"] \
            or slow["a request from %s meanwhile took s" % side] is not None \
            or meanwhile is None or meanwhile > 1 or not slow["a request afterwards took s"]
    sys.exit(1 if bad else 0)
