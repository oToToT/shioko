"""Soak runs against shioko, from the client container (tools/e2e.sh soak).

    python3 soak.py MINUTES

1. 500 connections at once, each sending requests on one kept-alive TLS
   connection for MINUTES; every response is checked.
2. More slow clients than the connection cap (512): each trickles a
   request head a byte at a time. The head deadline (60 s) must end them,
   and the server must serve normally afterwards. How long an ordinary
   request waits while they hold every slot is measured.
3. 50 WebSockets open for MINUTES, a message a second each, every echo
   checked.

Prints the numbers and writes them to /results/soak.json.
"""

import json
import socket
import sys
import threading
import time

from e2e import SHIOKO, connect, exchange, pattern, ws_open, ws_receive, ws_send

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


def slow_clients(count):
    socks, opened = [], 0
    for _ in range(count):
        try:
            s = socket.create_connection((SERVER, 80), 5)
            s.sendall(b"G")
            socks.append(s)
            opened += 1
        except OSError:
            break
    started = time.time()
    # While they hold the slots, an ordinary request waits.
    waited = None

    def ordinary():
        nonlocal waited
        t = time.time()
        try:
            with connect(SERVER, None, timeout=120) as sock:
                r = exchange(sock, "GET", "/", "nowhere.test")
                if r.status == 404:
                    waited = time.time() - t
        except OSError:
            pass
    time.sleep(2)
    probe = threading.Thread(target=ordinary)
    probe.start()
    # Trickle a byte every 5 s until shioko gives up on them.
    alive = list(socks)
    while alive and time.time() - started < 120:
        time.sleep(5)
        still = []
        for s in alive:
            try:
                s.sendall(b"E")
                still.append(s)
            except OSError:
                s.close()
        alive = still
        # A closed connection only shows on the next send or a read.
        for s in list(alive):
            s.setblocking(False)
            try:
                gone = s.recv(1) == b""
            except BlockingIOError:
                gone = False
            except OSError:
                gone = True
            if gone:
                alive.remove(s)
                s.close()
            else:
                s.setblocking(True)
    ended = time.time() - started
    probe.join()
    for s in alive:
        s.close()
    after = None
    t = time.time()
    with connect(SERVER, "chat.test") as sock:
        if exchange(sock, "GET", "/bytes?n=10", "chat.test").status == 200:
            after = round(time.time() - t, 3)
    numbers["slow clients"] = {
        "opened": opened, "still open after 120 s": len(alive),
        "all ended after s": round(ended, 1),
        "an ordinary request waited s": round(waited, 1) if waited else None,
        "a request afterwards took s": after,
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
                      ("600 slow clients", lambda: slow_clients(600)),
                      ("50 WebSockets", lambda: websockets(50, int(minutes * 60)))):
        print("== " + name, flush=True)
        run()
        print(json.dumps(numbers, indent=1), flush=True)
    with open("/results/soak.json", "w") as f:
        json.dump(numbers, f, indent=1)
    bad = numbers["connections"]["failed connections"] or numbers["websockets"]["failed"] \
        or numbers["slow clients"]["still open after 120 s"] or \
        not numbers["slow clients"]["a request afterwards took s"]
    sys.exit(1 if bad else 0)
