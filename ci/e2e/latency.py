"""Latency and throughput of shioko, next to nginx serving the same site
from the same upstream at the same time (tools/e2e.sh runs it).

    python3 latency.py

1. TLS handshakes: 200 new connections, one after the other.
2. Requests on one kept connection: 1000 small ones, one after the other.
3. Requests on 32 kept connections at once, 200 each.
4. One download of 50 MB.

Both servers open a new upstream connection for each request, so the
comparison is fair. The numbers go to /results/latency.json. shioko must
stay within a few times nginx's numbers (nginx is written in C, with
AES-GCM in hardware; shioko is portable ChaCha20 and a thread per
connection), so that a change that makes it much slower fails the run.
"""

import json
import sys
import threading
import time

from e2e import NGINX, SHIOKO, connect, exchange

SITE = "chat.test"
SMALL = "/bytes?n=100"


def percentile(values, p):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def ms(seconds):
    return round(1000 * seconds, 2)


def handshakes(server, count=200):
    times = []
    for _ in range(count):
        started = time.perf_counter()
        with connect(server, SITE):
            times.append(time.perf_counter() - started)
    return times


def kept(server, count, times):
    with connect(server, SITE, timeout=60) as sock:
        for _ in range(count):
            started = time.perf_counter()
            response = exchange(sock, "GET", SMALL, SITE, close=False)
            if response.status != 200 or len(response.body) != 100:
                raise SystemExit("%s answered %d" % (server, response.status))
            times.append(time.perf_counter() - started)


def concurrent(server, connections=32, each=200):
    times, threads = [], []
    started = time.perf_counter()
    for _ in range(connections):
        thread = threading.Thread(target=kept, args=(server, each, times))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return times, len(times) / (time.perf_counter() - started)


def download(server, size=50_000_000):
    with connect(server, SITE, timeout=60) as sock:
        started = time.perf_counter()
        sock.sendall(("GET /bytes?n=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                      % (size, SITE)).encode())
        got = 0
        while True:
            piece = sock.recv(1 << 16)
            if not piece:
                break
            got += len(piece)
        took = time.perf_counter() - started
    if got < size:
        raise SystemExit("%s sent %d bytes of %d" % (server, got, size))
    return size / took / 1e6


def measure(server):
    handshake = handshakes(server)
    one = []
    kept(server, 1000, one)
    many, rate = concurrent(server)
    return {
        "handshake p50 ms": ms(percentile(handshake, 0.5)),
        "handshake p99 ms": ms(percentile(handshake, 0.99)),
        "request p50 ms": ms(percentile(one, 0.5)),
        "request p99 ms": ms(percentile(one, 0.99)),
        "32 connections p50 ms": ms(percentile(many, 0.5)),
        "32 connections p99 ms": ms(percentile(many, 0.99)),
        "32 connections requests/s": round(rate),
        "download MB/s": round(download(server), 1),
    }


# (what, how much worse than nginx shioko may be: times nginx's number, plus
# this much); for rates, at least this share of nginx's.
SLOWER = [
    ("handshake p50 ms", 2, 2), ("handshake p99 ms", 3, 10),
    ("request p50 ms", 2, 1), ("request p99 ms", 3, 5),
    ("32 connections p50 ms", 2, 2), ("32 connections p99 ms", 3, 10),
]
RATES = [("32 connections requests/s", 0.5), ("download MB/s", 0.25)]


if __name__ == "__main__":
    # Each server measured twice, in turns, and its better run kept, so that
    # a hiccup of the machine does not decide.
    runs = {"shioko": [], "nginx": []}
    for _ in range(2):
        runs["nginx"].append(measure(NGINX["inside"]))
        runs["shioko"].append(measure(SHIOKO["inside"]))
    best = {}
    for name, results in runs.items():
        best[name] = {}
        for key in results[0]:
            values = [r[key] for r in results]
            best[name][key] = max(values) if key in dict(RATES) else min(values)
    failed = []
    for key, times, plus in SLOWER:
        if best["shioko"][key] > best["nginx"][key] * times + plus:
            failed.append(key)
    for key, share in RATES:
        if best["shioko"][key] < best["nginx"][key] * share:
            failed.append(key)
    print("%-28s %10s %10s" % ("", "shioko", "nginx"))
    for key in best["shioko"]:
        print("%-28s %10s %10s%s" % (key, best["shioko"][key], best["nginx"][key],
                                     "   too slow" if key in failed else ""))
    with open("/results/latency.json", "w") as f:
        json.dump(dict(best, runs=runs, failed=failed), f, indent=1)
    sys.exit(1 if failed else 0)
