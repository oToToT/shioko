"""Records TLS connections to shioko and turns them into traces that TLC
checks against spec/Handshake.tla (see spec/HandshakeTrace.tla).

    tlstrace.py relay PORT TARGET DIR
        Forwards connections on 127.0.0.1:PORT to TARGET (host:port), and
        logs each to DIR/<n>.log: "in|out <hex>" per chunk, in the order the
        chunks passed, and "in|out end|reset" when a side stopped.
    tlstrace.py module KEYLOG OUT.tla DIR...
        Decodes the logs with the secrets in KEYLOG (written by a shioko
        built with --features keylog) and writes the module Recorded, with
        Traces, the sequence of decoded connections.
    tlstrace.py check KEYLOG DIR...
        For each DIR, writes the module and has TLC check its traces with
        spec/HandshakeTrace.tla; says which were not accepted and how far
        each got. Needs `tlc` on the PATH, or TLA2TOOLS set to tla2tools.jar.
    tlstrace.py selftest KEYLOG DIR
        Shows that the check can fail: changes traces from DIR the way a
        server with a bug would have behaved (see BROKEN), and insists that
        TLC rejects every changed trace and accepts the originals.

The decoder is written from RFC 8446 alone, not from shioko: from the
shared secret and the handshake as it went over the wire it derives every
key, decrypts both directions, and checks our CertificateVerify and both
Finished messages. What it reports for each record is what was on the
wire; what shioko should have made of it is left to the spec.
"""

import hashlib
import hmac
import os
import socket
import struct
import sys
import threading

# ---------------------------------------------------------------- the relay


def relay(port, target, directory):
    serve(socket.create_server(("127.0.0.1", int(port))), target, directory)


def serve(listener, target, directory, threads=None):
    """Relays until the listener is closed; each connection's thread is
    added to `threads`."""
    host, _, target_port = target.rpartition(":")
    os.makedirs(directory, exist_ok=True)
    count = 0
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        count += 1
        path = os.path.join(directory, "%06d.log" % count)
        thread = threading.Thread(target=forward,
                                  args=(client, (host, int(target_port)), path),
                                  daemon=True)
        thread.start()
        if threads is not None:
            threads.append(thread)


def forward(client, target, path):
    server = socket.create_connection(target)
    lock = threading.Lock()
    log = open(path, "w")
    stopped = []  # a side we reset ourselves: its errors are ours, not news

    def note(line):
        with lock:
            log.write(line + "\n")
            log.flush()

    def pump(source, sink, way):
        while True:
            try:
                data = source.recv(1 << 16)
            except OSError:
                if source in stopped:
                    return
                note(way + " reset")
                stopped.append(sink)
                sink.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
                sink.close()
                return
            if not data:
                note(way + " end")
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            note(way + " " + data.hex())
            try:
                sink.sendall(data)
            except OSError:
                pass

    threads = [threading.Thread(target=pump, args=(client, server, "in")),
               threading.Thread(target=pump, args=(server, client, "out"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for sock in (client, server):
        try:
            sock.close()
        except OSError:
            pass
    log.close()


# ------------------------------------------------------ RFC 8446 key schedule


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + \
        bytes([len(context)]) + context
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive(secret, label, messages):
    return expand_label(secret, label, hashlib.sha256(messages).digest(), 32)


def traffic_keys(secret):
    return expand_label(secret, b"key", b"", 32), \
        expand_label(secret, b"iv", b"", 12)


def next_secret(secret):
    return expand_label(secret, b"traffic upd", b"", 32)


def finished(secret, messages):
    key = expand_label(secret, b"finished", b"", 32)
    return hmac.new(key, hashlib.sha256(messages).digest(),
                    hashlib.sha256).digest()


def unseal(secret, sequence, header, payload):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    key, iv = traffic_keys(secret)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, payload, header)
    except InvalidTag:
        return None


def signature_ok(certificate, signed, signature):
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = x509.load_der_x509_certificate(certificate).public_key()
        key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
          22: "record_overflow", 40: "handshake_failure",
          47: "illegal_parameter", 49: "access_denied", 50: "decode_error",
          51: "decrypt_error", 70: "protocol_version", 80: "internal_error",
          109: "missing_extension", 112: "unrecognized_name",
          120: "no_application_protocol"}
# The longest ClientHello there can be (msgs::MESSAGE_LIMIT).
MESSAGE_LIMIT = 2 + 32 + 33 + 65536 + 256 + 65537


def vectors(data, at, width):
    """Splits data[at:] as one vector of the given length width."""
    n = int.from_bytes(data[at:at + width], "big")
    if len(data) < at + width + n:
        raise ValueError
    return data[at + width:at + width + n], at + width + n


def hello_facts(message):
    """(offers early data, has an X25519 share) of a ClientHello, or None if
    it does not parse."""
    try:
        body = message[4:]
        at = 2 + 32
        _, at = vectors(body, at, 1)
        _, at = vectors(body, at, 2)
        _, at = vectors(body, at, 1)
        extensions, at = vectors(body, at, 2)
        early = share = False
        i = 0
        while i < len(extensions):
            kind = int.from_bytes(extensions[i:i + 2], "big")
            data, i = vectors(extensions, i + 2, 2)
            if kind == 42:
                early = True
            if kind == 51:
                shares, _ = vectors(data, 0, 2)
                j = 0
                while j < len(shares):
                    group = int.from_bytes(shares[j:j + 2], "big")
                    key, j = vectors(shares, j + 2, 2)
                    share |= group == 0x1d and len(key) == 32
        return early, share
    except (ValueError, IndexError):
        return None


# ------------------------------------------------------------ the decoder


class Connection:
    """Decodes one recorded connection into trace entries."""

    def __init__(self, keylog):
        self.keylog = keylog
        self.entries = []
        self.transcript = b""
        self.first_hello = None
        self.client = {}   # epoch -> [secret, next sequence]
        self.server = {}
        self.client_finished = None
        self.server_handshake = None
        self.client_handshake = None
        self.master = None
        self.certificate = None
        self.incoming = b""   # handshake bytes from the client, not yet whole
        self.outgoing = b""   # and from us
        self.flight = []      # the types of our flight's messages so far

    # -- epochs: ("handshake", 0), ("data", n)

    def open(self, keys, header, payload, exact):
        """Tries each epoch at its next sequence number (and, when not
        exact, at any earlier one, to catch a reused nonce): (epoch,
        sequence, plaintext) or None."""
        for epoch, entry in sorted(keys.items()):
            secret, sequence = entry
            tries = [sequence] if exact else [sequence] + list(range(sequence))
            for s in tries:
                plain = unseal(secret, s, header, payload)
                if plain is not None:
                    if s == sequence:
                        entry[1] += 1
                    if epoch[0] == "data" and ("data", epoch[1] + 1) not in keys:
                        keys[("data", epoch[1] + 1)] = [next_secret(secret), 0]
                    return epoch, s, plain
        return None

    def add_keys(self, keys, epoch, secret):
        keys[epoch] = [secret, 0]
        if epoch[0] == "data":
            keys[("data", epoch[1] + 1)] = [next_secret(secret), 0]

    # -- what the client sent

    def incoming_record(self, kind, header, payload):
        entry = dict(dir="in", what="record", sealed=kind == 23, outer=kind,
                     key="none", gen=0, c="", size=len(payload))
        content, inner = payload, kind
        if kind == 23:
            opened = self.open(self.client, header, payload, True)
            if opened is None:
                entry["c"] = "sealed"
                return self.entries.append(entry)
            (level, gen), _, plain = opened
            entry.update(key=level, gen=gen)
            if len(plain) > (1 << 14) + 1:
                entry["c"] = "overflow"
                return self.entries.append(entry)
            plain = plain.rstrip(b"\0")
            if not plain:
                entry["c"] = "nocontent"
                return self.entries.append(entry)
            content, inner = plain[:-1], plain[-1]
        entry["c"] = self.classify(inner, content, kind != 23)
        self.entries.append(entry)

    def classify(self, inner, content, plain):
        if inner == 20:
            return "ccs" if content == b"\1" else "ccs_bad"
        if inner == 21:
            if len(content) == 2:
                return "close_notify" if content[1] == 0 else "alert"
            return "alert_empty" if not content else "alert_bad"
        if inner == 23:
            return "data"
        if inner != 22:
            return "badtype"
        if not content:
            return "empty"
        self.incoming += content
        if len(self.incoming) < 4:
            return "fragment"
        length = int.from_bytes(self.incoming[1:4], "big")
        if length > MESSAGE_LIMIT:
            return "toolong"
        if len(self.incoming) < 4 + length:
            return "fragment"
        if len(self.incoming) > 4 + length:
            return "trailing"
        message, self.incoming = self.incoming, b""
        kind = message[0]
        if kind == 1 and plain:
            return self.client_hello(message)
        if kind == 20 and not plain:
            if len(message) != 4 + 32:
                return "finished_garbled"
            good = self.client_finished is not None and \
                hmac.compare_digest(message[4:], self.client_finished)
            return "finished" if good else "finished_bad"
        if kind == 24 and not plain:
            if len(message) != 5:
                return "key_update_garbled_length"
            if message[4] not in (0, 1):
                return "key_update_garbled_value"
            return "key_update_request" if message[4] else "key_update"
        return "other"

    def client_hello(self, message):
        if self.first_hello is None:
            self.first_hello = message
            self.transcript = message
        elif self.transcript.startswith(b"\xfe"):
            self.transcript += message  # after our HelloRetryRequest
        facts = hello_facts(message)
        if facts is None:
            return "hello_garbled"
        early, share = facts
        return ("hello" if share else "hello_retry") + \
            ("_early" if early else "")

    # -- what we sent

    def outgoing_record(self, kind, header, payload):
        entry = dict(dir="out", what="record", key="plain", gen=0, seq=0,
                     kind="other", more=False, alert="")
        content, inner = payload, kind
        if kind == 23:
            opened = self.open(self.server, header, payload, False)
            if opened is None:
                entry["key"] = "bad"
                return self.entries.append(entry)
            (level, gen), sequence, plain = opened
            entry.update(key=level, gen=gen, seq=sequence)
            plain = plain.rstrip(b"\0")
            if not plain:
                return self.entries.append(entry)
            content, inner = plain[:-1], plain[-1]
        if inner == 20 and kind == 20 and content == b"\1":
            entry["kind"] = "ccs"
        elif inner == 21 and len(content) == 2:
            entry.update(kind="alert", alert=ALERTS.get(content[1],
                                                         str(content[1])))
        elif inner == 23 and kind == 23:
            entry["kind"] = "data"
        elif inner == 22:
            entry["kind"], entry["more"] = self.our_handshake(
                content, entry["key"])
        self.entries.append(entry)

    def our_handshake(self, content, key):
        """The kind of record our handshake bytes make, and whether what it
        belongs to goes on in the next record."""
        self.outgoing += content
        kind = last = None
        while len(self.outgoing) >= 4:
            length = int.from_bytes(self.outgoing[1:4], "big")
            if len(self.outgoing) < 4 + length:
                break
            message = self.outgoing[:4 + length]
            self.outgoing = self.outgoing[4 + length:]
            last = message[0]
            this = self.our_message(message, key)
            if this == "other" or kind not in (None, this):
                return "other", False
            kind = this
        if kind is None:
            # Only the start of a message.
            kind = {2: "server_hello", 8: "flight", 11: "flight",
                    15: "flight", 20: "flight", 24: "key_update"}.get(
                        self.outgoing[0] if self.outgoing else None, "other")
        more = bool(self.outgoing) or (kind == "flight" and last != 20)
        return kind, more

    def our_message(self, message, key):
        kind = message[0]
        if kind == 2 and key == "plain":
            random = message[6:38]
            if random == HRR_RANDOM:
                if self.first_hello is None:
                    return "other"
                self.transcript = b"\xfe\0\0\x20" + \
                    hashlib.sha256(self.first_hello).digest() + message
                return "retry"
            self.transcript += message
            shared = self.keylog.get(random)
            if shared is None:
                return "other"
            early = hkdf_extract(b"\0" * 32, b"\0" * 32)
            handshake = hkdf_extract(derive(early, b"derived", b""), shared)
            self.server_handshake = derive(handshake, b"s hs traffic",
                                           self.transcript)
            client = derive(handshake, b"c hs traffic", self.transcript)
            self.add_keys(self.client, ("handshake", 0), client)
            self.add_keys(self.server, ("handshake", 0), self.server_handshake)
            self.client_handshake = client
            self.master = hkdf_extract(derive(handshake, b"derived", b""),
                                       b"\0" * 32)
            return "server_hello"
        if key == "handshake" and kind in (8, 11, 15, 20):
            # EncryptedExtensions, Certificate, CertificateVerify, Finished,
            # in that order, each checked.
            expected = [8, 11, 15, 20][len(self.flight)] \
                if len(self.flight) < 4 else None
            if kind != expected:
                return "other"
            if kind == 11:
                certificates, _ = vectors(message[4:], 1, 3)
                self.certificate, _ = vectors(certificates, 0, 3)
            if kind == 15:
                signed = b" " * 64 + \
                    b"TLS 1.3, server CertificateVerify\0" + \
                    hashlib.sha256(self.transcript).digest()
                if message[4:6] != b"\x04\x03" or not signature_ok(
                        self.certificate, signed, vectors(message, 6, 2)[0]):
                    return "other"
            if kind == 20:
                if message[4:] != finished(self.server_handshake,
                                           self.transcript):
                    return "other"
            self.transcript += message
            self.flight.append(kind)
            if kind == 20:
                self.client_finished = finished(self.client_handshake,
                                                self.transcript)
                client = derive(self.master, b"c ap traffic", self.transcript)
                server = derive(self.master, b"s ap traffic", self.transcript)
                self.add_keys(self.client, ("data", 0), client)
                self.add_keys(self.server, ("data", 0), server)
            return "flight"
        if kind == 24 and key == "data" and message == b"\x18\0\0\x01\0":
            return "key_update"
        return "other"


def records(data):
    """Splits a byte stream into records: [(start, end, type, header,
    payload)], and (the end of a header refused for its type or length,
    the alert), if there is one."""
    out, at = [], 0
    while len(data) >= at + 5:
        header = data[at:at + 5]
        kind, length = header[0], int.from_bytes(header[3:5], "big")
        if kind not in (20, 21, 22, 23):
            return out, (at + 5, "unexpected_message")
        if length > (1 << 14) + (256 if kind == 23 else 0):
            return out, (at + 5, "record_overflow")
        if len(data) < at + 5 + length:
            break
        out.append((at, at + 5 + length, kind, header,
                    data[at + 5:at + 5 + length]))
        at += 5 + length
    return out, None


def decode(path, keylog):
    """The trace of one recorded connection."""
    lines = [line.split() for line in open(path) if line.strip()]
    # Where each byte of each direction came in: the line it came on.
    streams = {"in": b"", "out": b""}
    starts = {"in": [], "out": []}
    events = []  # (line, order, kind, ...)
    for number, (way, what) in enumerate(lines):
        if what in ("end", "reset"):
            events.append((number, 1, way, what))
            continue
        starts[way].append((len(streams[way]), number))
        streams[way] += bytes.fromhex(what)

    def line_of(way, offset):
        found = 0
        for start, number in starts[way]:
            if start > offset:
                break
            found = number
        return found

    for way in ("in", "out"):
        found, refused = records(streams[way])
        for start, end, kind, header, payload in found:
            # The client's records count once whole, ours from their start.
            at = line_of(way, end - 1 if way == "in" else start)
            events.append((at, 0, way, (kind, header, payload)))
        if refused and way == "in":
            events.append((line_of("in", refused[0] - 1), 0, "in",
                           ("refused", refused[1])))
    events.sort(key=lambda e: (e[0], e[1]))
    connection = Connection(keylog)
    for _, _, way, item in events:
        if item in ("end", "reset"):
            connection.entries.append(dict(dir=way, what=item))
        elif item[0] == "refused":
            connection.entries.append(dict(dir="in", what="refused",
                                           c=item[1]))
        elif way == "in":
            connection.incoming_record(*item)
        else:
            connection.outgoing_record(*item)
    return connection.entries


# -------------------------------------------------------- writing the module

IN_FIELDS = ["pos", "what", "sealed", "outer", "key", "gen", "c", "size"]
OUT_FIELDS = ["pos", "what", "key", "gen", "seq", "kind", "more", "alert"]
DEFAULTS = dict(sealed=False, outer=0, key="none", gen=0, c="", size=0,
                seq=0, kind="", more=False, alert="")


def tla(value):
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    return '"' + value + '"'


def entry_tla(entry):
    fields = IN_FIELDS if entry["dir"] == "in" else OUT_FIELDS
    return "[" + ", ".join("{0} |-> {1}".format(f, tla(entry.get(f, DEFAULTS.get(f))))
                           for f in fields) + "]"


def read_keylog(path):
    keylog = {}
    for line in open(path):
        random, shared = line.split()
        keylog[bytes.fromhex(random)] = bytes.fromhex(shared)
    return keylog


def recorded(keylog_path, directories):
    """[(path, entries)] of every recorded connection."""
    keylog = read_keylog(keylog_path)
    found = []
    for directory in directories:
        for name in sorted(os.listdir(directory)):
            if name.endswith(".log"):
                path = os.path.join(directory, name)
                entries = decode(path, keylog)
                if entries:
                    found.append((path, entries))
    return found


def module(keylog_path, out, directories, traces=None):
    if traces is None:
        traces = recorded(keylog_path, directories)
    names = [name for name, _ in traces]
    traces = [entries for _, entries in traces]
    with open(out, "w") as f:
        f.write("---- MODULE Recorded ----\n")
        f.write("\\* Written by tools/tlstrace.py; one trace per connection.\n")
        f.write("Traces == <<\n")

        def side(trace, way):
            return "<<" + ",\n      ".join(
                entry_tla(dict(e, pos=i)) for i, e in enumerate(trace, 1)
                if e["dir"] == way) + ">>"
        f.write(",\n".join(
            "  [in |-> " + side(trace, "in") + ",\n   out |-> " +
            side(trace, "out") + "]" for trace in traces))
        f.write("\n>>\n====\n")
    with open(out + ".names", "w") as f:
        f.write("\n".join(names) + "\n")
    print("{0}: {1} traces".format(out, len(traces)))


# ------------------------------------------------------------ checking


def run_tlc(work, keylog_path, directories, traces=None):
    """Checks traces with TLC in the directory work: (names, accepted
    trace numbers, how far each got), or None if TLC failed."""
    import re
    import shutil
    import subprocess
    spec = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                        "spec")
    jar = os.environ.get("TLA2TOOLS")
    tlc = ["java", "-XX:+UseParallelGC", "-cp", jar, "tlc2.TLC"] if jar \
        else ["tlc"]
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    for name in ("Handshake.tla", "HandshakeTrace.tla", "HandshakeTrace.cfg"):
        shutil.copy(os.path.join(spec, name), work)
    module(keylog_path, os.path.join(work, "Recorded.tla"), directories,
           traces)
    names = open(os.path.join(work, "Recorded.tla.names")).read().split()
    result = subprocess.run(
            tlc + ["-workers", "auto", "-metadir", os.path.join(work, "states"),
                   "-config", "HandshakeTrace.cfg", "HandshakeTrace.tla"],
        cwd=work, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    open(os.path.join(work, "tlc.log"), "w").write(result.stdout)
    if result.returncode != 0:
        print("TLC failed: see " + os.path.join(work, "tlc.log"))
        return None
    accepted = {int(m) for m in
                re.findall(r'<<"accepted", (\d+)>>', result.stdout)}
    reached = {}
    for trace, ours, theirs in re.findall(
            r'<<"reached", (\d+), (\d+), (\d+)>>', result.stdout):
        key = (int(ours), int(theirs))
        reached[int(trace)] = max(reached.get(int(trace), (1, 1)), key)
    return names, accepted, reached


def check(keylog_path, directories):
    """Has TLC check each directory's traces. True if all were accepted."""
    good = True
    for directory in directories:
        work = directory.rstrip("/") + ".tlc"
        result = run_tlc(work, keylog_path, [directory])
        if result is None:
            good = False
            continue
        names, accepted, reached = result
        rejected = [i for i in range(1, len(names) + 1) if i not in accepted]
        print("{0}: {1} of {2} traces accepted".format(
            directory, len(names) - len(rejected), len(names)))
        for i in rejected[:10]:
            ours, theirs = reached.get(i, (1, 1))
            print("    {0}: stuck before our record {1}, with the client's "
                  "first {2} read".format(names[i - 1], ours, theirs - 1))
        good &= not rejected
    return good


# Each entry changes a recorded trace the way a server with this bug would
# have behaved; None where the trace has nothing to change.

def first(entries, test):
    return next((i for i, e in enumerate(entries) if test(e)), None)


def ours(kind, alert=None):
    return lambda e: e["dir"] == "out" and e.get("kind") == kind and \
        (alert is None or e.get("alert") == alert)


def without(entries, i):
    return None if i is None else entries[:i] + entries[i + 1:]


def changed(entries, i, **fields):
    return None if i is None else \
        entries[:i] + [dict(entries[i], **fields)] + entries[i + 1:]


def moved(entries, i, to):
    if i is None or to is None or to >= i:
        return None
    return entries[:to] + [entries[i]] + entries[to:i] + entries[i + 1:]


BROKEN = {
    "the client's close_notify is not answered":
        lambda t: without(t, first(t, ours("alert", "close_notify"))),
    "an alert of ours names the wrong error":
        lambda t: changed(t, first(t, ours("alert")), alert="decode_error"),
    "a record is sealed with a sequence number used before":
        lambda t: changed(t, first(t, lambda e: ours("alert")(e) and
                                   e["key"] == "data" and e["seq"] > 0), seq=0),
    "application data goes out before the client Finished":
        lambda t: moved(t, first(t, ours("data")),
                        first(t, lambda e: e["dir"] == "in" and
                              e.get("c") == "finished")),
    "application data goes out under the handshake keys":
        lambda t: changed(t, first(t, ours("data")), key="handshake"),
    "a requested KeyUpdate is not answered":
        lambda t: without(t, first(t, ours("key_update"))),
    "the ServerHello goes out before the ClientHello came":
        lambda t: moved(t, first(t, ours("server_hello")),
                        first(t, lambda e: e["dir"] == "in")),
    "the connection is closed before the alert is sent":
        lambda t: moved(t, first(t, lambda e: e["dir"] == "out" and
                                 e["what"] == "end"),
                        first(t, ours("alert"))),
    "data is sent after an alert":
        lambda t: None if first(t, ours("alert")) is None else
        t[:first(t, ours("alert")) + 1] + [dict(t[first(t, ours("data"))], seq=99)]
        + t[first(t, ours("alert")) + 1:] if first(t, ours("data")) is not None
        else None,
}


def selftest(keylog_path, directory):
    """True if TLC accepts the recorded traces and rejects each broken one."""
    traces = recorded(keylog_path, [directory])
    broken = []
    for what, change in BROKEN.items():
        for name, entries in traces:
            mutated = change(entries)
            if mutated is not None:
                broken.append((what + " (" + name + ")", mutated))
                break
        else:
            print("selftest: no trace in {0} to break as: {1}".format(
                directory, what))
            return False
    work = directory.rstrip("/") + ".selftest"
    result = run_tlc(work, keylog_path, [], traces + broken)
    if result is None:
        return False
    names, accepted, _ = result
    good = True
    for i, name in enumerate(names, 1):
        if i <= len(traces) and i not in accepted:
            print("selftest: the recorded trace was rejected: " + name)
            good = False
        if i > len(traces) and i in accepted:
            print("selftest: TLC accepted a server whose " + name)
            good = False
    if good:
        print("selftest: {0} recorded traces accepted, {1} broken ones "
              "rejected".format(len(traces), len(broken)))
    return good


if __name__ == "__main__":
    if sys.argv[1:2] == ["relay"]:
        relay(*sys.argv[2:5])
    elif sys.argv[1:2] == ["module"]:
        module(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif sys.argv[1:2] == ["check"]:
        sys.exit(0 if check(sys.argv[2], sys.argv[3:]) else 1)
    elif sys.argv[1:2] == ["selftest"]:
        sys.exit(0 if selftest(sys.argv[2], sys.argv[3]) else 1)
    else:
        sys.exit(__doc__)
