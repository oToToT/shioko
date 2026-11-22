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
    tlstrace.py selftest KEYLOG DIR...
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


# What tools/tlsfuzzer.sh configures shioko with: one site, no allowlist.
SITES = (b"site.test",)

TLS13, CHACHA20_POLY1305, ECDSA_P256 = 0x0304, 0x1303, 0x0403
X25519, X25519MLKEM768 = 0x001d, 0x11ec
SHARE_LENGTH = {X25519: 32, X25519MLKEM768: 1216}
# The X25519 public values of small order (RFC 7748, and the list
# libsodium refuses): their shared secret is all zeros.
P25519 = 2 ** 255 - 19
SMALL_ORDER = {0, 1, P25519 - 1,
               325606250916557431795983626356110631294008115727848805560023387167927233504,
               39382357235489614581723060781553021112529911719440698176882885853963445705823}


class Refused(Exception):
    """A ClientHello shioko must refuse, with this alert."""


class Reader:
    """A cursor over bytes that refuses to read past their end."""

    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, n):
        if self.at + n > len(self.data):
            raise Refused("decode_error")
        self.at += n
        return self.data[self.at - n:self.at]

    def number(self, width):
        return int.from_bytes(self.take(width), "big")

    def vector(self, width):
        return Reader(self.take(self.number(width)))

    def empty(self):
        return self.at == len(self.data)

    def rest(self):
        return self.data[self.at:]


def u16s(r):
    """A list of two-byte values that fills r; it must not be empty."""
    rest = r.rest()
    if not rest or len(rest) % 2:
        raise Refused("decode_error")
    r.at = len(r.data)
    return [int.from_bytes(rest[i:i + 2], "big") for i in range(0, len(rest), 2)]


def hello_verdict(message, first=None):
    """What shioko must make of a ClientHello, worked out here from RFC 8446,
    RFC 10024 and its configuration, without its code: (classification,
    facts). The classification is "hello", "hello_retry", "hello_early" or
    "hello_retry_early" for one it can serve, or Refused's alert for one it
    must refuse. `first` is the facts of the ClientHello our
    HelloRetryRequest answered, for a second one; facts are what a second
    ClientHello must then match. The checks go in shioko's order, which
    decides the alert when more than one applies (src/tls/msgs.rs)."""
    r = Reader(message)
    r.take(1)
    body = r.vector(3)
    if not r.empty():
        raise Refused("decode_error")
    legacy = body.number(2)
    random = body.take(32)
    session_id = body.vector(1).rest()
    if len(session_id) > 32:
        raise Refused("decode_error")
    suites = u16s(body.vector(2))
    compression = body.vector(1).rest()
    if not compression:
        raise Refused("decode_error")
    if body.empty():
        raise Refused("protocol_version")
    extensions = body.vector(2)
    if not body.empty():
        raise Refused("decode_error")
    found, repeated, psk_last = [], False, True
    while not extensions.empty():
        kind = extensions.number(2)
        data = extensions.vector(2).rest()
        repeated |= any(k == kind for k, _ in found)
        psk_last &= not any(k == 41 for k, _ in found)
        found.append((kind, data))

    def get(kind):
        return next((data for k, data in found if k == kind), None)

    def extension(kind, read):
        data = get(kind)
        if data is None:
            return None
        r = Reader(data)
        value = read(r)
        if value is None or not r.empty():
            raise Refused("decode_error")
        return value

    def key_shares(r):
        entries, out = r.vector(2), []
        while not entries.empty():
            group = entries.number(2)
            out.append((group, entries.vector(2).rest()))
        return out

    def server_name(r):
        names, name, two = r.vector(2), None, False
        while not names.empty():
            kind = names.number(1)
            entry = names.vector(2).rest()
            if kind == 0:
                two |= name is not None
                name = entry
        return (name, two) if name else None

    def alpn(r):
        protocols, http11 = r.vector(2), False
        if protocols.empty():
            return None
        while not protocols.empty():
            name = protocols.vector(1).rest()
            if not name:
                return None
            http11 |= name == b"http/1.1"
        return http11

    # 1. It parses, the extensions we read included.
    versions = extension(43, lambda r: u16s(r.vector(1)))
    signatures = extension(13, lambda r: u16s(r.vector(2)))
    groups = extension(10, lambda r: u16s(r.vector(2)))
    shares = extension(51, key_shares)
    name = extension(0, server_name)
    http11 = extension(16, alpn)
    early = extension(42, lambda r: True) is not None
    # 2. TLS 1.3, and nothing as old as SSL 3.0.
    if versions is None or TLS13 not in versions or legacy <= 0x0300:
        raise Refused("protocol_version")
    # 3. What may not be there, or not like this.
    if compression != b"\0" or repeated or get(44) is not None or not psk_last \
            or (name is not None and name[1]) \
            or (shares is not None and any(not key for _, key in shares)):
        raise Refused("illegal_parameter")
    if get(41) is not None and get(45) is None:
        raise Refused("missing_extension")
    # 4. What must be there.
    if signatures is None or groups is None or shares is None or name is None:
        raise Refused("missing_extension")
    # 5. What shioko can do.
    if CHACHA20_POLY1305 not in suites or ECDSA_P256 not in signatures \
            or not (X25519 in groups or X25519MLKEM768 in groups):
        raise Refused("handshake_failure")
    retry_group = X25519 if X25519 in groups else X25519MLKEM768
    # 6. The key shares: one per group, offered groups only, ours of the
    # right length. X25519MLKEM768 is used before X25519.
    share = None
    for index, (group, key) in enumerate(shares):
        if any(g == group for g, _ in shares[:index]) or group not in groups \
                or (group in SHARE_LENGTH and len(key) != SHARE_LENGTH[group]):
            raise Refused("illegal_parameter")
        if group == X25519MLKEM768 or (group == X25519 and share is None):
            share = (group, key)
    # 7. ALPN, if offered, must offer http/1.1.
    if http11 is False:
        raise Refused("no_application_protocol")
    # The site, which has no allowlist.
    if name[0].lower() not in SITES:
        raise Refused("unrecognized_name")
    # A second ClientHello repeats the first but for what may change, and
    # brings exactly the share asked for (RFC 8446 4.1.2).
    kept = (legacy, random, session_id, tuple(suites), compression,
            tuple((k, d) for k, d in found if k not in (51, 42, 41, 21)))
    if first is not None and (kept != first["kept"] or len(shares) != 1
                              or share is None or share[0] != first["group"]):
        raise Refused("illegal_parameter")
    facts = dict(kept=kept, group=retry_group)
    suffix = "_early" if early else ""
    if share is None:
        return "hello_retry" + suffix, facts
    group, key = share
    # The X25519 part may not be of small order, and the ML-KEM key must
    # pass the check of FIPS 203 section 7.2: every coefficient below q.
    u = int.from_bytes(key[-32:], "little") & ((1 << 255) - 1)
    if u % P25519 in SMALL_ORDER:
        raise Refused("illegal_parameter")
    if group == X25519MLKEM768:
        t = key[:1152]
        for i in range(0, len(t), 3):
            b0, b1, b2 = t[i], t[i + 1], t[i + 2]
            if (b0 | (b1 & 0x0f) << 8) >= 3329 or (b1 >> 4 | b2 << 4) >= 3329:
                raise Refused("illegal_parameter")
    return "hello" + suffix, facts


def judged(message, first=None):
    """hello_verdict as (classification, refusal's alert or "", facts)."""
    try:
        c, facts = hello_verdict(message, first)
        return c, "", facts
    except Refused as refused:
        return "refused", refused.args[0], None


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
        self.retry_facts = None   # of the ClientHello that earns a HelloRetryRequest
        self.hello = {}           # the verdicts on the ClientHello just read

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
        self.hello = {}
        entry["c"] = self.classify(inner, content, kind != 23)
        entry.update(self.hello)
        self.entries.append(entry)

    def classify(self, inner, content, plain):
        if inner == 20:
            return "ccs" if content == b"\1" else "ccs_bad"
        if inner == 21:
            if len(content) == 2:
                return "close_notify" if content[1] == 0 else "alert"
            return "alert_empty" if not content else "alert_bad"
        if inner == 23:
            return "data" if content else "empty_data"
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
        # Its verdict as a first ClientHello, and as a second one, after a
        # HelloRetryRequest; the trace spec takes the one its phase calls for.
        c, why, facts = judged(message)
        c2, why2 = c, why
        if self.retry_facts is not None:
            c2, why2, _ = judged(message, self.retry_facts)
        elif c.startswith("hello_retry"):
            self.retry_facts = facts
        self.hello = dict(why=why, c2=c2, why2=why2)
        return c

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

IN_FIELDS = ["pos", "what", "sealed", "outer", "key", "gen", "c", "why", "c2", "why2", "size"]
OUT_FIELDS = ["pos", "what", "key", "gen", "seq", "kind", "more", "alert"]
DEFAULTS = dict(sealed=False, outer=0, key="none", gen=0, c="", why="", c2=None, why2="", size=0,
                seq=0, kind="", more=False, alert="")


def tla(value):
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    return '"' + value + '"'


def entry_tla(entry):
    fields = IN_FIELDS if entry["dir"] == "in" else OUT_FIELDS
    if entry["dir"] == "in" and entry.get("c2") is None:
        entry = dict(entry, c2=entry.get("c", ""), why2=entry.get("why", ""))
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
    "a ClientHello it can serve is refused":
        lambda t: None if first(t, ours("server_hello")) is None else
        t[:first(t, ours("server_hello"))]
        + [dict(t[first(t, ours("server_hello"))], kind="alert", alert="handshake_failure",
                more=False)],
    "a ClientHello is refused with another alert than it must be":
        lambda t: None if first(t, lambda e: e["dir"] == "in" and e.get("c") == "refused") is None
        else changed(t, first(t, ours("alert")),
                     alert="illegal_parameter" if t[first(t, ours("alert"))]["alert"] != "illegal_parameter"
                     else "decode_error") if first(t, ours("alert")) is not None else None,
    "data is sent after an alert":
        lambda t: None if first(t, ours("alert")) is None else
        t[:first(t, ours("alert")) + 1] + [dict(t[first(t, ours("data"))], seq=99)]
        + t[first(t, ours("alert")) + 1:] if first(t, ours("data")) is not None
        else None,
}


def selftest(keylog_path, directories):
    """True if TLC accepts the recorded traces and rejects each broken one."""
    directory = " ".join(directories)
    traces = recorded(keylog_path, directories)
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
    work = directories[0].rstrip("/") + ".selftest"
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
        sys.exit(0 if selftest(sys.argv[2], sys.argv[3:]) else 1)
    else:
        sys.exit(__doc__)
