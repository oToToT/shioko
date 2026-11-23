"""Checks a run of the real server against spec/Server.tla with TLC.

    servertrace.py check RECORD
    servertrace.py selftest RECORD
        Shows the check can fail: changes the record the way a server with
        a bug would have behaved (see BROKEN) and insists TLC rejects each.

RECORD is what a shioko built with --features record wrote to the file
SHIOKO_RECORD names: one line per step of a thread, "WHO WHAT", where WHO
is a listener (l80, l443) or a connection's pump ("c7 up", "c7 down").
A listener's steps are "reserve", "release" (accept() failed), "accept
cN POOL ADDRESS", "turn_away POOL ADDRESS" and, once at its start,
"public_tls true|false".
This turns it into the sequence of steps of spec/Server.tla that the run
took (module ServerRecorded) and has TLC follow it with
spec/ServerTrace.tla, checking the spec's invariants at every step.

What the log says is turned into the spec's steps as follows:

- the up pump's data is not a step of the spec (it needs no write lock);
- a pump of a plain-HTTP tunnel has no write lock to record: its data is
  followed by the lock taken and the write done, or failed;
- a write that fails without sending anything takes the lock all the same;
- a pump whose reading ends with our answer to the client's alert (sent by
  the reading thread) is recorded taking the lock before its read ends; in
  the spec its read ends first, and that is the order given here. Moving
  the end of a read earlier is safe: it touches nothing another thread
  sees.
- the up pump taking the lock and then reading on (it copies data, or
  takes the lock again) is answering the client's KeyUpdate: the step
  Answer. Taking it and then ending is a goodbye, as above; a KeyUpdate
  answered just before the client's end of stream reads the same way, and
  both are steps the spec allows.
- connections get the names 1, 2, ... of the spec, reused once one ends,
  and addresses the names a1, a2, ...
"""

import os
import re
import shutil
import subprocess
import sys

CAP = 512          # each pool
PER_ADDRESS = 64


def steps(lines):
    """The spec's steps, as dicts, from the recorded lines."""
    events = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if parts[0].startswith("l"):
            events.append(([parts[0]], parts[1], parts[2:]))
        else:
            events.append((parts[:2], parts[2], parts[3:]))

    out = []
    names, free, plain = {}, list(range(2 * CAP, 0, -1)), set()
    addresses = {}
    state = {}  # (conn, side) -> "read", "wrote" (data sent, lock to come), "ended"

    def address(text):
        return addresses.setdefault(text, "a%d" % (len(addresses) + 1))

    def goes_on(index, who):
        """Whether the pump of events[index] reads on after the unlock that
        follows: it copies data or takes the lock again."""
        after = [w for who2, w, _ in events[index + 1:] if who2 == who]
        return len(after) > 1 and after[1] in ("data", "lock")

    def emit(what, conn=None, side=None, listener=None, pool="none", where="none"):
        out.append(dict(what=what, c=names.get(conn, 0), p=side or "",
                        l=listener or "", k=pool, a=where))

    for index, (who, what, args) in enumerate(events):
        if len(who) == 1:
            listener = who[0]
            if what == "accept":
                conn, pool, where = args
                names[conn] = free.pop()
                if listener == "l80":
                    plain.add(conn)
                emit("accept", conn, listener=listener, pool=pool, where=address(where))
            elif what == "turn_away":
                pool, where = args
                emit("turn_away", listener=listener, pool=pool, where=address(where))
            elif what == "public_tls":
                steps.public_tls = args == ["true"]
            else:
                emit({"reserve": "reserve", "release": "fail"}[what], listener=listener)
            continue
        conn, side = who[0], who[1]
        pump = (conn, side)
        if what == "release":
            emit("release", conn)
            free.append(names.pop(conn))
            for s in ("up", "down"):
                state.pop((conn, s), None)
            continue
        if what == "tunnel":
            emit("tunnel", conn)
            continue
        if what == "data":
            if side == "up":
                continue
            emit("data", conn, side)
            state[pump] = "wrote"
            if conn in plain:
                # No lock to record: the write took it, and it worked unless
                # the pump's next step says otherwise.
                nxt = next((w for who2, w, _ in events[index + 1:]
                            if who2 == who), None)
                emit("lock", conn, side)
                emit("unlock_fail" if nxt == "write_fails" else "unlock_ok", conn, side)
                state[pump] = "read" if nxt != "write_fails" else "failed"
            continue
        if what == "write_fails":
            if side == "up":
                what = "read_ends"
            elif state.get(pump) == "wrote":
                emit("lock", conn, side)
                emit("unlock_fail", conn, side)
                state[pump] = "failed"
                continue
            else:
                continue  # the lock steps were recorded, or synthesised
        if what == "lock":
            if state.get(pump, "read") == "read":
                if side == "up" and goes_on(index, who):
                    # Our answer to the client's KeyUpdate; it reads on.
                    emit("answer", conn, side)
                    state[pump] = "wrote"
                else:
                    # A goodbye: the read has ended.
                    emit("read_ends", conn, side)
                    state[pump] = "ended"
            emit("lock", conn, side)
            continue
        if what in ("unlock_ok", "unlock_fail"):
            emit(what, conn, side)
            if state.get(pump) == "wrote":
                state[pump] = "read" if what == "unlock_ok" else "failed"
            continue
        if what == "read_ends":
            if state.get(pump) != "ended":
                emit("read_ends", conn, side)
                state[pump] = "ended"
            continue
        if what == "stop":
            emit("stop", conn, side)
            continue
        raise SystemExit("cannot read: %s %s" % (" ".join(who), what))
    steps.addresses = sorted(addresses.values(), key=lambda a: int(a[1:]))
    return out


steps.public_tls = True
steps.addresses = []


def module(steps_, path):
    with open(path, "w") as f:
        f.write("---- MODULE ServerRecorded ----\nEXTENDS Naturals\n")
        f.write("\\* Written by tools/servertrace.py from a recorded run.\n")
        f.write("RecordedCap == %d\n" % CAP)
        f.write("RecordedPerAddress == %d\n" % PER_ADDRESS)
        f.write("RecordedConns == 1..%d\n" % (2 * CAP))
        f.write("RecordedAddresses == {%s}\n" % ", ".join('"%s"' % a for a in steps.addresses))
        f.write("RecordedPublicTls == %s\n" % ("TRUE" if steps.public_tls else "FALSE"))
        f.write("Steps == <<\n")
        f.write(",\n".join('  [what |-> "%s", c |-> %d, p |-> "%s", l |-> "%s", k |-> "%s", a |-> "%s"]'
                           % (s["what"], s["c"], s["p"], s["l"], s["k"], s["a"]) for s in steps_))
        f.write("\n>>\n====\n")


def check(record, lines=None, quiet=False):
    try:
        found = steps(lines if lines is not None else open(record).read().splitlines())
    except (KeyError, IndexError, ValueError) as error:
        if not quiet:
            print("the record cannot be read as steps of spec/Server.tla: %r" % error)
        return False
    work = record + ".tlc"
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    spec = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec")
    for name in ("Server.tla", "ServerTrace.tla", "ServerTrace.cfg"):
        shutil.copy(os.path.join(spec, name), work)
    module(found, os.path.join(work, "ServerRecorded.tla"))
    jar = os.environ.get("TLA2TOOLS")
    tlc = ["java", "-XX:+UseParallelGC", "-Xmx4g", "-cp", jar, "tlc2.TLC"] if jar else ["tlc"]
    result = subprocess.run(tlc + ["-workers", "1", "-metadir", os.path.join(work, "states"),
                                   "-config", "ServerTrace.cfg", "ServerTrace.tla"],
                            cwd=work, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    open(os.path.join(work, "tlc.log"), "w").write(result.stdout)
    reached = [int(m) for m in re.findall(r'<<"reached", (\d+)>>', result.stdout)]
    accepted = '<<"accepted">>' in result.stdout
    if result.returncode != 0 or not accepted:
        if quiet:
            return False
        stuck = max(reached, default=1)
        print("the run is not a behaviour of spec/Server.tla: no step explains "
              "step %d of %d, %r; see %s" % (
                  stuck, len(found), found[stuck - 1] if stuck <= len(found) else None,
                  os.path.join(work, "tlc.log")))
        for line in result.stdout.splitlines():
            if "is violated" in line or line.startswith("Error"):
                print("    " + line)
        return False
    if quiet:
        return True
    kinds = {}
    for s in found:
        kinds[s["what"]] = kinds.get(s["what"], 0) + 1
    print("the run is a behaviour of spec/Server.tla: %d steps (%s), every "
          "invariant held" % (len(found), ", ".join(
              "%d %s" % (n, k) for k, n in sorted(kinds.items()))))
    return True


def first(lines, test, after=0):
    return next((i for i, l in enumerate(lines) if i >= after and test(l)), None)


def tunnel_of(lines):
    """A TLS connection that became a tunnel and sent data, if the record
    has one."""
    tls = {l.split()[2] for l in lines if l.startswith("l443 accept ")}
    sent = {l.split()[0] for l in lines if l.endswith(" down lock")}
    tunnels = [l.split()[0] for l in lines if l.endswith(" up tunnel")]
    return next((c for c in tunnels if c in tls and c in sent), None)


def broken(lines):
    """[(what the bug is, the record as the buggy server would have made
    it)], for each change the record allows."""
    out = []
    c = tunnel_of(lines)
    release = first(lines, lambda l: l.endswith(" up release"))
    if release is not None:
        out.append(("a slot is given back twice", lines[:release + 1] + lines[release:]))
    reserve = first(lines, lambda l: l.endswith(" reserve"))
    out.append(("a connection is accepted without a slot", lines[:reserve] + lines[reserve + 1:]))
    if c:
        down_stop = first(lines, lambda l: l == c + " down stop")
        end = first(lines, lambda l: l == c + " up release")
        out.append(("a tunnel ends while its second thread still runs",
                    lines[:down_stop] + [lines[end]] + [l for l in lines[down_stop:] if l != lines[end]]))
        out.append(("a pump never shuts the sockets down",
                    [l for l in lines if l != c + " down stop"]))
        lock = first(lines, lambda l: l == c + " down lock")
        unlock = first(lines, lambda l: l.startswith(c + " down unlock"), lock or 0)
        if lock is not None and unlock is not None:
            out.append(("two pumps hold the write lock at once",
                        lines[:lock + 1] + [c + " up lock", c + " up unlock_ok"] + lines[lock + 1:]))
            out.append(("the write lock is never given back",
                        lines[:unlock] + lines[unlock + 1:]))
        data = first(lines, lambda l: l == c + " down data")
        if data is not None:
            out.append(("data is sent without the write lock",
                        [l for i, l in enumerate(lines) if not (i > data and l.startswith(c + " down ") and
                                                               ("lock" in l))]))
    away = first(lines, lambda l: " turn_away public " in l)
    if away is not None:
        out.append(("a connection is turned away and keeps its slot", lines[:away] + lines[away + 1:]))
        out.append(("an allowlisted peer is turned away while its pool has room",
                    lines[:away] + [lines[away].replace(" turn_away public ", " turn_away allowed ")]
                    + lines[away + 1:]))
    return out


def allowed(lines):
    """[(what, the record as a correct server could have made it)], which
    must be accepted: our answer to a KeyUpdate in the middle of a tunnel,
    which the clients of the end-to-end run do not ask for."""
    c = tunnel_of(lines)
    unlock = first(lines, lambda l: l == "%s down unlock_ok" % c) if c else None
    data = first(lines, lambda l: l == "%s up data" % c, unlock or 0) if unlock is not None else None
    if data is None:
        return []
    answer = [c + " up lock", c + " up unlock_ok"]
    return [("the up pump answers a KeyUpdate in the middle of a tunnel", lines[:unlock + 1] + answer + lines[unlock + 1:])]


def selftest(record):
    lines = open(record).read().splitlines()
    if not check(record, lines, quiet=True):
        print("selftest: the recorded run itself was rejected")
        return False
    for what, changed in allowed(lines):
        if not check(record, changed, quiet=True):
            print("selftest: TLC rejected a correct server in which " + what)
            return False
    changes = broken(lines)
    good = len(changes) >= 7
    if not good:
        print("selftest: the record has no tunnel with data to break")
    for what, changed in changes:
        if check(record, changed, quiet=True):
            print("selftest: TLC accepted a server in which " + what)
            good = False
    if good:
        print("selftest: the recorded run and %d correct variant accepted, %d broken ones rejected"
              % (len(allowed(lines)), len(changes)))
    return good


if __name__ == "__main__":
    if sys.argv[1:2] == ["check"] and len(sys.argv) == 3:
        sys.exit(0 if check(sys.argv[2]) else 1)
    if sys.argv[1:2] == ["selftest"] and len(sys.argv) == 3:
        sys.exit(0 if selftest(sys.argv[2]) else 1)
    sys.exit(__doc__)
