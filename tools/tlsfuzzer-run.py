"""Runs the tlsfuzzer scripts listed in tests/tlsfuzzer.txt against a
running shioko and checks every probe against what the list expects.

    python3 tools/tlsfuzzer-run.py [--record DIR] TLSFUZZER_DIR HOST PORT NAME [SCRIPT...]

TLSFUZZER_DIR holds tlsfuzzer, with tlslite-ng and ecdsa importable; NAME is
the server name to send. Each script runs through tools/tlsfuzzer-profile.py.
Every probe of a script runs (-n 0). A probe must pass unless a `fail` line of its script matches its name, and
then it must fail with that line's error. A `fail` line that matches no
probe is an error too, so the list cannot go stale. With SCRIPT arguments,
only those scripts run.

With --record, each script talks to shioko through tools/tlstrace.py's
relay, which logs its connections to DIR/<script>/ for checking with TLC.
"""

import importlib.util
import os
import re
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LIST = os.path.join(HERE, "..", "tests", "tlsfuzzer.txt")


def read_list():
    """[(script, options, [(regex, error, why)])] and [(script, why)]."""
    runs, skips = [], []
    for number, line in enumerate(open(LIST), 1):
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        word, _, rest = line.strip().partition(" ")
        if word == "run":
            script, *options = rest.split()
            runs.append((script, options, []))
        elif word == "fail" and runs:
            regex, error, why = (part.strip() for part in rest.split("~"))
            runs[-1][2].append((re.compile(regex), error, why))
        elif word == "skip":
            script, why = (part.strip() for part in rest.split("~"))
            skips.append((script, why))
        else:
            sys.exit("{0}:{1}: cannot read this line".format(LIST, number))
    return runs, skips


def probes(output):
    """The probes in a script's output: [(name, None or error message)]."""
    found = []
    for block in re.split(r"\n(?=\S[^\n]*\.\.\.\n)", "\n" + output):
        head, _, body = block.strip("\n").partition("...\n")
        head = head.rstrip()
        if not body:
            continue
        if re.search(r"^OK$", body, re.M) and "Error" not in body:
            found.append((head, None))
        else:
            errors = re.findall(r"^\w*(?:Error|Exception)\b.*$", body, re.M)
            found.append((head, errors[-1] if errors else body[:200]))
    return found


def recording(directory, target):
    """Starts a relay to target that logs to directory: (its port, a
    function that stops it once its connections are done)."""
    spec = importlib.util.spec_from_file_location(
        "tlstrace", os.path.join(HERE, "tlstrace.py"))
    tlstrace = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tlstrace)
    listener = socket.create_server(("127.0.0.1", 0))
    threads = []
    server = threading.Thread(target=tlstrace.serve,
                              args=(listener, target, directory, threads),
                              daemon=True)
    server.start()

    def stop():
        deadline = time.time() + 30
        for thread in threads:
            thread.join(max(0, deadline - time.time()))
        listener.close()
    return str(listener.getsockname()[1]), stop


def main():
    arguments = sys.argv[1:]
    record = None
    if arguments[:1] == ["--record"]:
        record, arguments = arguments[1], arguments[2:]
    fuzzer, host, port, name, *only = arguments
    runs, skips = read_list()
    env = dict(os.environ, PYTHONPATH=fuzzer)
    problems = 0
    for script, options, fails in runs:
        if only and script not in only:
            continue
        keep = ["--keep-groups"] if "--keep-groups" in options else []
        options = [o for o in options if o != "--keep-groups"]
        to_host, to_port, stop = host, port, None
        if record:
            to_port, stop = recording(
                os.path.join(record, script.replace(".py", "")),
                host + ":" + port)
            to_host = "127.0.0.1"
        # Every probe, not the random sample some scripts default to.
        command = [sys.executable, "-W", "ignore",
                   os.path.join(HERE, "tlsfuzzer-profile.py")] + keep + \
            [name, os.path.join(fuzzer, "scripts", script),
             "-h", to_host, "-p", to_port, "-n", "0"] + options
        result = subprocess.run(command, cwd=fuzzer, env=env, text=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if stop:
            stop()
            with open(os.path.join(record, script.replace(".py", ".out")),
                      "w") as f:
                f.write(result.stdout)
        found = probes(result.stdout)
        used = set()
        wrong = []
        for probe, error in found:
            expected = [(i, f) for i, f in enumerate(fails)
                        if f[0].search(probe)]
            if not expected:
                if error is not None:
                    wrong.append("{0}: failed: {1}".format(probe, error))
                continue
            i, (_, want, _) = expected[0]
            used.add(i)
            if error is None:
                wrong.append("{0}: passed, but is listed to fail".format(probe))
            elif want not in error:
                wrong.append("{0}: failed with {1}, not {2}"
                             .format(probe, error, want))
        for i, (regex, _, _) in enumerate(fails):
            if i not in used:
                wrong.append("no probe matches fail {0}".format(regex.pattern))
        if not found:
            wrong.append("no probes ran:\n" + result.stdout[-2000:])
        passed = sum(1 for _, e in found if e is None)
        print("{0:6} {1} ({2} probes, {3} passed, {4} failed as listed)".format(
            "FAIL" if wrong else "ok", script, len(found), passed,
            len(found) - passed))
        for line in wrong[:20]:
            print("         " + line)
        problems += bool(wrong)
    if not only:
        for script, why in skips:
            print("skip   {0}: {1}".format(script, why))
    if problems:
        sys.exit("{0} tlsfuzzer scripts did not do what tests/tlsfuzzer.txt "
                 "says".format(problems))


main()
