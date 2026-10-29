#!/usr/bin/env python3
"""tlsfuzzer (github.com/tlsfuzzer/tlsfuzzer) against this package's server.

tlsfuzzer's scripts talk to a server over TCP. This script builds
tools/peer.goose natively and puts a TCP front on it: each connection
gets its own `peer server` process, the socket's bytes go to it as "IN"
lines and its "OUT" bytes go back. A request (application data ending in
a blank line) is answered with a short HTTP response, as tlslite-ng's
test server does (after a KeyUpdate for GET /keyupdate), or echoed with
--echo; a close_notify is answered with one, and the socket closes once
the connection has failed or closed. A peer process that dies (an
assert, say) is a crash: it is logged with its stderr and the bytes that
caused it, whatever tlsfuzzer made of the dropped connection.

    python3 scripts/tlsfuzzer.py server [--echo] [--port 4433] [--cert C --key K] [--crash-log FILE]
    python3 scripts/tlsfuzzer.py run [--tlsfuzzer DIR] [--python PY] [--peer P] [--out DIR] [-j N]
                                     [--timeout S] [--only NAME] [config ...]

`run` starts a server for each configuration (a certificate, and the
scripts to run against it with their arguments), runs the scripts, and
writes each script's output, the crashes and results.md (the table) to
--out. The scripts need tlslite-ng and ecdsa (tlsfuzzer's
requirements.txt), and the ML-KEM ones kyber-py, so --python is an
interpreter that has them; by default ../.venv-tlsfuzzer/bin/python,
made with

    python3 -m venv ../.venv-tlsfuzzer
    ../.venv-tlsfuzzer/bin/pip install -r ../tlsfuzzer.git/requirements.txt kyber-py
"""

import argparse
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
GOOSE_DIR = os.path.normpath(os.path.join(ROOT, ".."))

# The server's TLS 1.2 suites: the defaults, and RSA key exchange and the
# SHA-256 CBC suites, which the defaults leave out (as Go's do) but
# tlsfuzzer's scripts mostly use.
SUITES12 = ["c02b", "c02f", "c02c", "c030", "cca9", "cca8", "c009", "c013", "c00a", "c014", "c023", "c027",
            "009c", "009d", "002f", "0035", "003c"]

# One ticket key for every connection's peer, as one server process would
# have, so that sessions resume across connections.
TICKET_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

HTTP_REPLY = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\ngoose\n"


def default_goose():
    if os.environ.get("GOOSE"):
        return os.environ["GOOSE"]
    return shutil.which("goose") or os.path.join(GOOSE_DIR, "goose.git", "build", "goose")


def build_peer(goose, out):
    r = subprocess.run([goose, "build", "-o", out, os.path.join(ROOT, "tools", "peer.goose")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"tools/peer.goose did not build:\n{r.stderr}")


# --- The server -----------------------------------------------------------------

class Crash(Exception):
    pass


class Peer:
    """One `peer server` process: feed it bytes, get back what it says."""

    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.state = 10

    def command(self, line):
        try:
            self.p.stdin.write(line + b"\n")
            self.p.stdin.flush()
        except (BrokenPipeError, OSError):
            raise Crash()
        out, app = b"", b""
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise Crash()
            line = line.strip()
            if line == b"END":
                return out, app
            kind, _, rest = line.partition(b" ")
            if kind == b"OUT":
                out += bytes.fromhex(rest.decode())
            elif kind == b"APP":
                app += bytes.fromhex(rest.decode())
            elif kind == b"STATE":
                self.state = int(rest.split()[0])

    def stop(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        return self.p.returncode, self.p.stderr.read().decode(errors="replace")


ST_CLOSED, ST_FAILED = 21, 22


def serve(args):
    cmd = [args.peer, "server", args.cert, args.key, "--ticket-key", TICKET_KEY]
    for s in SUITES12:
        cmd += ["--suite", s]
    for a in args.peer_arg:
        cmd += a.split(" ", 1)
    lock = threading.Lock()
    crashes = [0]

    def log_crash(code, err, received):
        with lock:
            crashes[0] += 1
            if args.crash_log:
                with open(args.crash_log, "a") as f:
                    f.write(json.dumps({"exit": code, "stderr": err.strip()[-2000:],
                                        "received": received.hex()}) + "\n")
            print(f"crash: exit {code}: {err.strip()[-300:]}", file=sys.stderr, flush=True)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            peer = Peer(cmd)
            received = b""
            pending = b""
            try:
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    received += data
                    out, app = peer.command(b"IN " + data.hex().encode())
                    if app:
                        pending += app
                        if args.echo:
                            o, _ = peer.command(b"SEND " + pending.hex().encode())
                            out += o
                            pending = b""
                        elif b"\r\n\r\n" in pending or b"\n\n" in pending:
                            # tlslite-ng's convention: GET /keyupdate has
                            # the server update its keys first.
                            if pending.startswith(b"GET /keyupdate "):
                                o, _ = peer.command(b"KEYUPDATE")
                                out += o
                            o, _ = peer.command(b"SEND " + HTTP_REPLY.hex().encode())
                            out += o
                            pending = b""
                    if peer.state == ST_CLOSED:
                        o, _ = peer.command(b"CLOSE")
                        out += o
                    if out:
                        sock.sendall(out)
                    if peer.state in (ST_CLOSED, ST_FAILED):
                        break
            except Crash:
                code, err = peer.stop()
                log_crash(code, err, received)
                return
            except OSError:
                pass
            finally:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            code, err = peer.stop()
            if code not in (0, None):
                log_crash(code, err, received)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        request_queue_size = 128

    with Server((args.host, args.port), Handler) as srv:
        print(f"listening on {args.host}:{args.port}", flush=True)
        srv.serve_forever()


# --- The runs ---------------------------------------------------------------------

# Certificates and keys are tlsfuzzer's (tests/). A script is a name, its
# arguments, and why it is run so, if it needs saying.
CONFIGS = {
    "rsa": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem",
        "comment": "RSA 2048 server; every script with its defaults",
        "scripts": "all",
    },
    "rsa-ecdhe": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem",
        "comment": "the scripts that default to RSA key exchange, run with -d (ECDHE)",
        "scripts": [
            ("test-aes-gcm-nonces.py", ["-d"]),
            ("test-chacha20.py", ["-d"]),
            ("test-conversation.py", ["-d"]),
            ("test-fuzzed-MAC.py", ["-d"]),
            ("test-fuzzed-padding.py", ["-d"]),
            ("test-fuzzed-ciphertext.py", ["-d"]),
            ("test-fuzzed-plaintext.py", ["-d"]),
            ("test-zero-length-data.py", ["-d"]),
        ],
    },
    "rsa-echo": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem", "echo": True,
        "comment": "an echoing server, for the record length scripts", "timeout": 7200,
        "scripts": [("test-lengths.py", ["-n", "0"]), ("test-tls13-lengths.py", ["-n", "0"])],
    },
    "rsa-tls12": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem",
        "server_args": ["--max-version 0303"],
        "comment": "a server that stops at TLS 1.2, for the fallback and downgrade scripts",
        "scripts": [("test-fallback-scsv.py", []), ("test-fallback-scsv.py", ["-d"]),
                    ("test-downgrade-protection.py", ["--server-max-protocol=TLSv1.2"])],
    },
    "rsa-alpn": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem",
        "server_args": ["--alpn http/1.1"],
        "comment": "ALPN: the server takes http/1.1",
        "scripts": [("test-alpn-negotiation.py", [])],
    },
    "rsa-client-auth": {
        "cert": "tests/serverX509Cert.pem", "key": "tests/serverX509Key.pem",
        "server_args": ["--client-auth 1"],
        "comment": "the server asks for a client certificate (as tlslite-ng's --reqcert; a CertificateVerify is checked)",
        "scripts": [(n, ["-k", "tests/clientX509Key.pem", "-c", "tests/clientX509Cert.pem"]) for n in [
            "test-certificate-verify.py", "test-certificate-verify-malformed.py",
            "test-certificate-verify-malformed-sig.py", "test-rsa-sigs-on-certificate-verify.py",
            "test-rsa-pss-sigs-on-certificate-verify.py", "test-certificate-malformed.py",
            "test-certificate-request.py", "test-tls13-certificate-verify.py",
            "test-tls13-certificate-request.py", "test-extended-master-secret-extension-with-client-cert.py",
            "test-renegotiation-disabled-client-cert.py"]] + [
            ("test-ecdsa-in-certificate-verify.py", ["-k", "tests/serverECKey.pem", "-c", "tests/serverECCert.pem"]),
            ("test-tls13-ecdsa-in-certificate-verify.py",
             ["-k", "tests/serverECKey.pem", "-c", "tests/serverECCert.pem"]),
            ("test-eddsa-in-certificate-verify.py",
             ["-k", "tests/serverEd25519Key.pem", "-c", "tests/serverEd25519Cert.pem"]),
            ("test-tls13-eddsa-in-certificate-verify.py",
             ["-k", "tests/serverEd25519Key.pem", "-c", "tests/serverEd25519Cert.pem"]),
            ("test-tls13-mldsa-in-certificate-verify.py",
             ["-k", "tests/serverMldsa65Key.pem", "-c", "tests/serverMldsa65Cert.pem"]),
        ],
    },
    "rsa-pss": {
        "cert": "tests/serverRSAPSSCert.pem", "key": "tests/serverRSAPSSKey.pem",
        "comment": "RSA-PSS certificate",
        "scripts": [("test-tls13-rsapss-signatures.py", []), ("test-sig-algs.py", []),
                    ("test-tls13-conversation.py", [])],
    },
    "ecdsa": {
        "cert": "tests/serverECCert.pem", "key": "tests/serverECKey.pem",
        "comment": "ECDSA P-256 certificate",
        "scripts": [("test-conversation.py", ["-d"]), ("test-ecdsa-sig-flexibility.py", []),
                    ("test-tls13-ecdsa-support.py", []), ("test-tls13-conversation.py", []),
                    ("test-tls13-minerva.py", []), ("test-ecdhe-padded-shared-secret.py", []),
                    ("test-tls13-ecdhe-curves.py", [])],
    },
    "ecdsa-p384": {
        "cert": "tests/serverP384ECCert.pem", "key": "tests/serverP384ECKey.pem",
        "comment": "ECDSA P-384 certificate",
        "scripts": [("test-tls13-ecdsa-support.py", []), ("test-tls13-conversation.py", [])],
    },
    "ecdsa-p521": {
        "cert": "tests/serverP521ECCert.pem", "key": "tests/serverP521ECKey.pem",
        "comment": "ECDSA P-521 certificate",
        "scripts": [("test-tls13-ecdsa-support.py", []), ("test-tls13-conversation.py", [])],
    },
    "ed25519": {
        "cert": "tests/serverEd25519Cert.pem", "key": "tests/serverEd25519Key.pem",
        "comment": "Ed25519 certificate",
        "scripts": [("test-tls13-eddsa.py", ["-x", "ed448 only", "-X", "handshake_failure"]),
                    ("test-tls13-conversation.py", [])],
    },
    "mldsa65": {
        "cert": "tests/serverMldsa65Cert.pem", "key": "tests/serverMldsa65Key.pem",
        "comment": "ML-DSA-65 certificate",
        "scripts": [("test-tls13-conversation.py", [])],
    },
}

# Scripts that `all` leaves out: they measure timing (and need root,
# tcpdump and requirements-timing.txt), generate data rather than test,
# or need the echo server.
SKIP = {
    "test-bleichenbacher-timing-marvin.py": "timing measurement (needs tcpdump and root)",
    "test-bleichenbacher-timing-pregenerate.py": "timing measurement (needs tcpdump and root)",
    "test-lucky13.py": "timing measurement (needs tcpdump and root)",
    "test-tls13-minerva.py": "timing measurement by default; run in the ecdsa configuration",
    "test-lengths.py": "needs an echo server: run in rsa-echo",
    "test-alpn-negotiation.py": "needs a server with ALPN: run in rsa-alpn",
    "test-fallback-scsv.py": "written for a server that stops at TLS 1.2: run in rsa-tls12",
    "test-downgrade-protection.py": "written for a server that stops at TLS 1.2: run in rsa-tls12",
    "test-tls13-lengths.py": "needs an echo server: run in rsa-echo",
}

for _n, _a in CONFIGS["rsa-client-auth"]["scripts"]:
    SKIP.setdefault(_n, "needs a client certificate: run in rsa-client-auth")

# Run with the arguments that fit this server, in `rsa` too.
ARGS = {
    # Go's limit on records that carry nothing, not OpenSSL's 4.
    "test-ssl-death-alert.py": ["--alerts", "16"],
}

SUMMARY = re.compile(r"^(TOTAL|SKIP|PASS|XFAIL|FAIL|XPASS):\s*(\d+)", re.M)


def wait_open(host, port, proc):
    t = time.time()
    while time.time() - t < 30:
        if proc.poll() is not None:
            sys.exit("the server exited")
        try:
            socket.create_connection((host, port), 1).close()
            return
        except OSError:
            time.sleep(0.1)
    sys.exit("the server did not start")


def failed_names(text):
    # Each script lists its failures after "Test end" as "\t'name'" lines
    # under a "FAIL" heading, or prints "... failed:" lines as it goes.
    names = []
    for m in re.finditer(r"^(.*?) \.\.\.\s*\n\s*(?:Error|Unexpected|FAIL)", text, re.M):
        names.append(m.group(1).strip())
    tail = text.split("Failed tests:", 1)
    if len(tail) == 2:
        for line in tail[1].splitlines()[1:]:
            line = line.strip()
            if not line or ":" in line and line.split(":")[0].isupper():
                break
            names.append(line.strip("'"))
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen


def run_one(args, tf, port, name, extra, logdir, tag, timeout):
    cmd = [args.python, os.path.join(tf, "scripts", name), "-h", "localhost", "-p", str(port), *extra]
    env = dict(os.environ, PYTHONPATH=tf)
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=tf, env=env, capture_output=True, text=True, timeout=timeout)
        code, text = r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        code = "timeout"
        text = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    secs = time.time() - t0
    log = os.path.join(logdir, f"{tag}.log")
    with open(log, "w") as f:
        f.write(" ".join(cmd) + "\n\n" + text)
    counts = {k: int(v) for k, v in SUMMARY.findall(text)}
    return {"script": name, "args": extra, "exit": code, "secs": round(secs, 1), "counts": counts,
            "failed": failed_names(text) if code != 0 else [], "log": os.path.basename(log)}


def run(args):
    tf = os.path.abspath(args.tlsfuzzer)
    os.makedirs(args.out, exist_ok=True)
    tmp = tempfile.mkdtemp()
    peer = args.peer or os.path.join(tmp, "peer")
    if not args.peer:
        build_peer(args.goose, peer)
    names = args.configs or list(CONFIGS)
    results = {}
    for ci, cname in enumerate(names):
        cfg = CONFIGS[cname]
        if cfg["scripts"] == "all":
            scripts = [(n, ARGS.get(n, [])) for n in sorted(os.listdir(os.path.join(tf, "scripts")))
                       if n.startswith("test-") and n.endswith(".py") and n not in SKIP]
        else:
            scripts = cfg["scripts"]
        if args.only:
            scripts = [s for s in scripts if args.only in s[0]]
        if not scripts:
            continue
        port = args.port + ci
        # A key the peer won't load fails every connection the same way:
        # the configuration is reported as unsupported, not run.
        probe = subprocess.run([peer, "server", os.path.join(tf, cfg["cert"]), os.path.join(tf, cfg["key"])],
                               input="", capture_output=True, text=True)
        if probe.returncode != 0:
            print(f"== {cname}: the server does not take {cfg['key']}: {probe.stderr.strip()[:200]}", flush=True)
            results[cname] = {"comment": cfg["comment"], "cert": cfg["cert"], "rows": [], "crashes": [],
                              "unsupported": probe.stderr.strip().splitlines()[0]}
            continue
        crash_log = os.path.join(args.out, f"{cname}.crashes.jsonl")
        if os.path.exists(crash_log):
            os.remove(crash_log)
        srv_cmd = [sys.executable, os.path.abspath(__file__), "server", "--peer", peer, "--port", str(port),
                   "--cert", os.path.join(tf, cfg["cert"]), "--key", os.path.join(tf, cfg["key"]),
                   "--crash-log", crash_log]
        if cfg.get("echo"):
            srv_cmd.append("--echo")
        for a in cfg.get("server_args", []):
            srv_cmd += ["--peer-arg", a]
        srv_log = open(os.path.join(args.out, f"{cname}.server.log"), "w")
        srv = subprocess.Popen(srv_cmd, stdout=srv_log, stderr=subprocess.STDOUT)
        try:
            wait_open("localhost", port, srv)
            logdir = os.path.join(args.out, cname)
            os.makedirs(logdir, exist_ok=True)
            print(f"== {cname}: {len(scripts)} scripts on port {port}", flush=True)
            with ThreadPoolExecutor(args.jobs) as ex:
                futs = []
                for i, (n, extra) in enumerate(scripts):
                    tag = n[:-3] + ("" if not extra else f".{i}")
                    futs.append(ex.submit(run_one, args, tf, port, n, extra, logdir, tag,
                                          cfg.get("timeout", args.timeout)))
                rows = []
                for f in futs:
                    r = f.result()
                    rows.append(r)
                    c = r["counts"]
                    print(f"  {r['script']} {' '.join(r['args'])}: exit {r['exit']} "
                          f"pass {c.get('PASS', '-')} fail {c.get('FAIL', '-')} ({r['secs']}s)", flush=True)
        finally:
            srv.terminate()
            srv.wait()
            srv_log.close()
        crashes = []
        if os.path.exists(crash_log):
            crashes = [json.loads(line) for line in open(crash_log)]
        results[cname] = {"comment": cfg["comment"], "cert": cfg["cert"], "rows": rows, "crashes": crashes}
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump(results, f, indent=1)
    with open(os.path.join(args.out, "results.md"), "w") as f:
        f.write(table(results))
    shutil.rmtree(tmp)
    print(f"results in {args.out}/results.md")


def table(results):
    lines = []
    for cname, res in results.items():
        lines.append(f"### {cname}: {res['comment']} (`{res['cert']}`)\n")
        if res.get("unsupported"):
            lines.append(f"Not run: the server does not load the key ({res['unsupported']}).\n")
            continue
        lines.append("| Script | Arguments | Result | Pass | Fail | Skip | XFail | Time (s) |")
        lines.append("|---|---|---|---:|---:|---:|---:|---:|")
        for r in res["rows"]:
            c = r["counts"]
            result = "pass" if r["exit"] == 0 else ("timeout" if r["exit"] == "timeout" else "FAIL")
            lines.append(f"| {r['script']} | {' '.join(r['args']) or '-'} | {result} | {c.get('PASS', '-')} | "
                         f"{c.get('FAIL', '-')} | {c.get('SKIP', '-')} | {c.get('XFAIL', '-')} | {r['secs']} |")
        lines.append(f"\nServer crashes: {len(res['crashes'])}\n")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--peer", help="a built tools/peer.goose (built if not given)")
    s.add_argument("--goose", default=default_goose())
    s.add_argument("--host", default="localhost")
    s.add_argument("--port", type=int, default=4433)
    s.add_argument("--cert", default=os.path.join(GOOSE_DIR, "tlsfuzzer.git", "tests", "serverX509Cert.pem"))
    s.add_argument("--key", default=os.path.join(GOOSE_DIR, "tlsfuzzer.git", "tests", "serverX509Key.pem"))
    s.add_argument("--echo", action="store_true", help="echo application data instead of answering HTTP")
    s.add_argument("--crash-log", default="", help="append each crash to this file, as JSON lines")
    s.add_argument("--peer-arg", action="append", default=[],
                   help='an option for each peer, as "--name value" (repeatable)')
    r = sub.add_parser("run")
    r.add_argument("--goose", default=default_goose())
    r.add_argument("--peer", help="a built tools/peer.goose to use instead of building one")
    r.add_argument("--tlsfuzzer", default=os.path.join(GOOSE_DIR, "tlsfuzzer.git"))
    r.add_argument("--python", default=os.path.join(GOOSE_DIR, ".venv-tlsfuzzer", "bin", "python"))
    r.add_argument("--out", default="tlsfuzzer-results")
    r.add_argument("--port", type=int, default=4433)
    r.add_argument("-j", "--jobs", type=int, default=4)
    r.add_argument("--timeout", type=int, default=900, help="seconds for each script")
    r.add_argument("--only", default="", help="only the scripts whose name has this")
    r.add_argument("configs", nargs="*", help=f"some of: {', '.join(CONFIGS)} (all)")
    args = ap.parse_args()
    if args.cmd == "server":
        if not args.peer:
            args.peer = os.path.join(tempfile.mkdtemp(), "peer")
            build_peer(args.goose, args.peer)
        serve(args)
    else:
        for c in args.configs:
            if c not in CONFIGS:
                sys.exit(f"no configuration {c}: {', '.join(CONFIGS)}")
        run(args)


if __name__ == "__main__":
    main()
