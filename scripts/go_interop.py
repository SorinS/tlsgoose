#!/usr/bin/env python3
"""Live TLS 1.3 against Go's crypto/tls (scripts/gointerop), over sockets
on 127.0.0.1, with resumption: this package's client (tools/peer.goose)
connects twice to a Go server, the second time with the session from the
first one's ticket; then a Go client with a session cache connects twice to
this package's server (one ticket key for both connections). Each side must
report the first connection full and the second resumed, and data must
cross both ways.

    python3 scripts/go_interop.py [--goose PATH]
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from live_interop import Peer, ROOT, VEC  # noqa: E402

GO = os.path.join(ROOT, "scripts", "gointerop")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def relay_until(peer, sock, done):
    """Moves bytes between the peer and the socket until done() holds."""
    app = b""
    for _ in range(50):
        if done(app):
            break
        data = sock.recv(65536)
        if not data:
            break
        out, got = peer.cmd("IN " + data.hex())
        app += got
        if out:
            sock.sendall(out)
    return app


def goose_client_go_server(exe, gobin):
    port = free_port()
    srv = subprocess.Popen([gobin, "server", os.path.join(VEC, "hs_p256.pem"), os.path.join(VEC, "hs_p256.key"),
                            str(port)], stdout=subprocess.PIPE, text=True)
    assert srv.stdout.readline().strip() == "ready"
    session, results = None, []
    try:
        for i in range(2):
            args = ["client", "example.com", os.path.join(VEC, "hs_root.pem")]
            if session:
                args += ["--session", session]
            peer = Peer(exe, args)
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            out, _ = peer.read()
            sock.sendall(out)
            relay_until(peer, sock, lambda app: peer.state[0] >= 20)
            if peer.state[0] != 20:
                return False, f"connection {i}: state {peer.state}"
            out, _ = peer.cmd("SEND " + f"hello {i}\n".encode().hex())
            sock.sendall(out)
            reply = relay_until(peer, sock, lambda app: b"resumed=" in app)
            # Go sends its ticket with the handshake's last flight; it is
            # in by now.
            peer.cmd("SESSION")
            session = peer.session
            results.append((peer.state[4], reply.decode()))
            sock.close()
            peer.close()
    finally:
        srv.kill()
    want = [(False, "echo hello 0 resumed=false"), (True, "echo hello 1 resumed=true")]
    return results == want, results


def go_client_goose_server(exe, gobin):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)
    port = ls.getsockname()[1]
    cli = subprocess.Popen([gobin, "client", str(port), os.path.join(VEC, "hs_root.pem"), "2"],
                           stdout=subprocess.PIPE, text=True)
    key = os.urandom(32).hex()
    ours = []
    for i in range(2):
        sock, _ = ls.accept()
        sock.settimeout(10)
        peer = Peer(exe, ["server", os.path.join(VEC, "hs_ed25519.pem"), os.path.join(VEC, "hs_ed25519.key"),
                          "--ticket-key", key])
        app = b""
        for _ in range(50):
            data = sock.recv(65536)
            if not data:
                break
            out, got = peer.cmd("IN " + data.hex())
            if out:
                sock.sendall(out)
            app += got
            if app.endswith(b"\n"):
                resumed = peer.state[4]
                out, _ = peer.cmd("SEND " + f"echo {app[:-1].decode()} resumed={str(resumed).lower()}".encode().hex())
                sock.sendall(out)
                ours.append(resumed)
                break
        out, _ = peer.cmd("CLOSE")
        try:
            sock.sendall(out)
        except OSError:
            pass
        sock.close()
        peer.close()
    lines = cli.communicate(timeout=30)[0].splitlines()
    ls.close()
    go = [("resumed=true" in l) for l in lines]
    ok = ours == [False, True] and go == [False, True] and all("reply=\"echo hello" in l for l in lines)
    return ok, lines


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    tmp = tempfile.mkdtemp()
    exe = os.path.join(tmp, "peer")
    gobin = os.path.join(tmp, "gointerop")
    subprocess.run([goose, "build", "-o", exe, os.path.join(ROOT, "tools", "peer.goose")], check=True,
                   capture_output=True)
    subprocess.run(["go", "build", "-o", gobin, "."], cwd=GO, check=True,
                   env={**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off"})
    passed = 0
    cases = [("goose client resumes with a Go server's ticket", goose_client_go_server),
             ("Go client resumes with this server's ticket", go_client_goose_server)]
    for label, fn in cases:
        ok, detail = fn(exe, gobin)
        print(("ok    " if ok else "FAIL  ") + label + ("" if ok else f"\n      {detail}"))
        passed += ok
    shutil.rmtree(tmp)
    print(f"\n{passed} passed, {len(cases) - passed} failed")
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
