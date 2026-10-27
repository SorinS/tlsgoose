#!/usr/bin/env python3
"""Live TLS 1.3 against Go's crypto/tls (scripts/gointerop), over sockets
on 127.0.0.1, with resumption: this package's client (tools/peer.goose)
connects twice to a Go server, the second time with the session from the
first one's ticket; then a Go client with a session cache connects twice to
this package's server (one ticket key for both connections). Each side must
report the first connection full and the second resumed, and data must
cross both ways. Then the same with client certificates, which each
server requires and checks, carried over by resumption. Then Encrypted
Client Hello both ways, for "localhost" behind the public name
"example.com": accepted with several KEMs and after a HelloRetryRequest,
and refused with another key, the client getting the server's retry
configs.

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


def goose_client_go_server(exe, gobin, client_cert=False):
    port = free_port()
    extra = [os.path.join(VEC, "hs_clientca.pem")] if client_cert else []
    srv = subprocess.Popen([gobin, "server", os.path.join(VEC, "hs_p256.pem"), os.path.join(VEC, "hs_p256.key"),
                            str(port), *extra], stdout=subprocess.PIPE, text=True)
    assert srv.stdout.readline().strip() == "ready"
    session, results = None, []
    try:
        for i in range(2):
            args = ["client", "example.com", os.path.join(VEC, "hs_root.pem")]
            if session:
                args += ["--session", session]
            if client_cert:
                args += ["--cert", os.path.join(VEC, "hs_client_ed25519.pem"),
                         "--key", os.path.join(VEC, "hs_client_ed25519.key")]
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
    client = "goose client ed25519" if client_cert else "-"
    want = [(False, f"echo hello 0 resumed=false client={client}"), (True, f"echo hello 1 resumed=true client={client}")]
    return results == want, results


def go_client_goose_server(exe, gobin, client_cert=False):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)
    port = ls.getsockname()[1]
    extra = [os.path.join(VEC, "hs_client_p256.pem"), os.path.join(VEC, "hs_client_p256.key")] if client_cert else []
    cli = subprocess.Popen([gobin, "client", str(port), os.path.join(VEC, "hs_root.pem"), "2", *extra],
                           stdout=subprocess.PIPE, text=True)
    key = os.urandom(32).hex()
    ours = []
    for i in range(2):
        sock, _ = ls.accept()
        sock.settimeout(10)
        args = ["server", os.path.join(VEC, "hs_ed25519.pem"), os.path.join(VEC, "hs_ed25519.key"), "--ticket-key", key]
        if client_cert:
            args += ["--client-auth", "4", "--client-cas", os.path.join(VEC, "hs_clientca.pem")]
        peer = Peer(exe, args)
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
                # With client certificates, this server must hold a checked one.
                if client_cert and not (peer.state[5] > 0 and peer.state[6]):
                    resumed = None
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


def echkey(exe, kem):
    out = subprocess.run([exe, "echkey", kem, "example.com"], capture_output=True, text=True, check=True).stdout
    vals = dict(line.split(" ", 1) for line in out.splitlines())
    return vals["CONFIG"], vals["KEY"]


def config_list(config):
    return f"{len(config) // 2:04x}" + config


def goose_client_ech(exe, gobin, kem, groups=(), reject=False, want_group=None):
    """This client offers ECH to a Go server; accepted, or refused with retry configs."""
    config, sk = echkey(exe, kem)
    server_config, server_sk = echkey(exe, kem) if reject else (config, sk)
    port = free_port()
    srv = subprocess.Popen([gobin, "ech-server", os.path.join(VEC, "hs_p256.pem"), os.path.join(VEC, "hs_p256.key"),
                            str(port), server_config, server_sk], stdout=subprocess.PIPE, text=True)
    assert srv.stdout.readline().strip() == "ready"
    try:
        args = ["client", "localhost", os.path.join(VEC, "hs_root.pem"), "--ech", config_list(config)]
        for g in groups:
            args += ["--group", g]
        peer = Peer(exe, args)
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        out, _ = peer.read()
        sock.sendall(out)
        relay_until(peer, sock, lambda app: peer.state[0] >= 20)
        if reject:
            ok = peer.state[1] == 121 and not peer.state[7] and peer.retry == config_list(server_config)
            detail = (peer.state, peer.retry)
        else:
            out, _ = peer.cmd("SEND " + b"hello\n".hex())
            sock.sendall(out)
            reply = relay_until(peer, sock, lambda app: b"sni=" in app)
            ok = peer.state[0] in (20, 21) and peer.state[7] and reply == b"echo hello ech=true sni=localhost"
            if want_group:
                ok = ok and peer.state[3] == want_group
            detail = (peer.state, reply)
        sock.close()
        peer.close()
    finally:
        srv.kill()
    return ok, detail


def go_client_ech(exe, gobin, kem, groups=(), reject=False, want_group=None):
    """A Go client offers ECH to this server; accepted, or refused with retry configs."""
    config, sk = echkey(exe, kem)
    server_config, server_sk = echkey(exe, kem) if reject else (config, sk)
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    cli = subprocess.Popen([gobin, "ech-client", str(port), os.path.join(VEC, "hs_root.pem"), "localhost",
                            config_list(config)], stdout=subprocess.PIPE, text=True)
    sock, _ = ls.accept()
    sock.settimeout(10)
    args = ["server", os.path.join(VEC, "hs_p256.pem"), os.path.join(VEC, "hs_p256.key"),
            "--ech-key", f"{server_config}:{server_sk}"]
    for g in groups:
        args += ["--group", g]
    peer = Peer(exe, args)
    app = b""
    for _ in range(50):
        try:
            data = sock.recv(65536)
        except OSError:
            break
        if not data:
            break
        out, got = peer.cmd("IN " + data.hex())
        if out:
            sock.sendall(out)
        app += got
        if app.endswith(b"\n"):
            out, _ = peer.cmd("SEND " + f"echo ech={str(peer.state[7]).lower()}".encode().hex())
            sock.sendall(out)
            break
        if peer.state[0] >= 21:
            break
    state = peer.state
    sock.close()
    peer.close()
    line = cli.communicate(timeout=30)[0].strip()
    ls.close()
    if reject:
        return line == f"rejected retry={config_list(server_config)}" and not state[7], (line, state)
    ok = line == 'ech=true reply="echo ech=true"' and state[7]
    return ok and (not want_group or state[3] == want_group), (line, state)


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
    cases = [("goose client resumes with a Go server's ticket", goose_client_go_server, False),
             ("Go client resumes with this server's ticket", go_client_goose_server, False),
             ("goose client's certificate to a Go server, resumed", goose_client_go_server, True),
             ("Go client's certificate to this server, resumed", go_client_goose_server, True)]
    for kem, name in (("0020", "X25519"), ("0010", "P-256"), ("647a", "MLKEM768-X25519"), ("0042", "ML-KEM-1024")):
        cases.append((f"goose client, ECH to a Go server ({name})", lambda e, g, k=kem: goose_client_ech(e, g, k), None))
        cases.append((f"Go client, ECH to this server ({name})", lambda e, g, k=kem: go_client_ech(e, g, k), None))
    cases += [
        ("goose client, ECH after a HelloRetryRequest",
         lambda e, g: goose_client_ech(e, g, "0020", groups=("0018", "11ec"), want_group=0x11ec), None),
        ("Go client, ECH after a HelloRetryRequest",
         lambda e, g: go_client_ech(e, g, "0020", groups=("0019",), want_group=0x0019), None),
        ("goose client, ECH refused: Go's retry configs", lambda e, g: goose_client_ech(e, g, "0020", reject=True), None),
        ("Go client, ECH refused: this server's retry configs",
         lambda e, g: go_client_ech(e, g, "0020", reject=True), None),
    ]
    for label, fn, cc in cases:
        ok, detail = fn(exe, gobin, cc) if cc is not None else fn(exe, gobin)
        print(("ok    " if ok else "FAIL  ") + label + ("" if ok else f"\n      {detail}"))
        passed += ok
    shutil.rmtree(tmp)
    print(f"\n{passed} passed, {len(cases) - passed} failed")
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
