#!/usr/bin/env python3
"""Live TLS 1.3 and TLS 1.2 interop between this package and OpenSSL.

tools/peer.goose is built natively and run as a subprocess; Python's ssl
module (OpenSSL) is the other side, through memory BIOs, and this script
relays every byte between them. Each case runs in a child process whose
OPENSSL_CONF pins OpenSSL's suites and groups when the case needs it.

Cases: the Goose client against an OpenSSL server for each certificate
type (ML-DSA ones included), cipher suite and group, with a HelloRetryRequest, ALPN, and a
KeyUpdate; the Goose server against an OpenSSL client likewise (which
offers its post-quantum hybrid first and so takes X25519 or a retry);
resumption both ways (also after a HelloRetryRequest); client
certificates both ways (sent, missing, refused); roots from a directory;
and failures: an untrusted root, the system's
roots (which lack the test root), and a wrong host name. TLS 1.2 both
ways: every suite (ECDHE with each certificate type, RSA key exchange,
GCM, ChaCha20-Poly1305 and CBC), each group, version negotiation with an
OpenSSL that stops at either version, resumption with session tickets
(with and without the extended master secret), client certificates and
ALPN.

    python3 scripts/live_interop.py [--goose PATH]
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
VEC = os.path.join(ROOT, "test", "vectors")
SUITES = {"1301": "TLS_AES_128_GCM_SHA256", "1302": "TLS_AES_256_GCM_SHA384",
          "1303": "TLS_CHACHA20_POLY1305_SHA256"}
GROUPS = {"001d": "X25519", "0017": "P-256", "0018": "P-384", "0019": "P-521", "11ec": "X25519MLKEM768",
          "11eb": "SecP256r1MLKEM768", "11ed": "SecP384r1MLKEM1024", "0202": "MLKEM1024"}


class Peer:
    def __init__(self, exe, args):
        self.p = subprocess.Popen([exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.state = None
        self.session = None
        self.retry = None

    def read(self):
        out, app = b"", b""
        while True:
            line = self.p.stdout.readline().strip()
            if not line:
                raise RuntimeError("peer exited")
            if line == "END":
                return out, app
            kind, _, rest = line.partition(" ")
            if kind == "OUT":
                out += bytes.fromhex(rest)
            elif kind == "APP":
                app += bytes.fromhex(rest)
            elif kind == "SESSION":
                self.session = None if rest == "-" else rest
            elif kind == "STATE":
                st, alert, alpn, group, resumed, peer, verified, ech, version, suite = rest.split()
                self.state = (int(st), int(alert), alpn, int(group), resumed == "1", int(peer), verified == "1",
                              ech == "1", version, suite)
            elif kind == "RETRY":
                self.retry = rest

    def cmd(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.read()

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def handshake(peer, obj, inc, outg, goose_is_client):
    """Relays until both sides are done; whether they connected."""
    import ssl
    if goose_is_client:
        out, app = peer.read()
        inc.write(out)
    done = False
    for _ in range(30):
        try:
            obj.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            pass
        data = outg.read()
        if data:
            out, app = peer.cmd("IN " + data.hex())
            if out:
                inc.write(out)
        elif done and peer.state[0] == 20:
            break
        elif peer.state[0] in (21, 22):
            break
    return done and peer.state[0] == 20


def exchange(peer, obj, inc, outg):
    """Data both ways, which also delivers the session tickets."""
    import ssl
    out, _ = peer.cmd("SEND " + b"ping".hex())
    inc.write(out)
    got = obj.read(100)
    obj.write(b"pong")
    data = outg.read()
    _, app = peer.cmd("IN " + data.hex())
    if app != b"pong":       # OpenSSL's tickets may come first, in their own records
        while not app.endswith(b"pong"):
            _, more = peer.cmd("IN ")
            app += more
            if not more:
                break
    return got == b"ping" and app.endswith(b"pong")


PY_VERSIONS = {"1.2": "TLSv1_2", "1.3": "TLSv1_3"}


def set_versions(ctx, case):
    """OpenSSL's versions (TLS 1.3 only unless the case says) and suites."""
    import ssl
    lo, hi = case.get("py_versions", ("1.3", "1.3"))
    ctx.minimum_version = getattr(ssl.TLSVersion, PY_VERSIONS[lo])
    ctx.maximum_version = getattr(ssl.TLSVersion, PY_VERSIONS[hi])
    if case.get("py_ciphers"):
        ctx.set_ciphers(case["py_ciphers"])


def run_resume_case(case):
    """In the child: two connections, the second resuming the first's session."""
    import ssl
    exe = case["exe"]
    goose_is_client = case["role"] == "client"
    if goose_is_client:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(VEC, f"hs_{case['cert']}.pem"), os.path.join(VEC, f"hs_{case['cert']}.key"))
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(os.path.join(VEC, "hs_root.pem"))
    set_versions(ctx, case)
    key = os.urandom(32).hex()
    session, py_session = None, None
    result = {"ok": False, "resumed": []}
    for round in range(2):
        inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
        if goose_is_client:
            obj = ctx.wrap_bio(inc, outg, server_side=True)
            args = ["client", "example.com", os.path.join(VEC, "hs_root.pem")]
            if session:
                args += ["--session", session]
        else:
            obj = ctx.wrap_bio(inc, outg, server_side=False, server_hostname="example.com", session=py_session)
            args = ["server", os.path.join(VEC, f"hs_{case['cert']}.pem"), os.path.join(VEC, f"hs_{case['cert']}.key"),
                    "--ticket-key", key]
        for g in case.get("goose_groups", []):
            args += ["--group", g]
        args += case.get("goose_args", [])
        peer = Peer(exe, args)
        if not handshake(peer, obj, inc, outg, goose_is_client) or not exchange(peer, obj, inc, outg):
            result["state"] = peer.state
            peer.close()
            return result
        result["resumed"].append([peer.state[4], obj.session_reused])
        result["goose_state"] = peer.state
        peer.cmd("SESSION")
        session = peer.session
        py_session = obj.session
        peer.close()
    result["ok"] = result["resumed"] == [[False, False], [True, True]]
    return result


def run_case(case):
    """In the child: one connection, returns a result dict."""
    import ssl
    if case.get("resume"):
        return run_resume_case(case)
    exe = case["exe"]
    goose_is_client = case["role"] == "client"
    if goose_is_client:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(VEC, f"hs_{case['cert']}.pem"), os.path.join(VEC, f"hs_{case['cert']}.key"))
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(os.path.join(VEC, "hs_root.pem"))
    set_versions(ctx, case)
    if case.get("alpn"):
        ctx.set_alpn_protocols(case["alpn"])
    # Client certificates: OpenSSL's server asks for one (required or
    # optional), or OpenSSL's client has one.
    if case.get("py_verify"):
        ctx.verify_mode = ssl.CERT_REQUIRED if case["py_verify"] == "required" else ssl.CERT_OPTIONAL
        ctx.load_verify_locations(os.path.join(VEC, "hs_clientca.pem"))
    if case.get("py_cert"):
        ctx.load_cert_chain(os.path.join(VEC, f"hs_{case['py_cert']}.pem"), os.path.join(VEC, f"hs_{case['py_cert']}.key"))
    inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, outg, server_side=goose_is_client,
                       server_hostname=None if goose_is_client else case.get("host", "example.com"))
    if goose_is_client:
        args = ["client", case.get("host", "example.com"), case.get("roots", os.path.join(VEC, "hs_root.pem"))]
    else:
        args = ["server", os.path.join(VEC, f"hs_{case['cert']}.pem"), os.path.join(VEC, f"hs_{case['cert']}.key")]
    for s in case.get("goose_suites", []):
        args += ["--suite", s]
    for g in case.get("goose_groups", []):
        args += ["--group", g]
    for a in case.get("goose_alpn", []):
        args += ["--alpn", a]
    if case.get("goose_cert"):
        args += ["--cert", os.path.join(VEC, f"hs_{case['goose_cert']}.pem"),
                 "--key", os.path.join(VEC, f"hs_{case['goose_cert']}.key")]
    if case.get("goose_client_auth") is not None:
        args += ["--client-auth", str(case["goose_client_auth"]), "--client-cas", os.path.join(VEC, "hs_clientca.pem")]
    args += case.get("goose_args", [])
    peer = Peer(exe, args)
    to_goose = b""
    result = {"ok": False}
    if goose_is_client:
        out, app = peer.read()
        inc.write(out)
    done = False
    for _ in range(30):
        try:
            obj.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as e:
            result["openssl_error"] = str(e)
        data = outg.read()
        if data:
            out, app = peer.cmd("IN " + data.hex())
            if out:
                inc.write(out)
        elif done and peer.state[0] == 20:
            break
        elif not data and not done:
            if peer.state[0] in (21, 22):
                break
    result["goose_state"] = peer.state
    if not (done and peer.state[0] == 20):
        peer.close()
        return result
    result["suite"] = obj.cipher()[0]
    result["version"] = obj.version()
    result["alpn"] = obj.selected_alpn_protocol()
    if goose_is_client:
        # The certificate OpenSSL's server got from this client, if any.
        der = obj.getpeercert(binary_form=True)
        result["openssl_peer"] = der.hex() if der else None
    # Goose -> OpenSSL, after a KeyUpdate that asks OpenSSL to update too.
    out, _ = peer.cmd("KEYUPDATE")
    inc.write(out)
    msg = os.urandom(30000)
    out, _ = peer.cmd("SEND " + msg.hex())
    inc.write(out)
    got = b""
    while len(got) < len(msg):
        got += obj.read(65536)
    result["to_openssl"] = got == msg
    # OpenSSL -> Goose, under OpenSSL's updated keys.
    reply = b"reply from openssl " + os.urandom(100)
    obj.write(reply)
    _, app = peer.cmd("IN " + outg.read().hex())
    result["to_goose"] = app == reply
    out, _ = peer.cmd("CLOSE")
    inc.write(out)
    # A close_notify reads as end of data: b"" or SSLZeroReturnError.
    try:
        tail = obj.read(10)
        result["close"] = tail == b""
        result["close_read"] = tail.hex()
    except ssl.SSLZeroReturnError:
        result["close"] = True
    result["ok"] = result["to_openssl"] and result["to_goose"] and result["close"]
    peer.close()
    return result


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        print(json.dumps(run_case(json.loads(sys.argv[2]))))
        return
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    tmp = tempfile.mkdtemp()
    exe = os.path.join(tmp, "peer")
    subprocess.run([goose, "build", "-o", exe, os.path.join(ROOT, "tools", "peer.goose")], check=True,
                   capture_output=True)
    cases = []
    for cert in ("ed25519", "p256", "p384", "p521", "rsa"):
        for s, g in (("1301", "001d"), ("1302", "0017"), ("1303", "0018"), ("1301", "0019")):
            cases.append(dict(name=f"goose client, {cert} server, {SUITES[s]}, {GROUPS[g]}", role="client",
                              cert=cert, goose_suites=[s], goose_groups=[g], want=True, suite=SUITES[s]))
            cases.append(dict(name=f"goose {cert} server, {SUITES[s]}, {GROUPS[g]}", role="server",
                              cert=cert, goose_suites=[s], goose_groups=[g], want=True, suite=SUITES[s]))
    cases += [
        dict(name="goose client, defaults: X25519MLKEM768", role="client", cert="p256", want=True, want_group=0x11ec),
        dict(name="goose server, defaults: X25519MLKEM768", role="server", cert="ed25519", want=True, want_group=0x11ec),
        dict(name="goose client, X25519MLKEM768 only", role="client", cert="rsa", goose_groups=["11ec"], want=True,
             want_group=0x11ec),
        dict(name="goose server, X25519MLKEM768 only", role="server", cert="p384", goose_groups=["11ec"], want=True,
             want_group=0x11ec),
        dict(name="goose client, HelloRetryRequest to X25519MLKEM768", role="client", cert="p256",
             goose_groups=["0017", "11ec"], openssl_groups="X25519MLKEM768", want=True, want_group=0x11ec),
        dict(name="goose client, OpenSSL without ML-KEM takes the X25519 share", role="client", cert="p256",
             openssl_groups="X25519:P-256", want=True, want_group=0x001d),
        dict(name="goose client, HelloRetryRequest to P-384", role="client", cert="p256",
             goose_groups=["001d", "0018"], openssl_groups="P-384", want=True),
        dict(name="goose server, HelloRetryRequest from OpenSSL's shares", role="server", cert="p256",
             goose_groups=["0018"], want=True),
    ]
    for g in ("11eb", "11ed", "0202"):
        cases.append(dict(name=f"goose client, {GROUPS[g]}", role="client", cert="p384", goose_groups=[g],
                          openssl_groups=GROUPS[g], want=True, want_group=int(g, 16)))
        cases.append(dict(name=f"goose server, {GROUPS[g]}", role="server", cert="rsa", goose_groups=[g],
                          openssl_groups=GROUPS[g], want=True, want_group=int(g, 16)))
    for cert in ("mldsa44", "mldsa65", "mldsa87"):
        cases.append(dict(name=f"goose client, {cert} server", role="client", cert=cert, want=True))
        cases.append(dict(name=f"goose {cert} server", role="server", cert=cert, want=True))
    cases += [
        dict(name="goose client, HelloRetryRequest to SecP384r1MLKEM1024", role="client", cert="p256",
             openssl_groups="SecP384r1MLKEM1024", want=True, want_group=0x11ed),
        dict(name="goose client, OpenSSL without ML-KEM takes the P-256 share", role="client", cert="ed25519",
             goose_groups=["11eb", "0017"], openssl_groups="P-256", want=True, want_group=0x0017),
        dict(name="goose client, ALPN", role="client", cert="ed25519", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1"], want=True, want_alpn="http/1.1"),
        dict(name="goose server, ALPN", role="server", cert="rsa", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1", "h2"], want=True, want_alpn="h2"),
        dict(name="goose client, wrong host name", role="client", cert="p256", host="other.org", want=False,
             goose_alert=42),
        dict(name="goose client, untrusted root", role="client", cert="p256",
             roots=os.path.join(VEC, "hs_p384.pem"), want=False, goose_alert=48),
        dict(name="goose client resumes with OpenSSL's ticket", role="client", cert="p256", resume=True, want=True),
        dict(name="OpenSSL client resumes with this server's ticket", role="server", cert="ed25519", resume=True,
             want=True),
        dict(name="goose client resumes after a HelloRetryRequest", role="client", cert="rsa", resume=True,
             goose_groups=["0018", "001d"], openssl_groups="X25519", want=True),
        dict(name="OpenSSL client resumes after a HelloRetryRequest", role="server", cert="p384", resume=True,
             goose_groups=["0019"], want=True),
        dict(name="goose client, roots from a directory", role="client", cert="mldsa65", roots=VEC, want=True),
        dict(name="goose client, system roots (no test root)", role="client", cert="p256", roots="system",
             want=False, goose_alert=48),
        dict(name="goose server, OpenSSL client checks the name", role="server", cert="p256",
             host="other.org", want=False),
    ]
    # Client certificates: this client's, to an OpenSSL server that
    # requires one (each key type) or would take one; none where one is
    # required; and OpenSSL's client's, to this server in each mode.
    for kind in ("client_p256", "client_ed25519", "client_mldsa44"):
        cases.append(dict(name=f"goose client sends a certificate ({kind[7:]})", role="client", cert="p256",
                          goose_cert=kind, py_verify="required", want=True, want_openssl_peer=kind))
    cases += [
        dict(name="goose client, optional certificate, none", role="client", cert="rsa", py_verify="optional",
             want=True, want_openssl_peer=None),
        dict(name="goose client without a certificate, one required", role="client", cert="p256",
             py_verify="required", want=False, goose_alert=116),
        dict(name="goose client, certificate OpenSSL refuses (server use only)", role="client", cert="p256",
             goose_cert="client_serveronly", py_verify="required", want=False),
        dict(name="goose server requires and checks: OpenSSL client's P-256", role="server", cert="ed25519",
             py_cert="client_p256", goose_client_auth=4, want=True, want_peer=True, want_verified=True),
        dict(name="goose server requires and checks: OpenSSL client's ML-DSA-44", role="server", cert="mldsa65",
             py_cert="client_mldsa44", goose_client_auth=4, want=True, want_peer=True, want_verified=True),
        dict(name="goose server requires a certificate, OpenSSL client has none", role="server", cert="p256",
             goose_client_auth=4, want=False, goose_alert=116),
        dict(name="goose server checks if given, OpenSSL client has none", role="server", cert="p256",
             goose_client_auth=3, want=True, want_peer=False, want_verified=False),
        dict(name="goose server refuses a server-only certificate", role="server", cert="p256",
             py_cert="client_serveronly", goose_client_auth=3, want=False, goose_alert=42),
        dict(name="goose server refuses a certificate of another CA", role="server", cert="p256",
             py_cert="p384", goose_client_auth=4, want=False, goose_alert=48),
        dict(name="goose server requests: another CA's certificate, unchecked", role="server", cert="rsa",
             py_cert="p384", goose_client_auth=1, want=True, want_peer=True, want_verified=False),
    ]
    # TLS 1.2: OpenSSL takes TLS 1.2 only; every suite, both ways.
    tls12 = dict(py_versions=("1.2", "1.2"), want_version="0303")
    ec12 = [("c02b", "ECDHE-ECDSA-AES128-GCM-SHA256"), ("c02c", "ECDHE-ECDSA-AES256-GCM-SHA384"),
            ("cca9", "ECDHE-ECDSA-CHACHA20-POLY1305"), ("c009", "ECDHE-ECDSA-AES128-SHA"),
            ("c00a", "ECDHE-ECDSA-AES256-SHA"), ("c023", "ECDHE-ECDSA-AES128-SHA256")]
    rsa12 = [("c02f", "ECDHE-RSA-AES128-GCM-SHA256"), ("c030", "ECDHE-RSA-AES256-GCM-SHA384"),
             ("cca8", "ECDHE-RSA-CHACHA20-POLY1305"), ("c013", "ECDHE-RSA-AES128-SHA"),
             ("c014", "ECDHE-RSA-AES256-SHA"), ("c027", "ECDHE-RSA-AES128-SHA256"),
             ("009c", "AES128-GCM-SHA256"), ("009d", "AES256-GCM-SHA384"), ("002f", "AES128-SHA"),
             ("0035", "AES256-SHA"), ("003c", "AES128-SHA256")]
    groups12 = ["001d", "0017", "0018", "0019"]
    n = 0
    for certs, suites in ((("ed25519", "p256", "p384", "p521"), ec12), (("rsa",), rsa12)):
        for cert in certs:
            for sid, name in suites:
                g = groups12[n % 4]
                n += 1
                # In TLS 1.2 the client's groups also limit the curve of an
                # ECDSA certificate (RFC 8422 §5.1.1), so the client lists it
                # after the group under test.
                curve = {"p256": "0017", "p384": "0018", "p521": "0019"}.get(cert, g)
                for role in ("client", "server"):
                    who = f"goose client, {cert} server" if role == "client" else f"goose {cert} server"
                    groups = [g] if role == "server" or curve == g else [g, curve]
                    # The group is the one under test unless OpenSSL's server
                    # had two to pick from; RSA key exchange has none.
                    want_group = int(g, 16) if len(groups) == 1 and not name.startswith("AES") else None
                    cases.append(dict(tls12, name=f"TLS 1.2 {who}, {name}, {GROUPS[g]}", role=role, cert=cert,
                                      goose_suites=[sid], goose_groups=groups, py_ciphers=name + ":@SECLEVEL=0",
                                      want=True, suite=name, want_group=want_group))
    cases += [
        # Versions: OpenSSL stops at TLS 1.2 against this side's defaults,
        # or this side stops at TLS 1.2 against OpenSSL's 1.2 and 1.3.
        dict(name="goose client (1.2 and 1.3), OpenSSL server stops at 1.2", role="client", cert="p256",
             py_versions=("1.2", "1.2"), want=True, want_version="0303"),
        dict(name="goose server (1.2 and 1.3), OpenSSL client stops at 1.2", role="server", cert="rsa",
             py_versions=("1.2", "1.2"), want=True, want_version="0303"),
        dict(name="goose server stops at 1.2, OpenSSL client takes 1.3 too", role="server", cert="ed25519",
             py_versions=("1.2", "1.3"), goose_args=["--max-version", "0303"], want=True, want_version="0303"),
        dict(name="goose client stops at 1.2, OpenSSL server takes 1.3 too", role="client", cert="p384",
             py_versions=("1.2", "1.3"), goose_args=["--max-version", "0303"], want=True, want_version="0303"),
        dict(name="goose client and OpenSSL server, both versions: 1.3", role="client", cert="rsa",
             py_versions=("1.2", "1.3"), want=True, want_version="0304"),
        dict(name="goose server stops at 1.2, OpenSSL client wants 1.3", role="server", cert="p256",
             goose_args=["--max-version", "0303"], want=False, goose_alert=70),
        dict(name="goose client wants 1.3, OpenSSL server stops at 1.2", role="client", cert="p256",
             py_versions=("1.2", "1.2"), goose_args=["--min-version", "0304"], want=False, goose_alert=70),
        # Resumption with session tickets, and without the extended master
        # secret.
        dict(tls12, name="TLS 1.2 goose client resumes with OpenSSL's ticket", role="client", cert="p256", resume=True,
             want=True),
        dict(tls12, name="TLS 1.2 OpenSSL client resumes with this server's ticket", role="server", cert="rsa",
             resume=True, want=True),
        dict(tls12, name="TLS 1.2 goose client resumes, no extended master secret", role="client", cert="ed25519",
             resume=True, openssl_options="-ExtendedMasterSecret", want=True),
        dict(tls12, name="TLS 1.2 OpenSSL client resumes, no extended master secret", role="server", cert="p384",
             resume=True, openssl_options="-ExtendedMasterSecret", want=True),
        dict(tls12, name="TLS 1.2 goose client, no extended master secret", role="client", cert="rsa",
             openssl_options="-ExtendedMasterSecret", want=True),
        dict(tls12, name="TLS 1.2 goose server, no extended master secret", role="server", cert="p256",
             openssl_options="-ExtendedMasterSecret", want=True),
        dict(tls12, name="TLS 1.2 goose client, ALPN", role="client", cert="p256", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1"], want=True, want_alpn="http/1.1"),
        dict(tls12, name="TLS 1.2 goose server, ALPN", role="server", cert="rsa", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1", "h2"], want=True, want_alpn="h2"),
        dict(tls12, name="TLS 1.2 goose client, wrong host name", role="client", cert="p256", host="other.org",
             want=False, goose_alert=42),
    ]
    for kind in ("client_p256", "client_ed25519"):
        cases.append(dict(tls12, name=f"TLS 1.2 goose client sends a certificate ({kind[7:]})", role="client",
                          cert="rsa", goose_cert=kind, py_verify="required", want=True, want_openssl_peer=kind))
        cases.append(dict(tls12, name=f"TLS 1.2 goose server requires and checks: OpenSSL client's {kind[7:]}",
                          role="server", cert="p256", py_cert=kind, goose_client_auth=4, want=True, want_peer=True,
                          want_verified=True))
    cases += [
        dict(tls12, name="TLS 1.2 goose client without a certificate, one required", role="client", cert="p256",
             py_verify="required", want=False),
        dict(tls12, name="TLS 1.2 goose server requires a certificate, OpenSSL client has none", role="server",
             cert="p256", goose_client_auth=4, want=False, goose_alert=42),
        dict(tls12, name="TLS 1.2 goose server checks if given, OpenSSL client has none", role="server", cert="rsa",
             goose_client_auth=3, want=True, want_peer=False, want_verified=False),
    ]
    passed = 0
    for case in cases:
        case["exe"] = exe
        env = dict(os.environ)
        conf_lines = []
        if case.get("openssl_groups"):
            conf_lines.append(f"Groups = {case['openssl_groups']}")
        if case.get("openssl_options"):
            conf_lines.append(f"Options = {case['openssl_options']}")
        if conf_lines:
            conf = os.path.join(tmp, "openssl.cnf")
            with open(conf, "w") as f:
                f.write("openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = tls\n[tls]\n"
                        + "\n".join(conf_lines) + "\n")
            env["OPENSSL_CONF"] = conf
        p = subprocess.run([sys.executable, "-I", __file__, "--child", json.dumps(case)], env=env,
                           capture_output=True, text=True)
        try:
            r = json.loads(p.stdout.strip().splitlines()[-1])
        except Exception:
            r = {"ok": False, "crash": p.stderr[-2000:]}
        good = r["ok"] == case["want"]
        if good and case.get("suite"):
            good = r.get("suite") == case["suite"]
        if good and case.get("want_alpn"):
            good = r.get("alpn") == case["want_alpn"]
        if good and case.get("want_group"):
            good = r.get("goose_state", [0, 0, 0, 0])[3] == case["want_group"]
        if good and case.get("want_version"):
            good = r.get("goose_state", [0] * 10)[8] == case["want_version"]
        if good and case.get("goose_alert"):
            good = r.get("goose_state", [0, 0])[1] == case["goose_alert"]
        if good and "want_peer" in case:
            good = (r["goose_state"][5] > 0) == case["want_peer"] and r["goose_state"][6] == case["want_verified"]
        if good and "want_openssl_peer" in case:
            want = case["want_openssl_peer"]
            if want:
                want = subprocess.run(["openssl", "x509", "-in", os.path.join(VEC, f"hs_{want}.pem"), "-outform", "DER"],
                                      capture_output=True, check=True).stdout.hex()
            good = r.get("openssl_peer") == want
        print(("ok    " if good else "FAIL  ") + case["name"] + ("" if good else f"  {r}"))
        passed += good
    shutil.rmtree(tmp)
    print(f"\n{passed} passed, {len(cases) - passed} failed")
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
