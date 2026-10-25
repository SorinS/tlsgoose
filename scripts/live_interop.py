#!/usr/bin/env python3
"""Live TLS 1.3 interop between this package and OpenSSL.

tools/peer.goose is built natively and run as a subprocess; Python's ssl
module (OpenSSL) is the other side, through memory BIOs, and this script
relays every byte between them. Each case runs in a child process whose
OPENSSL_CONF pins OpenSSL's suites and groups when the case needs it.

Cases: the Goose client against an OpenSSL server for each certificate
type, cipher suite and group, with a HelloRetryRequest, ALPN, and a
KeyUpdate; the Goose server against an OpenSSL client likewise (which
offers its post-quantum hybrid first and so takes X25519 or a retry);
and failures: an untrusted root and a wrong host name.

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
GROUPS = {"001d": "X25519", "0017": "P-256", "0018": "P-384", "0019": "P-521", "11ec": "X25519MLKEM768"}


class Peer:
    def __init__(self, exe, args):
        self.p = subprocess.Popen([exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.state = None

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
            elif kind == "STATE":
                st, alert, alpn, group = rest.split()
                self.state = (int(st), int(alert), alpn, int(group))

    def cmd(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.read()

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def run_case(case):
    """In the child: one connection, returns a result dict."""
    import ssl
    exe = case["exe"]
    goose_is_client = case["role"] == "client"
    if goose_is_client:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(VEC, f"hs_{case['cert']}.pem"), os.path.join(VEC, f"hs_{case['cert']}.key"))
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(os.path.join(VEC, "hs_root.pem"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if case.get("alpn"):
        ctx.set_alpn_protocols(case["alpn"])
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
            if peer.state[0] >= 21:
                break
    result["goose_state"] = peer.state
    if not (done and peer.state[0] == 20):
        peer.close()
        return result
    result["suite"] = obj.cipher()[0]
    result["alpn"] = obj.selected_alpn_protocol()
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
        dict(name="goose client, ALPN", role="client", cert="ed25519", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1"], want=True, want_alpn="http/1.1"),
        dict(name="goose server, ALPN", role="server", cert="rsa", goose_alpn=["h2", "http/1.1"],
             alpn=["http/1.1", "h2"], want=True, want_alpn="h2"),
        dict(name="goose client, wrong host name", role="client", cert="p256", host="other.org", want=False,
             goose_alert=42),
        dict(name="goose client, untrusted root", role="client", cert="p256",
             roots=os.path.join(VEC, "hs_p384.pem"), want=False, goose_alert=48),
        dict(name="goose server, OpenSSL client checks the name", role="server", cert="p256",
             host="other.org", want=False),
    ]
    passed = 0
    for case in cases:
        case["exe"] = exe
        env = dict(os.environ)
        conf_lines = []
        if case.get("openssl_groups"):
            conf_lines.append(f"Groups = {case['openssl_groups']}")
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
        if good and case.get("goose_alert"):
            good = r.get("goose_state", [0, 0])[1] == case["goose_alert"]
        print(("ok    " if good else "FAIL  ") + case["name"] + ("" if good else f"  {r}"))
        passed += good
    shutil.rmtree(tmp)
    print(f"\n{passed} passed, {len(cases) - passed} failed")
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
