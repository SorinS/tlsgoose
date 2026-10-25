#!/usr/bin/env python3
"""Capture real TLS 1.3 connections made by OpenSSL, for the interop test.

For each cipher suite, Python's ssl module (OpenSSL) runs a client and a
server against each other through memory BIOs: no sockets, every byte each
side sends is recorded. The key log gives the traffic secrets. The client
sends a short message and one longer than a record; the server answers.
Writes test/vectors/openssl_<suite>.txt:

    suite <id>
    secret <NSS key log label> <hex>
    c2s <hex of everything the client sent>
    s2c <hex of everything the server sent>
    app_c2s <hex>, app_s2c <hex>     the application data each way

Each suite runs in a child process with an OPENSSL_CONF that allows only
that suite, since Python cannot choose TLS 1.3 suites itself.

    python3 scripts/openssl_interop.py
"""

import os
import random
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
          0x1303: "TLS_CHACHA20_POLY1305_SHA256"}


def child(tmp, suite_id):
    import ssl
    keylog = os.path.join(tmp, f"keys-{suite_id:x}.txt")
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = sctx.maximum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem"))
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.minimum_version = cctx.maximum_version = ssl.TLSVersion.TLSv1_3
    cctx.load_verify_locations(os.path.join(tmp, "cert.pem"))
    cctx.keylog_filename = keylog
    cin, cout, sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = cctx.wrap_bio(cin, cout, server_hostname="localhost")
    server = sctx.wrap_bio(sin, sout, server_side=True)
    c2s, s2c = bytearray(), bytearray()

    def pump():
        moved = False
        data = cout.read()
        if data:
            c2s.extend(data)
            sin.write(data)
            moved = True
        data = sout.read()
        if data:
            s2c.extend(data)
            cin.write(data)
            moved = True
        return moved

    done = [False, False]
    while not all(done):
        for i, side in enumerate((client, server)):
            if not done[i]:
                try:
                    side.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        if not pump() and not all(done):
            raise RuntimeError("handshake stalled")
    rng = random.Random(suite_id)
    app_c2s = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" + bytes(rng.getrandbits(8) for _ in range(20000))
    app_s2c = b"HTTP/1.1 200 OK\r\n\r\nhello from openssl"
    client.write(app_c2s)
    pump()
    got = bytearray()
    while len(got) < len(app_c2s):
        got += server.read(65536)
    assert got == app_c2s
    server.write(app_s2c)
    pump()
    got = bytearray()
    while len(got) < len(app_s2c):
        try:
            got += client.read(65536)
        except ssl.SSLWantReadError:
            pump()
    assert got == app_s2c
    assert client.cipher()[0] == SUITES[suite_id], client.cipher()
    lines = [f"suite {suite_id:04x}"]
    for line in open(keylog).read().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        label, _, secret = line.split()
        lines.append(f"secret {label} {secret}")
    lines += [f"c2s {c2s.hex()}", f"s2c {s2c.hex()}", f"app_c2s {app_c2s.hex()}",
              f"app_s2c {app_s2c.hex()}"]
    path = os.path.join(ROOT, "test", "vectors", f"openssl_{suite_id:04x}.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {os.path.relpath(path, ROOT)}: {len(c2s)} bytes from the client, "
          f"{len(s2c)} from the server")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        child(sys.argv[2], int(sys.argv[3], 16))
        return
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost", "-days", "30",
                        "-keyout", os.path.join(tmp, "key.pem"),
                        "-out", os.path.join(tmp, "cert.pem")], check=True, capture_output=True)
        for sid, name in SUITES.items():
            conf = os.path.join(tmp, f"openssl-{sid:x}.cnf")
            with open(conf, "w") as f:
                f.write("openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\n"
                        "system_default = tls\n[tls]\n"
                        f"Ciphersuites = {name}\n")
            env = dict(os.environ, OPENSSL_CONF=conf)
            subprocess.run([sys.executable, "-I", __file__, "--child", tmp, f"{sid:x}"],
                           check=True, env=env)


if __name__ == "__main__":
    main()
