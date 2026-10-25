#!/usr/bin/env python3
"""Make test/vectors/hs_certs.txt: a root CA and one server certificate per
key type (Ed25519, P-256, P-384, RSA-2048) for example.com, made by
openssl, with each private key in PKCS #8 and in its own format (SEC 1 for
EC, PKCS #1 for RSA):

    root <DER hex> <PKCS #8 key hex>
    server <type> <certificate DER hex> <PKCS #8 hex> <native hex or ->

    python3 scripts/gen_handshake.py
"""

import os
import subprocess
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def ossl(*a, input=None):
    return subprocess.run(["openssl", *a], input=input, capture_output=True, check=True).stdout


def main():
    lines = []
    with tempfile.TemporaryDirectory() as t:
        p = lambda n: os.path.join(t, n)
        ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-subj", "/O=Goose TLS Test/CN=Test Root", "-days", "7300", "-keyout", p("root.key"),
             "-out", p("root.pem"), "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        der = lambda f: ossl("x509", "-in", f, "-outform", "DER")
        key8 = lambda f: ossl("pkey", "-in", f, "-outform", "DER")
        lines.append(f"root {der(p('root.pem')).hex()} {key8(p('root.key')).hex()}")
        with open(p("ext"), "w") as f:
            f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:example.com,DNS:localhost\n")
        for kind, args in [("ed25519", ["-algorithm", "ED25519"]),
                           ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                           ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]),
                           ("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])]:
            ossl("genpkey", *args, "-out", p(f"{kind}.key"))
            ossl("req", "-new", "-key", p(f"{kind}.key"), "-subj", "/CN=example.com", "-out", p(f"{kind}.csr"))
            ossl("x509", "-req", "-in", p(f"{kind}.csr"), "-CA", p("root.pem"), "-CAkey", p("root.key"),
                 "-days", "7000", "-extfile", p("ext"), "-out", p(f"{kind}.pem"))
            native = "-"
            if kind.startswith("p"):
                native = ossl("ec", "-in", p(f"{kind}.key"), "-outform", "DER").hex()
            elif kind == "rsa":
                native = ossl("rsa", "-in", p(f"{kind}.key"), "-outform", "DER", "-traditional").hex()
            lines.append(f"server {kind} {der(p(kind + '.pem')).hex()} {key8(p(kind + '.key')).hex()} {native}")
            # PEM copies, for the live interop script.
            for ext in ("pem", "key"):
                with open(os.path.join(ROOT, "test", "vectors", f"hs_{kind}.{ext}"), "w") as f:
                    f.write(open(p(f"{kind}.{ext}")).read())
        with open(os.path.join(ROOT, "test", "vectors", "hs_root.pem"), "w") as f:
            f.write(open(p("root.pem")).read())
    with open(os.path.join(ROOT, "test", "vectors", "hs_certs.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} lines")


if __name__ == "__main__":
    main()
