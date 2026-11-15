#!/usr/bin/env python3
"""Make test/vectors/hs_certs.txt: a root CA and one server certificate per
key type (Ed25519, P-256, P-384, P-521, RSA-2048, ML-DSA-44/65/87, Ed448,
brainpoolP256r1, P384r1, P512r1) for example.com, made by
openssl, with each private key in PKCS #8 and in its own format (SEC 1 for
EC, PKCS #1 for RSA); then a CA for clients and client certificates it
issued (P-256, Ed25519, ML-DSA-44, Ed448 and brainpoolP256r1 for client
authentication, and a P-256 one for server authentication only):

    root <DER hex> <PKCS #8 key hex>
    server <type> <certificate DER hex> <PKCS #8 hex> <native hex or ->
    clientca <DER hex> <PKCS #8 key hex>
    client <type> <certificate DER hex> <PKCS #8 hex>

    python3 scripts/gen_handshake.py          # everything anew
    python3 scripts/gen_handshake.py --add    # only the key types the file lacks, under its CAs
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def ossl(*a, input=None):
    return subprocess.run(["openssl", *a], input=input, capture_output=True, check=True).stdout


SERVER_KINDS = [("ed25519", ["-algorithm", "ED25519"]),
                ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]),
                ("p521", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"]),
                ("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
                ("mldsa44", ["-algorithm", "ML-DSA-44"]),
                ("mldsa65", ["-algorithm", "ML-DSA-65"]),
                ("mldsa87", ["-algorithm", "ML-DSA-87"]),
                ("ed448", ["-algorithm", "ED448"]),
                ("bp256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1"]),
                ("bp384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP384r1"]),
                ("bp512", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP512r1"])]
CLIENT_KINDS = [("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "clientAuth"),
                ("ed25519", ["-algorithm", "ED25519"], "clientAuth"),
                ("mldsa44", ["-algorithm", "ML-DSA-44"], "clientAuth"),
                ("serveronly", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "serverAuth"),
                ("ed448", ["-algorithm", "ED448"], "clientAuth"),
                ("bp256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1"], "clientAuth")]


def ca_from_line(line, p, name):
    """Writes a CA's certificate and key from an hs_certs.txt line as PEM."""
    w = line.split()
    open(p(name + ".pem"), "wb").write(ossl("x509", "-inform", "DER", "-outform", "PEM", input=bytes.fromhex(w[1])))
    open(p(name + ".key"), "wb").write(ossl("pkey", "-inform", "DER", "-outform", "PEM", input=bytes.fromhex(w[2])))


def main():
    add = "--add" in sys.argv[1:]
    out_path = os.path.join(ROOT, "test", "vectors", "hs_certs.txt")
    old = open(out_path).read().splitlines() if add else []
    have = {tuple(l.split()[:2]) for l in old}
    lines = []
    with tempfile.TemporaryDirectory() as t:
        p = lambda n: os.path.join(t, n)
        der = lambda f: ossl("x509", "-in", f, "-outform", "DER")
        key8 = lambda f: ossl("pkey", "-in", f, "-outform", "DER")
        if add:
            # The file's CAs issue the new certificates, so that those it
            # has (and what was made from them) stay as they are.
            ca_from_line(next(l for l in old if l.startswith("root ")), p, "root")
            ca_from_line(next(l for l in old if l.startswith("clientca ")), p, "clientca")
        else:
            ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-subj", "/O=Goose TLS Test/CN=Test Root", "-days", "7300", "-keyout", p("root.key"),
                 "-out", p("root.pem"), "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            lines.append(f"root {der(p('root.pem')).hex()} {key8(p('root.key')).hex()}")
        with open(p("ext"), "w") as f:
            f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:example.com,DNS:localhost\n")
        with open(p("ext_rsa"), "w") as f:
            f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:example.com,DNS:localhost\n")
        for kind, args in SERVER_KINDS:
            if ("server", kind) in have:
                continue
            ossl("genpkey", *args, "-out", p(f"{kind}.key"))
            ossl("req", "-new", "-key", p(f"{kind}.key"), "-subj", "/CN=example.com", "-out", p(f"{kind}.csr"))
            # An RSA key also encrypts, in TLS 1.2's RSA key exchange, so it
            # gets keyEncipherment as well (as Go's generate_cert gives it).
            ossl("x509", "-req", "-in", p(f"{kind}.csr"), "-CA", p("root.pem"), "-CAkey", p("root.key"),
                 "-days", "7000", "-extfile", p("ext_rsa" if kind == "rsa" else "ext"), "-out", p(f"{kind}.pem"))
            native = "-"
            if kind.startswith(("p", "bp")):
                native = ossl("ec", "-in", p(f"{kind}.key"), "-outform", "DER").hex()
            elif kind == "rsa":
                native = ossl("rsa", "-in", p(f"{kind}.key"), "-outform", "DER", "-traditional").hex()
            lines.append(f"server {kind} {der(p(kind + '.pem')).hex()} {key8(p(kind + '.key')).hex()} {native}")
            # PEM copies, for the live interop script.
            for ext in ("pem", "key"):
                with open(os.path.join(ROOT, "test", "vectors", f"hs_{kind}.{ext}"), "w") as f:
                    f.write(open(p(f"{kind}.{ext}")).read())
        if not add:
            with open(os.path.join(ROOT, "test", "vectors", "hs_root.pem"), "w") as f:
                f.write(open(p("root.pem")).read())
            ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-subj", "/O=Goose TLS Test/CN=Test Client CA", "-days", "7300", "-keyout", p("clientca.key"),
                 "-out", p("clientca.pem"), "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            lines.append(f"clientca {der(p('clientca.pem')).hex()} {key8(p('clientca.key')).hex()}")
        for kind, args, eku in CLIENT_KINDS:
            if ("client", kind) in have:
                continue
            with open(p("cext"), "w") as f:
                f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                        f"extendedKeyUsage={eku}\n")
            ossl("genpkey", *args, "-out", p(f"c{kind}.key"))
            ossl("req", "-new", "-key", p(f"c{kind}.key"), "-subj", f"/CN=goose client {kind}",
                 "-out", p(f"c{kind}.csr"))
            ossl("x509", "-req", "-in", p(f"c{kind}.csr"), "-CA", p("clientca.pem"), "-CAkey", p("clientca.key"),
                 "-days", "7000", "-extfile", p("cext"), "-out", p(f"c{kind}.pem"))
            lines.append(f"client {kind} {der(p('c' + kind + '.pem')).hex()} {key8(p('c' + kind + '.key')).hex()}")
            for ext in ("pem", "key"):
                with open(os.path.join(ROOT, "test", "vectors", f"hs_client_{kind}.{ext}"), "w") as f:
                    f.write(open(p(f"c{kind}.{ext}")).read())
        if not add:
            with open(os.path.join(ROOT, "test", "vectors", "hs_clientca.pem"), "w") as f:
                f.write(open(p("clientca.pem")).read())
    if add:
        # The new lines after the old ones of their kind: servers before
        # the client CA, clients last.
        at = next(i for i, l in enumerate(old) if l.startswith("clientca "))
        new_servers = [l for l in lines if l.startswith("server ")]
        lines = old[:at] + new_servers + old[at:] + [l for l in lines if l.startswith("client ")]
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} lines")


if __name__ == "__main__":
    main()
