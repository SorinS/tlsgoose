"""TLS handshakes and throughput against OpenSSL's on this machine.

Builds tools/bench.goose natively and tools/bench_openssl.c against
OpenSSL's libssl, writes test/vectors/hs_certs.txt's certificates and keys
as PEM for the C side, runs both (each a client and a server in one
process, joined in memory: the same cases, certificates, keys and checks),
and prints a Markdown table: the Goose figure, OpenSSL's, and Goose /
OpenSSL (above 1 is faster).

    python3 scripts/bench_openssl.py [--goose PATH] [--openssl-prefix DIR] [--ms MS] [prefix]

OpenSSL is taken from --openssl-prefix, else the installation of the
`openssl` on PATH (as bigmongoose.git's scripts/speed_vs_openssl.py uses),
else pkg-config's openssl.
"""

import argparse
import base64
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def default_goose():
    if os.environ.get("GOOSE"):
        return os.environ["GOOSE"]
    return shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")


def pem(der, label):
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}-----\n"


def write_pems(d):
    for line in open(os.path.join(ROOT, "test", "vectors", "hs_certs.txt")):
        w = line.split()
        if len(w) >= 3 and w[0] == "root":
            open(os.path.join(d, "root.crt"), "w").write(pem(bytes.fromhex(w[1]), "CERTIFICATE"))
        elif len(w) >= 4 and w[0] == "server":
            open(os.path.join(d, w[1] + ".crt"), "w").write(pem(bytes.fromhex(w[2]), "CERTIFICATE"))
            open(os.path.join(d, w[1] + ".key"), "w").write(pem(bytes.fromhex(w[3]), "PRIVATE KEY"))


def openssl_flags(prefix):
    # The libssl of the `openssl` on PATH, so that both of the repositories'
    # OpenSSL tables are of one version.
    exe = shutil.which("openssl")
    if not prefix and exe:
        p = os.path.dirname(os.path.dirname(os.path.realpath(exe)))
        if os.path.exists(os.path.join(p, "include", "openssl", "ssl.h")):
            prefix = p
    if prefix:
        return [f"-I{prefix}/include", f"-L{prefix}/lib", f"-Wl,-rpath,{prefix}/lib", "-lssl", "-lcrypto"], prefix
    r = subprocess.run(["pkg-config", "--cflags", "--libs", "openssl"], capture_output=True, text=True, check=True)
    return r.stdout.split(), None


def lines(out):
    got = {}
    for line in out.splitlines():
        name, value, unit = line.split()
        got[name] = (float(value), unit)
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose", default=default_goose())
    ap.add_argument("--openssl-prefix", default="")
    ap.add_argument("--ms", type=int, default=1000)
    ap.add_argument("prefix", nargs="?", default="")
    args = ap.parse_args()
    flags, prefix = openssl_flags(args.openssl_prefix)
    with tempfile.TemporaryDirectory() as tmp:
        write_pems(tmp)
        gexe = os.path.join(tmp, "bench")
        r = subprocess.run([args.goose, "build", "-o", gexe, os.path.join(ROOT, "tools", "bench.goose")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"bench.goose did not build:\n{r.stderr}")
        oexe = os.path.join(tmp, "bench_openssl")
        subprocess.run(["cc", "-O2", "-o", oexe, os.path.join(ROOT, "tools", "bench_openssl.c"), *flags], check=True)
        goose = lines(subprocess.run([gexe, args.prefix, str(args.ms)], check=True, capture_output=True,
                                     text=True).stdout)
        theirs = lines(subprocess.run([oexe, "-d", tmp, "-ms", str(args.ms), args.prefix], check=True,
                                      capture_output=True, text=True).stdout)
        ver = subprocess.run([os.path.join(prefix, "bin", "openssl") if prefix else "openssl", "version"],
                             capture_output=True, text=True).stdout.split()[1]
    print(f"| Case | Goose | OpenSSL {ver} | Goose / OpenSSL |")
    print("|---|---:|---:|---:|")
    for name, (value, unit) in goose.items():
        o = theirs.get(name)
        ratio = f"{value / o[0]:.2f}" if o else "-"
        print(f"| {name} | {value:,.1f} {unit} | {f'{o[0]:,.1f} {unit}' if o else '-'} | {ratio} |")


if __name__ == "__main__":
    main()
