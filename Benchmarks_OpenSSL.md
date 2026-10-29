# Benchmarks against OpenSSL

This package's TLS, and the bignum primitives under it, side by side with
OpenSSL 4.1.0 on the same machine. In every table the last column is
Goose / OpenSSL: above 1 means Goose is faster.

Measured on 2026-10-28:
- **Machine:** an Apple M1 (8 cores, 16 GB) on macOS 26.6.2.
- **Goose:** goose at `cfd2f489`, native builds (`goose build`: Apple
  clang 21, `-O2`).
- **OpenSSL:** Homebrew's OpenSSL 4.1.0.

Each figure is one second of one thread, after one untimed connection. Two
runs differed by up to about 10%, more for the fastest cases.

## TLS

Both sides run a client and a server in one process, with the bytes passed
between them in memory. tlsgoose does this through its I/O-free API, and
OpenSSL through two `SSL` objects joined by memory BIOs. So no sockets or
system calls are timed, only the TLS work of both ends. The two programs
are `tools/bench.goose` and `tools/bench_openssl.c`, and they run the same
cases:

- **Keys:** the same certificates and keys, from `test/vectors/hs_certs.txt`.
- **Verification:** the client verifies the server's chain to the test
  root (a P-256 CA), its signature, and the name `example.com`.
- **Negotiation:** exactly one version, suite and group is allowed. TLS
  1.2 also offers P-256 after X25519, because the ECDSA certificate's
  curve has to be among the groups. Both programs were checked to
  negotiate what each case is named for.
- **Tickets:** none, except in the resumption case. There the server sends
  one ticket after each handshake and the next connection resumes with
  it, since OpenSSL's client uses a ticket only once.
- **Closing:** no close_notify is sent.
- **Bulk:** application data from client to server in 16 KiB writes. The
  client seals each record and the server opens it, so a figure covers
  both directions of the cipher's work.

Case names give the version, the key exchange group and the server's key.

| Case | Goose | OpenSSL 4.1.0 | Goose / OpenSSL |
|---|---:|---:|---:|
| tls13-x25519-ed25519 | 283.5 hs/s | 2,370.2 hs/s | 0.12 |
| tls13-x25519-p256 | 159.2 hs/s | 2,668.0 hs/s | 0.06 |
| tls13-x25519-rsa2048 | 83.4 hs/s | 1,152.6 hs/s | 0.07 |
| tls13-p256-p256 | 95.9 hs/s | 2,657.6 hs/s | 0.04 |
| tls13-p384-p384 | 38.3 hs/s | 760.8 hs/s | 0.05 |
| tls13-x25519mlkem768-p256 | 153.5 hs/s | 2,005.6 hs/s | 0.08 |
| tls13-x25519mlkem768-mldsa65 | 234.7 hs/s | 953.5 hs/s | 0.25 |
| tls13-resume-x25519 | 1,468.4 hs/s | 4,210.4 hs/s | 0.35 |
| tls12-ecdhe-ecdsa-p256 | 158.8 hs/s | 2,930.2 hs/s | 0.05 |
| tls12-ecdhe-rsa2048 | 83.2 hs/s | 1,195.6 hs/s | 0.07 |
| bulk-tls13-aes128gcm | 45.9 MB/s | 2,602.4 MB/s | 0.02 |
| bulk-tls13-aes256gcm | 35.6 MB/s | 2,283.1 MB/s | 0.02 |
| bulk-tls13-chacha20 | 149.6 MB/s | 778.0 MB/s | 0.19 |
| bulk-tls12-aes128gcm | 45.7 MB/s | 2,579.4 MB/s | 0.02 |
| bulk-tls12-chacha20 | 162.5 MB/s | 791.2 MB/s | 0.21 |

### Where the time goes

A handshake is roughly the sum of its public-key operations. The
[primitive table](#primitives) predicts the Goose figures to within 7 to
14% in the two cases worked through below.

- **Every case pays one P-256 verification for the chain.** The root
  signs every server certificate with ECDSA P-256, so every client spends
  2.2 ms verifying that signature. At 461 verifications a second, P-256
  verification is Goose's slowest common operation.
- **`tls13-x25519-p256` (159 hs/s):**
  - four X25519 operations: 0.36 ms;
  - one P-256 signature: 1.2 ms;
  - two P-256 verifications (the CertificateVerify and the chain): 4.3 ms.

  That totals about 5.9 ms, or 170 a second.
- **`tls13-x25519-ed25519` (283 hs/s):** the same, with Ed25519 signing and
  verifying the handshake. Ed25519 is 4 to 8 times faster than P-256 here.
- **`tls13-x25519mlkem768-mldsa65` (235 hs/s, ratio 0.25):** the
  post-quantum case is the closest to OpenSSL. ML-KEM runs at 0.4 to 0.8
  of OpenSSL's speed. About half of this case's 4.3 ms is still the
  chain's P-256 verification. ML-DSA isn't in the primitive table, so its
  share is the rest less ML-KEM.
- **Resumption (ratio 0.35):** no certificate is involved, only one X25519
  exchange each way and the ticket's AES-GCM, so the gap is smallest.
  **Since 2026-10-29 (tlsgoose 0bbe13c) it is 348 hs/s (0.08):** a client
  that verifies checks a session's chain again under its roots now before
  it resumes, as Go's `loadSession` does, which adds the chain's P-256
  verification to every resumption. Before, a session got without
  verifying, or one whose root had since been removed, resumed anyway. A
  cache of successful verifications would win the speed back.
- **Bulk AES-GCM (0.02):** this is hardware. On this CPU, OpenSSL uses the
  AES and PMULL instructions. Goose has no intrinsics, so bignum runs a
  bitsliced, table-free, constant-time AES and a carry-less GHASH in
  integer arithmetic. Its 46 MB/s matches the primitive's 81 MB/s run
  twice, once to seal and once to open. The TLS layer adds little.
- **Bulk ChaCha20-Poly1305 (0.2):** neither side has a special instruction
  for it, so the gap is OpenSSL's NEON assembly against compiled C.

So the TLS layer itself (records, the transcript, the key schedule, the
state machines) is not where the gap is. The curves and AES set the
figures, and those come from bignum: 32-bit limbs with no 64×64→128
multiply, generic code over the prime for the NIST curves, and no
hardware AES. Those are the places to speed up first: a specialized
P-256, and AES and GHASH through `simd fn` or intrinsics, if Goose gets
them.

## Primitives

From bigmongoose.git's `scripts/speed_vs_openssl.py`:
- **Goose:** `examples/speed.goose`, 16 KiB buffers or operations a second.
- **OpenSSL:** `openssl speed -evp` over 16 KiB buffers, so it uses its
  assembly and the CPU's instructions.
- **PBKDF2 and scrypt:** through Python's hashlib, which calls OpenSSL.
- **Argon2id:** through `openssl kdf`, less its start-up time.

| Operation | Goose | OpenSSL 4.1.0 | Goose / OpenSSL |
|---|---:|---:|---:|
| md5 | 266.1 MB/s | 702.1 MB/s | 0.38 |
| sha1 | 238.8 MB/s | 2,387.9 MB/s | 0.10 |
| sha256 | 208.4 MB/s | 2,429.8 MB/s | 0.09 |
| sha512 | 305.3 MB/s | 1,422.5 MB/s | 0.21 |
| sha3-256 | 209.9 MB/s | 900.1 MB/s | 0.23 |
| blake2b512 | 586.4 MB/s | 742.5 MB/s | 0.79 |
| blake2s256 | 447.2 MB/s | 442.2 MB/s | 1.01 |
| hmac-sha256 | 206.1 MB/s | 2,436.0 MB/s | 0.08 |
| aes-128-gcm | 81.3 MB/s | 8,166.1 MB/s | 0.01 |
| aes-256-gcm | 61.5 MB/s | 6,814.0 MB/s | 0.01 |
| chacha20-poly1305 | 388.8 MB/s | 1,829.9 MB/s | 0.21 |
| chacha20 | 529.5 MB/s | 2,518.1 MB/s | 0.21 |
| aes-128-ctr | 91.5 MB/s | 12,876.5 MB/s | 0.01 |
| aes-256-ctr | 66.9 MB/s | 9,532.8 MB/s | 0.01 |
| aes-128-cbc | 48.1 MB/s | 1,585.8 MB/s | 0.03 |
| aes-256-cbc | 34.9 MB/s | 1,128.2 MB/s | 0.03 |
| aes-128-cfb | 48.0 MB/s | 1,101.3 MB/s | 0.04 |
| aes-128-ofb | 48.2 MB/s | 1,173.0 MB/s | 0.04 |
| des-cbc | 9.7 MB/s | 84.5 MB/s | 0.11 |
| des-ede3-cbc | 3.2 MB/s | 33.5 MB/s | 0.10 |
| rc4 | 1,058.8 MB/s | 1,290.3 MB/s | 0.82 |
| x25519 | 11,035 op/s | 33,318 op/s | 0.33 |
| ed25519-sign | 3,372 op/s | 33,387 op/s | 0.10 |
| ed25519-verify | 3,649 op/s | 11,837 op/s | 0.31 |
| ecdh-p224 | 1,240 op/s | 21,379 op/s | 0.06 |
| ecdsa-p224-sign | 1,166 op/s | 30,160 op/s | 0.04 |
| ecdsa-p224-verify | 617 op/s | 13,933 op/s | 0.04 |
| ecdh-p256 | 923 op/s | 25,221 op/s | 0.04 |
| ecdsa-p256-sign | 864 op/s | 58,962 op/s | 0.01 |
| ecdsa-p256-verify | 461 op/s | 19,079 op/s | 0.02 |
| ecdh-p384 | 304 op/s | 4,786 op/s | 0.06 |
| ecdsa-p384-sign | 287 op/s | 7,143 op/s | 0.04 |
| ecdsa-p384-verify | 153 op/s | 3,340 op/s | 0.05 |
| ecdh-p521 | 132 op/s | 4,699 op/s | 0.03 |
| ecdsa-p521-sign | 125 op/s | 4,774 op/s | 0.03 |
| ecdsa-p521-verify | 66.2 op/s | 2,656.0 op/s | 0.02 |
| rsa2048-sign | 113 op/s | 1,868 op/s | 0.06 |
| rsa2048-verify | 6,094 op/s | 71,889 op/s | 0.08 |
| rsa3072-sign | 39.2 op/s | 639.0 op/s | 0.06 |
| rsa3072-verify | 2,897 op/s | 33,869 op/s | 0.09 |
| rsa4096-sign | 16.8 op/s | 288.1 op/s | 0.06 |
| rsa4096-verify | 1,694 op/s | 19,613 op/s | 0.09 |
| mlkem512-keygen | 39,744 op/s | 47,309 op/s | 0.84 |
| mlkem512-encaps | 33,411 op/s | 63,564 op/s | 0.53 |
| mlkem512-decaps | 26,537 op/s | 39,553 op/s | 0.67 |
| mlkem768-keygen | 24,447 op/s | 29,145 op/s | 0.84 |
| mlkem768-encaps | 20,829 op/s | 43,983 op/s | 0.47 |
| mlkem768-decaps | 16,869 op/s | 27,846 op/s | 0.61 |
| mlkem1024-keygen | 15,808 op/s | 19,329 op/s | 0.82 |
| mlkem1024-encaps | 13,911 op/s | 32,099 op/s | 0.43 |
| mlkem1024-decaps | 11,495 op/s | 20,652 op/s | 0.56 |
| pbkdf2-sha256-100k | 14.1 op/s | 92.2 op/s | 0.15 |
| scrypt-n15-r8 | 17.3 op/s | 14.8 op/s | 1.17 |
| argon2id-t1-64m-p4 | 31.3 op/s | 25.0 op/s | 1.25 |

Where OpenSSL is far ahead, it is mostly hardware or assembly:
- **Instructions:** AES, PMULL (for GHASH), SHA-1, SHA-2 and SHA-3.
- **Big numbers:** 64-bit limbs with a wide multiply for the curves and
  RSA, and code specialized for P-256.
- **ML-KEM:** OpenSSL keeps the expanded matrix with the key, which
  bignum rebuilds on each encapsulation and decapsulation.

Where neither side has special instructions, the two are about even or
Goose is ahead: BLAKE2s (1.01), RC4, scrypt (1.17) and Argon2id (1.25).

## Reproducing

```bash
cd tlsgoose.git
python3 scripts/bench_openssl.py               # the TLS table (about 20 s)
python3 scripts/bench_openssl.py bulk-         # only the cases a prefix names
python3 scripts/bench_openssl.py --ms 3000     # three seconds a case
cd ../bigmongoose.git
python3 scripts/speed_vs_openssl.py            # the primitive table (about 2 min)
```

- **Compiler:** `bench_openssl.py` takes the compiler from `$GOOSE`, else
  `goose` on PATH, else `../goose.git/build/goose`.
- **OpenSSL:** it builds `tools/bench_openssl.c` against the installation
  of the `openssl` on PATH (the same one `speed_vs_openssl.py` measures),
  or the one `--openssl-prefix` names.
- **Running either side alone:** `goose build -o bench tools/bench.goose
  && ./bench [prefix] [ms]`. For OpenSSL, `bench_openssl -d pemdir [-ms
  ms] [prefix]`, with PEM files the script writes.

The figures depend on the machine, its load and its thermal state. Close
other work and run them twice before comparing.
