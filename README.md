# tls

TLS 1.3 (RFC 8446) for the Goose language: client and server
connections, the key schedule and the record layer. It builds on
[bignum](../bigmongoose.git) for the cryptography,
[x509](../x509goose.git) for certificates and [asn1](../asn1goose.git)
for keys. Nothing here does I/O: a connection is fed the bytes that
arrive, and hands back the bytes to send and the application data
received. The caller owns the socket, or the pipe, or the test harness.

- **`tls`**: cipher suites (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`), content,
  handshake and alert constants.
- **`tls.schedule`**: HKDF-Expand-Label, Derive-Secret, the early,
  handshake and master secrets and the traffic secrets derived from them,
  traffic keys, Finished, KeyUpdate, exporters, resumption PSKs and binder
  keys, and a running transcript hash, including the HelloRetryRequest
  restart.
- **`tls.handshake`**: `Conn`, the client and server state machines,
  their configurations, and key loading.
- **`tls.record`**: plaintext and protected records, the per-record nonce,
  content-type hiding and padding, size limits with the alert each failure
  calls for, fragmenting long data, and framing records and handshake
  messages out of a byte stream.

```goose
import tls from "../tlsgoose.git";
import bignum from "../bigmongoose.git";      // tls needs it; the root declares it
import tls.schedule;
import tls.record;

let s, ok = tls::suite(tls::TLS_AES_128_GCM_SHA256);
var sch = tls::schedule(s.hash, "");            // no PSK
var th = tls::transcript(s.hash);
tls::transcript_add(th, client_hello);
tls::transcript_add(th, server_hello);
tls::schedule_handshake(sch, ecdhe_shared, tls::transcript_hash(th));

var out = tls::record_keys(s, sch.s_hs);        // server writes with s_hs
let rec = tls::seal_record(out, tls::CT_HANDSHAKE, flight);
var inn = tls::record_keys(s, sch.s_hs);        // the client reads with it
let ctype, plaintext, alert = tls::open_record(inn, rec);   // alert != 0: send it, close
```

## Connections

```goose
import tls.handshake;

var cfg = tls::client_config("example.com", "");   // the system's roots, as Go with no RootCAs
// or: tls::client_config("example.com", roots_der)  (DER certificates concatenated)
// or: tls::client_config_pool("example.com", pool)  (an x509::CertPool, from files or a directory)
tls::add_alpn(cfg.alpn, "http/1.1");
var c = tls::client(cfg);
var out: u8[>..] = [];
var app: u8[>..] = [];
tls::client_start(c, cfg, out);                // the ClientHello
loop {
    // send `out`, read some bytes into `input`
    out.clear();
    if tls::client_feed(c, cfg, input, out, app) != 0 { break; }   // c.alert says why
    if tls::connected(c) { break; }
}
tls::send(c, request, out);                    // application data; replies arrive in `app`
tls::close(c, out);
```

A server is the same, built from
`tls::server_config(chain_der, key_der) -> ServerConfig, bool`, with
`tls::server(cfg)` and `tls::server_feed`. The key may be PKCS #8 (RSA,
EC, Ed25519, ML-DSA), SEC 1 or PKCS #1 DER.

| | Client | Server |
|---|---|---|
| Suites | all three, in `cfg.suites` order | its own order of preference |
| Key exchange | The post-quantum X25519MLKEM768 (the default), SecP256r1MLKEM768 and SecP384r1MLKEM1024 hybrids and MLKEM1024 alone; X25519, P-256, P-384, P-521. The defaults are Go's: everything but MLKEM1024. The client sends a share for the first of `cfg.groups` (plus, beside a hybrid, a share of its ECDH part on the same key, as Go does) and reaches the others through HelloRetryRequest | its first group the client has a share for, else a HelloRetryRequest for its first group the client supports |
| Certificates | checked by `x509::verify_with_roots`: chain to `cfg.roots`, or to the system's roots when `cfg.system_roots`, name `cfg.server_name`, time `cfg.now` (0 for now); `cfg.verify = false` skips it | sends `cfg.chain`, signs CertificateVerify with RSA-PSS, ECDSA (P-256, P-384, P-521), Ed25519 or ML-DSA as its key and the client allow |
| CertificateVerify | ML-DSA-44/65/87 (draft-ietf-tls-mldsa, offered first, as Go does), RSA-PSS, RSA PKCS #1 v1.5, ECDSA P-256/P-384/P-521, Ed25519 | |
| ALPN | `cfg.alpn` offered | its first protocol the client offered, or `no_application_protocol` |
| After the handshake | NewSessionTicket counted and dropped; KeyUpdate both ways (`key_update(c, request, out)`) | KeyUpdate |

Both sides use middlebox compatibility mode (a session ID and
change_cipher_spec), reassemble handshake messages across records, insist
that a key change falls on a record boundary, and on any error send the
fatal alert RFC 8446 calls for and stop. `c.alert` holds the alert sent or
received, and `c.error` the x509 error behind a certificate alert. Every
random value comes from an HMAC-DRBG seeded from the OS. A config's
`seed` fixes it, for tests.

Not supported: PSK, resumption and 0-RTT (tickets are ignored), client
certificates (a request is answered with an empty Certificate), and TLS
1.2 or older.

## The key schedule

`schedule(hash, psk)` starts from the early secret.
`schedule_handshake(s, shared, th)` adds the handshake secret and `c_hs` /
`s_hs`. `schedule_master(s, th)` adds the master secret, `c_ap` / `s_ap`
and the exporter secret. `schedule_resumption(s, th)` adds the resumption
master secret. Each takes the transcript hash at its point in the
handshake. `traffic_key` and `traffic_iv` turn a traffic secret into AEAD
keys. `finished_data` and `finished_ok` (constant time) handle Finished,
`next_traffic_secret` handles KeyUpdate, and `export_keying_material` is
the exporter. `hkdf_expand_label` and `derive_secret` are public for
anything else.

## Records

`RecordKeys` holds one direction's key, IV and sequence number; the AES key
is expanded once. `seal_record(k, type, payload, padding = 0)` and
`open_record(k, record) -> type, plaintext, alert` each advance the
sequence number. A record that fails to open leaves the number as it was
and names the alert to send: `bad_record_mac`, `record_overflow`,
`decode_error` or `unexpected_message`. The connection must then close.
`seal_records` fragments long data. `plain_record` is for the hellos and
change_cipher_spec. `record_length` and `handshake_length` find where the
next whole record or handshake message ends in a buffer, and return 0
while more bytes are needed.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
```

- `rfc8448`: the simple 1-RTT handshake of RFC 8448 §3, end to end. It
  starts from the two X25519 key pairs, runs every secret, key and
  Finished message, and reproduces every record of the trace byte for
  byte, then opens each one and refuses changed copies and replays.
  `scripts/rfc8448.py` extracts the values from the RFC's text.
- `openssl_interop`: real connections between an OpenSSL client and
  server, one per cipher suite, captured by `scripts/openssl_interop.py`
  through memory BIOs with their key logs. Every record from either side
  opens, both Finished messages verify against the transcript, and the
  application data comes back. Sealing each record again gives OpenSSL's
  bytes exactly.
- `record_api`: refused headers and records with their alerts, padding,
  typeless records, fragmenting, nonces, KeyUpdate, the HelloRetryRequest
  transcript, exporters.

- `handshake`: this package's client against its server in memory, for
  every server key type (ML-DSA included) with each suite and group. Each run includes
  HelloRetryRequest, ALPN, data both ways, KeyUpdate and close_notify.
  The failures covered: an unknown CA, a wrong name, an expired
  certificate, no common suite or group, an ALPN mismatch, and a changed
  record. Input is also fed a byte at a time.

`scripts/live_interop.py` runs live connections against OpenSSL (69
cases). It builds `tools/peer.goose`, a peer driven over stdin and stdout,
and relays its bytes to Python's ssl module through memory BIOs. It
covers:
- this client against an OpenSSL server, and this server against an
  OpenSSL client, for each certificate type, suite and group, and with
  ML-DSA-44, ML-DSA-65 and ML-DSA-87 certificates;
- X25519MLKEM768 by default, alone, and after a HelloRetryRequest, in
  both roles (so OpenSSL decapsulates this package's ML-KEM ciphertexts
  and encapsulates to its keys), and the X25519 fallback for a server
  without it;
- SecP256r1MLKEM768, SecP384r1MLKEM1024 and MLKEM1024 in both roles, a
  HelloRetryRequest to SecP384r1MLKEM1024, and the P-256 fallback beside
  SecP256r1MLKEM768;
- a HelloRetryRequest in each direction (the OpenSSL client offers its
  post-quantum hybrid share first);
- ALPN both ways, a KeyUpdate that OpenSSL answers, and close_notify;
- roots from a directory; an untrusted root, the system's roots (which lack
  the test root), and a wrong name.

The compiler is found as in bignum: `--goose`, `$GOOSE`, `goose` on PATH,
then `../goose.git/build/goose`.
