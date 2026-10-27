# tls

TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246) for the Goose language: client
and server connections, the key schedules and the record layer. It builds on
[bignum](../bigmongoose.git) for the cryptography,
[x509](../x509goose.git) for certificates and [asn1](../asn1goose.git)
for keys. Nothing here does I/O: a connection is fed the bytes that
arrive, and hands back the bytes to send and the application data
received. The caller owns the socket, or the pipe, or the test harness.

- **`tls`**: cipher suites (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, and TLS 1.2's
  `TLS_ECDHE_*` and `TLS_RSA_*`), versions, content, handshake and alert
  constants.
- **`tls.schedule`**: HKDF-Expand-Label, Derive-Secret, the early,
  handshake and master secrets and the traffic secrets derived from them,
  traffic keys, Finished, KeyUpdate, exporters, resumption PSKs and binder
  keys, and a running transcript hash, including the HelloRetryRequest
  restart; TLS 1.2's PRF, master secret (extended too), key block,
  Finished and exporter.
- **`tls.handshake`**: `Conn`, the client and server state machines,
  their configurations, version negotiation, and key loading.
- **`tls.handshake12`**: TLS 1.2's messages and flights, both sides.
- **`tls.session`**: `Session`, what a client keeps to resume, as bytes
  too, and the server's sealed tickets.
- **`tls.ech`**: Encrypted Client Hello: ECHConfig and ECHConfigList
  encoding, picking a config, server key generation, the accept
  confirmation, and rebuilding a ClientHelloInner.
- **`tls.record`**: plaintext and protected records, the per-record nonce,
  content-type hiding and padding, size limits with the alert each failure
  calls for, fragmenting long data, and framing records and handshake
  messages out of a byte stream; TLS 1.2's AES-GCM, ChaCha20-Poly1305 and
  AES-CBC with HMAC.

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
| Client certificates | sends `cfg.cert_chain` (set with `tls::set_client_certificate(cfg, chain_der, key_der)`) when asked, if its key signs with a scheme the server takes and, if the server names CAs, one of its certificates was issued by one of them; otherwise an empty Certificate | asks per `cfg.client_auth`, Go's modes: `NO_CLIENT_CERT` (the default), `REQUEST_CLIENT_CERT`, `REQUIRE_ANY_CLIENT_CERT`, `VERIFY_CLIENT_CERT_IF_GIVEN`, `REQUIRE_AND_VERIFY_CLIENT_CERT`; names the CAs of `cfg.client_cas` and checks chains against them (the system's roots when empty, as Go) for client authentication; `tls::peer_certificates(c)`, `tls::peer_verified(c)` |
| ALPN | `cfg.alpn` offered | its first protocol the client offered, or `no_application_protocol` |
| Resumption | offers `cfg.session` when it is unexpired, for `cfg.server_name`, and one of `cfg.suites` has its hash (also after a HelloRetryRequest); `tls::session(c)` is the latest ticket's session | takes a ticket sealed under `cfg.ticket_key` that is unexpired and of the suite's hash, checking its binder; sends `cfg.tickets` tickets (1, as Go) to clients that allow psk_dhe_ke |
| After the handshake | NewSessionTicket kept as the session; KeyUpdate both ways (`key_update(c, request, out)`) | KeyUpdate; `send_session_ticket(c, cfg, out)` for another ticket |

Both sides use middlebox compatibility mode (a session ID and
change_cipher_spec), reassemble handshake messages across records, insist
that a key change falls on a record boundary, and on any error send the
fatal alert RFC 8446 calls for and stop. `c.alert` holds the alert sent or
received, and `c.error` the x509 error behind a certificate alert. Every
random value comes from an HMAC-DRBG seeded from the OS. A config's
`seed` fixes it, for tests.

Not supported: 0-RTT, external PSKs, post-handshake client
authentication, and TLS 1.1 or older.

### Client certificates

```goose
var sc, ok = tls::server_config(chain, key);
sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
x509::pool_add_file(sc.client_cas, "clients-ca.pem");
...                                             // once connected:
tls::peer_certificates(c)                       // the client's chain, DER concatenated
tls::peer_verified(c)                           // checked against sc.client_cas

var cc = tls::client_config("example.com", roots);
tls::set_client_certificate(cc, client_chain, client_key);
```

A server that asks sends a CertificateRequest with its signature schemes
and the names of its client CAs. A missing certificate where one is
required fails with certificate_required. A checked chain must lead to a
client CA and allow client authentication (x509's
`verify_client_with_roots`, through the new `Options.key_usages`).
Whenever the client sends a certificate, its CertificateVerify must
verify, checked or not.

Resumed connections carry the client's certificate over in the ticket,
with whether it was checked. As in Go, a ticket is not taken when:
- one is required now and the ticket has none;
- none is asked for and the ticket has one;
- the certificate has expired;
- certificates are checked now and this one was not.

### Resumption

Resumption works as in Go's crypto/tls, with PSK and (EC)DHE
(psk_dhe_ke) and no 0-RTT:

```goose
var c = tls::client(cfg);  ...                  // a full handshake
let sess, has = tls::session(c);                // after the server's ticket
let saved = tls::session_bytes(sess);           // to keep across runs; tls::parse_session reads it
var cfg2 = tls::client_config("example.com", "");
cfg2.session = sess;                            // the next connection offers it
...                                             // tls::resumed(c2) once connected
```

A `Session` holds what the client needs:
- the suite, the PSK and the ticket, with its age_add, arrival time and
  lifetime (at most 7 days);
- the server name and ALPN protocol;
- the certificate's notAfter, after which the session is not offered, as
  in Go.

A resumed connection skips the server's Certificate and
CertificateVerify, so `c.chain` is empty.

The server keeps nothing: each ticket seals the session's state (suite,
PSK, creation time, age_add, ALPN, server name, the client's certificate)
with ChaCha20-Poly1305
under `cfg.ticket_key`. That key is random per `server_config`, so share
it to let several servers resume each other's sessions. A ticket it cannot
open, from another suite's hash, or older than its lifetime gives a full
handshake. A wrong binder fails the handshake with decrypt_error.

### Encrypted Client Hello

ECH (RFC 9849) hides the real ClientHello, server name included, inside
an outer one that names only the config's public name. It works as Go's
does:

```goose
// The server: a key, its ECHConfig published to clients (in DNS, say).
let config, sk = tls::generate_ech_key(1, bignum::HPKE_DHKEM_X25519, "public.example.com");
tls::add_ech_key(sc, config, sk, true);          // true: sent as a retry config
let list = tls::ech_config_list(config);

// The client.
cc.ech_config_list.append(list);                 // e.g. from the HTTPS record's ech= value
...                                              // once connected:
tls::ech_accepted(c)
```

The client:
- picks the first usable config, as Go does: this version, a valid public
  name, no mandatory extension, a KEM this package has, and an HKDF and a
  sealing AEAD;
- builds the inner ClientHello, with the real name, the PSK when
  resuming, and the shared extensions compressed into
  ech_outer_extensions;
- pads it as Go does, and seals it with HPKE under the config's key. The
  outer ClientHello is the AAD.

The outer ClientHello has its own random, the same key shares and no PSK.

Acceptance is read from the confirmation in the ServerHello's random, or
in the HelloRetryRequest. After a HelloRetryRequest the second ClientHello
seals with the same HPKE context.

When ECH is not accepted, the client finishes the handshake with the
public name:
- the certificate must be valid for that name;
- a certificate request is answered with none.

It then fails with `ech_required`, and `tls::ech_retry_configs(c)` holds
the server's retry configs to try again with.

The server tries each of its keys on an outer ClientHello. With the first
that opens it, it rebuilds the inner one and goes on with that one: the
name, the PSK and every other extension. It confirms that in the
ServerHello, or in a HelloRetryRequest, and checks the second ClientHello
under the same context. A server none of whose keys opens it goes on with
the outer one and sends its retry configs. An inner ClientHello sent
directly, by a client-facing server to a backend, is confirmed as it is.

KEMs: DHKEM X25519, P-256, P-384 and P-521, ML-KEM-768 and ML-KEM-1024,
and the MLKEM768-X25519, MLKEM768-P256 and MLKEM1024-P384 hybrids.

### TLS 1.2

Both sides take TLS 1.2 and TLS 1.3 by default, as Go: `cfg.min_version`
and `cfg.max_version` (`tls::VERSION_TLS12`, `tls::VERSION_TLS13`) narrow
that, and `tls::version(c)` says what was negotiated. The client offers
both in one ClientHello. Offering only TLS 1.2, it leaves out TLS 1.3's
extensions, its ML-KEM groups and its ML-DSA schemes, as Go does, since
some servers refuse a TLS 1.2 hello that has them. The server takes TLS
1.3 when the client offers it. A TLS 1.3 server that settles on TLS 1.2
ends its random in RFC 8446's downgrade sentinel, which a client that
offered TLS 1.3 refuses. It also refuses `TLS_FALLBACK_SCSV` from a client
that could do better.

| | Client | Server |
|---|---|---|
| Suites | `cfg.suites12`, Go's defaults: ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, AES-128-CBC-SHA and AES-256-CBC-SHA | its own order, for its key (ECDSA suites for EC and Ed25519 keys, RSA ones for RSA); the CBC-SHA256 suites and RSA key exchange (`TLS_RSA_WITH_*`) only when added, as in Go |
| Key exchange | X25519, P-256, P-384, P-521; the ServerKeyExchange signature checked against the certificate | its first ECDH group the client takes; RSA key exchange decrypts in constant time and goes on with a random premaster secret when the ciphertext is bad |
| Signatures | RSA-PSS, RSA PKCS #1 v1.5, ECDSA (any of its hashes on any curve, as TLS 1.2 allows), Ed25519; no SHA-1, as Go since 1.25 | the client's first scheme its key signs with |
| Master secret | extended (RFC 7627) when both take it; a session keeps what it had | the same |
| Resumption | session tickets (RFC 5077): `tls::session(c)` is a TLS 1.2 session after a TLS 1.2 handshake, offered again in session_ticket | stateless tickets under `cfg.ticket_key`, a new one on each resumption |
| Client certificates | sent when the server asks for its key's type and scheme and, if it names CAs, one of them issued it | Go's five modes, as in TLS 1.3 |
| Renegotiation | refused: secure renegotiation's extension is sent, and a HelloRequest gets a `no_renegotiation` warning | a ClientHello after the handshake gets the same warning |

The records are TLS 1.2's: AES-GCM with an explicit nonce (the sequence
number, as Go and OpenSSL send it), ChaCha20-Poly1305 (RFC 7905), and
AES-CBC with HMAC-SHA1 or HMAC-SHA256, MAC-then-encrypt, with a random IV
per record. CBC padding is checked in constant time, and the MAC is
computed over the same length whatever the padding says, with the
padding hashed after it, as Go does against Lucky13. TLS 1.2's warning
alerts are dropped, as Go drops them, and KeyUpdate is TLS 1.3's alone. ECH
is TLS 1.3's too: a client that offers it offers nothing older.

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
anything else. For TLS 1.2: `prf12`, `master_secret12` (extended or not),
`key_block12`, `finished12` and `export12` (RFC 5705).

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
while more bytes are needed. `record_keys12(suite, key, mac_key, iv)`
gives TLS 1.2 keys from the key block's parts, and the same two calls
then protect TLS 1.2 records.

## Standards

What this package implements, and where in it. The drafts are the
versions Go 1.27 and OpenSSL 3.6 interoperate with.

| Specification | What | Where |
|---|---|---|
| RFC 8446 | TLS 1.3: handshake, HelloRetryRequest, key schedule, record protection, KeyUpdate, PSK resumption (psk_dhe_ke), middlebox compatibility mode, signature schemes, the downgrade sentinel (§4.1.3) | `tls.handshake`, `tls.schedule`, `tls.record`, `tls.session` |
| RFC 8448 | TLS 1.3 example handshake traces, reproduced byte for byte | `test/rfc8448.goose` |
| RFC 5246 | TLS 1.2: handshake, PRF, key block, Finished, record protection | `tls.handshake12`, `tls.schedule`, `tls.record` |
| RFC 8422 (obsoletes RFC 4492) | ECDHE and ECDSA/EdDSA for TLS 1.2: ServerKeyExchange, named groups, point formats, Ed25519 certificates | `tls.handshake12` |
| RFC 5288, RFC 5289 | AES-GCM suites for TLS 1.2 (explicit nonce), and the ECDHE GCM and CBC-SHA256 suites | `tls`, `tls.record` |
| RFC 7905 | ChaCha20-Poly1305 suites for TLS 1.2 | `tls`, `tls.record` |
| RFC 7627 | Extended master secret, and its rules for resumption (§5.3) | `tls.schedule`, `tls.handshake12` |
| RFC 5077 | Session tickets for TLS 1.2, stateless on the server | `tls.handshake12`, `tls.session` |
| RFC 5746 | Secure renegotiation: renegotiation_info and its SCSV (renegotiation itself is refused) | `tls.handshake12` |
| RFC 7507 | TLS_FALLBACK_SCSV | `tls.handshake12` |
| RFC 5705 | Keying material exporter for TLS 1.2 (`export12`; TLS 1.3's is RFC 8446 §7.5) | `tls.schedule` |
| RFC 6066 §3 | Server Name Indication | `tls.handshake` |
| RFC 7301 | ALPN | `tls.handshake` |
| RFC 9849 | Encrypted Client Hello, client and server, with HelloRetryRequest and retry configs | `tls.ech`, `tls.handshake` |
| RFC 9180 | HPKE, the encryption under ECH | `tls.ech`, through `bignum.hpke` |
| draft-ietf-tls-ecdhe-mlkem | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | `tls.handshake` |
| draft-ietf-tls-mlkem | MLKEM1024 alone | `tls.handshake` |
| draft-ietf-tls-mldsa | ML-DSA-44/65/87 signature schemes (TLS 1.3 only) | `tls.handshake` |

Under these, the other packages supply the primitives and certificates:
X25519 (RFC 7748), Ed25519 (RFC 8032), ECDSA on P-256, P-384 and P-521
(FIPS 186-5), RSA PKCS #1 v1.5 and PSS (RFC 8017), HKDF (RFC 5869), HMAC
(RFC 2104), AES-GCM (SP 800-38D), ChaCha20-Poly1305 (RFC 8439), ML-KEM
(FIPS 203) and ML-DSA (FIPS 204) in bignum, and X.509 path validation
(RFC 5280) in x509.

Not implemented: 0-RTT early data (RFC 8446 §4.2.10), external PSKs,
post-handshake client authentication, GREASE (RFC 8701), encrypt-then-MAC
(RFC 7366, which Go does not do either), certificate compression (RFC
8879), record size limit (RFC 8449), OCSP stapling and SCTs, TLS 1.1 and
older, and renegotiation.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
python3 scripts/live_interop.py         # live, against OpenSSL (below)
python3 scripts/go_interop.py           # live, against Go's crypto/tls (below)
python3 scripts/gen_handshake.py        # remake vectors/hs_certs.txt
python3 scripts/openssl_interop.py      # recapture vectors of OpenSSL's connections
python3 scripts/rfc8448.py              # re-extract RFC 8448's trace (fetches the RFC)
tools/gointerop.sh <mode> ...           # Go's side by hand (modes in tools/gointerop/main.go)
```

They take the compiler from `--goose`, `$GOOSE`, `goose` on PATH or
`../goose.git/build/goose`, and asn1goose.git, bigmongoose.git and
x509goose.git beside this repository. The live scripts run everything on
127.0.0.1 and leave nothing running; go_interop.py needs Go (standard
library only).

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

- `resumption`: a session from a full handshake resumes:
  - under its suite and another of its hash, from a resumed connection's
    own ticket, after a HelloRetryRequest, and from session bytes;
  - with a full handshake instead under another hash, another ticket key,
    a server without tickets, a ticket too old or changed;
  - is not offered expired or for another name;
  - a changed binder is refused.

- `client_auth`: client certificates under each of the five modes:
  - requested or not, required or not, checked or not;
  - with P-256, P-384, Ed25519, RSA (RSA-PSS), ML-DSA-44 and ML-DSA-65
    keys;
  - refused for server authentication only, for an unknown CA, and for a
    key that is not the certificate's;
  - not sent when the server names other CAs;
  - carried over by resumption, or a full handshake under Go's rules for
    tickets.

- `ech`: ECH accepted:
  - with each KEM;
  - after a HelloRetryRequest, also when resuming;
  - with ALPN, a client certificate, and resumption.

  Not accepted:
  - a server without keys, with another key (whose retry configs then
    work), or without retry configs;
  - a changed payload;
  - a certificate request answered with none;
  - a public name the certificate does not cover.

  Picking configs past unknown versions, mandatory extensions and invalid
  names, and the padding.

- `tls12`: TLS 1.2 between this client and server:
  - every suite with each key type it takes (Ed25519, P-256, P-384, P-521,
    RSA, and RSA key exchange) and every group, with data many records
    long; RSA key exchange and CBC-SHA256 off by default; no suite for an
    ML-DSA server;
  - versions: TLS 1.3 by default, TLS 1.2 when either side stops there,
    none when they do not meet; the downgrade sentinel, set and refused;
    TLS_FALLBACK_SCSV;
  - resumption with tickets: resumed twice, from session bytes, a full
    handshake under another ticket key, without tickets, for a suite the
    client dropped, under TLS 1.3, or expired;
  - client certificates (P-256, Ed25519; ML-DSA not usable), required,
    missing, refused, and carried over by resumption; ALPN;
  - a wrong name, an unknown root; renegotiation refused both ways while
    data keeps flowing; a changed record under GCM, ChaCha20-Poly1305 and
    CBC.

`scripts/live_interop.py` runs live connections against OpenSSL (179
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
- resumption both ways, also after a HelloRetryRequest: the first
  connection full and the second resumed, by both sides' account;
- client certificates both ways: this client's (P-256, Ed25519, ML-DSA-44)
  to an OpenSSL server that requires one, none where one is optional or
  required, and one OpenSSL refuses; an OpenSSL client's to this server,
  checked, missing, unchecked, or refused for its usage or CA;
- roots from a directory; an untrusted root, the system's roots (which lack
  the test root), and a wrong name;
- TLS 1.2 both ways: every suite (ECDHE-ECDSA with Ed25519, P-256, P-384
  and P-521 certificates, ECDHE-RSA and RSA key exchange, with GCM,
  ChaCha20-Poly1305 and CBC), each group; version negotiation against an
  OpenSSL that stops at either version; resumption with tickets, also
  without the extended master secret; client certificates; ALPN.

`scripts/go_interop.py` runs this package against Go's crypto/tls
(`tools/gointerop`, standard library only; `tools/gointerop.sh` runs it
by hand) over sockets on 127.0.0.1.
It checks resumption both ways: this client with a Go server's ticket, and
a Go client with a session cache against this server. Both sides must
report the second connection resumed. The same runs again with client
certificates, which each server requires and checks, so they must survive
resumption.

ECH runs both ways for "localhost" behind the public name "example.com",
16 cases:
- accepted with X25519, P-256, MLKEM768-X25519 and ML-KEM-1024 keys, and
  after a HelloRetryRequest, both sides reporting it, and the Go server
  seeing the inner name;
- refused with another key, each client getting the other server's
  retry configs.

TLS 1.2 runs both ways too, 32 cases: ECDHE with P-256, P-384, P-521,
Ed25519 and RSA certificates under AES-GCM, ChaCha20-Poly1305 and
AES-CBC, and RSA key exchange, each resumed with a ticket; client
certificates carried over by resumption; and either side stopping at TLS
1.2 while the other takes TLS 1.3 too. 48 cases in all.

Live, this client's ECH was also accepted by crypto.cloudflare.com,
tls-ech.dev (whose page reports "You are using ECH") and defo.ie, with
configs from their DNS HTTPS records. Pinned to TLS 1.2, it got HTTP
answers from www.google.com, cloudflare.com, github.com, www.amazon.com,
www.apple.com, www.facebook.com, www.bing.com and badssl.com's TLS 1.2,
RSA and ECC hosts, under ECDHE-ECDSA and ECDHE-RSA with AES-GCM.

The compiler is found as in bignum: `--goose`, `$GOOSE`, `goose` on PATH,
then `../goose.git/build/goose`.
