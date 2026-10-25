# tls

TLS 1.3 (RFC 8446) for the Goose language, on the primitives of
[bignum](../bigmongoose.git). So far it has the key schedule and the record
layer. The handshake state machine comes next. Nothing here does I/O: all
functions work on byte strings, and the caller moves the bytes.

- **`tls`**: cipher suites (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`), content,
  handshake and alert constants.
- **`tls.schedule`**: HKDF-Expand-Label, Derive-Secret, the early,
  handshake and master secrets and the traffic secrets derived from them,
  traffic keys, Finished, KeyUpdate, exporters, resumption PSKs and binder
  keys, and a running transcript hash, including the HelloRetryRequest
  restart.
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

The compiler is found as in bignum: `--goose`, `$GOOSE`, `goose` on PATH,
then `../goose.git/build/goose`.
