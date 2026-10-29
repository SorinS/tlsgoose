// tls.handshake: TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246, in
// tls.handshake12) connections, client and server, without I/O. A Conn
// holds one connection's state; feed it the bytes that arrive, and it
// appends the bytes to send and the application data received to
// builders the caller owns.
//
//   var c = tls::client(cfg);
//   tls::client_start(c, cfg, out);                  // the ClientHello
//   ... send out, receive into input ...
//   tls::client_feed(c, cfg, input, out, app);       // until tls::connected(c)
//   tls::send(c, "GET / HTTP/1.1\r\n...", out);
//
// Supported: the three cipher suites; the post-quantum X25519MLKEM768,
// SecP256r1MLKEM768, SecP384r1MLKEM1024 and MLKEM1024, and X25519, P-256,
// P-384 and P-521 key exchange with
// HelloRetryRequest; server certificates checked by x509
// (chain, host name, CertificateVerify) with RSA-PSS, RSA PKCS #1 v1.5,
// ECDSA, Ed25519 and ML-DSA; client certificates, requested and checked as
// Go's ClientAuth modes do; Encrypted Client Hello (tls.ech) both ways; ALPN; KeyUpdate; middlebox compatibility mode;
// resumption with tickets (psk_dhe_ke, tls.session). TLS 1.2 too, as Go
// has it, negotiated with TLS 1.3 by default (min_version, max_version):
// ECDHE with ECDSA, Ed25519 or RSA certificates, RSA key exchange when
// its suites are configured, AES-GCM, ChaCha20-Poly1305 and AES-CBC,
// extended master secret, secure renegotiation's extension (renegotiation
// itself is refused), session tickets, client certificates, and the
// downgrade protection of RFC 8446 §4.1.3.
// Not supported: 0-RTT, external PSKs, post-handshake client
// authentication, and TLS below 1.2.

namespace tls;

import std;
import os;
import tls;
import schedule;
import record;
import bignum;
import bignum.x25519;
import bignum.ec;
import bignum.ed25519;
import bignum.rsa;
import bignum.mlkem;
import bignum.hmac;
import bignum.entropy;
import asn1;
import x509;
import x509.verify;
import x509.pool;
import x509.keys;
import session;
import ech;
import handshake12;

// Named groups and the signature schemes this package signs and verifies.
let GROUP_SECP256R1: u16 = 0x0017;
let GROUP_SECP384R1: u16 = 0x0018;
let GROUP_SECP521R1: u16 = 0x0019;
let GROUP_X25519: u16 = 0x001d;
// The hybrid of ML-KEM-768 and X25519 (draft-ietf-tls-ecdhe-mlkem), Go's
// and OpenSSL's first choice.
let GROUP_X25519MLKEM768: u16 = 0x11ec;
// The NIST hybrids of the same draft, and ML-KEM-1024 alone
// (draft-ietf-tls-mlkem), as Go has them.
let GROUP_SECP256R1MLKEM768: u16 = 0x11eb;
let GROUP_SECP384R1MLKEM1024: u16 = 0x11ed;
let GROUP_MLKEM1024: u16 = 0x0202;

// Extension types.
let EXT_SERVER_NAME: u16 = 0;
let EXT_SUPPORTED_GROUPS: u16 = 10;
let EXT_SIGNATURE_ALGORITHMS: u16 = 13;
let EXT_ALPN: u16 = 16;
let EXT_SUPPORTED_VERSIONS: u16 = 43;
let EXT_COOKIE: u16 = 44;
let EXT_KEY_SHARE: u16 = 51;
let EXT_PRE_SHARED_KEY: u16 = 41;
let EXT_EARLY_DATA: u16 = 42;
let EXT_PADDING: u16 = 21;
let EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
let EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
// TLS 1.2's: point formats (RFC 8422), extended master secret (RFC 7627),
// session tickets (RFC 5077), secure renegotiation (RFC 5746).
let EXT_EC_POINT_FORMATS: u16 = 11;
let EXT_EXTENDED_MASTER_SECRET: u16 = 23;
let EXT_SESSION_TICKET: u16 = 35;
let EXT_RENEGOTIATION_INFO: u16 = 0xff01;
let PSK_DHE_KE: u8 = 1;

// What a server asks of clients (ServerConfig.client_auth), as Go's
// ClientAuthType: no certificate; one requested, not checked; one
// required, not checked; one checked if given; one required and checked.
// Checked, it must lead to one of the client CAs and allow client
// authentication. A client that sends a certificate always proves it has
// its key (CertificateVerify).
let NO_CLIENT_CERT: i64 = 0;
let REQUEST_CLIENT_CERT: i64 = 1;
let REQUIRE_ANY_CLIENT_CERT: i64 = 2;
let VERIFY_CLIENT_CERT_IF_GIVEN: i64 = 3;
let REQUIRE_AND_VERIFY_CLIENT_CERT: i64 = 4;

// Connection states.
let ST_START: i64 = 0;
let ST_WAIT_SH: i64 = 1;
let ST_WAIT_EE: i64 = 2;
let ST_WAIT_CERT_CR: i64 = 3;
let ST_WAIT_CERT: i64 = 4;
let ST_WAIT_CV: i64 = 5;
let ST_WAIT_FINISHED: i64 = 6;
let ST_WAIT_CH: i64 = 10;
let ST_WAIT_CH2: i64 = 11;
let ST_WAIT_CLIENT_FINISHED: i64 = 12;
let ST_WAIT_CLIENT_CERT: i64 = 13;
let ST_WAIT_CLIENT_CV: i64 = 14;
// TLS 1.2's: the client waits for the server's Certificate,
// ServerKeyExchange, CertificateRequest or ServerHelloDone,
// ServerHelloDone, change_cipher_spec (or NewSessionTicket) and Finished;
// the server for the client's Certificate, ClientKeyExchange,
// CertificateVerify, change_cipher_spec and Finished.
let ST12_WAIT_CERT: i64 = 30;
let ST12_WAIT_SKE: i64 = 31;
let ST12_WAIT_CR_SHD: i64 = 32;
let ST12_WAIT_SHD: i64 = 33;
let ST12_WAIT_CCS: i64 = 34;
let ST12_WAIT_FINISHED: i64 = 35;
let ST12_WAIT_CLIENT_CERT: i64 = 40;
let ST12_WAIT_CKE: i64 = 41;
let ST12_WAIT_CLIENT_CV: i64 = 42;
let ST12_WAIT_CLIENT_CCS: i64 = 43;
let ST12_WAIT_CLIENT_FINISHED: i64 = 44;
let ST_CONNECTED: i64 = 20;
let ST_CLOSED: i64 = 21;              // the peer sent close_notify
let ST_FAILED: i64 = 22;              // an alert was sent or received

// SHA-256("HelloRetryRequest"), the random of a HelloRetryRequest.
let HRR_RANDOM: u8[32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

// The signature schemes offered and accepted, most preferred first: ML-DSA
// (draft-ietf-tls-mldsa) first, as Go has them.
let SIG_SCHEMES: u16[13] = [0x0904, 0x0905, 0x0906, 0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806,
                            0x0401, 0x0501, 0x0601];

// A handshake message's body, at most (Go's maxHandshake); its 4-byte header
// comes on top.
let MAX_HANDSHAKE: i64 = 65536;

// Records in a row that carry nothing (empty, or TLS 1.2 warning
// alerts) before the connection ends, as Go's maxUselessRecords.
let MAX_USELESS_RECORDS: i64 = 16;

// How much refused 0-RTT data the server skips (RFC 8446 §4.2.10).
let MAX_EARLY_SKIP: i64 = 1 << 16;

// What a client needs: the name it connects to (SNI and the certificate
// check), whether to check the certificate, the time for that check (0:
// now), the versions it takes (TLS 1.2 and 1.3 by default, as Go), its
// groups (the first gets a key share), TLS 1.3 and TLS 1.2 suites and ALPN
// protocols, a DRBG seed for tests (0: the OS's entropy), a session to
// resume (from tls::session of an earlier connection; none when its
// ticket is empty), a certificate chain (concatenated DER, the leaf first;
// none when empty) and its key for servers that ask for one (set with
// set_client_certificate), an ECHConfigList to encrypt the ClientHello
// under (Go's EncryptedClientHelloConfigList; none when empty), and the
// trusted roots: the system's
// (x509::system_roots), or a pool of its own when system_roots is false.
struct ClientConfig {
    server_name: u8[..255], verify: bool, now: i64, min_version: u16, max_version: u16,
    groups: u16[..8], suites: u16[..8], suites12: u16[..24], alpn: u8[..255], seed: u64,
    session: Session,
    cert_key: x509::PrivateKey, cert_chain: u8[..65536],
    ech_config_list: u8[..8192],
    system_roots: bool,
    roots: x509::CertPool,
}

// A client trusting the given roots (DER certificates concatenated), or,
// as Go does with no RootCAs, the system's when there are none.
fn client_config(server_name: const u8[:], roots: const u8[:]) -> ClientConfig {
    var c = ClientConfig {
        server_name: [], verify: true, now: 0, min_version: VERSION_TLS12, max_version: VERSION_TLS13,
        groups: [GROUP_X25519MLKEM768, GROUP_SECP256R1MLKEM768, GROUP_SECP384R1MLKEM1024, GROUP_X25519,
                 GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1],
        suites: [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256],
        suites12: [], alpn: [], seed: 0, session: no_session(), cert_key: x509::empty_key(), cert_chain: [], ech_config_list: [],
        system_roots: roots.len == 0, roots: x509::new_pool(),
    };
    c.server_name.append(server_name);
    c.suites12.append(DEFAULT_SUITES12);
    let ok = x509::pool_add_concatenated(c.roots, roots);
    return c;
}

// A client trusting the roots of a pool (built from files or a directory
// with x509::pool_add_file and pool_add_dir, say), and not the system's.
fn client_config_pool(server_name: const u8[:], roots: const x509::CertPool&) -> ClientConfig {
    var c = client_config(server_name, "");
    c.system_roots = false;
    c.roots = copy(roots);
    return c;
}

// The certificate the client sends when asked for one: a chain
// (concatenated DER, the leaf first) and its private key in DER, as
// server_config takes them. It is sent when the server accepts a scheme
// its key signs with and, if the server names the CAs it accepts, one of
// its certificates was issued by one of them (as Go picks one); otherwise
// the client sends none. False if the key does not parse.
fn set_client_certificate(cfg: ClientConfig&, chain: const u8[:], key_der: const u8[:]) -> bool {
    let k, ok = x509::parse_private_key(key_der);
    if !ok || chain.len > cfg.cert_chain.cap { return false; }
    cfg.cert_key = k;
    cfg.cert_chain.clear();
    cfg.cert_chain.append(chain);
    return true;
}

// Adds an ECH key (Go's EncryptedClientHelloKey): an ECHConfig as clients
// have it (from generate_ech_key, say) and its HPKE private key; with
// `send_as_retry`, the config is among the retry configs a client whose
// ECH was not accepted gets. False if the config is not one or there is
// no room.
fn add_ech_key(cfg: ServerConfig&, config: const u8[:], private_key: const u8[:], send_as_retry: bool) -> bool {
    let kem, id, ok = ech_server_config(config);
    if !ok || !bignum::hpke_kem_ok(kem) || cfg.ech_keys.len + 5 + config.len + private_key.len > cfg.ech_keys.cap {
        return false;
    }
    var b: u8[>..] = [];
    put_u16(b, config.len as! u16);
    b.append(config);
    put_u16(b, private_key.len as! u16);
    b.append(private_key);
    b.push(if send_as_retry { 1 } else { 0 });
    cfg.ech_keys.append(b);
    return true;
}

// Adds a protocol to an ALPN list (wire format: length-prefixed names).
fn add_alpn(list: u8[..255]&, proto: const u8[:]) {
    assert(proto.len > 0 && proto.len < 256 && list.len + 1 + proto.len <= 255);
    list.push(proto.len as! u8);
    list.append(proto);
}

// What a server needs: its private key (one of x509's KEY_* types), the
// versions it takes (TLS 1.2 and 1.3 by default), its groups, TLS 1.3 and
// TLS 1.2 suites (the RSA key exchange ones only if added, as in Go) and
// ALPN protocols in order of preference, a DRBG seed,
// the time (0: now), how many session tickets to send after a handshake
// (Go's one by default; 0 for none, which also refuses resumption) and the
// key that seals them (random; give every server that should resume the
// others' sessions the same one), its certificate chain as concatenated
// DER, the leaf first, what it asks of clients (NO_CLIENT_CERT, ...), and
// the CAs it accepts client certificates from: named to clients in the
// request, and the roots their chains are checked against (the system's
// when there are none, as Go does), and its ECH keys (add_ech_key).
struct ServerConfig {
    key: x509::PrivateKey, min_version: u16, max_version: u16,
    groups: u16[..8], suites: u16[..8], suites12: u16[..24], alpn: u8[..255], seed: u64, now: i64,
    tickets: i64, ticket_key: u8[32],
    chain: u8[..65536],
    client_auth: i64,
    ech_keys: u8[..16384],            // each: config (u16 length), private key (u16 length), send as retry (u8)
    client_cas: x509::CertPool,
}

// A server configuration from a chain (concatenated DER) and a private key
// in DER: PKCS #8 (RSA, EC or Ed25519), SEC 1 (EC) or PKCS #1 (RSA).
fn server_config(chain: const u8[:], key_der: const u8[:]) -> ServerConfig, bool {
    let k, ok = x509::parse_private_key(key_der);
    var s = ServerConfig {
        key: k, min_version: VERSION_TLS12, max_version: VERSION_TLS13,
        groups: [GROUP_X25519MLKEM768, GROUP_SECP256R1MLKEM768, GROUP_SECP384R1MLKEM1024, GROUP_X25519,
                 GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1],
        suites: [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256],
        suites12: [], alpn: [], seed: 0, now: 0, tickets: 1, ticket_key: [0; 32], chain: [],
        client_auth: NO_CLIENT_CERT, ech_keys: [], client_cas: x509::new_pool(),
    };
    bignum::random_bytes(s.ticket_key);
    s.suites12.append(DEFAULT_SUITES12);
    if chain.len > s.chain.cap { return s, false; }
    s.chain.append(chain);
    return s, ok;
}

// One connection, either side.
struct Conn {
    is_server: bool, state: i64,
    version: u16,                     // the version negotiated (0 until known)
    alert: u8,                        // the alert sent on failure, or received
    error: i64,                       // the x509 error behind a certificate alert
    suite: Suite, sch: Schedule, th: Transcript,
    read: RecordKeys, write: RecordKeys, read_protected: bool, write_protected: bool,
    drbg_k: u8[32], drbg_v: u8[32],
    random: u8[32], session_id: u8[..32],
    group: u16, group2: u16,          // the share's group, and a second share's (X25519 beside the hybrid)
    x25519_sk: u8[32], ec_sk: u8[..66], mlkem_seed: u8[64],
    hrr: bool, ccs_sent: bool, cert_requested: bool, cr_context: u8[..255],
    ccs_seen: bool,                   // TLS 1.3: the peer's one change_cipher_spec came
    useless: i64,                     // records in a row that carried nothing (warnings, empty data)
    skip_early: bool, early_skipped: i64,  // the server skips the 0-RTT data it refused, and how much
    ch1_digest: u8[32],               // the server's: what of the first ClientHello the second must repeat
    client_version: u16,              // TLS 1.2 server: the ClientHello's legacy_version, for RSA's premaster secret

    cert_scheme: u16,                 // the client's: the scheme of its CertificateVerify (0: no certificate)
    peer_verified: bool,              // the peer's certificate was checked against the roots
    peer_schemes: u16[..32], alpn: u8[..255], sni: u8[..255],
    tickets: i64, key_updates: i64,
    psk_offered: bool, resumed: bool,  // the client offered its session; the PSK was accepted
    psk_dhe: bool,                     // the client allows psk_dhe_ke, so takes tickets
    peer_not_after: i64,               // the server certificate's notAfter, for sessions (0: unchecked)
    has_session: bool, session: Session,   // the client's latest ticket
    // ECH: the client offered it, the server got a ClientHello with it,
    // the server confirms an inner ClientHello (it decrypted it, or it got
    // one as a backend server), it was accepted; the HPKE context and
    // suite, the config's id, maximum name length and public name, the
    // encapsulated key, the outer random, and the retry configs the
    // client got.
    ech_offered: bool, ech_seen: bool, ech_confirm: bool, ech_accepted: bool, ech_backend: bool,
    ech_ctx: bignum::HpkeContext, ech_kdf: u16, ech_aead: u16, ech_config_id: u8, ech_max_name: i64,
    ech_public_name: u8[..255], ech_enc: u8[..2048], outer_random: u8[32], ech_retry: u8[..8192],
    th_inner: Transcript,             // the client's inner transcript
    // TLS 1.2: the client offers TLS 1.2 and 1.3, and its TLS 1.2 session;
    // the master secret, extended or not; the peer's random; the peer
    // supports secure renegotiation; a NewSessionTicket comes (the
    // client's view) or goes (the server's); the server's ECDH share; and
    // the handshake messages so far, which CertificateVerify signs (log_over
    // once they no longer fit).
    offer12: bool, offer13: bool, session12_offered: bool,
    master: u8[..48], ems: bool, peer_random: u8[32], secure_reneg: bool, ticket12: bool,
    peer_share: u8[..256], log_over: bool,
    log: u8[..131072],
    ch_inner: u8[..8192],             // the client's first ClientHelloInner, until the hash is known
    ch: u8[..8192],                   // the client's first ClientHello, until the hash is known
    inbuf: u8[..18437],               // one record in arrival
    hs: u8[..65540],                  // handshake messages being reassembled: MAX_HANDSHAKE and a header
    chain: u8[..65536],               // the peer's certificates, DER concatenated, leaf first
}

fn suite_none() -> Suite { let s, ok = suite(TLS_AES_128_GCM_SHA256); return s; }

fn new_conn(is_server: bool, seed: u64) -> Conn {
    let s = suite_none();
    var zero: u8[32] = [0; 32];
    var c = Conn {
        is_server: is_server, state: if is_server { ST_WAIT_CH } else { ST_START }, version: 0, alert: 0, error: 0,
        suite: s, sch: schedule(256, ""), th: transcript(256),
        read: record_keys(s, zero), write: record_keys(s, zero), read_protected: false, write_protected: false,
        drbg_k: [0; 32], drbg_v: [1; 32], random: [0; 32], session_id: [],
        group: 0, group2: 0, x25519_sk: [0; 32], ec_sk: [], mlkem_seed: [0; 64], hrr: false, ccs_sent: false, cert_requested: false,
        ccs_seen: false, useless: 0, skip_early: false, early_skipped: 0, ch1_digest: [0; 32], client_version: 0,
        cr_context: [], cert_scheme: 0, peer_verified: false, peer_schemes: [], alpn: [], sni: [], tickets: 0, key_updates: 0,
        psk_offered: false, resumed: false, psk_dhe: false, peer_not_after: 0, has_session: false, session: no_session(),
        ech_offered: false, ech_seen: false, ech_confirm: false, ech_accepted: false, ech_backend: false,
        ech_ctx: bignum::hpke_empty_context(), ech_kdf: 0, ech_aead: 0, ech_config_id: 0, ech_max_name: 0,
        ech_public_name: [], ech_enc: [], outer_random: [0; 32], ech_retry: [], th_inner: transcript(256),
        offer12: false, offer13: false, session12_offered: false, master: [], ems: false, peer_random: [0; 32],
        secure_reneg: false, ticket12: false, peer_share: [], log_over: false, log: [],
        ch_inner: [], ch: [], inbuf: [], hs: [], chain: [],
    };
    var seed_bytes: u8[32] = [0; 32];
    if seed == 0 {
        bignum::random_bytes(seed_bytes);
    } else {
        for i in 8 { seed_bytes[i] = (seed >> (8 * i)) as! u8; }
    }
    drbg_update(c, seed_bytes);
    return c;
}

// HMAC-DRBG with SHA-256 (SP 800-90A), for every random value a
// connection needs.
fn drbg_update(c: Conn&, data: const u8[:]) {
    for round in 2 {
        var m: u8[>..] = [];
        m.append(c.drbg_v);
        m.push(round as! u8);
        m.append(data);
        let k = bignum::hmac_sha256(c.drbg_k, m);
        for i in 32 { c.drbg_k[i] = k[i]; }
        let v = bignum::hmac_sha256(c.drbg_k, c.drbg_v);
        for i in 32 { c.drbg_v[i] = v[i]; }
        if data.len == 0 { break; }
    }
}

fn drbg_fill(c: Conn&, out: u8[:]) {
    var off = 0;
    while off < out.len {
        let v = bignum::hmac_sha256(c.drbg_k, c.drbg_v);
        for i in 32 { c.drbg_v[i] = v[i]; }
        let n = ::min(32, out.len - off);
        for i in n { out[off + i] = v[i]; }
        off += n;
    }
    drbg_update(c, "");
}

// The time, in milliseconds: the configuration's (seconds), else now.
fn now_ms(configured: i64) -> i64 { if configured != 0 { configured * 1000 } else { time_ns() / 1000000 } }

fn client(cfg: const ClientConfig&) -> Conn { new_conn(false, cfg.seed) }
fn server(cfg: const ServerConfig&) -> Conn { new_conn(true, cfg.seed) }

fn connected(c: const Conn&) -> bool { c.state == ST_CONNECTED }

// The version negotiated: VERSION_TLS13 or VERSION_TLS12 (0 before the
// hellos are done).
fn version(c: const Conn&) -> u16 { c.version }

// Whether the connection resumed a session (no certificates were sent).
fn resumed(c: const Conn&) -> bool { c.resumed }

// The client's latest session ticket, to resume with later (set it as
// ClientConfig.session); false before the server has sent one.
fn session(c: const Conn&) -> Session, bool { return c.session, c.has_session; }
// The peer's certificates, DER concatenated, the leaf first: the server's,
// or the client's (also carried over by resumption); empty for none.
fn peer_certificates(c: const Conn&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(c.chain);
    return out;
}

// Whether the peer's certificate was checked against the trusted roots
// (for a client's, by a server that verifies them).
fn peer_verified(c: const Conn&) -> bool { c.peer_verified }

// Whether ECH was accepted: the server took the inner ClientHello. A
// client whose ECH was not accepted fails with ech_required once the
// handshake with the public name is done; ech_retry_configs then has the
// configs the server sent for a retry (empty for none).
fn ech_accepted(c: const Conn&) -> bool { c.ech_accepted }

fn ech_retry_configs(c: const Conn&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(c.ech_retry);
    return out;
}

fn failed(c: const Conn&) -> bool { c.state == ST_FAILED }
fn closed(c: const Conn&) -> bool { c.state == ST_CLOSED }

// --- Encoding helpers -------------------------------------------------------

fn put_u16(out: u8[>..]&, v: u16) { out.push((v >> 8) as! u8); out.push(v as! u8); }

// Patches the length of a vector whose `n`-byte length field starts at
// `mark`, to cover everything appended after it.
fn patch_len(out: u8[>..]&, mark: i64, n: i64) {
    let len = out.len - mark - n;
    for i in n { out[mark + i] = (len >> (8 * (n - 1 - i))) as! u8; }
}

fn begin_vec(out: u8[>..]&, n: i64) -> i64 {
    let mark = out.len;
    for i in n { out.push(0); }
    return mark;
}

fn begin_ext(out: u8[>..]&, ty: u16) -> i64 {
    put_u16(out, ty);
    return begin_vec(out, 2);
}

// A reader over [pos, end) of a message; `bad` sticks once it overruns.
struct Rd { pos: i64, end: i64, bad: bool }

fn rd(m: const u8[:]) -> Rd { Rd { pos: 0, end: m.len, bad: false } }

fn get_u8(r: Rd&, m: const u8[:]) -> i64 {
    if r.pos + 1 > r.end { r.bad = true; return 0; }
    r.pos++;
    return m[r.pos - 1];
}

fn get_u16(r: Rd&, m: const u8[:]) -> i64 { let a = get_u8(r, m); return a << 8 | get_u8(r, m); }
fn get_u24(r: Rd&, m: const u8[:]) -> i64 { let a = get_u16(r, m); return a << 8 | get_u8(r, m); }

// The next n bytes as a sub-reader.
fn get_bytes(r: Rd&, n: i64) -> Rd {
    if n < 0 || r.pos + n > r.end { r.bad = true; return Rd { pos: r.end, end: r.end, bad: true }; }
    let sub = Rd { pos: r.pos, end: r.pos + n, bad: false };
    r.pos += n;
    return sub;
}

// A vector with an `n`-byte length.
fn get_vec(r: Rd&, m: const u8[:], n: i64) -> Rd {
    var len = 0;
    for i in n { len = len << 8 | get_u8(r, m); }
    if r.bad { return Rd { pos: r.end, end: r.end, bad: true }; }
    return get_bytes(r, len);
}

fn done(r: const Rd&) -> bool { !r.bad && r.pos == r.end }

// --- Sending ----------------------------------------------------------------

// Sends a handshake message: into the transcript, then into a record.
fn send_hs(c: Conn&, msg: const u8[:], out: u8[>..]&) {
    transcript_add(c.th, msg);
    if c.version == VERSION_TLS12 { log_add(c, msg); }
    if c.write_protected {
        out.append(seal_records(c.write, CT_HANDSHAKE, msg));
    } else {
        // 0x0301 only on the first ClientHello (§5.1), which does not come
        // here; a second one after a HelloRetryRequest has 0x0303, as Go
        // insists.
        out.append(plain_record(CT_HANDSHAKE, msg, 0x0303));
    }
}

// TLS 1.2's record of the handshake messages, for CertificateVerify.
fn log_add(c: Conn&, msg: const u8[:]) {
    if c.log.len + msg.len > c.log.cap { c.log_over = true; return; }
    c.log.append(msg);
}

// A received handshake message, into the transcript (and TLS 1.2's log).
fn hs_add(c: Conn&, msg: const u8[:]) {
    transcript_add(c.th, msg);
    if c.version == VERSION_TLS12 { log_add(c, msg); }
}

fn send_ccs(c: Conn&, out: u8[>..]&) {
    if c.ccs_sent { return; }
    let one: u8[1] = [1];
    out.append(plain_record(CT_CHANGE_CIPHER_SPEC, one));
    c.ccs_sent = true;
}

// Fails the connection: the alert goes out (protected when keys exist).
fn fail(c: Conn&, desc: u8, out: u8[>..]&) -> i64 {
    if c.state == ST_FAILED { return -1; }
    let a = alert(ALERT_FATAL, desc);
    if c.write_protected { out.append(seal_record(c.write, CT_ALERT, a)); }
    else { out.append(plain_record(CT_ALERT, a)); }
    c.alert = desc;
    c.state = ST_FAILED;
    return -1;
}

// Application data, as records.
fn send(c: Conn&, data: const u8[:], out: u8[>..]&) -> bool {
    if c.state != ST_CONNECTED { return false; }
    out.append(seal_records(c.write, CT_APPLICATION_DATA, data));
    return true;
}

// close_notify; the connection sends nothing after it.
fn close(c: Conn&, out: u8[>..]&) {
    if !c.write_protected || c.state == ST_FAILED { return; }
    let a = alert(ALERT_WARNING, ALERT_CLOSE_NOTIFY);
    out.append(seal_record(c.write, CT_ALERT, a));
    if c.state == ST_CONNECTED { c.state = ST_CLOSED; }
}

fn update_write(c: Conn&) {
    if c.is_server {
        set48(c.sch.s_ap, next_traffic_secret(c.suite.hash, c.sch.s_ap));
        c.write = record_keys(c.suite, c.sch.s_ap);
    } else {
        set48(c.sch.c_ap, next_traffic_secret(c.suite.hash, c.sch.c_ap));
        c.write = record_keys(c.suite, c.sch.c_ap);
    }
}

// Sends a KeyUpdate and moves to the next write keys; with `request`, the
// peer is asked to update its own.
fn key_update(c: Conn&, request: bool, out: u8[>..]&) -> bool {
    if c.state != ST_CONNECTED || c.version != VERSION_TLS13 { return false; }
    let body: u8[1] = [if request { 1 } else { 0 }];
    out.append(seal_record(c.write, CT_HANDSHAKE, handshake_message(HS_KEY_UPDATE, body)));
    update_write(c);
    return true;
}

// --- Key exchange -----------------------------------------------------------

fn curve_of(group: u16) -> bignum::Curve {
    if group == GROUP_SECP256R1 { bignum::p256() } else if group == GROUP_SECP384R1 { bignum::p384() } else { bignum::p521() }
}

// A group's ML-KEM parameter k (3 for ML-KEM-768, 4 for ML-KEM-1024), 0
// for none, and its ECDH part: the group itself for the classical ones, 0
// for MLKEM1024.
fn mlkem_k(group: u16) -> i64 {
    if group == GROUP_X25519MLKEM768 || group == GROUP_SECP256R1MLKEM768 { 3 }
    else if group == GROUP_SECP384R1MLKEM1024 || group == GROUP_MLKEM1024 { 4 } else { 0 }
}

fn ecdh_part(group: u16) -> u16 {
    if group == GROUP_X25519MLKEM768 { GROUP_X25519 }
    else if group == GROUP_SECP256R1MLKEM768 { GROUP_SECP256R1 }
    else if group == GROUP_SECP384R1MLKEM1024 { GROUP_SECP384R1 }
    else if group == GROUP_MLKEM1024 { 0 } else { group }
}

// The length of an ECDH share, and of ML-KEM's encapsulation key and
// ciphertext.
fn ecdh_len(g: u16) -> i64 {
    if g == 0 { 0 } else if g == GROUP_X25519 { 32 } else if g == GROUP_SECP256R1 { 65 }
    else if g == GROUP_SECP384R1 { 97 } else { 133 }
}

fn mlkem_ek_len(k: i64) -> i64 { 384 * k + 32 }
fn mlkem_ct_len(k: i64) -> i64 { if k == 3 { 1088 } else { 1568 } }

// A fresh ECDH key for group g (X25519 or a NIST curve); its public value.
fn make_ecdh(c: Conn&, g: u16) -> u8[>..] {
    if g == GROUP_X25519 {
        drbg_fill(c, c.x25519_sk);
        return bignum::x25519_base(c.x25519_sk);
    }
    let curve = curve_of(g);
    var sk: u8[>..] = [];
    sk.resize(curve.len, 0);
    loop {
        drbg_fill(c, sk);
        let k, ok = bignum::ec_scalar(curve, sk);
        if ok { break; }
    }
    c.ec_sk.clear();
    c.ec_sk.append(sk);
    return bignum::ec_public_key(curve, sk);
}

fn ecdh_public(c: const Conn&, g: u16) -> u8[>..] {
    if g == GROUP_X25519 { return bignum::x25519_base(c.x25519_sk); }
    let curve = curve_of(g);
    return bignum::ec_public_key(curve, c.ec_sk);
}

fn ecdh_secret(c: const Conn&, g: u16, peer: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if peer.len != ecdh_len(g) { return out, false; }
    if g == GROUP_X25519 {
        let s, ok = bignum::x25519_shared(c.x25519_sk, peer);
        out.append(s);
        return out, ok;
    }
    let curve = curve_of(g);
    let s, ok = bignum::ecdh_shared(curve, c.ec_sk, peer);
    out.append(s);
    return out, ok;
}

// Joins a hybrid's two parts as draft-ietf-tls-ecdhe-mlkem orders them:
// ML-KEM first for X25519MLKEM768, ECDH first for the NIST hybrids.
fn hybrid_join(group: u16, kem: const u8[:], ecdh: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if group == GROUP_X25519MLKEM768 { out.append(kem); out.append(ecdh); }
    else { out.append(ecdh); out.append(kem); }
    return out;
}

// Splits a hybrid share whose ML-KEM part is n bytes: the ML-KEM part,
// then the ECDH part.
fn hybrid_split(group: u16, share: const u8[:], n: i64) -> const u8[:], const u8[:] {
    if group == GROUP_X25519MLKEM768 { return share[..n], share[n..]; }
    let e = share.len - n;
    return share[e..], share[..e];
}

// A fresh share for `group`: the public value to send. A hybrid's is the
// ML-KEM encapsulation key and the ECDH public value; MLKEM1024's is the
// encapsulation key alone.
fn make_share(c: Conn&, group: u16) -> u8[>..] {
    c.group = group;
    let k = mlkem_k(group);
    if k == 0 { return make_ecdh(c, group); }
    drbg_fill(c, c.mlkem_seed);
    let ek, dk = bignum::mlkem_keys_from_seed(k, c.mlkem_seed);
    let g = ecdh_part(group);
    var e: u8[>..] = [];
    if g != 0 { e = make_ecdh(c, g); }
    return hybrid_join(group, ek, e);
}

// The shared secret from the peer's share, and false for a bad share. A
// client's for a hybrid: the ML-KEM secret of the server's ciphertext and
// the ECDH secret, in the share's order.
fn shared_secret(c: const Conn&, peer: const u8[:]) -> u8[>..], bool {
    let k = mlkem_k(c.group);
    if k == 0 { return ecdh_secret(c, c.group, peer); }
    let g = ecdh_part(c.group);
    var out: u8[>..] = [];
    if peer.len != mlkem_ct_len(k) + ecdh_len(g) { return out, false; }
    let ct, pe = hybrid_split(c.group, peer, mlkem_ct_len(k));
    let s1, ok1 = bignum::mlkem_decaps(k, c.mlkem_seed, ct);
    if g == 0 { out.append(s1); return out, ok1; }
    let s2, ok2 = ecdh_secret(c, g, pe);
    return hybrid_join(c.group, s1, s2), ok1 && ok2;
}

fn known_group(g: i64) -> bool {
    g == GROUP_X25519 || g == GROUP_SECP256R1 || g == GROUP_SECP384R1 || g == GROUP_SECP521R1 ||
        g == GROUP_X25519MLKEM768 || g == GROUP_SECP256R1MLKEM768 || g == GROUP_SECP384R1MLKEM1024 || g == GROUP_MLKEM1024
}

// The server's share and the shared secret, from the client's share. For
// ML-KEM the server encapsulates to the client's key: its share is the
// ciphertext, with its ECDH public value for a hybrid.
fn server_share(c: Conn&, group: u16, peer: const u8[:]) -> u8[>..], u8[>..], bool {
    let k = mlkem_k(group);
    if k == 0 {
        let mine = make_share(c, group);
        let shared, ok = shared_secret(c, peer);
        return mine, shared, ok;
    }
    c.group = group;
    let g = ecdh_part(group);
    var share: u8[>..] = [];
    var shared: u8[>..] = [];
    if peer.len != mlkem_ek_len(k) + ecdh_len(g) { return share, shared, false; }
    let ek, pe = hybrid_split(group, peer, mlkem_ek_len(k));
    var m: u8[32] = [0; 32];
    drbg_fill(c, m);
    let s1, ct, ok1 = bignum::mlkem_encaps_with(k, ek, m);
    if g == 0 { share.append(ct); shared.append(s1); return share, shared, ok1; }
    let mine = make_ecdh(c, g);
    let s2, ok2 = ecdh_secret(c, g, pe);
    return hybrid_join(group, ct, mine), hybrid_join(group, s1, s2), ok1 && ok2;
}

// --- Signatures -------------------------------------------------------------

// What CertificateVerify signs (§4.4.3).
fn cv_content(server_side: bool, th: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    for i in 64 { m.push(0x20); }
    m.append(if server_side { "TLS 1.3, server CertificateVerify" } else { "TLS 1.3, client CertificateVerify" });
    m.push(0);
    m.append(th);
    return m;
}

fn offered_scheme(list: const u16[:], s: u16) -> bool {
    for x in list { if x == s { return true; } }
    return false;
}

// The scheme to sign CertificateVerify with, for a key and the peer's list;
// 0 for none.
// Whether a TLS 1.3 CertificateVerify may use a scheme with a key: RSA
// with PSS only, ECDSA with its curve's hash, Ed25519 and ML-DSA with
// their own (RFC 8446 §4.2.3, §4.4.3).
fn scheme_fits13(kind: i64, s: u16) -> bool {
    if kind == x509::KEY_RSA {
        return s == x509::RSA_PSS_RSAE_SHA256 || s == x509::RSA_PSS_RSAE_SHA384 || s == x509::RSA_PSS_RSAE_SHA512;
    }
    if kind == x509::KEY_EC_P256 { return s == x509::ECDSA_SECP256R1_SHA256; }
    if kind == x509::KEY_EC_P384 { return s == x509::ECDSA_SECP384R1_SHA384; }
    if kind == x509::KEY_EC_P521 { return s == x509::ECDSA_SECP521R1_SHA512; }
    if kind == x509::KEY_ED25519 { return s == x509::ED25519; }
    if x509::is_mldsa(kind) { return s == x509::mldsa_scheme(x509::mldsa_set(kind)); }
    return false;
}

fn pick_scheme(key: const x509::PrivateKey&, peer: const u16[:]) -> u16 {
    if key.kind == x509::KEY_ED25519 && offered_scheme(peer, x509::ED25519) { return x509::ED25519; }
    if x509::is_mldsa(key.kind) {
        let s = x509::mldsa_scheme(x509::mldsa_set(key.kind));
        if offered_scheme(peer, s) { return s; }
    }
    if key.kind == x509::KEY_EC_P256 && offered_scheme(peer, x509::ECDSA_SECP256R1_SHA256) { return x509::ECDSA_SECP256R1_SHA256; }
    if key.kind == x509::KEY_EC_P384 && offered_scheme(peer, x509::ECDSA_SECP384R1_SHA384) { return x509::ECDSA_SECP384R1_SHA384; }
    if key.kind == x509::KEY_EC_P521 && offered_scheme(peer, x509::ECDSA_SECP521R1_SHA512) { return x509::ECDSA_SECP521R1_SHA512; }
    if key.kind == x509::KEY_RSA {
        for s in [x509::RSA_PSS_RSAE_SHA256, x509::RSA_PSS_RSAE_SHA384, x509::RSA_PSS_RSAE_SHA512] {
            if offered_scheme(peer, s) { return s; }
        }
    }
    return 0;
}

// A signature with a scheme, and false when signing fails (x509::sign):
// the handshake then ends with internal_error, as Go's does.
fn sign(key: const x509::PrivateKey&, scheme: u16, msg: const u8[:]) -> u8[>..], bool {
    var alg = x509::SIG_RSA_PSS;
    var h: i64 = 512;
    if scheme == x509::ED25519 { alg = x509::SIG_ED25519; h = 0; }
    else if scheme == x509::MLDSA44 || scheme == x509::MLDSA65 || scheme == x509::MLDSA87 {
        alg = x509::SIG_MLDSA;
        h = x509::mldsa_set(key.kind);
    }
    else if scheme == x509::ECDSA_SECP256R1_SHA256 { alg = x509::SIG_ECDSA; h = 256; }
    else if scheme == x509::ECDSA_SECP384R1_SHA384 { alg = x509::SIG_ECDSA; h = 384; }
    else if scheme == x509::ECDSA_SECP521R1_SHA512 { alg = x509::SIG_ECDSA; h = 512; }
    else if scheme == x509::RSA_PKCS1_SHA256 { alg = x509::SIG_RSA_PKCS1; h = 256; }
    else if scheme == x509::RSA_PKCS1_SHA384 { alg = x509::SIG_RSA_PKCS1; h = 384; }
    else if scheme == x509::RSA_PKCS1_SHA512 { alg = x509::SIG_RSA_PKCS1; h = 512; }
    else if scheme == x509::RSA_PSS_RSAE_SHA256 { h = 256; }
    else if scheme == x509::RSA_PSS_RSAE_SHA384 { h = 384; }
    let sig, ok = x509::sign(key, alg, h, msg);
    return sig, ok;
}

// The alert for a certificate the client refuses.
fn cert_alert(e: i64) -> u8 {
    if e == x509::ERR_EXPIRED || e == x509::ERR_NOT_YET_VALID { return ALERT_CERTIFICATE_EXPIRED; }
    if e == x509::ERR_UNKNOWN_ISSUER || e == x509::ERR_BAD_SIGNATURE { return ALERT_UNKNOWN_CA; }
    if e == x509::ERR_UNSUPPORTED_ALGORITHM { return ALERT_BAD_CERTIFICATE; }
    if e == x509::ERR_REVOKED { return 44; }                 // certificate_revoked
    return ALERT_BAD_CERTIFICATE;
}

// --- The client -------------------------------------------------------------

// The client's key_share list: a share for `share_group`, and beside a
// hybrid a share of its ECDH part with the same key (as Go sends), for
// servers without ML-KEM; not after a HelloRetryRequest, which allows only
// the share it asked for.
fn client_shares(c: Conn&, cfg: const ClientConfig&, share_group: u16) -> u8[>..] {
    var b: u8[>..] = [];
    if !c.offer13 { return b; }
    let kl = begin_vec(b, 2);
    put_u16(b, share_group);
    let pubkey = make_share(c, share_group);
    put_u16(b, pubkey.len as! u16);
    b.append(pubkey);
    c.group2 = 0;
    let fallback = ecdh_part(share_group);
    if !c.hrr && mlkem_k(share_group) > 0 && fallback != 0 {
        var wanted = false;
        for g in cfg.groups { if g == fallback { wanted = true; } }
        if wanted {
            let e = ecdh_public(c, fallback);
            put_u16(b, fallback);
            put_u16(b, e.len as! u16);
            b.append(e);
            c.group2 = fallback;
        }
    }
    patch_len(b, kl, 2);
    return b;
}

// A ClientHello naming `sni`, with `random`, `sid`, the key_share list
// `shares` and a cookie. `ech` is the encrypted_client_hello extension's
// data (none when empty). Encoded, the extensions from supported_versions
// to psk_key_exchange_modes become one ech_outer_extensions naming them
// (EncodedClientHelloInner, §5.1); they follow sni and
// encrypted_client_hello so that the outer ClientHello has them in that
// order. With `psk`, pre_shared_key offers the session, its binder zero.
// Offering TLS 1.2, it has TLS 1.2's suites and extensions too, with the
// TLS 1.2 session's ticket if one is offered; offering only TLS 1.2, none
// of TLS 1.3's.
fn hello_message(c: const Conn&, cfg: const ClientConfig&, sni: const u8[:], random: const u8[:], sid: const u8[:],
                 shares: const u8[:], cookie: const u8[:], ech: const u8[:], encoded: bool, psk: bool) -> u8[>..] {
    var b: u8[>..] = [];
    put_u16(b, 0x0303);
    b.append(random);
    b.push(sid.len as! u8);
    b.append(sid);
    let suites = begin_vec(b, 2);
    if c.offer13 { for s in cfg.suites { put_u16(b, s); } }
    if c.offer12 { for s in cfg.suites12 { put_u16(b, s); } }
    patch_len(b, suites, 2);
    b.push(1);
    b.push(0);
    let exts = begin_vec(b, 2);
    if sni.len > 0 {
        let e = begin_ext(b, EXT_SERVER_NAME);
        let list = begin_vec(b, 2);
        b.push(0);
        put_u16(b, sni.len as! u16);
        b.append(sni);
        patch_len(b, list, 2);
        patch_len(b, e, 2);
    }
    if ech.len > 0 {
        let e = begin_ext(b, EXT_ENCRYPTED_CLIENT_HELLO);
        b.append(ech);
        patch_len(b, e, 2);
    }
    if encoded {
        let oe = begin_ext(b, EXT_ECH_OUTER_EXTENSIONS);
        let ol = begin_vec(b, 1);
        put_u16(b, EXT_SUPPORTED_VERSIONS);
        put_u16(b, EXT_SUPPORTED_GROUPS);
        put_u16(b, EXT_SIGNATURE_ALGORITHMS);
        put_u16(b, EXT_KEY_SHARE);
        if cfg.alpn.len > 0 { put_u16(b, EXT_ALPN); }
        if cookie.len > 0 { put_u16(b, EXT_COOKIE); }
        put_u16(b, EXT_PSK_KEY_EXCHANGE_MODES);
        patch_len(b, ol, 1);
        patch_len(b, oe, 2);
    } else {
        if c.offer13 {
            let sv = begin_ext(b, EXT_SUPPORTED_VERSIONS);
            b.push(if c.offer12 { 4 } else { 2 });
            put_u16(b, VERSION_TLS13);
            if c.offer12 { put_u16(b, VERSION_TLS12); }
            patch_len(b, sv, 2);
        }
        // Without TLS 1.3, none of its groups (ML-KEM) or schemes (ML-DSA),
        // as Go leaves them out; some servers refuse a TLS 1.2 hello with
        // them.
        let sg = begin_ext(b, EXT_SUPPORTED_GROUPS);
        let gl = begin_vec(b, 2);
        for g in cfg.groups { if c.offer13 || mlkem_k(g) == 0 { put_u16(b, g); } }
        patch_len(b, gl, 2);
        patch_len(b, sg, 2);
        let sa = begin_ext(b, EXT_SIGNATURE_ALGORITHMS);
        let sl = begin_vec(b, 2);
        if c.offer13 { for s in SIG_SCHEMES { put_u16(b, s); } }
        else { for s in SIG_SCHEMES12 { put_u16(b, s); } }
        patch_len(b, sl, 2);
        patch_len(b, sa, 2);
        if c.offer13 {
            let ks = begin_ext(b, EXT_KEY_SHARE);
            b.append(shares);
            patch_len(b, ks, 2);
        }
        if cfg.alpn.len > 0 {
            let a = begin_ext(b, EXT_ALPN);
            put_u16(b, cfg.alpn.len as! u16);
            b.append(cfg.alpn);
            patch_len(b, a, 2);
        }
        if cookie.len > 0 {
            let ck = begin_ext(b, EXT_COOKIE);
            put_u16(b, cookie.len as! u16);
            b.append(cookie);
            patch_len(b, ck, 2);
        }
        // psk_key_exchange_modes always, without which servers send no
        // tickets (§4.2.9).
        if c.offer13 {
            let pm = begin_ext(b, EXT_PSK_KEY_EXCHANGE_MODES);
            b.push(1);
            b.push(PSK_DHE_KE);
            patch_len(b, pm, 2);
        }
    }
    if c.offer12 {
        // Uncompressed points only, the extended master secret, secure
        // renegotiation (an empty renegotiated_connection) and a session
        // ticket, empty to ask for one.
        let pf = begin_ext(b, EXT_EC_POINT_FORMATS);
        b.push(1);
        b.push(0);
        patch_len(b, pf, 2);
        put_u16(b, EXT_EXTENDED_MASTER_SECRET);
        put_u16(b, 0);
        let ri = begin_ext(b, EXT_RENEGOTIATION_INFO);
        b.push(0);
        patch_len(b, ri, 2);
        let st = begin_ext(b, EXT_SESSION_TICKET);
        if c.session12_offered { b.append(cfg.session.ticket); }
        patch_len(b, st, 2);
    }
    if psk {
        // The session as a PSK: pre_shared_key, which must come last, its
        // binder a placeholder until the rest is hashed (§4.2.11.2).
        let sess = cfg.session;
        let st, oks = suite(sess.suite);
        let hl = hash_len(st);
        let pk = begin_ext(b, EXT_PRE_SHARED_KEY);
        let ids = begin_vec(b, 2);
        put_u16(b, sess.ticket.len as! u16);
        b.append(sess.ticket);
        let age = obfuscated_age(sess, now_ms(cfg.now));
        for i in 4 { b.push((age >> (8 * (3 - i))) as! u8); }
        patch_len(b, ids, 2);
        put_u16(b, (hl + 1) as! u16);
        b.push(hl as! u8);
        for i in hl { b.push(0); }
        patch_len(b, pk, 2);
    }
    patch_len(b, exts, 2);
    return handshake_message(HS_CLIENT_HELLO, b);
}

// The binder of a ClientHello that offers the session: over the
// transcript so far (`prior`, after a HelloRetryRequest) and the
// ClientHello up to its binders.
fn set_binder(c: const Conn&, cfg: const ClientConfig&, msg: u8[>..]&, prior: const Transcript&) {
    let st, oks = suite(cfg.session.suite);
    let hl = hash_len(st);
    var th = if c.hrr { prior } else { transcript(st.hash) };
    transcript_add(th, msg[..msg.len - 3 - hl]);
    let early = schedule(st.hash, cfg.session.psk);
    let binder = finished_data(st.hash, binder_key(early, false), transcript_hash(th));
    for i in hl { msg[msg.len - hl + i] = binder[i]; }
}

// The outer encrypted_client_hello extension's data (§5).
fn ech_outer_ext(c: const Conn&, enc: const u8[:], payload: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    b.push(ECH_OUTER);
    put_u16(b, c.ech_kdf);
    put_u16(b, c.ech_aead);
    b.push(c.ech_config_id);
    put_u16(b, enc.len as! u16);
    b.append(enc);
    put_u16(b, payload.len as! u16);
    b.append(payload);
    return b;
}

// The ClientHello to send, and with ECH the ClientHelloInner it carries
// (for the inner transcript; empty without ECH). With ECH the one sent is
// the outer one: the config's public name, its own random, the same key
// shares and no PSK, and the inner one encoded, padded and sealed under
// the config's key with the outer one as AAD (§6.1). A second ClientHello
// seals with the same HPKE context and an empty enc (§6.1.5).
fn build_client_hello(c: Conn&, cfg: const ClientConfig&, share_group: u16, cookie: const u8[:]) -> u8[>..], u8[>..] {
    let shares = client_shares(c, cfg, share_group);
    if !c.ech_offered {
        var msg = hello_message(c, cfg, cfg.server_name, c.random, c.session_id, shares, cookie, "", false, c.psk_offered);
        if c.psk_offered { set_binder(c, cfg, msg, c.th); }
        var none: u8[>..] = [];
        return msg, none;
    }
    let inner_ext: u8[1] = [ECH_INNER];
    var inner = hello_message(c, cfg, cfg.server_name, c.random, c.session_id, shares, cookie, inner_ext, false,
                              c.psk_offered);
    if c.psk_offered { set_binder(c, cfg, inner, c.th_inner); }
    var enc_msg = hello_message(c, cfg, cfg.server_name, c.random, "", shares, cookie, inner_ext, true, c.psk_offered);
    if c.psk_offered {
        let st, oks = suite(cfg.session.suite);
        let hl = hash_len(st);
        for i in hl { enc_msg[enc_msg.len - hl + i] = inner[inner.len - hl + i]; }
    }
    var encoded: u8[>..] = [];
    encoded.append(enc_msg[4..]);
    let npad = ech_padding(encoded.len, cfg.server_name.len, c.ech_max_name);
    for i in npad { encoded.push(0); }
    let enc: u8[>..] = if c.hrr { "" } else { c.ech_enc[..] };
    var zeros: u8[>..] = [];
    zeros.resize(encoded.len + 16, 0);
    let ext0 = ech_outer_ext(c, enc, zeros);
    let outer0 = hello_message(c, cfg, c.ech_public_name, c.outer_random, c.session_id, shares, cookie, ext0, false,
                               false);
    let payload, ok = bignum::hpke_seal(c.ech_ctx, outer0[4..], encoded);
    assert(ok && payload.len == zeros.len);
    let ext = ech_outer_ext(c, enc, payload);
    let outer = hello_message(c, cfg, c.ech_public_name, c.outer_random, c.session_id, shares, cookie, ext, false,
                              false);
    return outer, inner;
}

// Sends the ClientHello.
fn client_start(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&) {
    assert(c.state == ST_START && cfg.groups.len > 0);
    // The versions: TLS 1.3 with its suites, TLS 1.2 with its, but not
    // with ECH, which is TLS 1.3's alone.
    c.offer13 = cfg.max_version >= VERSION_TLS13 && cfg.min_version <= VERSION_TLS13 && cfg.suites.len > 0;
    c.offer12 = cfg.min_version <= VERSION_TLS12 && cfg.max_version >= VERSION_TLS12 && cfg.suites12.len > 0 &&
                cfg.ech_config_list.len == 0;
    if !c.offer13 && !c.offer12 || (cfg.ech_config_list.len > 0 && !c.offer13) {
        c.alert = ALERT_INTERNAL_ERROR;
        c.state = ST_FAILED;
        return;
    }
    drbg_fill(c, c.random);
    var sid: u8[32] = [0; 32];
    drbg_fill(c, sid);
    c.session_id.append(sid);                      // middlebox compatibility mode; TLS 1.2 resumption
    // A session is offered when it is still good for this server and one of
    // the suites offered has its hash (TLS 1.3), or is its suite (TLS 1.2).
    c.psk_offered = false;
    let usable = session_resumable(cfg);
    if usable && cfg.session.version == VERSION_TLS12 && c.offer12 {
        for s12 in cfg.suites12 { if s12 == cfg.session.suite { c.session12_offered = true; } }
    }
    if usable && cfg.session.version == VERSION_TLS13 && c.offer13 {
        let st, oks = suite(cfg.session.suite);
        for sid2 in cfg.suites {
            let s2, ok2 = suite(sid2);
            if oks && ok2 && s2.hash == st.hash { c.psk_offered = true; }
        }
    }
    // ECH: the first usable config, and an HPKE context for it.
    if cfg.ech_config_list.len > 0 {
        let ec, okc = pick_ech_config(cfg.ech_config_list);
        var enc: u8[>..] = [];
        var ctx = bignum::hpke_empty_context();
        var oks = false;
        if okc {
            let e, x, ok = bignum::hpke_sender(ec.kem, ec.kdf, ec.aead, ec.public_key, ech_info(ec.raw));
            enc = copy(e);
            ctx = copy(x);
            oks = ok;
        }
        if !okc || !oks || enc.len > c.ech_enc.cap {
            c.alert = ALERT_INTERNAL_ERROR;
            c.state = ST_FAILED;
            return;
        }
        c.ech_offered = true;
        c.ech_ctx = ctx;
        c.ech_enc.append(enc);
        c.ech_kdf = ec.kdf as! u16;
        c.ech_aead = ec.aead as! u16;
        c.ech_config_id = ec.config_id;
        c.ech_max_name = ec.max_name_len;
        c.ech_public_name.append(ec.public_name);
        drbg_fill(c, c.outer_random);
    }
    let ch, inner = build_client_hello(c, cfg, cfg.groups[0], "");
    c.ch.append(ch);
    c.ch_inner.append(inner);
    out.append(plain_record(CT_HANDSHAKE, ch, 0x0301));
    c.state = ST_WAIT_SH;
}

// Whether a ServerHello's extensions (offsets into m) have
// supported_versions: without it, the server speaks TLS 1.2 or older.
fn has_supported_versions(m: const u8[:], exts: Rd) -> bool {
    var l = exts;
    while l.pos < l.end {
        let ty = get_u16(l, m);
        let e = get_vec(l, m, 2);
        if l.bad { return false; }
        if ty == EXT_SUPPORTED_VERSIONS { return true; }
    }
    return false;
}

fn client_server_hello(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var r = rd(m);
    let body = get_bytes(r, 4);
    var b = Rd { pos: 4, end: m.len, bad: false };
    if get_u16(b, m) != 0x0303 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    let random = get_bytes(b, 32);
    let sid = get_vec(b, m, 1);
    let suite_id = get_u16(b, m);
    let comp = get_u8(b, m);
    // No extensions at all: TLS 1.2 (or older).
    if !b.bad && b.pos == b.end { return client_server_hello12(c, cfg, m, out); }
    var exts = get_vec(b, m, 2);
    if b.bad || !done(b) || comp != 0 { return fail(c, ALERT_DECODE_ERROR, out); }
    if !has_supported_versions(m, exts) { return client_server_hello12(c, cfg, m, out); }
    if !c.offer13 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    if m[sid.pos..sid.end] != c.session_id[..] { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    var offered = false;
    for s in cfg.suites { if s == suite_id { offered = true; } }
    let s, oks = suite(suite_id as! u16);
    if !offered || !oks || (c.hrr && s.id != c.suite.id) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let is_hrr = m[random.pos..random.end] == HRR_RANDOM[..];
    var version = 0;
    var share_group = -1;
    var share = Rd { pos: 0, end: 0, bad: false };
    var cookie = Rd { pos: 0, end: 0, bad: false };
    var psk_selected = -1;
    var ech_hrr = empty_rd();
    var has_ech_hrr = false;
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
        if ty == EXT_SUPPORTED_VERSIONS {
            version = get_u16(e, m);
        } else if ty == EXT_KEY_SHARE {
            share_group = get_u16(e, m);
            if !is_hrr { share = get_vec(e, m, 2); }
        } else if ty == EXT_COOKIE && is_hrr {
            cookie = get_vec(e, m, 2);
        } else if ty == EXT_PRE_SHARED_KEY && !is_hrr && c.psk_offered {
            psk_selected = get_u16(e, m);
        } else if ty == EXT_ENCRYPTED_CLIENT_HELLO && is_hrr && c.ech_offered {
            ech_hrr = get_bytes(e, 8);
            has_ech_hrr = true;
        } else {
            return fail(c, ALERT_UNSUPPORTED_EXTENSION, out);
        }
        if !done(e) { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    if version != 0x0304 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    c.version = VERSION_TLS13;
    if is_hrr {
        var known = false;
        for g in cfg.groups { if g == share_group { known = true; } }
        if c.hrr || !known || share_group == c.group || share_group == c.group2 {
            return fail(c, ALERT_ILLEGAL_PARAMETER, out);
        }
        c.hrr = true;
        c.suite = s;
        // The session stays on offer only under a suite of its hash.
        if c.psk_offered {
            let st, okst = suite(cfg.session.suite);
            if st.hash != s.hash { c.psk_offered = false; }
        }
        c.th = transcript(s.hash);
        transcript_add(c.th, c.ch);
        transcript_restart_hrr(c.th);
        transcript_add(c.th, m);
        // ECH: accepted if the HelloRetryRequest confirms it (§7.2.1), over
        // the inner transcript with the confirmation zeroed.
        if c.ech_offered {
            c.th_inner = transcript(s.hash);
            transcript_add(c.th_inner, c.ch_inner);
            transcript_restart_hrr(c.th_inner);
            if has_ech_hrr {
                var zeroed: u8[>..] = [];
                zeroed.append(m);
                for i in 8 { zeroed[ech_hrr.pos + i] = 0; }
                var t = c.th_inner;
                transcript_add(t, zeroed);
                let conf = ech_confirmation(s.hash, c.random, "hrr ech accept confirmation", transcript_hash(t));
                c.ech_accepted = conf[..] == m[ech_hrr.pos..ech_hrr.end];
            }
            transcript_add(c.th_inner, m);
        }
        send_ccs(c, out);
        var ck: u8[>..] = [];
        ck.append(m[cookie.pos..cookie.end]);
        let ch2, inner2 = build_client_hello(c, cfg, share_group as! u16, ck);
        send_hs(c, ch2, out);
        if c.ech_offered { transcript_add(c.th_inner, inner2); }
        return 0;
    }
    if c.group2 != 0 && share_group == c.group2 { c.group = c.group2; }
    if share_group != c.group || share.bad { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let shared, okx = shared_secret(c, m[share.pos..share.end]);
    if !okx { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    if !c.hrr {
        c.suite = s;
        c.th = transcript(s.hash);
        transcript_add(c.th, c.ch);
        if c.ech_offered {
            c.th_inner = transcript(s.hash);
            transcript_add(c.th_inner, c.ch_inner);
        }
    }
    // ECH: accepted if the ServerHello's random ends in the confirmation
    // (§7.2), over the inner transcript with those bytes zeroed; then the
    // inner ClientHello is the one in the transcript.
    if c.ech_offered {
        var zeroed: u8[>..] = [];
        zeroed.append(m);
        for i in 8 { zeroed[30 + i] = 0; }
        var t = c.th_inner;
        transcript_add(t, zeroed);
        let conf = ech_confirmation(s.hash, c.random, "ech accept confirmation", transcript_hash(t));
        c.ech_accepted = conf[..] == m[30..38];
        if c.ech_accepted { c.th = c.th_inner; }
    }
    transcript_add(c.th, m);
    // The PSK, if the server took it: the one identity offered (in the
    // inner ClientHello with ECH), under a suite of the session's hash.
    if psk_selected >= 0 {
        let st, okst = suite(cfg.session.suite);
        if psk_selected != 0 || st.hash != s.hash || (c.ech_offered && !c.ech_accepted) {
            return fail(c, ALERT_ILLEGAL_PARAMETER, out);
        }
        c.resumed = true;
        resume_peer(c, cfg);
    }
    c.sch = schedule(s.hash, if c.resumed { cfg.session.psk[..] } else { "" });
    schedule_handshake(c.sch, shared, transcript_hash(c.th));
    c.read = record_keys(s, c.sch.s_hs);
    c.read_protected = true;
    c.state = ST_WAIT_EE;
    return 0;
}

let ALERT_UNSUPPORTED_EXTENSION: u8 = 110;

// The server's ALPN extension (e, offsets into m): one protocol, which the
// client offered. 0, or -1 after failing.
fn accept_alpn(c: Conn&, cfg: const ClientConfig&, m: const u8[:], e: Rd, out: u8[>..]&) -> i64 {
    var x = e;
    var list = get_vec(x, m, 2);
    let p = get_vec(list, m, 1);
    if !done(list) || !done(x) || p.end == p.pos { return fail(c, ALERT_DECODE_ERROR, out); }
    var found = false;
    var i = 0;
    while i < cfg.alpn.len {
        let n: i64 = cfg.alpn[i];
        if cfg.alpn[i + 1..i + 1 + n] == m[p.pos..p.end] { found = true; }
        i += 1 + n;
    }
    if !found { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    c.alpn.clear();
    c.alpn.append(m[p.pos..p.end]);
    return 0;
}

fn client_encrypted_extensions(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    var exts = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
        if ty == EXT_ALPN {
            if accept_alpn(c, cfg, m, e, out) != 0 { return -1; }
        } else if ty == EXT_ENCRYPTED_CLIENT_HELLO && c.ech_offered {
            // Retry configs, only when ECH was not accepted (§7.1).
            if c.ech_accepted { return fail(c, ALERT_UNSUPPORTED_EXTENSION, out); }
            if e.end - e.pos <= c.ech_retry.cap {
                c.ech_retry.clear();
                c.ech_retry.append(m[e.pos..e.end]);
            }
        } else if ty == EXT_KEY_SHARE || ty == EXT_SUPPORTED_VERSIONS || ty == EXT_COOKIE || ty == EXT_SIGNATURE_ALGORITHMS {
            return fail(c, ALERT_ILLEGAL_PARAMETER, out);     // forbidden in EncryptedExtensions
        }
    }
    transcript_add(c.th, m);
    // Resumed, the server authenticates with the PSK alone.
    c.state = if c.resumed { ST_WAIT_FINISHED } else { ST_WAIT_CERT_CR };
    return 0;
}

// The certificates of a Certificate message, whose context must be
// `context`, into c.chain; how many, or -1 after failing.
fn read_certificates(c: Conn&, m: const u8[:], context: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ctx = get_vec(b, m, 1);
    var list = get_vec(b, m, 3);
    if !done(b) || m[ctx.pos..ctx.end] != context { return fail(c, ALERT_DECODE_ERROR, out); }
    c.chain.clear();
    var count = 0;
    while list.pos < list.end {
        let cert = get_vec(list, m, 3);
        let exts = get_vec(list, m, 2);
        if list.bad || cert.end == cert.pos { return fail(c, ALERT_DECODE_ERROR, out); }
        if c.chain.len + cert.end - cert.pos > c.chain.cap { return fail(c, ALERT_BAD_CERTIFICATE, out); }
        c.chain.append(m[cert.pos..cert.end]);
        count++;
    }
    return count;
}

fn client_certificate(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let count = read_certificates(c, m, "", out);
    if count < 0 { return count; }
    if count == 0 { return fail(c, ALERT_DECODE_ERROR, out); }
    if check_server_chain(c, cfg, out) != 0 { return -1; }
    transcript_add(c.th, m);
    c.state = ST_WAIT_CV;
    return 0;
}

// A server's chain (DER concatenated, leaf first) checked for `name`
// under the client's roots now: x509::OK or the error.
fn server_chain_error(cfg: const ClientConfig&, chain: const u8[:], name: const u8[:]) -> i64 {
    let ct, okt = asn1::read(chain, 0, chain.len);
    if !okt { return x509::ERR_MALFORMED; }
    let now = if cfg.now != 0 { cfg.now } else { time_ns() / 1000000000 };
    if cfg.system_roots {
        let es, found = x509::verify_with_system_roots(chain[..ct.end], chain[ct.end..], now, name);
        return es;
    }
    return x509::verify_with_roots(chain[..ct.end], chain[ct.end..], cfg.roots, now, name);
}

// Whether the client may offer its session: still good for this server
// and, when the client verifies, verified when it was made and its chain
// still verifying under today's roots, time and name (Go's loadSession).
fn session_resumable(cfg: const ClientConfig&) -> bool {
    if !session_usable(cfg.session, cfg.server_name, now_ms(cfg.now)) { return false; }
    if !cfg.verify { return true; }
    return cfg.session.verified && server_chain_error(cfg, cfg.session.chain, cfg.server_name) == x509::OK;
}

// A new session gets the connection's verification and, when it fits,
// the server's chain; one too long to keep is saved unverified, to resume
// only without verifying.
fn keep_chain(c: const Conn&, s: Session&) {
    s.chain.clear();
    s.verified = false;
    if c.chain.len <= s.chain.cap {
        s.chain.append(c.chain);
        s.verified = c.peer_verified;
    }
}

// A resumed connection's peer, as its session had it: verified only when
// the client verifies (session_resumable checked the chain again).
fn resume_peer(c: Conn&, cfg: const ClientConfig&) {
    c.peer_not_after = cfg.session.not_after;
    c.peer_verified = cfg.verify && cfg.session.verified;
    c.chain.clear();
    c.chain.append(cfg.session.chain);
}

// The server's chain in c.chain, checked when the client checks them: 0,
// or -1 after failing.
fn check_server_chain(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&) -> i64 {
    let ct, okt = asn1::read(c.chain, 0, c.chain.len);
    if !okt { return fail(c, ALERT_BAD_CERTIFICATE, out); }
    if cfg.verify {
        // ECH not accepted, the certificate must be for the public name
        // (§6.1.7).
        var name: u8[>..] = [];
        name.append(if c.ech_offered && !c.ech_accepted { c.ech_public_name[..] } else { cfg.server_name[..] });
        let e = server_chain_error(cfg, c.chain, name);
        if e != x509::OK {
            c.error = e;
            return fail(c, cert_alert(e), out);
        }
        let leaf, el = x509::parse(c.chain[..ct.end]);
        c.peer_not_after = leaf.not_after;
        c.peer_verified = true;
    }
    return 0;
}

// Whether a certificate's keyUsage, when it has one, lets its key sign
// (RFC 5280 §4.2.1.3): digitalSignature, as TLS 1.3 requires (RFC 8446
// §4.4.2.2) and TLS 1.2 for every signing key, RSA's included (RFC 5246
// §7.4.2, §7.4.6). OpenSSL lets an RSA key sign in TLS 1.2 without it;
// this does not.
fn usage_signs(leaf: const x509::Cert&) -> bool {
    !leaf.has_key_usage || leaf.key_usage & x509::KU_DIGITAL_SIGNATURE != 0
}

// The peer's CertificateVerify, by the leaf of c.chain over the transcript
// so far (§4.4.3); 0, or -1 after failing.
fn peer_certificate_verify(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let scheme = get_u16(b, m);
    let sig = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    if !offered_scheme(SIG_SCHEMES, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let ct, okt = asn1::read(c.chain, 0, c.chain.len);
    let leaf, e = x509::parse(c.chain[..ct.end]);
    if e != x509::OK { return fail(c, ALERT_BAD_CERTIFICATE, out); }
    if !usage_signs(leaf) {
        c.error = x509::ERR_KEY_USAGE;
        return fail(c, ALERT_BAD_CERTIFICATE, out);
    }
    if !scheme_fits13(leaf.key_type, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let content = cv_content(!c.is_server, transcript_hash(c.th));
    if x509::verify_scheme(leaf, scheme as! u16, content, m[sig.pos..sig.end]) != x509::OK {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    transcript_add(c.th, m);
    return 0;
}

// A CertificateRequest (§4.3.2): the signature schemes the server takes
// and, if it names them, the CAs it accepts. The client's certificate is
// picked now, sent with its Finished: when its key signs with one of those
// schemes and, if CAs are named, one of the chain's certificates was
// issued by one of them (Go's CertificateRequestInfo.SupportsCertificate).
fn client_certificate_request(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ctx = get_vec(b, m, 1);
    var exts = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    var schemes: u16[..64] = [];
    var has_schemes = false;
    var cas = empty_rd();
    var has_cas = false;
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
        if ty == EXT_SIGNATURE_ALGORITHMS {
            var l = get_vec(e, m, 2);
            while l.pos + 1 < l.end {
                let v = get_u16(l, m);
                if schemes.len < schemes.cap { schemes.push(v as! u16); }
            }
            has_schemes = true;
        } else if ty == EXT_CERTIFICATE_AUTHORITIES {
            cas = get_vec(e, m, 2);
            has_cas = true;
        }
        if e.bad { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    if !has_schemes { return fail(c, ALERT_MISSING_EXTENSION, out); }
    c.cr_context.clear();
    c.cr_context.append(m[ctx.pos..ctx.end]);
    c.cert_requested = true;
    c.cert_scheme = 0;
    if cfg.cert_chain.len > 0 {
        let sch = pick_scheme(cfg.cert_key, schemes);
        if sch != 0 && (!has_cas || issued_by_one_of(cfg.cert_chain, m, cas)) { c.cert_scheme = sch; }
    }
    if c.ech_offered && !c.ech_accepted { c.cert_scheme = 0; }    // none for the public name
    transcript_add(c.th, m);
    c.state = ST_WAIT_CERT;
    return 0;
}

// Whether a certificate of a chain was issued by one of a list of
// DistinguishedNames (offsets into m).
fn issued_by_one_of(chain: const u8[:], m: const u8[:], cas: Rd) -> bool {
    var off = 0;
    while off < chain.len {
        let t, ok = asn1::read(chain, off, chain.len);
        if !ok { return false; }
        let cert, e = x509::parse(chain[t.start..t.end]);
        if e == x509::OK {
            let issuer = cert.der[cert.issuer.start..cert.issuer.end];
            var l = cas;
            while l.pos < l.end {
                let dn = get_vec(l, m, 2);
                if l.bad { break; }
                if m[dn.pos..dn.end] == issuer { return true; }
            }
        }
        off = t.end;
    }
    return false;
}

// A Certificate message (§4.4.2) of a chain (concatenated DER; none when
// empty); false if the chain is malformed.
fn certificate_message(context: const u8[:], chain: const u8[:]) -> u8[>..], bool {
    var body: u8[>..] = [];
    body.push(context.len as! u8);
    body.append(context);
    let list = begin_vec(body, 3);
    var off = 0;
    while off < chain.len {
        let t, ok = asn1::read(chain, off, chain.len);
        if !ok {
            var none: u8[>..] = [];
            return none, false;
        }
        let one = begin_vec(body, 3);
        body.append(chain[t.start..t.end]);
        patch_len(body, one, 3);
        put_u16(body, 0);
        off = t.end;
    }
    patch_len(body, list, 3);
    return handshake_message(HS_CERTIFICATE, body), true;
}

// A CertificateVerify by `key` over the transcript hash `th`, and false
// when signing fails.
fn certificate_verify_message(key: const x509::PrivateKey&, scheme: u16, server_side: bool,
                              th: const u8[:]) -> u8[>..], bool {
    let sig, ok = sign(key, scheme, cv_content(server_side, th));
    if !ok {
        var none: u8[>..] = [];
        return none, false;
    }
    var cv: u8[>..] = [];
    put_u16(cv, scheme);
    put_u16(cv, sig.len as! u16);
    cv.append(sig);
    return handshake_message(HS_CERTIFICATE_VERIFY, cv), true;
}

fn client_finished(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if m.len - 4 != c.suite.hash / 8 { return fail(c, ALERT_DECODE_ERROR, out); }
    if !finished_ok(c.suite.hash, c.sch.s_hs, transcript_hash(c.th), m[4..]) {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }   // the key change ends a record
    transcript_add(c.th, m);
    schedule_master(c.sch, transcript_hash(c.th));
    // The client's flight: change_cipher_spec; if a certificate was asked
    // for, Certificate (empty without a suitable one) and CertificateVerify;
    // Finished.
    send_ccs(c, out);
    c.write = record_keys(c.suite, c.sch.c_hs);
    c.write_protected = true;
    if c.cert_requested && c.cert_scheme == 0 {
        let cm, okm = certificate_message(c.cr_context, "");
        send_hs(c, cm, out);
    } else if c.cert_requested {
        let cm, okm = certificate_message(c.cr_context, cfg.cert_chain);
        if !okm { return fail(c, ALERT_INTERNAL_ERROR, out); }
        send_hs(c, cm, out);
        let cv, okv = certificate_verify_message(cfg.cert_key, c.cert_scheme, false, transcript_hash(c.th));
        if !okv { return fail(c, ALERT_INTERNAL_ERROR, out); }
        send_hs(c, cv, out);
    }
    let fin = finished_data(c.suite.hash, c.sch.c_hs, transcript_hash(c.th));
    send_hs(c, handshake_message(HS_FINISHED, fin), out);
    schedule_resumption(c.sch, transcript_hash(c.th));
    c.write = record_keys(c.suite, c.sch.c_ap);
    c.read = record_keys(c.suite, c.sch.s_ap);
    c.state = ST_CONNECTED;
    // ECH not accepted: the handshake with the public name only served to
    // authenticate the retry configs (§6.1.6).
    if c.ech_offered && !c.ech_accepted { return fail(c, ALERT_ECH_REQUIRED, out); }
    return 0;
}

fn client_message(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if c.version == VERSION_TLS12 { return client_message12(c, cfg, m, out); }
    if c.state == ST_WAIT_SH && t == HS_SERVER_HELLO { return client_server_hello(c, cfg, m, out); }
    if c.state == ST_WAIT_EE && t == HS_ENCRYPTED_EXTENSIONS { return client_encrypted_extensions(c, cfg, m, out); }
    if c.state == ST_WAIT_CERT_CR && t == HS_CERTIFICATE_REQUEST { return client_certificate_request(c, cfg, m, out); }
    if (c.state == ST_WAIT_CERT_CR || c.state == ST_WAIT_CERT) && t == HS_CERTIFICATE {
        return client_certificate(c, cfg, m, out);
    }
    if c.state == ST_WAIT_CV && t == HS_CERTIFICATE_VERIFY {
        let r = peer_certificate_verify(c, m, out);
        if r == 0 { c.state = ST_WAIT_FINISHED; }
        return r;
    }
    if c.state == ST_WAIT_FINISHED && t == HS_FINISHED { return client_finished(c, cfg, m, out); }
    if c.state == ST_CONNECTED && t == HS_NEW_SESSION_TICKET { return client_ticket(c, cfg, m, out); }
    if c.state == ST_CONNECTED { return post_handshake(c, m, out); }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}

// NewSessionTicket (§4.6.1): kept as the client's session, the PSK derived
// from the resumption secret and the ticket's nonce. A ticket of lifetime 0,
// or too long to keep, is dropped.
fn client_ticket(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let lifetime = get_u16(b, m) << 16 | get_u16(b, m);
    let age_add = get_u16(b, m) << 16 | get_u16(b, m);
    let nonce = get_vec(b, m, 1);
    let ticket = get_vec(b, m, 2);
    var exts = get_vec(b, m, 2);
    if !done(b) || ticket.end == ticket.pos { return fail(c, ALERT_DECODE_ERROR, out); }
    if lifetime > MAX_TICKET_LIFETIME { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    var max_early: i64 = 0;
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if ty == EXT_EARLY_DATA { max_early = get_u16(e, m) << 16 | get_u16(e, m); }
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    c.tickets++;
    var s = no_session();
    if lifetime == 0 || ticket.end - ticket.pos > s.ticket.cap { return 0; }
    s.suite = c.suite.id;
    s.psk.append(resumption_psk(c.suite.hash, c.sch.resumption, m[nonce.pos..nonce.end]));
    s.age_add = age_add as! u32;
    s.lifetime = lifetime;
    s.received_ms = now_ms(cfg.now);
    s.server_name.append(cfg.server_name);
    s.alpn.append(c.alpn);
    s.not_after = c.peer_not_after;
    keep_chain(c, s);
    s.max_early_data = max_early as! u32;
    s.ticket.append(m[ticket.pos..ticket.end]);
    c.session = s;
    c.has_session = true;
    return 0;
}

// --- The server -------------------------------------------------------------

// What a ClientHello offers, as offsets into it.
// pre_shared_key's identities and binders, and where the binders start
// (what they do not cover), with whether psk_dhe_ke is allowed. For TLS
// 1.2: legacy_version, whether supported_versions was there and has TLS
// 1.2, the point formats, extended master secret, renegotiation_info
// (and whether it is empty, as in a first handshake) and session_ticket.
struct Hello {
    suites: Rd, groups: Rd, shares: Rd, schemes: Rd, sni: Rd, alpn: Rd, cookie: Rd,
    sid: Rd, random: Rd, has_versions13: bool, has_groups: bool, has_shares: bool, has_schemes: bool,
    psk_ids: Rd, psk_binders: Rd, binders_at: i64, has_psk: bool, psk_dhe: bool,
    version: i64, has_versions: bool, has_versions12: bool, points: Rd, has_points: bool, ems: bool,
    has_reneg: bool, reneg_empty: bool, ticket: Rd, has_ticket: bool,
    comp_null_only: bool, early_data: bool,
    alert: u8,                        // when parsing fails: the alert, if not decode_error
}

fn empty_rd() -> Rd { Rd { pos: 0, end: 0, bad: false } }

fn parse_hello(m: const u8[:]) -> Hello, bool {
    var h = Hello {
        suites: empty_rd(), groups: empty_rd(), shares: empty_rd(), schemes: empty_rd(), sni: empty_rd(),
        alpn: empty_rd(), cookie: empty_rd(), sid: empty_rd(), random: empty_rd(),
        has_versions13: false, has_groups: false, has_shares: false, has_schemes: false,
        psk_ids: empty_rd(), psk_binders: empty_rd(), binders_at: 0, has_psk: false, psk_dhe: false,
        version: 0, has_versions: false, has_versions12: false, points: empty_rd(), has_points: false, ems: false,
        has_reneg: false, reneg_empty: false, ticket: empty_rd(), has_ticket: false,
        comp_null_only: false, early_data: false, alert: 0,
    };
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ver = get_u16(b, m);
    h.version = ver;
    h.random = get_bytes(b, 32);
    h.sid = get_vec(b, m, 1);
    h.suites = get_vec(b, m, 2);
    let comp = get_vec(b, m, 1);
    // cipher_suites<2..2^16-2>, legacy_compression_methods<1..2^8-1>
    // (RFC 8446 §4.1.2, RFC 5246 §7.4.1.2): an empty list of either is a
    // malformed message, decode_error, not a hello with nothing in common.
    let nsuites = h.suites.end - h.suites.pos;
    if b.bad || h.sid.end - h.sid.pos > 32 || comp.end == comp.pos || nsuites == 0 || nsuites % 2 != 0 {
        return h, false;
    }
    // The null compression method: offered (RFC 5246 §7.4.1.2), and alone
    // for TLS 1.3 (§4.1.2), which server_client_hello checks.
    var has_null = false;
    for i in comp.pos..comp.end { if m[i] == 0 { has_null = true; } }
    if !has_null { h.alert = ALERT_ILLEGAL_PARAMETER; return h, false; }
    h.comp_null_only = comp.end - comp.pos == 1;
    // A TLS 1.2 hello may end here, with no extensions (RFC 5246 §7.4.1.2).
    var exts = if b.pos == b.end { empty_rd() } else { get_vec(b, m, 2) };
    if !done(b) { return h, false; }
    // No extension twice (RFC 8446 §4.2, RFC 5246 §7.4.1.4): types below
    // 64 in a mask, the first 16 above in a list (renegotiation_info and
    // encrypted_client_hello among them, in any real ClientHello).
    var seen: u64 = 0;
    var seen_high: u16[..16] = [];
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return h, false; }
        if ty < 64 {
            let bit: u64 = 1 << ty;
            if seen & bit != 0 { return h, false; }
            seen = seen | bit;
        } else {
            for t in seen_high { if t == ty { return h, false; } }
            if seen_high.len < seen_high.cap { seen_high.push(ty as! u16); }
        }
        if ty == EXT_SUPPORTED_VERSIONS {
            var l = get_vec(e, m, 1);
            h.has_versions = true;
            while l.pos < l.end {
                let v = get_u16(l, m);
                if v == 0x0304 { h.has_versions13 = true; }
                if v == 0x0303 { h.has_versions12 = true; }
            }
            if l.bad { return h, false; }
        } else if ty == EXT_EC_POINT_FORMATS {
            h.points = get_vec(e, m, 1);
            h.has_points = true;
            if h.points.end == h.points.pos { return h, false; }
        } else if ty == EXT_EXTENDED_MASTER_SECRET {
            h.ems = true;
        } else if ty == EXT_RENEGOTIATION_INFO {
            let rc = get_vec(e, m, 1);
            h.has_reneg = true;
            h.reneg_empty = rc.end == rc.pos;
        } else if ty == EXT_SESSION_TICKET {
            h.ticket = get_bytes(e, e.end - e.pos);
            h.has_ticket = true;
        } else if ty == EXT_SUPPORTED_GROUPS {
            h.groups = get_vec(e, m, 2);
            h.has_groups = true;
            if h.groups.end == h.groups.pos || (h.groups.end - h.groups.pos) % 2 != 0 { return h, false; }
        } else if ty == EXT_KEY_SHARE {
            h.shares = get_vec(e, m, 2);
            h.has_shares = true;
            // Each entry whole: a group and a non-empty key.
            var l = h.shares;
            while l.pos < l.end {
                let g = get_u16(l, m);
                let k = get_vec(l, m, 2);
                if k.end == k.pos { l.bad = true; }
            }
            if l.bad { return h, false; }
        } else if ty == EXT_SIGNATURE_ALGORITHMS {
            h.schemes = get_vec(e, m, 2);
            h.has_schemes = true;
            if h.schemes.end == h.schemes.pos || (h.schemes.end - h.schemes.pos) % 2 != 0 { return h, false; }
        } else if ty == EXT_SERVER_NAME {
            // One host_name, not empty; names of other types are skipped
            // (RFC 6066 §3).
            var l = get_vec(e, m, 2);
            if l.end == l.pos { return h, false; }
            var names = 0;
            while l.pos < l.end {
                let kind = get_u8(l, m);
                let name = get_vec(l, m, 2);
                if l.bad || name.end == name.pos { return h, false; }
                if kind == 0 {
                    names++;
                    h.sni = name;
                    if !host_name_ok(m[name.pos..name.end]) { h.alert = ALERT_ILLEGAL_PARAMETER; return h, false; }
                }
            }
            if names > 1 { h.alert = ALERT_ILLEGAL_PARAMETER; return h, false; }
        } else if ty == EXT_EARLY_DATA {
            h.early_data = true;
        } else if ty == EXT_ALPN {
            // A non-empty list of non-empty names (RFC 7301 §3.1).
            h.alpn = get_vec(e, m, 2);
            if h.alpn.end == h.alpn.pos { return h, false; }
            var l = h.alpn;
            while l.pos < l.end {
                let p = get_vec(l, m, 1);
                if p.end == p.pos { l.bad = true; }
            }
            if l.bad { return h, false; }
        } else if ty == EXT_COOKIE {
            h.cookie = get_vec(e, m, 2);
        } else if ty == EXT_PSK_KEY_EXCHANGE_MODES {
            var l = get_vec(e, m, 1);
            while l.pos < l.end { if get_u8(l, m) == PSK_DHE_KE as i64 { h.psk_dhe = true; } }
            if l.bad { return h, false; }
        } else if ty == EXT_PRE_SHARED_KEY {
            // The last extension (§4.2.11).
            if exts.pos != exts.end { return h, false; }
            h.psk_ids = get_vec(e, m, 2);
            h.binders_at = e.pos;
            h.psk_binders = get_vec(e, m, 2);
            h.has_psk = true;
        } else {
            e.pos = e.end;
        }
        if !done(e) { return h, false; }
    }
    return h, true;
}

// The client's signature schemes that this package has, in its order and
// once each: however long its list, the ones that matter fit.
fn take_peer_schemes(c: Conn&, m: const u8[:], schemes: Rd, known: const u16[:]) {
    c.peer_schemes.clear();
    var sl = schemes;
    while sl.pos + 1 < sl.end {
        let v = get_u16(sl, m) as! u16;
        if offered_scheme(known, v) && !offered_scheme(c.peer_schemes, v) && c.peer_schemes.len < c.peer_schemes.cap {
            c.peer_schemes.push(v);
        }
    }
}

// A digest of what a ClientHello after a HelloRetryRequest must repeat:
// all but the extensions that may change (§4.1.2: key_share, early_data,
// cookie, pre_shared_key; padding; and encrypted_client_hello, whose
// payload is new), in their order. m is a ClientHello parse_hello took.
fn hello_digest(m: const u8[:]) -> u8[>..] {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ver = get_u16(b, m);
    let random = get_bytes(b, 32);
    let sid = get_vec(b, m, 1);
    let suites = get_vec(b, m, 2);
    let comp = get_vec(b, m, 1);
    var st = bignum::sha256_init();
    bignum::sha256_update(st, m[4..b.pos]);
    var exts = if b.pos == b.end { empty_rd() } else { get_vec(b, m, 2) };
    while exts.pos < exts.end {
        let at = exts.pos;
        let ty = get_u16(exts, m);
        let e = get_vec(exts, m, 2);
        if ty != EXT_KEY_SHARE && ty != EXT_EARLY_DATA && ty != EXT_COOKIE && ty != EXT_PRE_SHARED_KEY &&
           ty != EXT_PADDING && ty != EXT_ENCRYPTED_CLIENT_HELLO {
            bignum::sha256_update(st, m[at..exts.pos]);
        }
    }
    var out: u8[>..] = [];
    out.append(bignum::sha256_final(st));
    return out;
}

// Whether an SNI host_name is a DNS name (RFC 6066 §3): letters, digits,
// '-', '_' and dots, with no trailing dot; no NUL, control or non-ASCII
// bytes (a name beyond ASCII comes as an A-label).
fn host_name_ok(n: const u8[:]) -> bool {
    if n.len == 0 || n[n.len - 1] == '.' { return false; }
    for b in n {
        let ok = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
                 b == '-' || b == '_' || b == '.';
        if !ok { return false; }
    }
    return true;
}

// The highest version a client offers: supported_versions' highest that
// this package knows, else legacy_version (at most TLS 1.3).
fn client_max_version(h: const Hello&) -> i64 {
    if h.has_versions {
        if h.has_versions13 { return VERSION_TLS13; }
        if h.has_versions12 { return VERSION_TLS12; }
        return 0x0302;
    }
    return if h.version > VERSION_TLS13 { VERSION_TLS13 } else { h.version };
}

// The client's share for a group, as offsets, or an empty reader.
fn find_share(h: const Hello&, m: const u8[:], group: u16) -> Rd, bool {
    var l = h.shares;
    while l.pos < l.end {
        let g = get_u16(l, m);
        let k = get_vec(l, m, 2);
        if l.bad { return empty_rd(), false; }
        if g == group { return k, true; }
    }
    return empty_rd(), false;
}

fn in_u16_list(m: const u8[:], list: Rd, v: u16) -> bool {
    var l = list;
    while l.pos + 1 < l.end { if get_u16(l, m) == v { return true; } }
    return false;
}

// A ServerHello or HelloRetryRequest. With ECH confirmed, `inner_random`
// is the inner ClientHello's: the confirmation goes in the last 8 bytes of
// a ServerHello's random, or in a HelloRetryRequest's
// encrypted_client_hello (§7.2).
fn send_server_hello(c: Conn&, random: const u8[:], share: const u8[:], hrr: bool, out: u8[>..]&,
                     psk_identity: i64 = -1, inner_random: const u8[:] = "") {
    var b: u8[>..] = [];
    put_u16(b, 0x0303);
    b.append(random);
    b.push(c.session_id.len as! u8);
    b.append(c.session_id);
    put_u16(b, c.suite.id);
    b.push(0);
    let exts = begin_vec(b, 2);
    let sv = begin_ext(b, EXT_SUPPORTED_VERSIONS);
    put_u16(b, 0x0304);
    patch_len(b, sv, 2);
    let ks = begin_ext(b, EXT_KEY_SHARE);
    put_u16(b, c.group);
    if !hrr {
        put_u16(b, share.len as! u16);
        b.append(share);
    }
    patch_len(b, ks, 2);
    if psk_identity >= 0 {
        let pk = begin_ext(b, EXT_PRE_SHARED_KEY);
        put_u16(b, psk_identity as! u16);
        patch_len(b, pk, 2);
    }
    if hrr && inner_random.len > 0 {
        let ee = begin_ext(b, EXT_ENCRYPTED_CLIENT_HELLO);
        for i in 8 { b.push(0); }
        patch_len(b, ee, 2);
    }
    patch_len(b, exts, 2);
    var msg = handshake_message(HS_SERVER_HELLO, b);
    if inner_random.len > 0 {
        let at = if hrr { msg.len - 8 } else { 30 };
        for i in 8 { msg[at + i] = 0; }
        var th = c.th;
        transcript_add(th, msg);
        let label: const u8[:] = if hrr { "hrr ech accept confirmation" } else { "ech accept confirmation" };
        let conf = ech_confirmation(c.suite.hash, inner_random, label, transcript_hash(th));
        for i in 8 { msg[at + i] = conf[i]; }
    }
    send_hs(c, msg, out);
}

// ECH on the server (§7.1), before anything else looks at a ClientHello:
// the ClientHello to go on with. An outer one is decrypted with each ECH
// key in turn, the first that opens it giving the inner one; with none,
// the outer one goes on (and the client may get retry configs). A second
// ClientHello after one that was accepted must carry the inner one under
// the same HPKE context. An inner one (from a client-facing server, to a
// backend) is confirmed as it is. -1 after failing.
fn server_ech(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> u8[>..], i64 {
    var same: u8[>..] = [];
    same.append(m);
    let second = c.state == ST_WAIT_CH2;
    var exts, okx = ech_hello_extensions(m);
    if !okx { return same, 0; }
    var ext = EchRd { pos: 0, end: 0, bad: true };
    var found = false;
    while exts.pos < exts.end {
        let ty = ech_u16(exts, m);
        let d = ech_vec(exts, m, 2);
        if exts.bad { return same, 0; }
        if ty == EXT_ENCRYPTED_CLIENT_HELLO { ext = d; found = true; }
    }
    if second && c.ech_confirm && !found { return same, fail(c, ALERT_MISSING_EXTENSION, out); }
    if !found || (second && !c.ech_confirm) { return same, 0; }
    var r = ext;
    let kind = ech_u8(r, m);
    if r.bad { return same, fail(c, ALERT_DECODE_ERROR, out); }
    if kind == ECH_INNER {
        if r.pos != r.end || (second && !c.ech_backend) { return same, fail(c, ALERT_DECODE_ERROR, out); }
        c.ech_backend = true;
        c.ech_confirm = true;
        return same, 0;
    }
    if kind != ECH_OUTER { return same, fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let kdf = ech_u16(r, m);
    let aead = ech_u16(r, m);
    let id = ech_u8(r, m);
    let enc = ech_vec(r, m, 2);
    let payload = ech_vec(r, m, 2);
    if r.bad || r.pos != r.end { return same, fail(c, ALERT_DECODE_ERROR, out); }
    let aad = ech_aad(m, payload.pos, payload.end);
    if second {
        if c.ech_backend { return same, fail(c, ALERT_DECODE_ERROR, out); }
        if kdf != c.ech_kdf || aead != c.ech_aead || id != c.ech_config_id || enc.end != enc.pos {
            return same, fail(c, ALERT_ILLEGAL_PARAMETER, out);
        }
        let pt, oko = bignum::hpke_open(c.ech_ctx, aad, m[payload.pos..payload.end]);
        if !oko { return same, fail(c, ALERT_DECRYPT_ERROR, out); }
        let inner, okd = ech_decode_inner(m, pt);
        if !okd || !ech_inner_ok(inner) { return same, fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        return inner, 0;
    }
    c.ech_seen = true;
    if !ech_kdf_ok(kdf) || !ech_aead_ok(aead) { return same, 0; }
    var k = EchRd { pos: 0, end: cfg.ech_keys.len, bad: false };
    while k.pos < k.end {
        let config = ech_vec(k, cfg.ech_keys, 2);
        let sk = ech_vec(k, cfg.ech_keys, 2);
        let retry = ech_u8(k, cfg.ech_keys);
        if k.bad { break; }
        let kem, cid, okc = ech_server_config(cfg.ech_keys[config.pos..config.end]);
        if !okc { continue; }
        var ctx, okr = bignum::hpke_recipient(kem, kdf, aead, cfg.ech_keys[sk.pos..sk.end], m[enc.pos..enc.end],
                                              ech_info(cfg.ech_keys[config.pos..config.end]));
        if !okr { continue; }
        let pt, oko = bignum::hpke_open(ctx, aad, m[payload.pos..payload.end]);
        if !oko { continue; }
        let inner, okd = ech_decode_inner(m, pt);
        if !okd || !ech_inner_ok(inner) { return same, fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        c.ech_confirm = true;
        c.ech_accepted = true;
        c.ech_ctx = ctx;
        c.ech_kdf = kdf as! u16;
        c.ech_aead = aead as! u16;
        c.ech_config_id = id as! u8;
        return inner, 0;
    }
    return same, 0;
}

// The retry configs (an ECHConfigList) of the keys sent as retry; empty
// for none.
fn ech_retry_list(cfg: const ServerConfig&) -> u8[>..] {
    var configs: u8[>..] = [];
    var k = EchRd { pos: 0, end: cfg.ech_keys.len, bad: false };
    while k.pos < k.end {
        let config = ech_vec(k, cfg.ech_keys, 2);
        let sk = ech_vec(k, cfg.ech_keys, 2);
        let retry = ech_u8(k, cfg.ech_keys);
        if k.bad { break; }
        if retry == 1 { configs.append(cfg.ech_keys[config.pos..config.end]); }
    }
    var none: u8[>..] = [];
    if configs.len == 0 { return none; }
    return ech_config_list(configs);
}

fn server_client_hello(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let h, ok = parse_hello(m);
    if !ok { return fail(c, if h.alert != 0 { h.alert } else { ALERT_DECODE_ERROR }, out); }
    // A legacy_version below TLS 1.0 is no version this server has.
    if h.version < 0x0301 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    let second = c.state == ST_WAIT_CH2;
    // After a HelloRetryRequest, the same ClientHello but for what may
    // change (§4.1.2).
    if second && hello_digest(m) != c.ch1_digest[..] { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // The version: TLS 1.3 if both take it, else TLS 1.2 (named in
    // supported_versions, or by legacy_version without it), not after a
    // HelloRetryRequest or for an inner ClientHello.
    let v13 = h.has_versions13 && cfg.max_version >= VERSION_TLS13 && cfg.min_version <= VERSION_TLS13;
    let v12 = (if h.has_versions { h.has_versions12 } else { h.version >= 0x0303 }) &&
              cfg.min_version <= VERSION_TLS12 && cfg.max_version >= VERSION_TLS12 && cfg.suites12.len > 0;
    if !v13 {
        if v12 && !second && !c.ech_confirm { return server_client_hello12(c, cfg, m, h, out); }
        // TLS_FALLBACK_SCSV from a client that could do better is told so,
        // even when its version is one this server lacks (RFC 7507 §3).
        if in_u16_list(m, h.suites, TLS_FALLBACK_SCSV) && client_max_version(h) < cfg.max_version {
            return fail(c, ALERT_INAPPROPRIATE_FALLBACK, out);
        }
        return fail(c, ALERT_PROTOCOL_VERSION, out);
    }
    c.version = VERSION_TLS13;
    if !h.comp_null_only { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // 0-RTT is never accepted: what the client sent of it is skipped.
    c.skip_early = h.early_data && !second;
    if !h.has_groups || !h.has_shares || !h.has_schemes { return fail(c, ALERT_MISSING_EXTENSION, out); }
    if second && m[h.sid.pos..h.sid.end] != c.session_id[..] { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // The suite: the server's first that the client offers.
    var chosen: u16 = 0;
    for s in cfg.suites {
        if chosen == 0 && in_u16_list(m, h.suites, s) { chosen = s; }
    }
    if chosen == 0 { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
    let s, oks = suite(chosen);
    if second && s.id != c.suite.id { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    c.suite = s;
    // The group: the server's first with a share from the client, else
    // its first the client supports (via HelloRetryRequest).
    var group: u16 = 0;
    var share = empty_rd();
    for g in cfg.groups {
        if group != 0 { break; }
        let k, found = find_share(h, m, g);
        if found && in_u16_list(m, h.groups, g) { group = g; share = k; }
    }
    if group == 0 {
        var fallback: u16 = 0;
        for g in cfg.groups { if fallback == 0 && in_u16_list(m, h.groups, g) { fallback = g; } }
        if fallback == 0 || second { return fail(c, if second { ALERT_ILLEGAL_PARAMETER } else { ALERT_HANDSHAKE_FAILURE }, out); }
        c.session_id.clear();
        c.session_id.append(m[h.sid.pos..h.sid.end]);
        let d = hello_digest(m);
        for i in 32 { c.ch1_digest[i] = d[i]; }
        c.group = fallback;
        c.th = transcript(s.hash);
        transcript_add(c.th, m);
        transcript_restart_hrr(c.th);
        if c.ech_confirm { send_server_hello(c, HRR_RANDOM, "", true, out, -1, m[h.random.pos..h.random.end]); }
        else { send_server_hello(c, HRR_RANDOM, "", true, out); }
        if c.session_id.len > 0 { send_ccs(c, out); }
        c.hrr = true;
        c.state = ST_WAIT_CH2;
        return 0;
    }
    if second && group != c.group { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // The client's signature schemes, for CertificateVerify.
    take_peer_schemes(c, m, h.schemes, SIG_SCHEMES);
    let scheme = pick_scheme(cfg.key, c.peer_schemes);
    if select_alpn(c, cfg, h, m, out) != 0 { return -1; }
    c.sni.clear();
    if h.sni.end - h.sni.pos <= 255 { c.sni.append(m[h.sni.pos..h.sni.end]); }
    if !second {
        c.session_id.clear();
        c.session_id.append(m[h.sid.pos..h.sid.end]);
        c.th = transcript(s.hash);
    }
    // Resumption: the first identity that is a ticket of ours, unexpired,
    // for a suite of this hash; its binder must then be right.
    var psk: u8[>..] = [];
    var psk_identity = -1;
    c.psk_dhe = h.psk_dhe;
    if h.has_psk && h.psk_dhe && cfg.tickets > 0 {
        let now = now_ms(cfg.now) / 1000;
        var ids = h.psk_ids;
        var idx = 0;
        while ids.pos < ids.end && psk_identity < 0 {
            let id = get_vec(ids, m, 2);
            let age = get_bytes(ids, 4);
            if ids.bad { return fail(c, ALERT_DECODE_ERROR, out); }
            let t, okt = open_ticket(cfg.ticket_key, m[id.pos..id.end]);
            let ts, okts = suite(t.suite);
            if okt && okts && t.version == VERSION_TLS13 && ts.hash == s.hash && now >= t.created && now - t.created <= t.lifetime &&
               ticket_client_ok(cfg, t, now) {
                psk_identity = idx;
                psk.append(t.psk);
                // The client's certificate, carried over.
                c.chain.clear();
                c.chain.append(t.client_chain);
                c.peer_verified = t.client_verified;
                c.peer_not_after = t.client_not_after;
            }
            idx++;
        }
        if psk_identity >= 0 {
            var bl = h.psk_binders;
            var binder = empty_rd();
            for i in psk_identity + 1 { binder = get_vec(bl, m, 1); }
            if bl.bad { return fail(c, ALERT_DECODE_ERROR, out); }
            var th = c.th;
            transcript_add(th, m[..h.binders_at]);
            let early = schedule(s.hash, psk);
            if !finished_ok(s.hash, binder_key(early, false), transcript_hash(th), m[binder.pos..binder.end]) {
                return fail(c, ALERT_DECRYPT_ERROR, out);
            }
            c.resumed = true;
        }
    }
    if !c.resumed && scheme == 0 { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
    transcript_add(c.th, m);
    // ServerHello and the key schedule.
    let mine, shared, okx = server_share(c, group, m[share.pos..share.end]);
    if !okx { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    drbg_fill(c, c.random);
    if c.ech_confirm { send_server_hello(c, c.random, mine, false, out, psk_identity, m[h.random.pos..h.random.end]); }
    else { send_server_hello(c, c.random, mine, false, out, psk_identity); }
    if c.session_id.len > 0 { send_ccs(c, out); }
    c.sch = schedule(s.hash, psk);
    schedule_handshake(c.sch, shared, transcript_hash(c.th));
    c.write = record_keys(s, c.sch.s_hs);
    c.write_protected = true;
    c.read = record_keys(s, c.sch.c_hs);
    c.read_protected = true;
    // EncryptedExtensions, Certificate, CertificateVerify, Finished.
    var ee: u8[>..] = [];
    let exts = begin_vec(ee, 2);
    if c.alpn.len > 0 {
        let a = begin_ext(ee, EXT_ALPN);
        let l = begin_vec(ee, 2);
        ee.push(c.alpn.len as! u8);
        ee.append(c.alpn);
        patch_len(ee, l, 2);
        patch_len(ee, a, 2);
    }
    // ECH offered and not accepted: the retry configs, if any (§7.1).
    if c.ech_seen && !c.ech_confirm {
        let retry = ech_retry_list(cfg);
        if retry.len > 0 {
            let e = begin_ext(ee, EXT_ENCRYPTED_CLIENT_HELLO);
            ee.append(retry);
            patch_len(ee, e, 2);
        }
    }
    patch_len(ee, exts, 2);
    send_hs(c, handshake_message(HS_ENCRYPTED_EXTENSIONS, ee), out);
    // Resumed, the PSK authenticates both sides; the client's certificate,
    // if any, comes from the ticket.
    if !c.resumed {
        if cfg.client_auth != NO_CLIENT_CERT { send_certificate_request(c, cfg, out); }
        let e = send_certificate(c, cfg, scheme, out);
        if e != 0 { return e; }
    }
    let fin = finished_data(s.hash, c.sch.s_hs, transcript_hash(c.th));
    send_hs(c, handshake_message(HS_FINISHED, fin), out);
    schedule_master(c.sch, transcript_hash(c.th));
    c.write = record_keys(s, c.sch.s_ap);
    c.state = if c.cert_requested { ST_WAIT_CLIENT_CERT } else { ST_WAIT_CLIENT_FINISHED };
    return 0;
}

// ALPN: the server's first protocol the client offered; 0, or -1 after
// failing.
fn select_alpn(c: Conn&, cfg: const ServerConfig&, h: const Hello&, m: const u8[:], out: u8[>..]&) -> i64 {
    c.alpn.clear();
    if h.alpn.end > h.alpn.pos && cfg.alpn.len > 0 {
        var i = 0;
        while i < cfg.alpn.len && c.alpn.len == 0 {
            let n: i64 = cfg.alpn[i];
            var l = h.alpn;
            while l.pos < l.end {
                let p = get_vec(l, m, 1);
                if l.bad { return fail(c, ALERT_DECODE_ERROR, out); }
                if m[p.pos..p.end] == cfg.alpn[i + 1..i + 1 + n] { c.alpn.append(m[p.pos..p.end]); break; }
            }
            i += 1 + n;
        }
        if c.alpn.len == 0 { return fail(c, ALERT_NO_APPLICATION_PROTOCOL, out); }
    }
    return 0;
}

// Whether a ticket's client certificate suits what the server asks of
// clients now, as Go checks: one if required, none if none is asked for,
// unexpired, and, if the server checks them, checked then and still
// verifying under today's client CAs.
fn ticket_client_ok(cfg: const ServerConfig&, t: const TicketState&, now: i64) -> bool {
    if t.client_chain.len == 0 {
        return cfg.client_auth != REQUIRE_ANY_CLIENT_CERT && cfg.client_auth != REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if cfg.client_auth == NO_CLIENT_CERT || now > t.client_not_after { return false; }
    if cfg.client_auth < VERIFY_CLIENT_CERT_IF_GIVEN { return true; }
    return t.client_verified && client_chain_error(cfg, t.client_chain) == x509::OK;
}

// CertificateRequest (§4.3.2): an empty context, the schemes accepted and,
// when the server has client CAs, their names (as Go sends them).
fn send_certificate_request(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) {
    var b: u8[>..] = [];
    b.push(0);
    let exts = begin_vec(b, 2);
    let sa = begin_ext(b, EXT_SIGNATURE_ALGORITHMS);
    let sl = begin_vec(b, 2);
    for sc in SIG_SCHEMES { put_u16(b, sc); }
    patch_len(b, sl, 2);
    patch_len(b, sa, 2);
    let names = client_ca_names(cfg);
    if names.len > 0 {
        let ca = begin_ext(b, EXT_CERTIFICATE_AUTHORITIES);
        put_u16(b, names.len as! u16);
        b.append(names);
        patch_len(b, ca, 2);
    }
    patch_len(b, exts, 2);
    send_hs(c, handshake_message(HS_CERTIFICATE_REQUEST, b), out);
    c.cert_requested = true;
}

// Certificate and CertificateVerify.
fn send_certificate(c: Conn&, cfg: const ServerConfig&, scheme: u16, out: u8[>..]&) -> i64 {
    let cm, ok = certificate_message("", cfg.chain);
    if !ok { return fail(c, ALERT_INTERNAL_ERROR, out); }
    send_hs(c, cm, out);
    let cv, okv = certificate_verify_message(cfg.key, scheme, true, transcript_hash(c.th));
    if !okv { return fail(c, ALERT_INTERNAL_ERROR, out); }
    send_hs(c, cv, out);
    return 0;
}

// The client's Certificate: none (if allowed), or a chain that is checked
// when the server checks them; CertificateVerify follows.
fn server_client_certificate(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let count = read_certificates(c, m, c.cr_context, out);
    if count < 0 { return count; }
    if count == 0 {
        if cfg.client_auth == REQUIRE_ANY_CLIENT_CERT || cfg.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT {
            return fail(c, ALERT_CERTIFICATE_REQUIRED, out);
        }
        transcript_add(c.th, m);
        c.state = ST_WAIT_CLIENT_FINISHED;
        return 0;
    }
    if check_client_chain(c, cfg, out) != 0 { return -1; }
    transcript_add(c.th, m);
    c.state = ST_WAIT_CLIENT_CV;
    return 0;
}

// A client's chain (DER concatenated, leaf first) checked under the
// server's client CAs now: x509::OK or the error.
fn client_chain_error(cfg: const ServerConfig&, chain: const u8[:]) -> i64 {
    let ct, okt = asn1::read(chain, 0, chain.len);
    if !okt { return x509::ERR_MALFORMED; }
    let now = now_ms(cfg.now) / 1000;
    if x509::pool_len(cfg.client_cas) == 0 {
        let es, found = x509::verify_client_with_system_roots(chain[..ct.end], chain[ct.end..], now);
        return es;
    }
    return x509::verify_client_with_roots(chain[..ct.end], chain[ct.end..], cfg.client_cas, now);
}

// The client's chain in c.chain, checked when the server checks them: 0,
// or -1 after failing.
fn check_client_chain(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) -> i64 {
    let ct, okt = asn1::read(c.chain, 0, c.chain.len);
    if !okt { return fail(c, ALERT_BAD_CERTIFICATE, out); }
    let leaf, el = x509::parse(c.chain[..ct.end]);
    if el != x509::OK {
        c.error = el;
        return fail(c, ALERT_BAD_CERTIFICATE, out);
    }
    if cfg.client_auth >= VERIFY_CLIENT_CERT_IF_GIVEN {
        let e = client_chain_error(cfg, c.chain);
        if e != x509::OK {
            c.error = e;
            return fail(c, cert_alert(e), out);
        }
        c.peer_verified = true;
    }
    c.peer_not_after = leaf.not_after;
    return 0;
}

// A NewSessionTicket (§4.6.1) for the connection, sealed under the ticket
// key; the server sends cfg.tickets of them after the handshake and may
// send more at any time. False before the handshake is done.
fn send_session_ticket(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) -> bool {
    if c.state != ST_CONNECTED || !c.is_server || c.version != VERSION_TLS13 { return false; }
    let nonce: u8[1] = [c.tickets as! u8];
    c.tickets++;
    var age_add: u8[4] = [0; 4];
    drbg_fill(c, age_add);
    var tn: u8[12] = [0; 12];
    drbg_fill(c, tn);
    var t = TicketState { version: VERSION_TLS13, suite: c.suite.id, psk: [], ems: false, created: now_ms(cfg.now) / 1000,
                          age_add: (age_add[0] as u32) << 24 | (age_add[1] as u32) << 16 | (age_add[2] as u32) << 8 | age_add[3],
                          lifetime: MAX_TICKET_LIFETIME, alpn: [], sni: [], client_not_after: 0,
                          client_verified: false, client_chain: [] };
    t.psk.append(resumption_psk(c.suite.hash, c.sch.resumption, nonce));
    t.alpn.append(c.alpn);
    t.sni.append(c.sni);
    // The client's certificate goes in the ticket; one too big for it gets
    // no ticket.
    if c.chain.len > t.client_chain.cap { return false; }
    t.client_chain.append(c.chain);
    t.client_verified = c.peer_verified;
    t.client_not_after = c.peer_not_after;
    let ticket = seal_ticket(cfg.ticket_key, tn, t);
    var b: u8[>..] = [];
    for i in 4 { b.push((MAX_TICKET_LIFETIME >> (8 * (3 - i))) as! u8); }
    b.append(age_add);
    b.push(1);
    b.append(nonce);
    put_u16(b, ticket.len as! u16);
    b.append(ticket);
    put_u16(b, 0);
    // After the handshake, outside the transcript.
    out.append(seal_records(c.write, CT_HANDSHAKE, handshake_message(HS_NEW_SESSION_TICKET, b)));
    return true;
}

fn server_message(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if c.version == VERSION_TLS12 { return server_message12(c, cfg, m, out); }
    if (c.state == ST_WAIT_CH || c.state == ST_WAIT_CH2) && t == HS_CLIENT_HELLO {
        let ch, re = server_ech(c, cfg, m, out);
        if re != 0 { return re; }
        let r = server_client_hello(c, cfg, ch, out);
        if r == 0 && c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        return r;
    }
    if c.state == ST_WAIT_CLIENT_CERT && t == HS_CERTIFICATE { return server_client_certificate(c, cfg, m, out); }
    if c.state == ST_WAIT_CLIENT_CV && t == HS_CERTIFICATE_VERIFY {
        let r = peer_certificate_verify(c, m, out);
        if r == 0 { c.state = ST_WAIT_CLIENT_FINISHED; }
        return r;
    }
    if c.state == ST_WAIT_CLIENT_FINISHED && t == HS_FINISHED {
        if m.len - 4 != c.suite.hash / 8 { return fail(c, ALERT_DECODE_ERROR, out); }
        if !finished_ok(c.suite.hash, c.sch.c_hs, transcript_hash(c.th), m[4..]) {
            return fail(c, ALERT_DECRYPT_ERROR, out);
        }
        if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        transcript_add(c.th, m);
        schedule_resumption(c.sch, transcript_hash(c.th));
        c.read = record_keys(c.suite, c.sch.c_ap);
        c.state = ST_CONNECTED;
        // Tickets only for a client that can use them (§4.2.9).
        if c.psk_dhe { for i in cfg.tickets { let ok = send_session_ticket(c, cfg, out); } }
        return 0;
    }
    if c.state == ST_CONNECTED { return post_handshake(c, m, out); }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}

// --- Both sides ---------------------------------------------------------------

// Messages after the handshake: NewSessionTicket (to the client) and
// KeyUpdate.
fn post_handshake(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    if m[0] == HS_NEW_SESSION_TICKET && !c.is_server {
        c.tickets++;
        return 0;
    }
    if m[0] == HS_KEY_UPDATE {
        if m.len != 5 { return fail(c, ALERT_DECODE_ERROR, out); }
        if m[4] > 1 { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        if c.is_server {
            set48(c.sch.c_ap, next_traffic_secret(c.suite.hash, c.sch.c_ap));
            c.read = record_keys(c.suite, c.sch.c_ap);
        } else {
            set48(c.sch.s_ap, next_traffic_secret(c.suite.hash, c.sch.s_ap));
            c.read = record_keys(c.suite, c.sch.s_ap);
        }
        c.key_updates++;
        if m[4] == 1 { let ok = key_update(c, false, out); }
        return 0;
    }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}

// One whole record.
fn handle_record(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, rec: const u8[:],
                 out: u8[>..]&, app: u8[>..]&) -> i64 {
    let outer = rec[0];
    var ctype = outer;
    var payload: u8[>..] = [];
    if outer == CT_CHANGE_CIPHER_SPEC {
        if rec.len != 6 || rec[5] != 1 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        // TLS 1.2's turns on the peer's keys, at the end of a flight.
        if c.version == VERSION_TLS12 { return change_cipher_spec12(c, out); }
        // Middlebox compatibility: one byte 1, once, only during the
        // handshake (and not between a handshake message's fragments).
        if c.state == ST_CONNECTED || c.ccs_seen || c.hs.len > 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        c.ccs_seen = true;
        return 0;
    }
    if c.read_protected && outer == CT_ALERT && c.version == VERSION_TLS13 && c.state != ST_CONNECTED &&
       rec.len == 7 && rec[5] == ALERT_FATAL {
        // A peer that could not process our flight may have no keys to
        // protect its alert: a plaintext fatal alert ends the handshake.
        c.alert = rec[6];
        c.state = ST_FAILED;
        return -1;
    }
    if c.read_protected {
        // TLS 1.2 protects every type as itself; TLS 1.3 hides it.
        if outer != CT_APPLICATION_DATA && c.version != VERSION_TLS12 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        let t, p, a = open_record(c.read, rec);
        if a != 0 {
            // 0-RTT data the server refused: records its handshake keys
            // don't open are skipped, up to a limit (RFC 8446 §4.2.10).
            if c.skip_early && a == ALERT_BAD_RECORD_MAC {
                c.early_skipped += rec.len - 5;
                if c.early_skipped <= MAX_EARLY_SKIP { return 0; }
            }
            return fail(c, a, out);
        }
        c.skip_early = false;
        ctype = t;
        payload = copy(p);
    } else {
        // After a HelloRetryRequest the client's 0-RTT data, still under
        // its early keys, comes before its second ClientHello.
        if outer == CT_APPLICATION_DATA && c.skip_early && c.state == ST_WAIT_CH2 {
            c.early_skipped += rec.len - 5;
            if c.early_skipped <= MAX_EARLY_SKIP { return 0; }
        }
        if outer == CT_APPLICATION_DATA { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        if rec.len - 5 > MAX_FRAGMENT { return fail(c, ALERT_RECORD_OVERFLOW, out); }
        payload.append(rec[5..]);
    }
    // Handshake messages are not interleaved with other types (RFC 8446
    // §5.1); a peer's alert still ends the connection as its own.
    if ctype != CT_HANDSHAKE && ctype != CT_ALERT && c.hs.len > 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    // Records that carry nothing, many in a row, end the connection, as in
    // Go: else a peer could keep it busy forever.
    if payload.len == 0 || (ctype == CT_ALERT && payload.len == 2 && payload[0] == ALERT_WARNING &&
                            payload[1] != ALERT_CLOSE_NOTIFY && c.version == VERSION_TLS12) {
        c.useless++;
        if c.useless > MAX_USELESS_RECORDS { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    } else {
        c.useless = 0;
    }
    if ctype == CT_ALERT {
        // An empty alert is no alert (RFC 8446 §5.1, §6).
        if payload.len == 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        if payload.len != 2 { return fail(c, ALERT_DECODE_ERROR, out); }
        // TLS 1.2's warnings, no_renegotiation say, are dropped, as Go does.
        if c.version == VERSION_TLS12 && payload[0] == ALERT_WARNING && payload[1] != ALERT_CLOSE_NOTIFY { return 0; }
        c.alert = payload[1];
        c.state = if payload[1] == ALERT_CLOSE_NOTIFY { ST_CLOSED } else { ST_FAILED };
        return if c.state == ST_CLOSED { 0 } else { -1 };
    }
    if ctype == CT_APPLICATION_DATA {
        if c.state != ST_CONNECTED { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        app.append(payload);
        return 0;
    }
    if ctype != CT_HANDSHAKE || payload.len == 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    // A handshake message longer than MAX_HANDSHAKE: its length is wrong
    // for this implementation, so decode_error (RFC 8446 §6.2: "the length
    // of the message was incorrect"), as tlsfuzzer expects; Go sends
    // internal_error. unexpected_message would say the message was out of
    // place, which it is not.
    if c.hs.len + payload.len > c.hs.cap { return fail(c, ALERT_DECODE_ERROR, out); }
    c.hs.append(payload);
    loop {
        let n = handshake_length(c.hs);
        if n == 0 { break; }
        var msg: u8[>..] = [];
        msg.append(c.hs[..n]);
        var rest: u8[..65540] = [];
        rest.append(c.hs[n..]);
        c.hs = rest;
        let r = if c.is_server { server_message(c, scfg, msg, out) } else { client_message(c, ccfg, msg, out) };
        if r != 0 { return r; }
        // A change of read keys (after ServerHello) must fall at a record boundary.
        if c.hs.len > 0 && c.state == ST_WAIT_EE { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    }
    if c.hs.len >= 4 {
        let want = (c.hs[1] as i64) << 16 | (c.hs[2] as i64) << 8 | c.hs[3];
        if want > MAX_HANDSHAKE { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    return 0;
}

// Feeds received bytes; appends what to send to `out` and application
// data to `app`. Returns 0, or -1 once the connection has failed (the
// alert, already in `out` when it was ours, is in c.alert).
fn feed(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, input: const u8[:],
        out: u8[>..]&, app: u8[>..]&) -> i64 {
    var off = 0;
    while off < input.len {
        if c.state == ST_FAILED { return -1; }
        if c.state == ST_CLOSED { return 0; }
        // Collect the header, then the rest of one record.
        var need = 5 - c.inbuf.len;
        if c.inbuf.len >= 5 {
            let n = record_length(c.inbuf, c.version == VERSION_TLS12);
            if n < 0 { return fail(c, record_alert(c.inbuf, c.version == VERSION_TLS12), out); }
            let total = 5 + ((c.inbuf[3] as i64) << 8 | c.inbuf[4]);
            need = total - c.inbuf.len;
        }
        let take = ::min(need, input.len - off);
        c.inbuf.append(input[off..off + take]);
        off += take;
        if c.inbuf.len < 5 { continue; }
        let n = record_length(c.inbuf, c.version == VERSION_TLS12);
        if n < 0 { return fail(c, record_alert(c.inbuf, c.version == VERSION_TLS12), out); }
        if n == 0 { continue; }
        var rec: u8[>..] = [];
        rec.append(c.inbuf);
        c.inbuf.clear();
        let r = handle_record(c, ccfg, scfg, rec, out, app);
        if r != 0 { return r; }
    }
    return if c.state == ST_FAILED { -1 } else { 0 };
}

fn no_server() -> ServerConfig {
    ServerConfig { key: x509::empty_key(), min_version: VERSION_TLS12, max_version: VERSION_TLS13, groups: [], suites: [],
                   suites12: [], alpn: [], seed: 0, now: 0, tickets: 0,
                   ticket_key: [0; 32], chain: [], client_auth: NO_CLIENT_CERT, ech_keys: [],
                   client_cas: x509::new_pool() }
}

fn no_client() -> ClientConfig {
    ClientConfig { server_name: [], verify: false, now: 0, min_version: VERSION_TLS12, max_version: VERSION_TLS13,
                   groups: [], suites: [], suites12: [], alpn: [], seed: 0,
                   session: no_session(), cert_key: x509::empty_key(), cert_chain: [], ech_config_list: [],
                   system_roots: false, roots: x509::new_pool() }
}

fn client_feed(c: Conn&, cfg: const ClientConfig&, input: const u8[:], out: u8[>..]&, app: u8[>..]&) -> i64 {
    let none = no_server();
    return feed(c, cfg, none, input, out, app);
}

fn server_feed(c: Conn&, cfg: const ServerConfig&, input: const u8[:], out: u8[>..]&, app: u8[>..]&) -> i64 {
    let none = no_client();
    return feed(c, none, cfg, input, out, app);
}
