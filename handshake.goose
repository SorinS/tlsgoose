// tls.handshake: TLS 1.3 connections (RFC 8446), client and server,
// without I/O. A Conn holds one connection's state; feed it the bytes that
// arrive, and it appends the bytes to send and the application data
// received to builders the caller owns.
//
//   var c = tls::client(cfg);
//   tls::client_start(c, cfg, out);                  // the ClientHello
//   ... send out, receive into input ...
//   tls::client_feed(c, cfg, input, out, app);       // until tls::connected(c)
//   tls::send(c, "GET / HTTP/1.1\r\n...", out);
//
// Supported: the three cipher suites; X25519, P-256, P-384 and P-521 key
// exchange with HelloRetryRequest; server certificates checked by x509
// (chain, host name, CertificateVerify) with RSA-PSS, RSA PKCS #1 v1.5,
// ECDSA and Ed25519; ALPN; KeyUpdate; middlebox compatibility mode.
// Not supported: PSK and resumption (tickets are accepted and dropped),
// 0-RTT, client certificates (a request is answered with none), and TLS
// below 1.3.

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
import bignum.hmac;
import bignum.entropy;
import asn1;
import x509;
import x509.verify;

// Named groups and the signature schemes this package signs and verifies.
let GROUP_SECP256R1: u16 = 0x0017;
let GROUP_SECP384R1: u16 = 0x0018;
let GROUP_SECP521R1: u16 = 0x0019;
let GROUP_X25519: u16 = 0x001d;

// Extension types.
let EXT_SERVER_NAME: u16 = 0;
let EXT_SUPPORTED_GROUPS: u16 = 10;
let EXT_SIGNATURE_ALGORITHMS: u16 = 13;
let EXT_ALPN: u16 = 16;
let EXT_SUPPORTED_VERSIONS: u16 = 43;
let EXT_COOKIE: u16 = 44;
let EXT_KEY_SHARE: u16 = 51;

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
let ST_CONNECTED: i64 = 20;
let ST_CLOSED: i64 = 21;              // the peer sent close_notify
let ST_FAILED: i64 = 22;              // an alert was sent or received

// SHA-256("HelloRetryRequest"), the random of a HelloRetryRequest.
let HRR_RANDOM: u8[32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

// The signature schemes offered and accepted, most preferred first.
let SIG_SCHEMES: u16[10] = [0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];

let MAX_HANDSHAKE: i64 = 65536;

// What a client needs: the name it connects to (SNI and the certificate
// check), whether to check the certificate, the time for that check (0:
// now), its groups (the first gets a key share), suites and ALPN
// protocols, a DRBG seed for tests (0: the OS's entropy), and the trusted
// roots as concatenated DER.
struct ClientConfig {
    server_name: u8[..255], verify: bool, now: i64,
    groups: u16[..8], suites: u16[..8], alpn: u8[..255], seed: u64,
    roots: u8[>..],
}

fn client_config(server_name: const u8[:], roots: const u8[:]) -> ClientConfig {
    var c = ClientConfig {
        server_name: [], verify: true, now: 0,
        groups: [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1],
        suites: [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256],
        alpn: [], seed: 0, roots: [],
    };
    c.server_name.append(server_name);
    c.roots.append(roots);
    return c;
}

// Adds a protocol to an ALPN list (wire format: length-prefixed names).
fn add_alpn(list: u8[..255]&, proto: const u8[:]) {
    assert(proto.len > 0 && proto.len < 256 && list.len + 1 + proto.len <= 255);
    list.push(proto.len as! u8);
    list.append(proto);
}

// What a server needs: its private key (one of x509's KEY_* types), its
// groups, suites and ALPN protocols in order of preference, a DRBG seed,
// and its certificate chain as concatenated DER, the leaf first.
struct ServerConfig {
    key_type: i64, ec_sk: u8[..66], ed_seed: u8[32], rsa: bignum::RsaPrivateKey,
    groups: u16[..8], suites: u16[..8], alpn: u8[..255], seed: u64,
    chain: u8[>..],
}

fn empty_rsa() -> bignum::RsaPrivateKey {
    bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] }
}

// A server configuration from a chain (concatenated DER) and a private key
// in DER: PKCS #8 (RSA, EC or Ed25519), SEC 1 (EC) or PKCS #1 (RSA).
fn server_config(chain: const u8[:], key_der: const u8[:]) -> ServerConfig, bool {
    var s = ServerConfig {
        key_type: x509::KEY_UNKNOWN, ec_sk: [], ed_seed: [0; 32], rsa: empty_rsa(),
        groups: [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1],
        suites: [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256],
        alpn: [], seed: 0, chain: [],
    };
    s.chain.append(chain);
    let ok = load_key(s, key_der);
    return s, ok;
}

fn load_rsa(s: ServerConfig&, d: const u8[:], t: asn1::Tlv) -> bool {
    let f, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || f.len < 9 { return false; }
    let n, ok1 = asn1::read_uint(d, f[1]);
    let e, ok2 = asn1::read_uint(d, f[2]);
    let dd, ok3 = asn1::read_uint(d, f[3]);
    let p, ok4 = asn1::read_uint(d, f[4]);
    let q, ok5 = asn1::read_uint(d, f[5]);
    if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 { return false; }
    let k, okk = bignum::rsa_key_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e), bignum::from_bytes_be(dd),
                                      bignum::from_bytes_be(p), bignum::from_bytes_be(q));
    if !okk { return false; }
    s.rsa = k;
    s.key_type = x509::KEY_RSA;
    return true;
}

// ECPrivateKey ::= SEQUENCE { 1, privateKey OCTET STRING, [0] curve OPTIONAL, [1] public OPTIONAL }
fn load_ec(s: ServerConfig&, d: const u8[:], t: asn1::Tlv, curve: i64) -> bool {
    let f, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || f.len < 2 { return false; }
    let sk, oks = asn1::read_octets(d, f[1]);
    if !oks { return false; }
    var kind = curve;
    for x in f {
        if x.tag == asn1::ctx(0, true) {
            let o, oko = asn1::explicit(d, x);
            if asn1::oid_is(d, o, "1.2.840.10045.3.1.7") { kind = x509::KEY_EC_P256; }
            else if asn1::oid_is(d, o, "1.3.132.0.34") { kind = x509::KEY_EC_P384; }
            else if asn1::oid_is(d, o, "1.3.132.0.35") { kind = x509::KEY_EC_P521; }
            else { return false; }
        }
    }
    let want = if kind == x509::KEY_EC_P256 { 32 } else if kind == x509::KEY_EC_P384 { 48 }
               else if kind == x509::KEY_EC_P521 { 66 } else { 0 };
    if want == 0 || sk.len != want { return false; }
    s.ec_sk.clear();
    s.ec_sk.append(sk);
    s.key_type = kind;
    return true;
}

fn load_key(s: ServerConfig&, d: const u8[:]) -> bool {
    let top, ok = asn1::parse(d);
    let f, okf = asn1::children_of(d, top, asn1::SEQUENCE);
    if !ok || !okf || f.len < 2 { return false; }
    // PKCS #8: version, AlgorithmIdentifier, OCTET STRING.
    if f.len >= 3 && f[1].tag == asn1::SEQUENCE && f[2].tag == asn1::OCTET_STRING {
        let alg, oka = asn1::children(d, f[1]);
        if !oka || alg.len < 1 { return false; }
        let inner, oki = asn1::read(d, f[2].off, f[2].end);
        if asn1::oid_is(d, alg[0], "1.2.840.113549.1.1.1") { return oki && load_rsa(s, d, inner); }
        if asn1::oid_is(d, alg[0], "1.3.101.112") {
            let seed, okseed = asn1::read_octets(d, inner);
            if !oki || !okseed || seed.len != 32 { return false; }
            for i in 32 { s.ed_seed[i] = seed[i]; }
            s.key_type = x509::KEY_ED25519;
            return true;
        }
        if asn1::oid_is(d, alg[0], "1.2.840.10045.2.1") && alg.len == 2 {
            let curve = if asn1::oid_is(d, alg[1], "1.2.840.10045.3.1.7") { x509::KEY_EC_P256 }
                        else if asn1::oid_is(d, alg[1], "1.3.132.0.34") { x509::KEY_EC_P384 }
                        else if asn1::oid_is(d, alg[1], "1.3.132.0.35") { x509::KEY_EC_P521 } else { 0 };
            return oki && load_ec(s, d, inner, curve);
        }
        return false;
    }
    if f.len == 9 { return load_rsa(s, d, top); }                  // PKCS #1
    if f[1].tag == asn1::OCTET_STRING { return load_ec(s, d, top, 0); }   // SEC 1
    return false;
}

// One connection, either side.
struct Conn {
    is_server: bool, state: i64,
    alert: u8,                        // the alert sent on failure, or received
    error: i64,                       // the x509 error behind a certificate alert
    suite: Suite, sch: Schedule, th: Transcript,
    read: RecordKeys, write: RecordKeys, read_protected: bool, write_protected: bool,
    drbg_k: u8[32], drbg_v: u8[32],
    random: u8[32], session_id: u8[..32],
    group: u16, x25519_sk: u8[32], ec_sk: u8[..66],
    hrr: bool, ccs_sent: bool, cert_requested: bool, cr_context: u8[..255],
    peer_schemes: u16[..32], alpn: u8[..255], sni: u8[..255],
    tickets: i64, key_updates: i64,
    ch: u8[..8192],                   // the client's first ClientHello, until the hash is known
    inbuf: u8[..16645],               // one record in arrival
    hs: u8[..65536],                  // handshake messages being reassembled
    chain: u8[..65536],               // the peer's certificates, DER concatenated, leaf first
}

fn suite_none() -> Suite { let s, ok = suite(TLS_AES_128_GCM_SHA256); return s; }

fn new_conn(is_server: bool, seed: u64) -> Conn {
    let s = suite_none();
    var zero: u8[32] = [0; 32];
    var c = Conn {
        is_server: is_server, state: if is_server { ST_WAIT_CH } else { ST_START }, alert: 0, error: 0,
        suite: s, sch: schedule(256, ""), th: transcript(256),
        read: record_keys(s, zero), write: record_keys(s, zero), read_protected: false, write_protected: false,
        drbg_k: [0; 32], drbg_v: [1; 32], random: [0; 32], session_id: [],
        group: 0, x25519_sk: [0; 32], ec_sk: [], hrr: false, ccs_sent: false, cert_requested: false,
        cr_context: [], peer_schemes: [], alpn: [], sni: [], tickets: 0, key_updates: 0,
        ch: [], inbuf: [], hs: [], chain: [],
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

fn client(cfg: const ClientConfig&) -> Conn { new_conn(false, cfg.seed) }
fn server(cfg: const ServerConfig&) -> Conn { new_conn(true, cfg.seed) }

fn connected(c: const Conn&) -> bool { c.state == ST_CONNECTED }
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
    if c.write_protected {
        out.append(seal_records(c.write, CT_HANDSHAKE, msg));
    } else {
        out.append(plain_record(CT_HANDSHAKE, msg, if c.is_server { 0x0303 } else { 0x0301 }));
    }
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
    if c.state != ST_CONNECTED { return false; }
    let body: u8[1] = [if request { 1 } else { 0 }];
    out.append(seal_record(c.write, CT_HANDSHAKE, handshake_message(HS_KEY_UPDATE, body)));
    update_write(c);
    return true;
}

// --- Key exchange -----------------------------------------------------------

fn curve_of(group: u16) -> bignum::Curve {
    if group == GROUP_SECP256R1 { bignum::p256() } else if group == GROUP_SECP384R1 { bignum::p384() } else { bignum::p521() }
}

// A fresh share for `group`: the public value to send.
fn make_share(c: Conn&, group: u16) -> u8[>..] {
    var out: u8[>..] = [];
    c.group = group;
    if group == GROUP_X25519 {
        drbg_fill(c, c.x25519_sk);
        out.append(bignum::x25519_base(c.x25519_sk));
        return out;
    }
    let curve = curve_of(group);
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

// The shared secret from the peer's share, and false for a bad share.
fn shared_secret(c: const Conn&, peer: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if c.group == GROUP_X25519 {
        if peer.len != 32 { return out, false; }
        let s, ok = bignum::x25519_shared(c.x25519_sk, peer);
        out.append(s);
        return out, ok;
    }
    let curve = curve_of(c.group);
    let s, ok = bignum::ecdh_shared(curve, c.ec_sk, peer);
    out.append(s);
    return out, ok;
}

fn known_group(g: i64) -> bool { g == GROUP_X25519 || g == GROUP_SECP256R1 || g == GROUP_SECP384R1 || g == GROUP_SECP521R1 }

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

// The scheme the server signs with, for its key and the client's list; 0
// for none.
fn pick_scheme(cfg: const ServerConfig&, peer: const u16[:]) -> u16 {
    if cfg.key_type == x509::KEY_ED25519 && offered_scheme(peer, x509::ED25519) { return x509::ED25519; }
    if cfg.key_type == x509::KEY_EC_P256 && offered_scheme(peer, x509::ECDSA_SECP256R1_SHA256) { return x509::ECDSA_SECP256R1_SHA256; }
    if cfg.key_type == x509::KEY_EC_P384 && offered_scheme(peer, x509::ECDSA_SECP384R1_SHA384) { return x509::ECDSA_SECP384R1_SHA384; }
    if cfg.key_type == x509::KEY_EC_P521 && offered_scheme(peer, x509::ECDSA_SECP521R1_SHA512) { return x509::ECDSA_SECP521R1_SHA512; }
    if cfg.key_type == x509::KEY_RSA {
        for s in [x509::RSA_PSS_RSAE_SHA256, x509::RSA_PSS_RSAE_SHA384, x509::RSA_PSS_RSAE_SHA512] {
            if offered_scheme(peer, s) { return s; }
        }
    }
    return 0;
}

fn sign(cfg: const ServerConfig&, scheme: u16, msg: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if scheme == x509::ED25519 {
        out.append(bignum::ed25519_sign(cfg.ed_seed, msg));
    } else if scheme == x509::ECDSA_SECP256R1_SHA256 || scheme == x509::ECDSA_SECP384R1_SHA384
              || scheme == x509::ECDSA_SECP521R1_SHA512 {
        let curve = if scheme == x509::ECDSA_SECP256R1_SHA256 { bignum::p256() }
                    else if scheme == x509::ECDSA_SECP384R1_SHA384 { bignum::p384() } else { bignum::p521() };
        out = bignum::ecdsa_sig_to_der(bignum::ecdsa_sign(curve, cfg.ec_sk, msg));
    } else {
        let h = if scheme == x509::RSA_PSS_RSAE_SHA256 { 256 } else if scheme == x509::RSA_PSS_RSAE_SHA384 { 384 } else { 512 };
        out = bignum::rsa_sign_pss(cfg.rsa, msg, -1, h);
    }
    return out;
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

fn build_client_hello(c: Conn&, cfg: const ClientConfig&, share_group: u16, cookie: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    put_u16(b, 0x0303);
    b.append(c.random);
    b.push(c.session_id.len as! u8);
    b.append(c.session_id);
    let suites = begin_vec(b, 2);
    for s in cfg.suites { put_u16(b, s); }
    patch_len(b, suites, 2);
    b.push(1);
    b.push(0);
    let exts = begin_vec(b, 2);
    if cfg.server_name.len > 0 {
        let e = begin_ext(b, EXT_SERVER_NAME);
        let list = begin_vec(b, 2);
        b.push(0);
        put_u16(b, cfg.server_name.len as! u16);
        b.append(cfg.server_name);
        patch_len(b, list, 2);
        patch_len(b, e, 2);
    }
    let sv = begin_ext(b, EXT_SUPPORTED_VERSIONS);
    b.push(2);
    put_u16(b, 0x0304);
    patch_len(b, sv, 2);
    let sg = begin_ext(b, EXT_SUPPORTED_GROUPS);
    let gl = begin_vec(b, 2);
    for g in cfg.groups { put_u16(b, g); }
    patch_len(b, gl, 2);
    patch_len(b, sg, 2);
    let sa = begin_ext(b, EXT_SIGNATURE_ALGORITHMS);
    let sl = begin_vec(b, 2);
    for s in SIG_SCHEMES { put_u16(b, s); }
    patch_len(b, sl, 2);
    patch_len(b, sa, 2);
    let ks = begin_ext(b, EXT_KEY_SHARE);
    let kl = begin_vec(b, 2);
    put_u16(b, share_group);
    let pubkey = make_share(c, share_group);
    put_u16(b, pubkey.len as! u16);
    b.append(pubkey);
    patch_len(b, kl, 2);
    patch_len(b, ks, 2);
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
    patch_len(b, exts, 2);
    return handshake_message(HS_CLIENT_HELLO, b);
}

// Sends the ClientHello.
fn client_start(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&) {
    assert(c.state == ST_START && cfg.groups.len > 0 && cfg.suites.len > 0);
    drbg_fill(c, c.random);
    var sid: u8[32] = [0; 32];
    drbg_fill(c, sid);
    c.session_id.append(sid);                      // middlebox compatibility mode
    let ch = build_client_hello(c, cfg, cfg.groups[0], "");
    c.ch.append(ch);
    out.append(plain_record(CT_HANDSHAKE, ch, 0x0301));
    c.state = ST_WAIT_SH;
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
    var exts = get_vec(b, m, 2);
    if b.bad || !done(b) || comp != 0 { return fail(c, ALERT_DECODE_ERROR, out); }
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
        } else {
            return fail(c, ALERT_UNSUPPORTED_EXTENSION, out);
        }
        if !done(e) { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    // Without supported_versions this is TLS 1.2 or older, which is not
    // supported (§4.1.3's downgrade sentinels concern servers that are).
    if version != 0x0304 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    if is_hrr {
        var known = false;
        for g in cfg.groups { if g == share_group { known = true; } }
        if c.hrr || !known || share_group == c.group { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        c.hrr = true;
        c.suite = s;
        c.th = transcript(s.hash);
        transcript_add(c.th, c.ch);
        transcript_restart_hrr(c.th);
        transcript_add(c.th, m);
        send_ccs(c, out);
        var ck: u8[>..] = [];
        ck.append(m[cookie.pos..cookie.end]);
        let ch2 = build_client_hello(c, cfg, share_group as! u16, ck);
        send_hs(c, ch2, out);
        return 0;
    }
    if share_group != c.group || share.bad { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let shared, okx = shared_secret(c, m[share.pos..share.end]);
    if !okx { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    if !c.hrr {
        c.suite = s;
        c.th = transcript(s.hash);
        transcript_add(c.th, c.ch);
    }
    transcript_add(c.th, m);
    c.sch = schedule(s.hash, "");
    schedule_handshake(c.sch, shared, transcript_hash(c.th));
    c.read = record_keys(s, c.sch.s_hs);
    c.read_protected = true;
    c.state = ST_WAIT_EE;
    return 0;
}

let ALERT_UNSUPPORTED_EXTENSION: u8 = 110;

fn client_encrypted_extensions(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    var exts = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
        if ty == EXT_ALPN {
            var list = get_vec(e, m, 2);
            let p = get_vec(list, m, 1);
            if !done(list) || !done(e) || p.end == p.pos { return fail(c, ALERT_DECODE_ERROR, out); }
            // The protocol must be one the client offered.
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
        } else if ty == EXT_KEY_SHARE || ty == EXT_SUPPORTED_VERSIONS || ty == EXT_COOKIE || ty == EXT_SIGNATURE_ALGORITHMS {
            return fail(c, ALERT_ILLEGAL_PARAMETER, out);     // forbidden in EncryptedExtensions
        }
    }
    transcript_add(c.th, m);
    c.state = ST_WAIT_CERT_CR;
    return 0;
}

fn client_certificate(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ctx = get_vec(b, m, 1);
    var list = get_vec(b, m, 3);
    if !done(b) || ctx.end != ctx.pos { return fail(c, ALERT_DECODE_ERROR, out); }
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
    if count == 0 { return fail(c, ALERT_DECODE_ERROR, out); }
    let ct, okt = asn1::read(c.chain, 0, c.chain.len);
    if !okt { return fail(c, ALERT_BAD_CERTIFICATE, out); }
    if cfg.verify {
        let now = if cfg.now != 0 { cfg.now } else { time() as i64 };
        let e = x509::verify_chain(c.chain[..ct.end], c.chain[ct.end..], cfg.roots, now, cfg.server_name);
        if e != x509::OK {
            c.error = e;
            return fail(c, cert_alert(e), out);
        }
    }
    transcript_add(c.th, m);
    c.state = ST_WAIT_CV;
    return 0;
}

fn client_certificate_verify(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let scheme = get_u16(b, m);
    let sig = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    if !offered_scheme(SIG_SCHEMES, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    let ct, okt = asn1::read(c.chain, 0, c.chain.len);
    let leaf, e = x509::parse(c.chain[..ct.end]);
    if e != x509::OK { return fail(c, ALERT_BAD_CERTIFICATE, out); }
    let content = cv_content(true, transcript_hash(c.th));
    if x509::verify_scheme(leaf, scheme as! u16, content, m[sig.pos..sig.end]) != x509::OK {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    transcript_add(c.th, m);
    c.state = ST_WAIT_FINISHED;
    return 0;
}

fn client_finished(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    if !finished_ok(c.suite.hash, c.sch.s_hs, transcript_hash(c.th), m[4..]) {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }   // the key change ends a record
    transcript_add(c.th, m);
    schedule_master(c.sch, transcript_hash(c.th));
    // The client's flight: change_cipher_spec, an empty Certificate if one
    // was asked for, Finished.
    send_ccs(c, out);
    c.write = record_keys(c.suite, c.sch.c_hs);
    c.write_protected = true;
    if c.cert_requested {
        var body: u8[>..] = [];
        body.push(c.cr_context.len as! u8);
        body.append(c.cr_context);
        body.push(0); body.push(0); body.push(0);
        send_hs(c, handshake_message(HS_CERTIFICATE, body), out);
    }
    let fin = finished_data(c.suite.hash, c.sch.c_hs, transcript_hash(c.th));
    send_hs(c, handshake_message(HS_FINISHED, fin), out);
    schedule_resumption(c.sch, transcript_hash(c.th));
    c.write = record_keys(c.suite, c.sch.c_ap);
    c.read = record_keys(c.suite, c.sch.s_ap);
    c.state = ST_CONNECTED;
    return 0;
}

fn client_message(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if c.state == ST_WAIT_SH && t == HS_SERVER_HELLO { return client_server_hello(c, cfg, m, out); }
    if c.state == ST_WAIT_EE && t == HS_ENCRYPTED_EXTENSIONS { return client_encrypted_extensions(c, cfg, m, out); }
    if c.state == ST_WAIT_CERT_CR && t == HS_CERTIFICATE_REQUEST {
        var b = Rd { pos: 4, end: m.len, bad: false };
        let ctx = get_vec(b, m, 1);
        let exts = get_vec(b, m, 2);
        if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
        c.cr_context.clear();
        c.cr_context.append(m[ctx.pos..ctx.end]);
        c.cert_requested = true;
        transcript_add(c.th, m);
        c.state = ST_WAIT_CERT;
        return 0;
    }
    if (c.state == ST_WAIT_CERT_CR || c.state == ST_WAIT_CERT) && t == HS_CERTIFICATE {
        return client_certificate(c, cfg, m, out);
    }
    if c.state == ST_WAIT_CV && t == HS_CERTIFICATE_VERIFY { return client_certificate_verify(c, m, out); }
    if c.state == ST_WAIT_FINISHED && t == HS_FINISHED { return client_finished(c, m, out); }
    if c.state == ST_CONNECTED { return post_handshake(c, m, out); }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}

// --- The server -------------------------------------------------------------

// What a ClientHello offers, as offsets into it.
struct Hello {
    suites: Rd, groups: Rd, shares: Rd, schemes: Rd, sni: Rd, alpn: Rd, cookie: Rd,
    sid: Rd, random: Rd, has_versions13: bool, has_groups: bool, has_shares: bool, has_schemes: bool,
}

fn empty_rd() -> Rd { Rd { pos: 0, end: 0, bad: false } }

fn parse_hello(m: const u8[:]) -> Hello, bool {
    var h = Hello {
        suites: empty_rd(), groups: empty_rd(), shares: empty_rd(), schemes: empty_rd(), sni: empty_rd(),
        alpn: empty_rd(), cookie: empty_rd(), sid: empty_rd(), random: empty_rd(),
        has_versions13: false, has_groups: false, has_shares: false, has_schemes: false,
    };
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ver = get_u16(b, m);
    h.random = get_bytes(b, 32);
    h.sid = get_vec(b, m, 1);
    h.suites = get_vec(b, m, 2);
    let comp = get_vec(b, m, 1);
    if b.bad || h.sid.end - h.sid.pos > 32 || ver < 0x0301 { return h, false; }
    // Only the null compression method, alone (§4.1.2).
    if comp.end - comp.pos != 1 || m[comp.pos] != 0 { return h, false; }
    var exts = get_vec(b, m, 2);
    if !done(b) { return h, false; }
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return h, false; }
        if ty == EXT_SUPPORTED_VERSIONS {
            var l = get_vec(e, m, 1);
            while l.pos < l.end { if get_u16(l, m) == 0x0304 { h.has_versions13 = true; } }
            if l.bad { return h, false; }
        } else if ty == EXT_SUPPORTED_GROUPS {
            h.groups = get_vec(e, m, 2);
            h.has_groups = true;
        } else if ty == EXT_KEY_SHARE {
            h.shares = get_vec(e, m, 2);
            h.has_shares = true;
        } else if ty == EXT_SIGNATURE_ALGORITHMS {
            h.schemes = get_vec(e, m, 2);
            h.has_schemes = true;
        } else if ty == EXT_SERVER_NAME {
            var l = get_vec(e, m, 2);
            let kind = get_u8(l, m);
            h.sni = get_vec(l, m, 2);
            if kind != 0 { return h, false; }
        } else if ty == EXT_ALPN {
            h.alpn = get_vec(e, m, 2);
        } else if ty == EXT_COOKIE {
            h.cookie = get_vec(e, m, 2);
        }
        if e.bad { return h, false; }
    }
    return h, true;
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

fn send_server_hello(c: Conn&, random: const u8[:], share: const u8[:], hrr: bool, out: u8[>..]&) {
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
    patch_len(b, exts, 2);
    send_hs(c, handshake_message(HS_SERVER_HELLO, b), out);
}

fn server_client_hello(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let h, ok = parse_hello(m);
    if !ok { return fail(c, ALERT_DECODE_ERROR, out); }
    if !h.has_versions13 { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    if !h.has_groups || !h.has_shares || !h.has_schemes { return fail(c, ALERT_MISSING_EXTENSION, out); }
    let second = c.state == ST_WAIT_CH2;
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
        c.group = fallback;
        c.th = transcript(s.hash);
        transcript_add(c.th, m);
        transcript_restart_hrr(c.th);
        send_server_hello(c, HRR_RANDOM, "", true, out);
        if c.session_id.len > 0 { send_ccs(c, out); }
        c.hrr = true;
        c.state = ST_WAIT_CH2;
        return 0;
    }
    if second && group != c.group { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // The client's signature schemes, for CertificateVerify.
    c.peer_schemes.clear();
    var sl = h.schemes;
    while sl.pos + 1 < sl.end && c.peer_schemes.len < c.peer_schemes.cap { c.peer_schemes.push(get_u16(sl, m) as! u16); }
    let scheme = pick_scheme(cfg, c.peer_schemes);
    if scheme == 0 { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
    // ALPN: the server's first protocol the client offered.
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
    c.sni.clear();
    if h.sni.end - h.sni.pos <= 255 { c.sni.append(m[h.sni.pos..h.sni.end]); }
    if !second {
        c.session_id.clear();
        c.session_id.append(m[h.sid.pos..h.sid.end]);
        c.th = transcript(s.hash);
    }
    transcript_add(c.th, m);
    // ServerHello and the key schedule.
    let mine = make_share(c, group);
    let shared, okx = shared_secret(c, m[share.pos..share.end]);
    if !okx { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    drbg_fill(c, c.random);
    send_server_hello(c, c.random, mine, false, out);
    if c.session_id.len > 0 { send_ccs(c, out); }
    c.sch = schedule(s.hash, "");
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
    patch_len(ee, exts, 2);
    send_hs(c, handshake_message(HS_ENCRYPTED_EXTENSIONS, ee), out);
    var cert: u8[>..] = [];
    cert.push(0);
    let list = begin_vec(cert, 3);
    var off = 0;
    while off < cfg.chain.len {
        let t, okc = asn1::read(cfg.chain, off, cfg.chain.len);
        if !okc { return fail(c, ALERT_INTERNAL_ERROR, out); }
        let one = begin_vec(cert, 3);
        cert.append(cfg.chain[t.start..t.end]);
        patch_len(cert, one, 3);
        put_u16(cert, 0);
        off = t.end;
    }
    patch_len(cert, list, 3);
    send_hs(c, handshake_message(HS_CERTIFICATE, cert), out);
    let sig = sign(cfg, scheme, cv_content(true, transcript_hash(c.th)));
    var cv: u8[>..] = [];
    put_u16(cv, scheme);
    put_u16(cv, sig.len as! u16);
    cv.append(sig);
    send_hs(c, handshake_message(HS_CERTIFICATE_VERIFY, cv), out);
    let fin = finished_data(s.hash, c.sch.s_hs, transcript_hash(c.th));
    send_hs(c, handshake_message(HS_FINISHED, fin), out);
    schedule_master(c.sch, transcript_hash(c.th));
    c.write = record_keys(s, c.sch.s_ap);
    c.state = ST_WAIT_CLIENT_FINISHED;
    return 0;
}

fn server_message(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if (c.state == ST_WAIT_CH || c.state == ST_WAIT_CH2) && t == HS_CLIENT_HELLO {
        let r = server_client_hello(c, cfg, m, out);
        if r == 0 && c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        return r;
    }
    if c.state == ST_WAIT_CLIENT_FINISHED && t == HS_FINISHED {
        if !finished_ok(c.suite.hash, c.sch.c_hs, transcript_hash(c.th), m[4..]) {
            return fail(c, ALERT_DECRYPT_ERROR, out);
        }
        if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        transcript_add(c.th, m);
        schedule_resumption(c.sch, transcript_hash(c.th));
        c.read = record_keys(c.suite, c.sch.c_ap);
        c.state = ST_CONNECTED;
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
        if m.len != 5 || m[4] > 1 { return fail(c, ALERT_DECODE_ERROR, out); }
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
        // Middlebox compatibility: one byte 1, only during the handshake.
        if rec.len != 6 || rec[5] != 1 || c.state == ST_CONNECTED { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        return 0;
    }
    if c.read_protected {
        if outer != CT_APPLICATION_DATA { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        let t, p, a = open_record(c.read, rec);
        if a != 0 { return fail(c, a, out); }
        ctype = t;
        payload = copy(p);
    } else {
        if outer == CT_APPLICATION_DATA { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
        payload.append(rec[5..]);
    }
    if ctype == CT_ALERT {
        if payload.len != 2 { return fail(c, ALERT_DECODE_ERROR, out); }
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
    if c.hs.len + payload.len > c.hs.cap { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    c.hs.append(payload);
    loop {
        let n = handshake_length(c.hs);
        if n == 0 { break; }
        var msg: u8[>..] = [];
        msg.append(c.hs[..n]);
        var rest: u8[..65536] = [];
        rest.append(c.hs[n..]);
        c.hs = rest;
        let r = if c.is_server { server_message(c, scfg, msg, out) } else { client_message(c, ccfg, msg, out) };
        if r != 0 { return r; }
        // A change of read keys (after ServerHello) must fall at a record boundary.
        if c.hs.len > 0 && c.state == ST_WAIT_EE { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    }
    if c.hs.len >= 4 {
        let want = (c.hs[1] as i64) << 16 | (c.hs[2] as i64) << 8 | c.hs[3];
        if want + 4 > MAX_HANDSHAKE { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
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
            let n = record_length(c.inbuf);
            if n < 0 { return fail(c, ALERT_DECODE_ERROR, out); }
            let total = 5 + ((c.inbuf[3] as i64) << 8 | c.inbuf[4]);
            need = total - c.inbuf.len;
        }
        let take = ::min(need, input.len - off);
        c.inbuf.append(input[off..off + take]);
        off += take;
        if c.inbuf.len < 5 { continue; }
        let n = record_length(c.inbuf);
        if n < 0 { return fail(c, ALERT_DECODE_ERROR, out); }
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
    ServerConfig { key_type: 0, ec_sk: [], ed_seed: [0; 32], rsa: empty_rsa(), groups: [], suites: [],
                   alpn: [], seed: 0, chain: [] }
}

fn no_client() -> ClientConfig {
    ClientConfig { server_name: [], verify: false, now: 0, groups: [], suites: [], alpn: [], seed: 0, roots: [] }
}

fn client_feed(c: Conn&, cfg: const ClientConfig&, input: const u8[:], out: u8[>..]&, app: u8[>..]&) -> i64 {
    let none = no_server();
    return feed(c, cfg, none, input, out, app);
}

fn server_feed(c: Conn&, cfg: const ServerConfig&, input: const u8[:], out: u8[>..]&, app: u8[>..]&) -> i64 {
    let none = no_client();
    return feed(c, none, cfg, input, out, app);
}
