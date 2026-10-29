// tls.handshake12: TLS 1.2 (RFC 5246) for tls.handshake's connections,
// both sides, as Go's crypto/tls has it. tls.handshake negotiates the
// version and hands TLS 1.2's messages here.
//
// Full handshake: ClientHello; ServerHello, Certificate,
// ServerKeyExchange (ECDHE, signed), [CertificateRequest],
// ServerHelloDone; [Certificate], ClientKeyExchange, [CertificateVerify],
// change_cipher_spec, Finished; [NewSessionTicket], change_cipher_spec,
// Finished. Resumed with a session ticket (RFC 5077): ClientHello;
// ServerHello with the client's session ID, [NewSessionTicket],
// change_cipher_spec, Finished; change_cipher_spec, Finished.
//
// The master secret is the extended one (RFC 7627) when both sides take
// it; RSA key exchange runs only when its suites are configured, and a
// bad ClientKeyExchange goes on with a random premaster secret
// (Bleichenbacher); renegotiation is refused with no_renegotiation.

namespace tls;

import std;
import tls;
import schedule;
import record;
import session;
import handshake;
import bignum;
import bignum.rsa;
import asn1;
import x509;
import x509.keys;

// The end of a TLS 1.3 server's random when it negotiates TLS 1.2, and
// TLS 1.1 or below (RFC 8446 §4.1.3): "DOWNGRD" and 1 or 0.
let DOWNGRADE12: u8[8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
let DOWNGRADE11: u8[8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

// The signature schemes of TLS 1.2: TLS 1.3's but ML-DSA, no SHA-1 (as Go
// since 1.25).
let SIG_SCHEMES12: u16[10] = [0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];

// Whether a scheme suits a key in TLS 1.2: RSA with PSS or PKCS #1 v1.5,
// ECDSA with any of its hashes whatever the curve (§7.4.1.4.1), Ed25519
// (RFC 8422).
fn scheme_fits12(kind: i64, s: u16) -> bool {
    if kind == x509::KEY_RSA {
        return s == x509::RSA_PSS_RSAE_SHA256 || s == x509::RSA_PSS_RSAE_SHA384 || s == x509::RSA_PSS_RSAE_SHA512 ||
               s == x509::RSA_PKCS1_SHA256 || s == x509::RSA_PKCS1_SHA384 || s == x509::RSA_PKCS1_SHA512;
    }
    if kind == x509::KEY_ED25519 { return s == x509::ED25519; }
    if kind == x509::KEY_EC_P256 || kind == x509::KEY_EC_P384 || kind == x509::KEY_EC_P521 {
        return s == x509::ECDSA_SECP256R1_SHA256 || s == x509::ECDSA_SECP384R1_SHA384 || s == x509::ECDSA_SECP521R1_SHA512;
    }
    return false;
}

// The scheme to sign with: the peer's first that suits the key, as Go
// picks it; 0 for none.
fn pick_scheme12(kind: i64, peer: const u16[:]) -> u16 {
    for s in peer { if offered_scheme(SIG_SCHEMES12, s) && scheme_fits12(kind, s) { return s; } }
    return 0;
}

// Whether sig over msg is the leaf's by scheme s.
fn verify12(leaf: const x509::Cert&, s: u16, msg: const u8[:], sig: const u8[:]) -> bool {
    if !scheme_fits12(leaf.key_type, s) { return false; }
    if s == x509::ECDSA_SECP256R1_SHA256 || s == x509::ECDSA_SECP384R1_SHA384 || s == x509::ECDSA_SECP521R1_SHA512 {
        let h = if s == x509::ECDSA_SECP256R1_SHA256 { 256 } else if s == x509::ECDSA_SECP384R1_SHA384 { 384 } else { 512 };
        return x509::verify_with(leaf, x509::SIG_ECDSA, h, 0, msg, sig) == x509::OK;
    }
    return x509::verify_scheme(leaf, s, msg, sig) == x509::OK;
}

// Whether a key serves a suite's key exchange: ECDSA suites take EC and
// Ed25519 keys, the others RSA ones.
fn kx_fits(kx: i64, kind: i64) -> bool {
    if kx == KX_ECDHE_ECDSA {
        return kind == x509::KEY_EC_P256 || kind == x509::KEY_EC_P384 || kind == x509::KEY_EC_P521 || kind == x509::KEY_ED25519;
    }
    return kind == x509::KEY_RSA;
}

// The groups of TLS 1.2's ECDHE: no ML-KEM.
fn ecdh_group12(g: u16) -> bool {
    g == GROUP_X25519 || g == GROUP_SECP256R1 || g == GROUP_SECP384R1 || g == GROUP_SECP521R1
}

let ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;

// --- Keys ---------------------------------------------------------------------

// One direction's record keys, from the key block.
fn keys12(c: const Conn&, client_write: bool) -> RecordKeys {
    var cr = c.random;
    var sr = c.peer_random;
    if c.is_server { cr = c.peer_random; sr = c.random; }
    let kb = key_block12(c.suite, c.master, cr, sr);
    let ml = c.suite.mac / 8;
    let kl = c.suite.key_len;
    let il = (kb.len - 2 * (ml + kl)) / 2;
    let w = if client_write { 0 } else { 1 };
    let k0 = 2 * ml;
    let i0 = 2 * (ml + kl);
    return record_keys12(c.suite, kb[k0 + w * kl..k0 + (w + 1) * kl], kb[w * ml..(w + 1) * ml],
                         kb[i0 + w * il..i0 + (w + 1) * il]);
}

// change_cipher_spec, then this side's keys.
fn send_ccs12(c: Conn&, out: u8[>..]&) {
    let one: u8[1] = [1];
    out.append(plain_record(CT_CHANGE_CIPHER_SPEC, one));
    c.write = keys12(c, !c.is_server);
    c.write_protected = true;
}

// The peer's change_cipher_spec: its keys from here on, only where the
// handshake expects them and at the end of its flight's messages.
fn change_cipher_spec12(c: Conn&, out: u8[>..]&) -> i64 {
    let want = if c.is_server { ST12_WAIT_CLIENT_CCS } else { ST12_WAIT_CCS };
    if c.state != want || c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    // A server that said it would send a ticket sends it first.
    if !c.is_server && c.ticket12 && c.tickets == 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    c.read = keys12(c, c.is_server);
    c.read_protected = true;
    c.state = if c.is_server { ST12_WAIT_CLIENT_FINISHED } else { ST12_WAIT_FINISHED };
    return 0;
}

fn send_finished12(c: Conn&, out: u8[>..]&) {
    let fin = finished12(c.suite.hash, c.master, !c.is_server, transcript_hash(c.th));
    send_hs(c, handshake_message(HS_FINISHED, fin), out);
}

// --- Certificates -------------------------------------------------------------

// A TLS 1.2 Certificate message: the chain's certificates, with no
// context or extensions; false if the chain is malformed.
fn certificate_message12(chain: const u8[:]) -> u8[>..], bool {
    var body: u8[>..] = [];
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
        off = t.end;
    }
    patch_len(body, list, 3);
    return handshake_message(HS_CERTIFICATE, body), true;
}

// The certificates of a TLS 1.2 Certificate message into c.chain; how
// many, or -1 after failing.
fn read_certificates12(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    var list = get_vec(b, m, 3);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    c.chain.clear();
    var count = 0;
    while list.pos < list.end {
        let cert = get_vec(list, m, 3);
        if list.bad || cert.end == cert.pos { return fail(c, ALERT_DECODE_ERROR, out); }
        if c.chain.len + cert.end - cert.pos > c.chain.cap { return fail(c, ALERT_BAD_CERTIFICATE, out); }
        c.chain.append(m[cert.pos..cert.end]);
        count++;
    }
    return count;
}

// The peer's leaf certificate.
fn peer_leaf(c: const Conn&) -> x509::Cert, bool {
    let t, ok = asn1::read(c.chain, 0, c.chain.len);
    var end = 0;
    if ok { end = t.end; }
    let leaf, e = x509::parse(c.chain[..end]);
    return leaf, ok && e == x509::OK;
}

// The names of the client CAs, as CertificateRequest lists them (each
// with a 2-byte length); empty for none, or too many to send.
fn client_ca_names(cfg: const ServerConfig&) -> u8[>..] {
    var names: u8[>..] = [];
    for i in x509::pool_len(cfg.client_cas) {
        let ca = x509::pool_cert(cfg.client_cas, i);
        let dn = ca.der[ca.subject.start..ca.subject.end];
        put_u16(names, dn.len as! u16);
        names.append(dn);
    }
    if names.len > MAX_HANDSHAKE - 1024 { names.clear(); }
    return names;
}

// --- The client ---------------------------------------------------------------

fn client_server_hello12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let ver = get_u16(b, m);
    let random = get_bytes(b, 32);
    let sid = get_vec(b, m, 1);
    let suite_id = get_u16(b, m);
    let comp = get_u8(b, m);
    var exts = empty_rd();
    if b.pos < b.end { exts = get_vec(b, m, 2); }
    if !done(b) || comp != 0 || sid.end - sid.pos > 32 { return fail(c, ALERT_DECODE_ERROR, out); }
    // TLS 1.2 only if offered, and not after a HelloRetryRequest.
    if ver != 0x0303 || !c.offer12 || c.hrr { return fail(c, ALERT_PROTOCOL_VERSION, out); }
    // Offering TLS 1.3, the client refuses a server that says it could
    // have done it (RFC 8446 §4.1.3).
    let tail = m[random.pos + 24..random.end];
    if c.offer13 && (tail == DOWNGRADE12[..] || tail == DOWNGRADE11[..]) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    var offered = false;
    for x in cfg.suites12 { if x == suite_id { offered = true; } }
    let s, oks = suite(suite_id as! u16);
    if !offered || !oks || !is_tls12_suite(s) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    // Only extensions the client sent.
    var ems = false;
    var reneg = false;
    var ticket = false;
    while exts.pos < exts.end {
        let ty = get_u16(exts, m);
        var e = get_vec(exts, m, 2);
        if exts.bad { return fail(c, ALERT_DECODE_ERROR, out); }
        if ty == EXT_RENEGOTIATION_INFO {
            let rc = get_vec(e, m, 1);
            if rc.end != rc.pos { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
            reneg = true;
        } else if ty == EXT_EXTENDED_MASTER_SECRET {
            ems = true;
        } else if ty == EXT_SESSION_TICKET {
            ticket = true;
        } else if ty == EXT_ALPN {
            if accept_alpn(c, cfg, m, e, out) != 0 { return -1; }
            e.pos = e.end;
        } else if ty == EXT_EC_POINT_FORMATS {
            let l = get_vec(e, m, 1);
        } else if ty != EXT_SERVER_NAME {
            return fail(c, ALERT_UNSUPPORTED_EXTENSION, out);
        }
        if !done(e) { return fail(c, ALERT_DECODE_ERROR, out); }
    }
    c.version = VERSION_TLS12;
    c.suite = s;
    c.ems = ems;
    c.secure_reneg = reneg;
    c.ticket12 = ticket;
    for i in 32 { c.peer_random[i] = m[random.pos + i]; }
    c.th = transcript(s.hash);
    c.log.clear();
    hs_add(c, c.ch);
    hs_add(c, m);
    // Resumed: the server sent back the session ID that came with the
    // ticket; the session's suite, and its extended master secret, are
    // kept (RFC 7627 §5.3).
    if c.session12_offered && m[sid.pos..sid.end] == c.session_id[..] {
        if s.id != cfg.session.suite { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        if cfg.session.ems != ems { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
        c.resumed = true;
        set48(c.master, cfg.session.psk);
        c.peer_not_after = cfg.session.not_after;
        c.state = ST12_WAIT_CCS;
        return 0;
    }
    c.state = ST12_WAIT_CERT;
    return 0;
}

// The server's Certificate: checked as in TLS 1.3, with a key for the
// suite.
fn client_certificate12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let count = read_certificates12(c, m, out);
    if count < 0 { return count; }
    if count == 0 { return fail(c, ALERT_DECODE_ERROR, out); }
    if check_server_chain(c, cfg, out) != 0 { return -1; }
    let leaf, okl = peer_leaf(c);
    if !okl || !kx_fits(c.suite.kx, leaf.key_type) { return fail(c, ALERT_UNSUPPORTED_CERTIFICATE, out); }
    hs_add(c, m);
    c.state = if c.suite.kx == KX_RSA { ST12_WAIT_CR_SHD } else { ST12_WAIT_SKE };
    return 0;
}

// ServerKeyExchange (RFC 8422 §5.4): a named group the client offered and
// the server's share, signed with both randoms by the certificate's key.
fn client_server_key_exchange12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let curve_type = get_u8(b, m);
    let group = get_u16(b, m);
    let point = get_vec(b, m, 1);
    let params_end = b.pos;
    let scheme = get_u16(b, m);
    let sig = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    var offered = false;
    for g in cfg.groups { if g == group { offered = true; } }
    if curve_type != 3 || !offered || !ecdh_group12(group as! u16) || point.end - point.pos != ecdh_len(group as! u16) {
        return fail(c, ALERT_ILLEGAL_PARAMETER, out);
    }
    if !offered_scheme(SIG_SCHEMES12, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    var signed: u8[>..] = [];
    signed.append(c.random);
    signed.append(c.peer_random);
    signed.append(m[4..params_end]);
    let leaf, okl = peer_leaf(c);
    // A scheme that does not fit the key is refused before any signature
    // check, as TLS 1.3's (RFC 8446 §4.4.3); Go gives decrypt_error.
    if okl && !scheme_fits12(leaf.key_type, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    if !okl || !verify12(leaf, scheme as! u16, signed, m[sig.pos..sig.end]) { return fail(c, ALERT_DECRYPT_ERROR, out); }
    c.group = group as! u16;
    c.peer_share.clear();
    c.peer_share.append(m[point.pos..point.end]);
    hs_add(c, m);
    c.state = ST12_WAIT_CR_SHD;
    return 0;
}

// A TLS 1.2 CertificateRequest: certificate types, schemes and CA names.
// The client's certificate goes if its key is of a type asked for (RSA, or
// ECDSA for EC and Ed25519 keys, as Go has it) and signs with one of the
// schemes, and, if CAs are named, one of its certificates was issued by
// one of them.
fn client_certificate_request12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    var types = get_vec(b, m, 1);
    var sl = get_vec(b, m, 2);
    let cas = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    var schemes: u16[..64] = [];
    while sl.pos + 1 < sl.end {
        let v = get_u16(sl, m);
        if schemes.len < schemes.cap { schemes.push(v as! u16); }
    }
    c.cert_requested = true;
    c.cert_scheme = 0;
    if cfg.cert_chain.len > 0 {
        let want: i64 = if cfg.cert_key.kind == x509::KEY_RSA { 1 } else { 64 };     // rsa_sign, ecdsa_sign
        var type_ok = false;
        while types.pos < types.end { if get_u8(types, m) == want { type_ok = true; } }
        let sch = pick_scheme12(cfg.cert_key.kind, schemes);
        if type_ok && sch != 0 && (cas.end == cas.pos || issued_by_one_of(cfg.cert_chain, m, cas)) { c.cert_scheme = sch; }
    }
    hs_add(c, m);
    c.state = ST12_WAIT_SHD;
    return 0;
}

// ServerHelloDone, and the client's flight: [Certificate],
// ClientKeyExchange, [CertificateVerify over the messages so far],
// change_cipher_spec, Finished.
fn client_server_hello_done12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if m.len != 4 { return fail(c, ALERT_DECODE_ERROR, out); }
    hs_add(c, m);
    if c.cert_requested {
        var chain: u8[>..] = [];
        if c.cert_scheme != 0 { chain.append(cfg.cert_chain); }
        let cm, okm = certificate_message12(chain);
        if !okm { return fail(c, ALERT_INTERNAL_ERROR, out); }
        send_hs(c, cm, out);
    }
    var pms: u8[>..] = [];
    var cke: u8[>..] = [];
    if c.suite.kx == KX_RSA {
        // RSA: a premaster secret of the client's version and 46 random
        // bytes, encrypted to the server's key.
        let leaf, okl = peer_leaf(c);
        let pub, okp = x509::rsa_public_key(leaf);
        if !okl || !okp { return fail(c, ALERT_UNSUPPORTED_CERTIFICATE, out); }
        var r: u8[46] = [0; 46];
        drbg_fill(c, r);
        pms.push(3);
        pms.push(3);
        pms.append(r);
        let enc = bignum::rsa_encrypt_pkcs1(pub, pms);
        put_u16(cke, enc.len as! u16);
        cke.append(enc);
    } else {
        let mine = make_ecdh(c, c.group);
        let shared, ok = ecdh_secret(c, c.group, c.peer_share);
        if !ok { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        pms.append(shared);
        cke.push(mine.len as! u8);
        cke.append(mine);
    }
    send_hs(c, handshake_message(HS_CLIENT_KEY_EXCHANGE, cke), out);
    set48(c.master, master_secret12(c.suite.hash, pms, c.ems, transcript_hash(c.th), c.random, c.peer_random));
    if c.cert_scheme != 0 {
        if c.log_over { return fail(c, ALERT_INTERNAL_ERROR, out); }
        let sig, oks = sign(cfg.cert_key, c.cert_scheme, c.log);
        if !oks { return fail(c, ALERT_INTERNAL_ERROR, out); }
        var cv: u8[>..] = [];
        put_u16(cv, c.cert_scheme);
        put_u16(cv, sig.len as! u16);
        cv.append(sig);
        send_hs(c, handshake_message(HS_CERTIFICATE_VERIFY, cv), out);
    }
    send_ccs12(c, out);
    send_finished12(c, out);
    c.state = ST12_WAIT_CCS;
    return 0;
}

// NewSessionTicket (RFC 5077 §3.3), before the server's
// change_cipher_spec: kept as the client's session, with the master
// secret. Go ignores the lifetime hint and keeps a ticket for seven days;
// so does this. An empty ticket is none.
fn client_new_session_ticket12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if !c.ticket12 || c.tickets > 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    var b = Rd { pos: 4, end: m.len, bad: false };
    let hint = get_u16(b, m) << 16 | get_u16(b, m);
    let ticket = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    hs_add(c, m);
    c.tickets++;
    var s = no_session();
    if ticket.end == ticket.pos || ticket.end - ticket.pos > s.ticket.cap { return 0; }
    s.version = VERSION_TLS12;
    s.suite = c.suite.id;
    s.psk.append(c.master);
    s.ems = c.ems;
    s.lifetime = MAX_TICKET_LIFETIME;
    s.received_ms = now_ms(cfg.now);
    s.server_name.append(cfg.server_name);
    s.alpn.append(c.alpn);
    s.not_after = c.peer_not_after;
    s.ticket.append(m[ticket.pos..ticket.end]);
    c.session = s;
    return 0;
}

// The server's Finished; resumed, the client's change_cipher_spec and
// Finished follow it. A resumed session without a new ticket stays the
// client's session.
fn client_finished12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if m.len - 4 != 12 { return fail(c, ALERT_DECODE_ERROR, out); }
    if !finished12_ok(c.suite.hash, c.master, false, transcript_hash(c.th), m[4..]) {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    hs_add(c, m);
    if c.resumed {
        send_ccs12(c, out);
        send_finished12(c, out);
        if c.session.ticket.len == 0 { c.session = cfg.session; }
    }
    c.has_session = c.session.ticket.len > 0;
    c.state = ST_CONNECTED;
    c.log.clear();
    return 0;
}

fn client_message12(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if t == HS_HELLO_REQUEST {
        // Renegotiation is refused, with a warning (RFC 5746 §4.2); a
        // HelloRequest during the handshake is ignored (RFC 5246 §7.4.1.1).
        if m.len != 4 { return fail(c, ALERT_DECODE_ERROR, out); }
        if c.state == ST_CONNECTED {
            let a = alert(ALERT_WARNING, ALERT_NO_RENEGOTIATION);
            out.append(seal_record(c.write, CT_ALERT, a));
        }
        return 0;
    }
    if c.state == ST12_WAIT_CERT && t == HS_CERTIFICATE { return client_certificate12(c, cfg, m, out); }
    if c.state == ST12_WAIT_SKE && t == HS_SERVER_KEY_EXCHANGE { return client_server_key_exchange12(c, cfg, m, out); }
    if c.state == ST12_WAIT_CR_SHD && t == HS_CERTIFICATE_REQUEST { return client_certificate_request12(c, cfg, m, out); }
    if (c.state == ST12_WAIT_CR_SHD || c.state == ST12_WAIT_SHD) && t == HS_SERVER_HELLO_DONE {
        return client_server_hello_done12(c, cfg, m, out);
    }
    if c.state == ST12_WAIT_CCS && t == HS_NEW_SESSION_TICKET { return client_new_session_ticket12(c, cfg, m, out); }
    if c.state == ST12_WAIT_FINISHED && t == HS_FINISHED { return client_finished12(c, cfg, m, out); }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}

// --- The server ---------------------------------------------------------------

// A ClientHello that gets TLS 1.2: the suite, ECDHE group and signature
// scheme, resumption, and the server's flight.
fn server_client_hello12(c: Conn&, cfg: const ServerConfig&, m: const u8[:], h: const Hello&, out: u8[>..]&) -> i64 {
    c.version = VERSION_TLS12;
    // TLS_FALLBACK_SCSV from a client that could do better (RFC 7507).
    if in_u16_list(m, h.suites, TLS_FALLBACK_SCSV) && client_max_version(h) < cfg.max_version {
        return fail(c, ALERT_INAPPROPRIATE_FALLBACK, out);
    }
    // Secure renegotiation: an empty renegotiation_info, or the SCSV.
    if h.has_reneg && !h.reneg_empty { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
    c.secure_reneg = h.has_reneg || in_u16_list(m, h.suites, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    take_peer_schemes(c, m, h.schemes, SIG_SCHEMES12);
    let scheme = pick_scheme12(cfg.key.kind, c.peer_schemes);
    // ECDHE: the server's first ECDH group the client takes, if it takes
    // uncompressed points (as it does without the extension, RFC 8422
    // §5.1.2).
    // A list without uncompressed is refused (RFC 8422 §5.1.2). Without
    // supported_groups the client takes any curve (RFC 8422 §4): P-256.
    var points_ok = !h.has_points;
    var pl = h.points;
    while pl.pos < pl.end { if get_u8(pl, m) == 0 { points_ok = true; } }
    if !points_ok { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    var group: u16 = 0;
    for g in cfg.groups {
        let offered = if h.has_groups { in_u16_list(m, h.groups, g) } else { g == GROUP_SECP256R1 };
        if group == 0 && ecdh_group12(g) && offered { group = g; }
    }
    // The suite: the server's first that the client offers and the key,
    // group and schemes allow.
    var chosen: u16 = 0;
    for id in cfg.suites12 {
        let st, okst = suite(id);
        if chosen == 0 && okst && is_tls12_suite(st) && in_u16_list(m, h.suites, id) && kx_fits(st.kx, cfg.key.kind) &&
           (st.kx == KX_RSA || (group != 0 && scheme != 0)) {
            chosen = id;
        }
    }
    if chosen == 0 { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
    var s, oks = suite(chosen);
    if select_alpn(c, cfg, h, m, out) != 0 { return -1; }
    c.sni.clear();
    if h.sni.end - h.sni.pos <= 255 { c.sni.append(m[h.sni.pos..h.sni.end]); }
    c.ems = h.ems;
    c.ticket12 = h.has_ticket && cfg.tickets > 0;
    for i in 32 { c.peer_random[i] = m[h.random.pos + i]; }
    c.client_version = h.version as! u16;
    // Resumption: a TLS 1.2 ticket of ours, unexpired, for a suite both
    // still take, with a client certificate that suits, and with the
    // extended master secret if it had one (a session that had it is
    // refused without, one that had not is not resumed with it, RFC 7627
    // §5.3).
    var resumed = false;
    if c.ticket12 && h.ticket.end > h.ticket.pos && h.sid.end > h.sid.pos {
        let t, okt = open_ticket(cfg.ticket_key, m[h.ticket.pos..h.ticket.end]);
        let now = now_ms(cfg.now) / 1000;
        var ours = false;
        for id in cfg.suites12 { if id == t.suite { ours = true; } }
        if okt && t.version == VERSION_TLS12 && ours && in_u16_list(m, h.suites, t.suite) && now >= t.created &&
           now - t.created <= t.lifetime && ticket_client_ok(cfg, t, now) {
            if t.ems && !h.ems { return fail(c, ALERT_HANDSHAKE_FAILURE, out); }
            if t.ems == h.ems {
                resumed = true;
                let st, okst = suite(t.suite);
                s = st;
                set48(c.master, t.psk);
                c.chain.clear();
                c.chain.append(t.client_chain);
                c.peer_verified = t.client_verified;
                c.peer_not_after = t.client_not_after;
            }
        }
    }
    c.suite = s;
    c.resumed = resumed;
    c.th = transcript(s.hash);
    c.log.clear();
    hs_add(c, m);
    // ServerHello: the client's session ID back when resuming, none
    // otherwise (nothing is kept to resume by ID, as in Go); a TLS 1.3
    // server's random ends in the downgrade sentinel.
    drbg_fill(c, c.random);
    if cfg.max_version >= VERSION_TLS13 { for i in 8 { c.random[24 + i] = DOWNGRADE12[i]; } }
    c.session_id.clear();
    if resumed { c.session_id.append(m[h.sid.pos..h.sid.end]); }
    var b: u8[>..] = [];
    put_u16(b, VERSION_TLS12);
    b.append(c.random);
    b.push(c.session_id.len as! u8);
    b.append(c.session_id);
    put_u16(b, s.id);
    b.push(0);
    let exts = begin_vec(b, 2);
    if c.secure_reneg {
        let ri = begin_ext(b, EXT_RENEGOTIATION_INFO);
        b.push(0);
        patch_len(b, ri, 2);
    }
    if c.ems {
        put_u16(b, EXT_EXTENDED_MASTER_SECRET);
        put_u16(b, 0);
    }
    if c.ticket12 {
        put_u16(b, EXT_SESSION_TICKET);
        put_u16(b, 0);
    }
    if c.alpn.len > 0 {
        let a = begin_ext(b, EXT_ALPN);
        let l = begin_vec(b, 2);
        b.push(c.alpn.len as! u8);
        b.append(c.alpn);
        patch_len(b, l, 2);
        patch_len(b, a, 2);
    }
    if s.kx != KX_RSA && h.has_points && !resumed {
        let pf = begin_ext(b, EXT_EC_POINT_FORMATS);
        b.push(1);
        b.push(0);
        patch_len(b, pf, 2);
    }
    patch_len(b, exts, 2);
    send_hs(c, handshake_message(HS_SERVER_HELLO, b), out);
    if resumed {
        if c.ticket12 { send_ticket12(c, cfg, out); }
        send_ccs12(c, out);
        send_finished12(c, out);
        c.state = ST12_WAIT_CLIENT_CCS;
        return 0;
    }
    // Certificate, ServerKeyExchange, [CertificateRequest], ServerHelloDone.
    let cm, okm = certificate_message12(cfg.chain);
    if !okm { return fail(c, ALERT_INTERNAL_ERROR, out); }
    send_hs(c, cm, out);
    if s.kx != KX_RSA {
        c.group = group;
        let mine = make_ecdh(c, group);
        var ske: u8[>..] = [];
        ske.push(3);                                // named_curve
        put_u16(ske, group);
        ske.push(mine.len as! u8);
        ske.append(mine);
        var signed: u8[>..] = [];
        signed.append(c.peer_random);
        signed.append(c.random);
        signed.append(ske);
        let sig, oks = sign(cfg.key, scheme, signed);
        if !oks { return fail(c, ALERT_INTERNAL_ERROR, out); }
        put_u16(ske, scheme);
        put_u16(ske, sig.len as! u16);
        ske.append(sig);
        send_hs(c, handshake_message(HS_SERVER_KEY_EXCHANGE, ske), out);
    }
    if cfg.client_auth != NO_CLIENT_CERT { send_certificate_request12(c, cfg, out); }
    send_hs(c, handshake_message(HS_SERVER_HELLO_DONE, ""), out);
    c.state = if c.cert_requested { ST12_WAIT_CLIENT_CERT } else { ST12_WAIT_CKE };
    return 0;
}

// CertificateRequest: RSA and ECDSA certificates (Go's types), the
// schemes, and the client CAs' names.
fn send_certificate_request12(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) {
    var b: u8[>..] = [];
    b.push(2);
    b.push(1);                                      // rsa_sign
    b.push(64);                                     // ecdsa_sign
    let sl = begin_vec(b, 2);
    for sc in SIG_SCHEMES12 { put_u16(b, sc); }
    patch_len(b, sl, 2);
    let names = client_ca_names(cfg);
    put_u16(b, names.len as! u16);
    b.append(names);
    send_hs(c, handshake_message(HS_CERTIFICATE_REQUEST, b), out);
    c.cert_requested = true;
}

// A NewSessionTicket with the session sealed under the ticket key: the
// master secret, whether it is extended, and the client's certificate;
// empty (no ticket) when the certificate does not fit in one.
fn send_ticket12(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) {
    var tn: u8[12] = [0; 12];
    drbg_fill(c, tn);
    var t = TicketState { version: VERSION_TLS12, suite: c.suite.id, psk: [], ems: c.ems, created: now_ms(cfg.now) / 1000,
                          age_add: 0, lifetime: MAX_TICKET_LIFETIME, alpn: [], sni: [], client_not_after: 0,
                          client_verified: false, client_chain: [] };
    t.psk.append(c.master);
    t.alpn.append(c.alpn);
    t.sni.append(c.sni);
    var ticket: u8[>..] = [];
    if c.chain.len <= t.client_chain.cap {
        t.client_chain.append(c.chain);
        t.client_verified = c.peer_verified;
        t.client_not_after = c.peer_not_after;
        ticket = seal_ticket(cfg.ticket_key, tn, t);
    }
    var b: u8[>..] = [];
    for i in 4 { b.push((MAX_TICKET_LIFETIME >> (8 * (3 - i))) as! u8); }
    put_u16(b, ticket.len as! u16);
    b.append(ticket);
    send_hs(c, handshake_message(HS_NEW_SESSION_TICKET, b), out);
}

// The client's Certificate: none (if allowed) or a chain, checked as in
// TLS 1.3.
fn server_client_certificate12(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let count = read_certificates12(c, m, out);
    if count < 0 { return count; }
    if count == 0 {
        if cfg.client_auth == REQUIRE_ANY_CLIENT_CERT || cfg.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT {
            return fail(c, ALERT_BAD_CERTIFICATE, out);
        }
    } else if check_client_chain(c, cfg, out) != 0 {
        return -1;
    }
    hs_add(c, m);
    c.state = ST12_WAIT_CKE;
    return 0;
}

// ClientKeyExchange: the client's ECDH share, or its RSA-encrypted
// premaster secret. A ciphertext that does not decrypt to 48 bytes, or
// whose first two bytes are not the ClientHello's version, leaves a random
// premaster secret in its place, chosen in constant time, with nothing to
// tell them apart until Finished fails (RFC 5246 §7.4.7.1).
fn server_client_key_exchange12(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    var pms: u8[>..] = [];
    if c.suite.kx == KX_RSA {
        let enc = get_vec(b, m, 2);
        if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
        var p: u8[48] = [0; 48];
        drbg_fill(c, p);
        var random: u8[48] = [0; 48];
        for i in 48 { random[i] = p[i]; }
        // A ciphertext the RSA operation refuses (of the wrong length, or
        // not below the modulus) is treated as any bad one: the random
        // premaster secret stays, and Finished fails.
        let ok = bignum::rsa_decrypt_pkcs1_session_key(cfg.key.rsa, m[enc.pos..enc.end], p);
        let hi: u32 = c.client_version >> 8;
        let lo: u32 = c.client_version & 0xff;
        let a: u32 = p[0];
        let b: u32 = p[1];
        let mask = bignum::ct_mask(bignum::ct_eq_u32(a, hi) & bignum::ct_eq_u32(b, lo));
        for i in 48 {
            let x: u32 = p[i];
            let y: u32 = random[i];
            p[i] = bignum::ct_select_u32(mask, x, y) as! u8;
        }
        pms.append(p);
    } else {
        // ECPoint is <1..2^8-1> (RFC 8422 §5.7).
        let p = get_vec(b, m, 1);
        if !done(b) || p.end == p.pos { return fail(c, ALERT_DECODE_ERROR, out); }
        let shared, ok = ecdh_secret(c, c.group, m[p.pos..p.end]);
        if !ok { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
        pms.append(shared);
    }
    hs_add(c, m);
    set48(c.master, master_secret12(c.suite.hash, pms, c.ems, transcript_hash(c.th), c.peer_random, c.random));
    c.state = if c.chain.len > 0 { ST12_WAIT_CLIENT_CV } else { ST12_WAIT_CLIENT_CCS };
    return 0;
}

// The client's CertificateVerify, over the handshake messages before it.
fn server_certificate_verify12(c: Conn&, m: const u8[:], out: u8[>..]&) -> i64 {
    var b = Rd { pos: 4, end: m.len, bad: false };
    let scheme = get_u16(b, m);
    let sig = get_vec(b, m, 2);
    if !done(b) { return fail(c, ALERT_DECODE_ERROR, out); }
    if !offered_scheme(SIG_SCHEMES12, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    if c.log_over { return fail(c, ALERT_INTERNAL_ERROR, out); }
    let leaf, okl = peer_leaf(c);
    if okl && !scheme_fits12(leaf.key_type, scheme as! u16) { return fail(c, ALERT_ILLEGAL_PARAMETER, out); }
    if !okl || !verify12(leaf, scheme as! u16, c.log, m[sig.pos..sig.end]) { return fail(c, ALERT_DECRYPT_ERROR, out); }
    hs_add(c, m);
    c.state = ST12_WAIT_CLIENT_CCS;
    return 0;
}

// The client's Finished; after a full handshake the server's
// [NewSessionTicket], change_cipher_spec and Finished follow it.
fn server_finished12(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if m.len - 4 != 12 { return fail(c, ALERT_DECODE_ERROR, out); }
    if !finished12_ok(c.suite.hash, c.master, true, transcript_hash(c.th), m[4..]) {
        return fail(c, ALERT_DECRYPT_ERROR, out);
    }
    if c.hs.len != 0 { return fail(c, ALERT_UNEXPECTED_MESSAGE, out); }
    hs_add(c, m);
    if !c.resumed {
        if c.ticket12 { send_ticket12(c, cfg, out); }
        send_ccs12(c, out);
        send_finished12(c, out);
    }
    c.state = ST_CONNECTED;
    c.log.clear();
    return 0;
}

fn server_message12(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    let t = m[0];
    if c.state == ST_CONNECTED {
        // Renegotiation is refused, with a warning; the connection goes on.
        if t == HS_CLIENT_HELLO {
            let a = alert(ALERT_WARNING, ALERT_NO_RENEGOTIATION);
            out.append(seal_record(c.write, CT_ALERT, a));
            return 0;
        }
        return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
    }
    if c.state == ST12_WAIT_CLIENT_CERT && t == HS_CERTIFICATE { return server_client_certificate12(c, cfg, m, out); }
    if c.state == ST12_WAIT_CKE && t == HS_CLIENT_KEY_EXCHANGE { return server_client_key_exchange12(c, cfg, m, out); }
    if c.state == ST12_WAIT_CLIENT_CV && t == HS_CERTIFICATE_VERIFY { return server_certificate_verify12(c, m, out); }
    if c.state == ST12_WAIT_CLIENT_FINISHED && t == HS_FINISHED { return server_finished12(c, cfg, m, out); }
    return fail(c, ALERT_UNEXPECTED_MESSAGE, out);
}
