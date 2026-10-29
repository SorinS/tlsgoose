// TLS 1.2 between this package's client and server, in memory:
// - every TLS 1.2 suite with every server key type it takes (ECDHE with
//   Ed25519, P-256, P-384, P-521 and RSA certificates, RSA key exchange),
//   and every ECDHE group;
// - version negotiation, the downgrade sentinel and TLS_FALLBACK_SCSV;
// - the extended master secret and secure renegotiation's extension;
// - resumption with session tickets, and a TLS 1.2 session that TLS 1.3
//   does not use;
// - client certificates and ALPN;
// - a changed record, renegotiation refused both ways, and servers whose
//   keys TLS 1.2 cannot use (ML-DSA);
// - keyUsage against what the key does, in TLS 1.3 and 1.2.
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import tls.session;
import tls.record;
import x509.create;
import x509.keys;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// Field `idx` of the line `tag kind ...` (root and clientca lines have no
// kind).
fn field(tag: const u8[:], kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 || w[0] != tag { continue; }
        if tag == "root" || tag == "clientca" { return unhex(w[idx - 1]); }
        if w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;

fn pump(c: tls::Conn&, cc: const tls::ClientConfig&, s: tls::Conn&, sc: const tls::ServerConfig&,
        to_server: u8[>..]&, capp: u8[>..]&, sapp: u8[>..]&) {
    for round in 20 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        let rs = tls::server_feed(s, sc, to_server, to_client, sapp);
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::client_feed(c, cc, to_client, to_server, capp);
    }
}

fn server_cfg(kind: const u8[:]) -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("server", kind, 2), field("server", kind, 3));
    check("load key", ok);
    sc.now = NOW;
    return sc;
}

// A client that takes TLS 1.2 only.
fn client12() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    cc.max_version = tls::VERSION_TLS12;
    return cc;
}

// What a connection came to.
struct Outcome { ok: bool, version: u16, suite: u16, group: u16, resumed: bool, ems: bool, reneg: bool,
                 client_alert: u8, server_alert: u8, verified: bool, has_session: bool, alpn: u8[..255],
                 session: tls::Session }

// A handshake, then data both ways (some of it many records long) and
// close_notify.
fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> Outcome {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var ok = tls::connected(c) && tls::connected(s);
    if ok {
        var big: u8[>..] = [];
        for i in 40000 { big.push((i * 7) as! u8); }
        let sent = tls::send(c, big, to_server);
        pump(c, cc, s, sc, to_server, capp, sapp);
        var to_client: u8[>..] = [];
        let sent2 = tls::send(s, "pong", to_client);
        let r = tls::client_feed(c, cc, to_client, to_server, capp);
        ok = sapp == big && capp == "pong";
        tls::close(c, to_server);
        pump(c, cc, s, sc, to_server, capp, sapp);
        ok = ok && tls::closed(s);
    }
    let sess, has = tls::session(c);
    var o = Outcome { ok: ok, version: tls::version(c), suite: c.suite.id, group: c.group, resumed: tls::resumed(c) && tls::resumed(s),
                      ems: c.ems && s.ems, reneg: c.secure_reneg && s.secure_reneg, client_alert: c.alert,
                      server_alert: s.alert, verified: tls::peer_verified(s), has_session: has, alpn: [], session: sess };
    o.alpn.append(c.alpn);
    return o;
}

fn suite_name(id: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, id, 16, 4, '0');
    return o;
}

// Every suite with each key type it takes, over X25519; the defaults; every
// group; a key TLS 1.2 cannot use.
fn suites_and_groups() {
    let ecdsa_suites: u16[7] = [tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                                tls::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                                tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let rsa_suites: u16[12] = [tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                               tls::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                               tls::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                               tls::TLS_RSA_WITH_AES_128_GCM_SHA256, tls::TLS_RSA_WITH_AES_256_GCM_SHA384,
                               tls::TLS_RSA_WITH_AES_128_CBC_SHA, tls::TLS_RSA_WITH_AES_256_CBC_SHA,
                               tls::TLS_RSA_WITH_AES_128_CBC_SHA256, tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];
    let ec_kinds: const u8[:][4] = ["ed25519", "p256", "p384", "p521"];
    for kind in ec_kinds {
        var sc = server_cfg(kind);
        sc.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);     // not on by default, as in Go
        for id in ecdsa_suites[..6] {
            var cc = client12();
            cc.suites12.clear();
            cc.suites12.push(id);
            let o = connect(cc, sc);
            check(str(kind, " ", suite_name(id)), o.ok && o.version == tls::VERSION_TLS12 && o.suite == id && o.ems && o.reneg);
        }
    }
    var rsa_sc = server_cfg("rsa");
    rsa_sc.suites12.append(rsa_suites[5..11]);      // CBC-SHA256 and RSA key exchange, configured
    for id in rsa_suites[..11] {
        var cc = client12();
        cc.suites12.clear();
        cc.suites12.push(id);
        let o = connect(cc, rsa_sc);
        check(str("rsa ", suite_name(id)), o.ok && o.version == tls::VERSION_TLS12 && o.suite == id && o.ems);
    }
    // RSA key exchange is off by default, as in Go.
    let rsa_default = server_cfg("rsa");
    var cc_rsakx = client12();
    cc_rsakx.suites12.clear();
    cc_rsakx.suites12.push(tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    let o_rsakx = connect(cc_rsakx, rsa_default);
    check("rsa kx off by default", !o_rsakx.ok && o_rsakx.server_alert == tls::ALERT_HANDSHAKE_FAILURE);
    // The defaults: ECDHE-ECDSA-AES128-GCM for an EC key, ECDHE-RSA for RSA.
    let o_def_c = client12();
    let o_def_s = server_cfg("p256");
    let o_def = connect(o_def_c, o_def_s);
    check("default ecdsa suite", o_def.ok && o_def.suite == tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    let o_defr_c = client12();
    let o_defr = connect(o_defr_c, rsa_default);
    check("default rsa suite", o_defr.ok && o_defr.suite == tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    // Every ECDHE group; a hybrid the client prefers is skipped.
    let groups: u16[4] = [tls::GROUP_X25519, tls::GROUP_SECP256R1, tls::GROUP_SECP384R1, tls::GROUP_SECP521R1];
    for g in groups {
        var cc = client12();
        cc.groups.clear();
        cc.groups.push(tls::GROUP_X25519MLKEM768);
        cc.groups.push(g);
        let o_s = server_cfg("p256");
        let o = connect(cc, o_s);
        check(str("group ", suite_name(g)), o.ok && o.group == g);
    }
    // No ML-DSA in TLS 1.2: such a server has no suite for a TLS 1.2 client.
    let o_mldsa_c = client12();
    let o_mldsa_s = server_cfg("mldsa44");
    let o_mldsa = connect(o_mldsa_c, o_mldsa_s);
    check("mldsa server", !o_mldsa.ok && o_mldsa.server_alert == tls::ALERT_HANDSHAKE_FAILURE);
}

// Versions: TLS 1.3 when both take it; TLS 1.2 when either side stops
// there; neither when they do not meet; the downgrade sentinel and
// TLS_FALLBACK_SCSV.
fn versions() {
    let o13_c = tls::client_config("example.com", field("root", "", 2));
    let o13_s = server_cfg("p256");
    let o13 = connect(o13_c, o13_s);
    check("default is 1.3", o13.ok && o13.version == tls::VERSION_TLS13);
    var sc12 = server_cfg("p256");
    sc12.max_version = tls::VERSION_TLS12;
    var cc_both = tls::client_config("example.com", field("root", "", 2));
    cc_both.now = NOW;
    let o_s12 = connect(cc_both, sc12);
    check("server stops at 1.2", o_s12.ok && o_s12.version == tls::VERSION_TLS12);
    var cc13 = client12();
    cc13.max_version = tls::VERSION_TLS13;
    cc13.min_version = tls::VERSION_TLS13;
    let o_no = connect(cc13, sc12);
    check("client wants 1.3", !o_no.ok && o_no.client_alert == tls::ALERT_PROTOCOL_VERSION);
    var sc13 = server_cfg("p256");
    sc13.min_version = tls::VERSION_TLS13;
    let o_no2_c = client12();
    let o_no2 = connect(o_no2_c, sc13);
    check("server wants 1.3", !o_no2.ok && o_no2.server_alert == tls::ALERT_PROTOCOL_VERSION);

    // The downgrade sentinel: a TLS 1.3 server's ServerHello for TLS 1.2,
    // given to a client that offered TLS 1.3.
    {
        let sc = server_cfg("p256");
        let cc_old = client12();
        var c_old = tls::client(cc_old);
        var s = tls::server(sc);
        var ch: u8[>..] = [];
        tls::client_start(c_old, cc_old, ch);
        var flight: u8[>..] = [];
        var app: u8[>..] = [];
        let r = tls::server_feed(s, sc, ch, flight, app);
        check("sentinel set", s.random[24..] == "DOWNGRD\x01");
        var cc_new = tls::client_config("example.com", field("root", "", 2));
        cc_new.now = NOW;
        var c_new = tls::client(cc_new);
        var ch2: u8[>..] = [];
        tls::client_start(c_new, cc_new, ch2);
        var out: u8[>..] = [];
        let r2 = tls::client_feed(c_new, cc_new, flight, out, app);
        check("downgrade refused", tls::failed(c_new) && c_new.alert == tls::ALERT_ILLEGAL_PARAMETER);
        // A server that stops at TLS 1.2 sets no sentinel.
        var s2 = tls::server(sc12);
        var flight2: u8[>..] = [];
        let r3 = tls::server_feed(s2, sc12, ch, flight2, app);
        check("no sentinel", s2.random[24..] != "DOWNGRD\x01");
    }
    // TLS_FALLBACK_SCSV: refused by a server that does better, not by one
    // that does not.
    var cc_fb = client12();
    cc_fb.suites12.push(tls::TLS_FALLBACK_SCSV);
    let o_fb_s = server_cfg("p256");
    let o_fb = connect(cc_fb, o_fb_s);
    check("fallback refused", !o_fb.ok && o_fb.server_alert == tls::ALERT_INAPPROPRIATE_FALLBACK);
    let o_fb2 = connect(cc_fb, sc12);
    check("fallback to a 1.2 server", o_fb2.ok);
}

// Resumption with session tickets: a session from the first connection
// resumes the second, which gets a new ticket that resumes the third.
fn resumption() {
    {
        let sc = server_cfg("p256");
        var cc = client12();
        let o1 = connect(cc, sc);
        check("first full", o1.ok && !o1.resumed && o1.has_session && o1.session.version == tls::VERSION_TLS12);
        cc.session = o1.session;
        let o2 = connect(cc, sc);
        check("resumed", o2.ok && o2.resumed && o2.ems && o2.has_session);
        check("new ticket", o2.session.ticket[..] != o1.session.ticket[..] && o2.session.psk[..] == o1.session.psk[..]);
        cc.session = o2.session;
        let o3 = connect(cc, sc);
        check("resumed again", o3.ok && o3.resumed);
        // The session as bytes and back.
        let back, okb = tls::parse_session(tls::session_bytes(o2.session));
        check("session bytes", okb && back.version == tls::VERSION_TLS12 && back.ems && back.psk[..] == o2.session.psk[..] &&
              back.ticket[..] == o2.session.ticket[..]);
        // Another ticket key: a full handshake instead.
        var sc_other = server_cfg("p256");
        let o4 = connect(cc, sc_other);
        check("other key, full", o4.ok && !o4.resumed);
        // Tickets off: none, and no resumption.
        var sc_none = copy(sc);
        sc_none.tickets = 0;
        let o5 = connect(cc, sc_none);
        check("tickets off", o5.ok && !o5.resumed && !o5.has_session);
        // A session's suite must be one the client still offers.
        var cc_other = copy(cc);
        cc_other.suites12.clear();
        cc_other.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        let o6 = connect(cc_other, sc);
        check("suite gone, full", o6.ok && !o6.resumed && o6.suite == tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        // TLS 1.3 does not take a TLS 1.2 session.
        var cc13r = copy(cc);
        cc13r.max_version = tls::VERSION_TLS13;
        let o7 = connect(cc13r, sc);
        check("1.2 session, 1.3 handshake", o7.ok && o7.version == tls::VERSION_TLS13 && !o7.resumed);
        // An expired session is not offered.
        var cc_late = copy(cc);
        cc_late.now = NOW + 8 * 86400;
        var sc_late = copy(sc);
        sc_late.now = NOW + 8 * 86400;
        let o8 = connect(cc_late, sc_late);
        check("expired, full", o8.ok && !o8.resumed);
    }
    // A session got without verifying resumes only without verifying; one
    // verified stops resuming when the roots no longer take its chain.
    {
        let sc = server_cfg("p256");
        var nv = client12();
        nv.verify = false;
        let o1 = connect(nv, sc);
        check("unverified session", o1.ok && !o1.session.verified);
        nv.session = o1.session;
        check("unverified: resumed without verifying", connect(nv, sc).resumed);
        var strict = client12();
        strict.session = o1.session;
        var c = tls::client(strict);
        var out: u8[>..] = [];
        tls::client_start(c, strict, out);
        check("unverified: not offered when verifying", !c.session12_offered);
        let o2 = connect(strict, sc);
        check("full handshake instead", o2.ok && !o2.resumed && o2.session.verified);
        var other = tls::client_config("example.com", field("clientca", "", 2));
        other.now = NOW;
        other.max_version = tls::VERSION_TLS12;
        other.session = o2.session;
        var c2 = tls::client(other);
        var out2: u8[>..] = [];
        tls::client_start(c2, other, out2);
        check("roots replaced: not offered", !c2.session12_offered);
    }
}

fn client_certificates() {
    {
        var sc = server_cfg("p256");
        sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
        check("client CA", x509::pool_add(sc.client_cas, field("clientca", "", 2)));
        let client_kinds: const u8[:][2] = ["p256", "ed25519"];
        for kind in client_kinds {
            var cc = client12();
            check("client key", tls::set_client_certificate(cc, field("client", kind, 2), field("client", kind, 3)));
            let o = connect(cc, sc);
            check(str("client cert ", kind), o.ok && o.verified);
            // Carried over by resumption.
            cc.session = o.session;
            let o2 = connect(cc, sc);
            check(str("client cert resumed ", kind), o2.ok && o2.resumed && o2.verified);
            // Under other client CAs the ticket's certificate no longer
            // verifies: a full handshake, which then refuses it.
            var sc_other = copy(sc);
            sc_other.client_cas = x509::new_pool();
            check("other CA", x509::pool_add(sc_other.client_cas, field("root", "", 2)));
            let o3 = connect(cc, sc_other);
            check(str("client CAs changed: not resumed ", kind), !o3.ok && !o3.resumed);
        }
        // ML-DSA cannot sign in TLS 1.2: the client sends no certificate.
        var cc_pq = client12();
        check("client key", tls::set_client_certificate(cc_pq, field("client", "mldsa44", 2), field("client", "mldsa44", 3)));
        let o_pq = connect(cc_pq, sc);
        check("no usable client cert", !o_pq.ok && o_pq.server_alert == tls::ALERT_BAD_CERTIFICATE);
        let o_none_c = client12();
        let o_none = connect(o_none_c, sc);
        check("client cert required", !o_none.ok && o_none.server_alert == tls::ALERT_BAD_CERTIFICATE);
        var cc_so = client12();
        check("client key", tls::set_client_certificate(cc_so, field("client", "serveronly", 2), field("client", "serveronly", 3)));
        let o_so = connect(cc_so, sc);
        check("server-only certificate", !o_so.ok && o_so.server_alert != 0);
        var sc_req = copy(sc);
        sc_req.client_auth = tls::REQUEST_CLIENT_CERT;
        let o_req_c = client12();
        let o_req = connect(o_req_c, sc_req);
        check("requested, none sent", o_req.ok && !o_req.verified);
        // RSA server, client certificate.
        var sc_rsa = server_cfg("rsa");
        sc_rsa.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
        check("client CA", x509::pool_add(sc_rsa.client_cas, field("clientca", "", 2)));
        var cc = client12();
        check("client key", tls::set_client_certificate(cc, field("client", "p256", 2), field("client", "p256", 3)));
        let o_rsa = connect(cc, sc_rsa);
        check("client cert, rsa server", o_rsa.ok && o_rsa.verified);
    }
}

// ALPN, and certificate failures as in TLS 1.3.
fn alpn_and_failures() {
    {
        var sc = server_cfg("p256");
        tls::add_alpn(sc.alpn, "h2");
        tls::add_alpn(sc.alpn, "http/1.1");
        var cc = client12();
        tls::add_alpn(cc.alpn, "http/1.1");
        let o = connect(cc, sc);
        check("alpn", o.ok && o.alpn[..] == "http/1.1");
        var cc2 = client12();
        tls::add_alpn(cc2.alpn, "spdy/1");
        let o2 = connect(cc2, sc);
        check("no common alpn", !o2.ok && o2.server_alert == tls::ALERT_NO_APPLICATION_PROTOCOL);
    }

    // Certificate failures, as in TLS 1.3.
    {
        var cc = client12();
        cc.server_name.clear();
        cc.server_name.append("other.example");
        let o_s = server_cfg("p256");
        let o = connect(cc, o_s);
        check("wrong name", !o.ok && o.client_alert == tls::ALERT_BAD_CERTIFICATE);
        var cc2 = tls::client_config("example.com", field("clientca", "", 2));
        cc2.now = NOW;
        cc2.max_version = tls::VERSION_TLS12;
        let o2_s = server_cfg("p256");
        let o2 = connect(cc2, o2_s);
        check("unknown root", !o2.ok && o2.client_alert == tls::ALERT_UNKNOWN_CA);
    }
}

// Renegotiation is refused both ways and the connection goes on; then a
// changed record fails its MAC, for each kind of protection.
fn records() {
    let kinds: u16[3] = [tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                         tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA];
    for id in kinds {
        let sc = server_cfg("p256");
        var cc = client12();
        cc.suites12.clear();
        cc.suites12.push(id);
        var c = tls::client(cc);
        var s = tls::server(sc);
        var to_server: u8[>..] = [];
        var capp: u8[>..] = [];
        var sapp: u8[>..] = [];
        tls::client_start(c, cc, to_server);
        pump(c, cc, s, sc, to_server, capp, sapp);
        check("connected", tls::connected(c) && tls::connected(s));
        // The server's HelloRequest: the client answers no_renegotiation.
        let hello_request: u8[4] = [0, 0, 0, 0];
        var to_client = tls::seal_record(s.write, tls::CT_HANDSHAKE, hello_request);
        var back: u8[>..] = [];
        let r1 = tls::client_feed(c, cc, to_client, back, capp);
        check(str("hello request ", suite_name(id)), tls::connected(c) && back.len > 0);
        let r2 = tls::server_feed(s, sc, back, to_client, sapp);
        check("warning dropped", tls::connected(s));
        // A ClientHello after the handshake: the server answers the same.
        var hello: u8[>..] = [];
        var c2 = tls::client(cc);
        tls::client_start(c2, cc, hello);
        var renego = tls::seal_record(c.write, tls::CT_HANDSHAKE, hello[5..]);
        var reply: u8[>..] = [];
        let r3 = tls::server_feed(s, sc, renego, reply, sapp);
        check("renegotiation refused", tls::connected(s) && reply.len > 0);
        let r4 = tls::client_feed(c, cc, reply, back, capp);
        check("still connected", tls::connected(c));
        // Data still flows; then one changed byte.
        var data: u8[>..] = [];
        check("send", tls::send(c, "hello", data));
        let r5 = tls::server_feed(s, sc, data, reply, sapp);
        check("data after refusal", sapp == "hello");
        var bad: u8[>..] = [];
        check("send", tls::send(c, "hello again", bad));
        bad[bad.len - 3] ^= 1;
        reply.clear();
        let r6 = tls::server_feed(s, sc, bad, reply, sapp);
        check(str("tampered ", suite_name(id)), tls::failed(s) && s.alert == tls::ALERT_BAD_RECORD_MAC);
    }
}

// A leaf for example.com under root, on key, with that keyUsage.
fn usage_leaf(root: const u8[:], root_key: const x509::PrivateKey&, key: const x509::PrivateKey&, usage: u32) -> u8[>..] {
    var t, ok = x509::template("CN=example.com", NOW - 3600, NOW + 86400);
    t.key_usage = usage;
    t.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(t.san, "example.com");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), root, root_key);
    check("leaf made", ok && e == x509::OK);
    return der;
}

fn usage_server(chain: const u8[:], key: const x509::PrivateKey&, suite12: u16) -> tls::ServerConfig {
    var sc, ok = tls::server_config(chain, x509::marshal_pkcs8(key));
    check("server key", ok);
    sc.now = NOW;
    if suite12 != 0 {
        sc.suites12.clear();
        sc.suites12.push(suite12);
    }
    return sc;
}

// keyUsage, when a certificate has it, must allow what TLS does with the
// key: signing in TLS 1.3 (digitalSignature, RFC 8446 §4.4.2.2), and in
// TLS 1.2 for every key but RSA (as OpenSSL); encrypting to it in TLS
// 1.2's RSA key exchange (keyEncipherment).
fn key_usage() {
    let root_key = x509::generate_key(x509::KEY_ED25519);
    var rt, okr = x509::template("CN=Goose Usage Root", NOW - 3600, NOW + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    check("root made", okr && er == x509::OK);
    var cc13 = tls::client_config("example.com", root);
    cc13.now = NOW;
    var cc12 = copy(cc13);
    cc12.max_version = tls::VERSION_TLS12;
    let ek = x509::generate_key(x509::KEY_EC_P256);
    let ec_enc = usage_server(usage_leaf(root, root_key, ek, x509::KU_KEY_ENCIPHERMENT), ek, 0);
    let ec_sign = usage_server(usage_leaf(root, root_key, ek, x509::KU_DIGITAL_SIGNATURE), ek, 0);
    let o1 = connect(cc13, ec_enc);
    check("1.3, keyEncipherment only: refused", !o1.ok && o1.client_alert == tls::ALERT_BAD_CERTIFICATE);
    check("1.3, digitalSignature", connect(cc13, ec_sign).ok);
    let o2 = connect(cc12, ec_enc);
    check("1.2 ECDHE_ECDSA, keyEncipherment only: refused", !o2.ok && o2.client_alert == tls::ALERT_BAD_CERTIFICATE);
    check("1.2 ECDHE_ECDSA, digitalSignature", connect(cc12, ec_sign).ok);
    let rk, okk = x509::parse_private_key(field("server", "rsa", 3));
    check("rsa key", okk);
    let rsa_enc = usage_leaf(root, root_key, rk, x509::KU_KEY_ENCIPHERMENT);
    let rsa_sign = usage_leaf(root, root_key, rk, x509::KU_DIGITAL_SIGNATURE);
    let s_enc = usage_server(rsa_enc, rk, 0);
    let o3 = connect(cc13, s_enc);
    check("1.3 RSA, keyEncipherment only: refused", !o3.ok && o3.client_alert == tls::ALERT_BAD_CERTIFICATE);
    let s_ecdhe = usage_server(rsa_enc, rk, tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    check("1.2 ECDHE_RSA, keyEncipherment only: taken", connect(cc12, s_ecdhe).ok);
    var cck = copy(cc12);
    cck.suites12.clear();
    cck.suites12.push(tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    let s_kx = usage_server(rsa_enc, rk, tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    check("1.2 RSA key exchange, keyEncipherment", connect(cck, s_kx).ok);
    let s_kx_sign = usage_server(rsa_sign, rk, tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    let o4 = connect(cck, s_kx_sign);
    check("1.2 RSA key exchange, digitalSignature only: refused", !o4.ok && o4.client_alert == tls::ALERT_BAD_CERTIFICATE);
}

fn main() {
    suites_and_groups();
    versions();
    resumption();
    client_certificates();
    alpn_and_failures();
    records();
    key_usage();
    print("tls12: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
