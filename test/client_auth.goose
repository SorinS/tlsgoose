// Client certificates between this package's client and server, in memory,
// under each of Go's ClientAuth modes:
// - the certificate is requested or not, required or not, checked or not;
// - checked, it must lead to a client CA and allow client authentication;
// - with each key type, the client proving it has the key;
// - the client sending none when the server names other CAs;
// - carried over by resumption, under the rules Go applies to tickets.
// The client CA and its certificates are in vectors/hs_certs.txt
// (scripts/gen_handshake.py); the server certificates there allow client
// authentication too, under the other root.
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import tls.session;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
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

// A server with the P-256 certificate, asking `mode` of clients, the client
// CA its only one.
fn server_cfg(mode: i64) -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("server", "p256", 2), field("server", "p256", 3));
    check("load key", ok);
    sc.now = NOW;
    sc.client_auth = mode;
    check("client CA", x509::pool_add(sc.client_cas, field("clientca", "", 2)));
    return sc;
}

fn client_cfg() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    return cc;
}

// A client with the client CA's certificate of `kind`.
fn client_with(kind: const u8[:]) -> tls::ClientConfig {
    var cc = client_cfg();
    check(str("client key ", kind), tls::set_client_certificate(cc, field("client", kind, 2), field("client", kind, 3)));
    return cc;
}

// What a connection came to: whether both sides connected, data crossing
// both ways, and the two connections.
struct Outcome { ok: bool, resumed: bool, server_alert: u8, client_alert: u8, error: i64, verified: bool,
                 session: tls::Session, has_session: bool, peer: u8[..65536] }

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
        let sent = tls::send(c, "ping", to_server);
        pump(c, cc, s, sc, to_server, capp, sapp);
        var to_client: u8[>..] = [];
        let sent2 = tls::send(s, "pong", to_client);
        let r = tls::client_feed(c, cc, to_client, to_server, capp);
        ok = sent && sent2 && sapp == "ping" && capp == "pong" && tls::resumed(c) == tls::resumed(s);
    }
    let sess, has = tls::session(c);
    var o = Outcome { ok: ok, resumed: tls::resumed(s), server_alert: s.alert, client_alert: c.alert, error: s.error,
                      verified: tls::peer_verified(s), session: sess, has_session: has, peer: [] };
    o.peer.append(tls::peer_certificates(s));
    return o;
}

// Required and checked: the client CA's certificate of `kind`, or a
// server certificate of the other root (RSA, giving RSA-PSS, P-384,
// ML-DSA-65) with that root among the client CAs.
fn required_and_checked(kind: const u8[:]) {
    let ours = kind == "p256" || kind == "ed25519" || kind == "mldsa44";
    let tag = if ours { "client" } else { "server" };
    var cc = client_cfg();
    check(str("key ", kind), tls::set_client_certificate(cc, field(tag, kind, 2), field(tag, kind, 3)));
    var sc = server_cfg(tls::REQUIRE_AND_VERIFY_CLIENT_CERT);
    if !ours { check("root as client CA", x509::pool_add(sc.client_cas, field("root", "", 2))); }
    let o = connect(cc, sc);
    check(str("required and checked: ", kind), o.ok && o.verified && o.peer == field(tag, kind, 2));
}

fn main() {
    let none = client_cfg();
    let p256 = client_with("p256");
    let serveronly = client_with("serveronly");
    // A certificate the client CA did not issue: the P-256 server
    // certificate (clientAuth too), under the other root.
    var foreign = client_cfg();
    check("foreign key", tls::set_client_certificate(foreign, field("server", "p256", 2), field("server", "p256", 3)));

    // No certificate asked for: none sent, whatever the client has.
    let sc1 = server_cfg(tls::NO_CLIENT_CERT);
    let o1 = connect(p256, sc1);
    check("not requested", o1.ok && o1.peer.len == 0 && !o1.verified);

    // Requested: optional, not checked.
    let sc2 = server_cfg(tls::REQUEST_CLIENT_CERT);
    let o2 = connect(none, sc2);
    check("requested, none", o2.ok && o2.peer.len == 0);
    let sc3 = server_cfg(tls::REQUEST_CLIENT_CERT);
    let o3 = connect(p256, sc3);
    check("requested, sent", o3.ok && o3.peer == field("client", "p256", 2) && !o3.verified);
    let sc4 = server_cfg(tls::REQUEST_CLIENT_CERT);
    let o4 = connect(serveronly, sc4);
    check("requested: not checked", o4.ok && o4.peer.len > 0 && !o4.verified);

    // Required, not checked.
    let sc5 = server_cfg(tls::REQUIRE_ANY_CLIENT_CERT);
    let o5 = connect(none, sc5);
    check("required, none", !o5.ok && o5.server_alert == tls::ALERT_CERTIFICATE_REQUIRED &&
          o5.client_alert == tls::ALERT_CERTIFICATE_REQUIRED);
    let sc6 = server_cfg(tls::REQUIRE_ANY_CLIENT_CERT);
    let o6 = connect(serveronly, sc6);
    check("required: any", o6.ok && o6.peer.len > 0 && !o6.verified);

    // Checked if given.
    let sc7 = server_cfg(tls::VERIFY_CLIENT_CERT_IF_GIVEN);
    let o7 = connect(none, sc7);
    check("checked if given, none", o7.ok && o7.peer.len == 0 && !o7.verified);
    let sc8 = server_cfg(tls::VERIFY_CLIENT_CERT_IF_GIVEN);
    let o8 = connect(p256, sc8);
    check("checked if given", o8.ok && o8.verified && o8.peer == field("client", "p256", 2));
    let sc9 = server_cfg(tls::VERIFY_CLIENT_CERT_IF_GIVEN);
    let o9 = connect(serveronly, sc9);
    check("server authentication only", !o9.ok && o9.server_alert == tls::ALERT_BAD_CERTIFICATE &&
          o9.error == x509::ERR_EXTENDED_KEY_USAGE);

    // Required and checked, with each key type.
    let sc10 = server_cfg(tls::REQUIRE_AND_VERIFY_CLIENT_CERT);
    let o10 = connect(none, sc10);
    check("required and checked, none", !o10.ok && o10.server_alert == tls::ALERT_CERTIFICATE_REQUIRED);
    required_and_checked("p256");
    required_and_checked("ed25519");
    required_and_checked("mldsa44");
    required_and_checked("rsa");
    required_and_checked("p384");
    required_and_checked("mldsa65");

    // Named CAs: a certificate of another CA is not sent...
    let sc12 = server_cfg(tls::REQUEST_CLIENT_CERT);
    let o11 = connect(foreign, sc12);
    check("other CA: not sent", o11.ok && o11.peer.len == 0);
    let sc13 = server_cfg(tls::REQUIRE_ANY_CLIENT_CERT);
    let o12 = connect(foreign, sc13);
    check("other CA: not sent, required", !o12.ok && o12.server_alert == tls::ALERT_CERTIFICATE_REQUIRED);
    // ...unless the server names none (an empty pool: the system's roots,
    // not named, which do not include the test root).
    var sc_unnamed = server_cfg(tls::VERIFY_CLIENT_CERT_IF_GIVEN);
    sc_unnamed.client_cas = x509::new_pool();
    let o13 = connect(foreign, sc_unnamed);
    check("no CAs named: sent, checked against the system's", !o13.ok && o13.server_alert == tls::ALERT_UNKNOWN_CA &&
          o13.error == x509::ERR_UNKNOWN_ISSUER);
    var sc_req_unnamed = server_cfg(tls::REQUEST_CLIENT_CERT);
    sc_req_unnamed.client_cas = x509::new_pool();
    let o14 = connect(foreign, sc_req_unnamed);
    check("no CAs named: sent", o14.ok && o14.peer == field("server", "p256", 2));
    // A key that is not the certificate's: its CertificateVerify's scheme
    // does not fit the certificate's key (illegal_parameter, as in Go).
    var mismatched = client_cfg();
    check("mismatched key", tls::set_client_certificate(mismatched, field("client", "p256", 2),
                                                        field("client", "ed25519", 3)));
    let sc14 = server_cfg(tls::REQUEST_CLIENT_CERT);
    let o15 = connect(mismatched, sc14);
    check("key not the certificate's", !o15.ok && o15.server_alert == tls::ALERT_ILLEGAL_PARAMETER);
    // The same in TLS 1.2, where the scheme is refused before any
    // signature check too.
    var mismatched12 = mismatched;
    mismatched12.max_version = tls::VERSION_TLS12;
    let o15b = connect(mismatched12, sc14);
    check("key not the certificate's, TLS 1.2", !o15b.ok && o15b.server_alert == tls::ALERT_ILLEGAL_PARAMETER);
    var junk = client_cfg();
    check("junk key refused", !tls::set_client_certificate(junk, field("client", "p256", 2), "junk"));

    // Resumption carries the certificate over.
    let sc_v = server_cfg(tls::REQUIRE_AND_VERIFY_CLIENT_CERT);
    let full = connect(p256, sc_v);
    check("full handshake, ticket", full.ok && !full.resumed && full.has_session);
    var rc = client_cfg();                       // resuming needs no certificate of the client's
    rc.session = full.session;
    let r1 = connect(rc, sc_v);
    check("resumed with the certificate", r1.ok && r1.resumed && r1.verified && r1.peer == field("client", "p256", 2));
    var sc_same_key = server_cfg(tls::REQUEST_CLIENT_CERT);
    sc_same_key.ticket_key = sc_v.ticket_key;
    let r2 = connect(rc, sc_same_key);
    check("resumed under a server that only requests", r2.ok && r2.resumed && r2.peer.len > 0);
    var sc_none = server_cfg(tls::NO_CLIENT_CERT);
    sc_none.ticket_key = sc_v.ticket_key;
    let r3 = connect(rc, sc_none);
    check("certificate in the ticket, none asked: full handshake", r3.ok && !r3.resumed && r3.peer.len == 0);
    // A session without a certificate, where one is required: full
    // handshake (with the client's certificate).
    let sc_req = server_cfg(tls::REQUEST_CLIENT_CERT);
    let bare = connect(none, sc_req);
    check("ticket without a certificate", bare.ok && bare.has_session);
    var rc2 = client_with("p256");
    rc2.session = bare.session;
    var sc_req_any = server_cfg(tls::REQUIRE_ANY_CLIENT_CERT);
    sc_req_any.ticket_key = sc_req.ticket_key;
    let r4 = connect(rc2, sc_req_any);
    check("no certificate in the ticket, one required: full handshake", r4.ok && !r4.resumed && r4.peer.len > 0);
    var rc2b = client_cfg();
    rc2b.session = bare.session;
    let r4b = connect(rc2b, sc_req);
    check("no certificate in the ticket, optional: resumed", r4b.ok && r4b.resumed && r4b.peer.len == 0);
    // An unchecked certificate, where they are checked: full handshake.
    let unchecked = connect(p256, sc_req);
    check("ticket with an unchecked certificate", unchecked.ok && !unchecked.verified && unchecked.has_session);
    var rc3 = client_with("p256");
    rc3.session = unchecked.session;
    var sc_ver = server_cfg(tls::VERIFY_CLIENT_CERT_IF_GIVEN);
    sc_ver.ticket_key = sc_req.ticket_key;
    let r5 = connect(rc3, sc_ver);
    check("unchecked in the ticket, checked now: full handshake", r5.ok && !r5.resumed && r5.verified);
    print("client auth: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
