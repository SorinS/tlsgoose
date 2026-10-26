// TLS 1.3 resumption (tls.session) between this package's client and
// server, in memory. A full handshake leaves the client a session from the
// server's ticket. The session must then resume:
// - with each suite of its hash, without certificates, data flowing;
// - from a resumed connection's own ticket;
// - after a HelloRetryRequest;
// - after a round trip through session_bytes.
// A session must fall back to a full handshake under a suite of another
// hash, another ticket key, or a server sending no tickets. It must not be
// offered expired, for another name or with a changed ticket. A changed
// binder must fail the handshake.
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

fn field(kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 { continue; }
        if w[0] == "root" && kind == "root" { return unhex(w[idx - 1]); }
        if w[0] == "server" && w[1] == kind { return unhex(w[idx]); }
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
    var sc, ok = tls::server_config(field(kind, 2), field(kind, 3));
    check("load key", ok);
    sc.now = NOW;
    return sc;
}

fn client_cfg() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", 2));
    cc.now = NOW;
    return cc;
}

// One connection; whether it connected and resumed, with data both ways,
// and the session the client got from it.
fn connect(label: const u8[:], cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> bool, bool, tls::Session {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    let ok = tls::connected(c) && tls::connected(s);
    if !ok { print("   ", label, ": client state ", c.state, " alert ", c.alert, "; server state ", s.state, " alert ", s.alert); }
    let sent = tls::send(c, "ping", to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var to_client: u8[>..] = [];
    let sent2 = tls::send(s, "pong", to_client);
    let r = tls::client_feed(c, cc, to_client, to_server, capp);
    let data = sent && sent2 && sapp == "ping" && capp == "pong";
    // Both sides agree on resumption; resumed, no certificate was sent.
    let agree = tls::resumed(c) == tls::resumed(s) && (!tls::resumed(c) || c.chain.len == 0);
    check(str(label, ": connected"), ok && data && agree);
    let sess, has = tls::session(c);
    check(str(label, ": a ticket"), has == (sc.tickets > 0) && c.tickets == sc.tickets);
    return ok, tls::resumed(c), sess;
}

fn main() {
    let sc = server_cfg("p256");
    let cc = client_cfg();
    let ok0, r0, sess = connect("full handshake", cc, sc);
    check("not resumed at first", ok0 && !r0);
    check("session", sess.suite == tls::TLS_AES_128_GCM_SHA256 && sess.psk.len == 32 && sess.lifetime == 604800 &&
          sess.server_name == "example.com" && sess.received_ms == NOW * 1000 && sess.not_after > NOW);

    // Resumed: under its own suite, and under ChaCha20-Poly1305 (also SHA-256).
    var rc = client_cfg();
    rc.session = sess;
    let ok1, r1, sess1 = connect("resumed", rc, sc);
    check("resumed", ok1 && r1);
    check("new ticket differs", sess1.ticket != sess.ticket && sess1.psk != sess.psk);
    var rc_chacha = client_cfg();
    rc_chacha.session = sess;
    rc_chacha.suites.clear();
    rc_chacha.suites.push(tls::TLS_CHACHA20_POLY1305_SHA256);
    let ok2, r2, sess2 = connect("resumed under ChaCha20-Poly1305", rc_chacha, sc);
    check("resumed, other suite of the hash", ok2 && r2 && sess2.suite == tls::TLS_CHACHA20_POLY1305_SHA256);
    // A resumed connection's ticket resumes too.
    var rc2 = client_cfg();
    rc2.session = sess1;
    let ok3, r3, sess3 = connect("resumed again", rc2, sc);
    check("resumed from a resumed ticket", ok3 && r3 && sess3.not_after == sess.not_after);
    // A session kept as bytes.
    let saved = tls::session_bytes(sess);
    let back, okb = tls::parse_session(saved);
    check("session bytes", okb && tls::session_bytes(back) == saved);
    var junk: u8[>..] = [];
    junk.append(saved[..saved.len - 1]);
    let jb, okj = tls::parse_session(junk);
    check("truncated session bytes refused", !okj);
    var rc_saved = client_cfg();
    rc_saved.session = back;
    let ok4, r4, s4 = connect("resumed from bytes", rc_saved, sc);
    check("resumed from bytes", ok4 && r4);
    // After a HelloRetryRequest: the client's first share is for a group
    // the server does not take.
    var rc_hrr = client_cfg();
    rc_hrr.session = sess;
    rc_hrr.groups.clear();
    rc_hrr.groups.push(tls::GROUP_SECP384R1);
    rc_hrr.groups.push(tls::GROUP_X25519);
    var sc_hrr = server_cfg("p256");
    sc_hrr.ticket_key = sc.ticket_key;
    sc_hrr.groups.clear();
    sc_hrr.groups.push(tls::GROUP_X25519);
    var c5 = tls::client(rc_hrr);
    var s5 = tls::server(sc_hrr);
    var ts: u8[>..] = [];
    var ca: u8[>..] = [];
    var sa: u8[>..] = [];
    tls::client_start(c5, rc_hrr, ts);
    pump(c5, rc_hrr, s5, sc_hrr, ts, ca, sa);
    check("resumed after HelloRetryRequest", tls::connected(c5) && tls::connected(s5) && c5.hrr && tls::resumed(c5) &&
          tls::resumed(s5));

    // Full handshakes instead.
    var rc_384 = client_cfg();
    rc_384.session = sess;
    rc_384.suites.clear();
    rc_384.suites.push(tls::TLS_AES_256_GCM_SHA384);
    let ok6, r6, s6 = connect("SHA-384 suite only", rc_384, sc);
    check("not offered under another hash", ok6 && !r6);
    var other_key = server_cfg("p256");          // a fresh random ticket key
    let ok7, r7, s7 = connect("another ticket key", rc, other_key);
    check("other server: full handshake", ok7 && !r7);
    var no_tickets = server_cfg("p256");
    no_tickets.ticket_key = sc.ticket_key;
    no_tickets.tickets = 0;
    let ok8, r8, s8 = connect("server without tickets", rc, no_tickets);
    check("tickets off: full handshake", ok8 && !r8);
    var late = client_cfg();
    late.session = sess;
    late.now = NOW + 604800;
    var sc_late = server_cfg("p256");
    sc_late.ticket_key = sc.ticket_key;
    sc_late.now = late.now;
    var c9 = tls::client(late);
    var out9: u8[>..] = [];
    tls::client_start(c9, late, out9);
    check("expired session not offered", !c9.psk_offered);
    var other_name = client_cfg();
    other_name.session = sess;
    other_name.server_name.clear();
    other_name.server_name.append("localhost");
    var c10 = tls::client(other_name);
    var out10: u8[>..] = [];
    tls::client_start(c10, other_name, out10);
    check("other name: not offered", !c10.psk_offered);
    // The server's own clock: a ticket older than its lifetime is refused.
    var sc_old = server_cfg("p256");
    sc_old.ticket_key = sc.ticket_key;
    sc_old.now = NOW + 604801;
    let ok11, r11, s11 = connect("ticket too old for the server", rc, sc_old);
    check("old ticket: full handshake", ok11 && !r11);
    // A changed ticket is not ours; a changed binder fails the handshake.
    var bad_ticket = client_cfg();
    bad_ticket.session = sess;
    bad_ticket.session.ticket[20] ^= 1;
    let ok12, r12, s12 = connect("changed ticket", bad_ticket, sc);
    check("changed ticket: full handshake", ok12 && !r12);
    var c13 = tls::client(rc);
    var s13 = tls::server(sc);
    var hello: u8[>..] = [];
    tls::client_start(c13, rc, hello);
    hello[hello.len - 1] ^= 1;                   // the binder ends the ClientHello
    var reply: u8[>..] = [];
    var app13: u8[>..] = [];
    let rr = tls::server_feed(s13, sc, hello, reply, app13);
    check("changed binder", rr == -1 && s13.alert == tls::ALERT_DECRYPT_ERROR);

    print("resumption: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
