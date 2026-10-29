// TLS 1.3 handshakes between this package's client and server, in
// memory: every server key type (Ed25519, P-256, P-384, P-521, RSA,
// ML-DSA-44/65/87) with every cipher suite and key exchange group,
// HelloRetryRequest, ALPN, application data both ways, KeyUpdate,
// close_notify, and the failures a client must report: an untrusted root,
// a wrong name, a changed record, no common suite or group.
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import x509.pool;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 15 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
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

// Moves bytes between the two sides until neither has more to say.
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
    let sc, ok = tls::server_config(field(kind, 2), field(kind, 3));
    check("load key", ok);
    return sc;
}

fn client_cfg() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", 2));
    cc.now = NOW;
    return cc;
}

fn handshake_ok(label: const u8[:], cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> bool {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    let ok = tls::connected(c) && tls::connected(s);
    check(label, ok);
    if !ok { print("   client state ", c.state, " alert ", c.alert, " error ", c.error, "; server state ", s.state, " alert ", s.alert); return false; }
    // Data both ways, a KeyUpdate asked of the server, then more data.
    check("send", tls::send(c, "ping", to_server));
    pump(c, cc, s, sc, to_server, capp, sapp);
    check("server got", sapp == "ping");
    var to_client: u8[>..] = [];
    check("server send", tls::send(s, "pong", to_client));
    let r1 = tls::client_feed(c, cc, to_client, to_server, capp);
    check("client got", capp == "pong");
    check("key update", tls::key_update(c, true, to_server));
    var big: u8[>..] = [];
    big.resize(40000, 0x41);
    check("send big", tls::send(c, big, to_server));
    sapp.clear();
    pump(c, cc, s, sc, to_server, capp, sapp);
    check("after update", sapp == big && s.key_updates == 1 && c.key_updates == 1);
    var more: u8[>..] = [];
    check("server after update", tls::send(s, "again", more));
    capp.clear();
    let r2 = tls::client_feed(c, cc, more, to_server, capp);
    check("client after update", capp == "again");
    // Close.
    tls::close(c, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    check("closed", tls::closed(s) && s.alert == tls::ALERT_CLOSE_NOTIFY);
    return true;
}

// The client's alert from a handshake expected to fail.
fn handshake_alert(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> u8, u8 {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    return c.alert, s.alert;
}

// The checks come in parts, each a function of its own, so that a part's
// connections (large values) leave the stack when it returns: main
// holding them all overflowed Linux's 8 MB stack.

// Every key type, suite and group.
fn suites_and_groups() {
    let kinds = ["ed25519", "p256", "p384", "p521", "rsa", "mldsa44", "mldsa65", "mldsa87"];
    let suites: u16[4] = [tls::TLS_AES_128_GCM_SHA256, tls::TLS_AES_256_GCM_SHA384, tls::TLS_CHACHA20_POLY1305_SHA256,
                          tls::TLS_AES_128_GCM_SHA256];
    let groups: u16[4] = [tls::GROUP_X25519MLKEM768, tls::GROUP_SECP256R1, tls::GROUP_SECP384R1, tls::GROUP_SECP521R1];
    for kind in kinds {
        let sc = server_cfg(kind);
        for si in 4 {
            var cc = client_cfg();
            cc.suites.clear();
            cc.suites.push(suites[si]);
            cc.groups.clear();
            cc.groups.push(groups[si]);
            let ok = handshake_ok(kind, cc, sc);
        }
    }
}

// The other ML-KEM groups.
fn mlkem_groups() {
    // The other ML-KEM groups, each alone on both sides, and a hybrid's
    // ECDH share taken by a server without ML-KEM.
    let pq: u16[3] = [tls::GROUP_SECP256R1MLKEM768, tls::GROUP_SECP384R1MLKEM1024, tls::GROUP_MLKEM1024];
    let classic: u16[3] = [tls::GROUP_SECP256R1, tls::GROUP_SECP384R1, 0];
    for gi in 3 {
        var cg = client_cfg();
        cg.groups.clear();
        cg.groups.push(pq[gi]);
        var sg = server_cfg("p384");
        sg.groups.clear();
        sg.groups.push(pq[gi]);
        var cq = tls::client(cg);
        var sq = tls::server(sg);
        var tq: u8[>..] = [];
        var caq: u8[>..] = [];
        var saq: u8[>..] = [];
        tls::client_start(cq, cg, tq);
        pump(cq, cg, sq, sg, tq, caq, saq);
        check("ml-kem group", tls::connected(cq) && tls::connected(sq) && cq.group == pq[gi] && sq.group == pq[gi] &&
              !cq.hrr && cq.sch.c_ap == sq.sch.c_ap);
        if classic[gi] == 0 { continue; }
        cg.groups.push(classic[gi]);
        var sf = server_cfg("ed25519");
        sf.groups.clear();
        sf.groups.push(classic[gi]);
        var cf = tls::client(cg);
        var sff = tls::server(sf);
        tq.clear();
        tls::client_start(cf, cg, tq);
        pump(cf, cg, sff, sf, tq, caq, saq);
        check("ecdh beside the hybrid", tls::connected(cf) && cf.group == classic[gi] && !cf.hrr);
    }
}

// The hybrid defaults and retries.
fn hybrid_defaults() {
    // The defaults offer the NIST hybrids; a server preferring one takes it
    // through a retry.
    var cn = client_cfg();
    var sn = server_cfg("rsa");
    sn.groups.clear();
    sn.groups.push(tls::GROUP_SECP384R1MLKEM1024);
    var c3 = tls::client(cn);
    var s3 = tls::server(sn);
    var t3: u8[>..] = [];
    var ca3: u8[>..] = [];
    var sa3: u8[>..] = [];
    tls::client_start(c3, cn, t3);
    pump(c3, cn, s3, sn, t3, ca3, sa3);
    check("hrr to secp384r1mlkem1024", tls::connected(c3) && c3.hrr && c3.group == tls::GROUP_SECP384R1MLKEM1024);
    // The native key formats load too.
    let sc_sec1, ok1 = tls::server_config(field("p256", 2), field("p256", 4));
    check("sec1", ok1 && sc_sec1.key.kind == x509::KEY_EC_P256);
    let sc_pkcs1, ok2 = tls::server_config(field("rsa", 2), field("rsa", 4));
    check("pkcs1", ok2 && sc_pkcs1.key.kind == x509::KEY_RSA);
    let bad_key, ok3 = tls::server_config(field("rsa", 2), "junk");
    check("bad key", !ok3);

    // The defaults: the hybrid, chosen over the X25519 share beside it.
    var cd = client_cfg();
    let sd = server_cfg("p256");
    var c0 = tls::client(cd);
    var s0 = tls::server(sd);
    var ts: u8[>..] = [];
    var ca0: u8[>..] = [];
    var sa0: u8[>..] = [];
    tls::client_start(c0, cd, ts);
    pump(c0, cd, s0, sd, ts, ca0, sa0);
    check("hybrid default", tls::connected(c0) && c0.group == tls::GROUP_X25519MLKEM768 && s0.group == tls::GROUP_X25519MLKEM768);
    // A server without ML-KEM takes the X25519 share, with no retry.
    var sx = server_cfg("p256");
    sx.groups.clear();
    sx.groups.push(tls::GROUP_X25519);
    var c1 = tls::client(cd);
    var s1 = tls::server(sx);
    ts.clear();
    tls::client_start(c1, cd, ts);
    pump(c1, cd, s1, sx, ts, ca0, sa0);
    check("x25519 beside the hybrid", tls::connected(c1) && c1.group == tls::GROUP_X25519 && !c1.hrr);
    // A retry for the hybrid.
    var cr = client_cfg();
    cr.groups.clear();
    cr.groups.push(tls::GROUP_SECP256R1);
    cr.groups.push(tls::GROUP_X25519MLKEM768);
    var sh = server_cfg("ed25519");
    sh.groups.clear();
    sh.groups.push(tls::GROUP_X25519MLKEM768);
    var c2h = tls::client(cr);
    var s2h = tls::server(sh);
    ts.clear();
    tls::client_start(c2h, cr, ts);
    pump(c2h, cr, s2h, sh, ts, ca0, sa0);
    check("hrr to the hybrid", tls::connected(c2h) && c2h.hrr && c2h.group == tls::GROUP_X25519MLKEM768);
}

// A HelloRetryRequest and ALPN.
fn hrr_and_alpn() {
    // HelloRetryRequest: the client's share is X25519, the server only
    // takes P-256.
    var cc = client_cfg();
    cc.groups.clear();
    cc.groups.push(tls::GROUP_X25519);
    cc.groups.push(tls::GROUP_SECP256R1);
    var sc = server_cfg("p256");
    sc.groups.clear();
    sc.groups.push(tls::GROUP_SECP256R1);
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    check("hrr", tls::connected(c) && tls::connected(s) && c.hrr && s.hrr && c.group == tls::GROUP_SECP256R1);

    // ALPN: the server's preference among the client's offers.
    var ca = client_cfg();
    tls::add_alpn(ca.alpn, "http/1.1");
    tls::add_alpn(ca.alpn, "h2");
    var sa = server_cfg("ed25519");
    tls::add_alpn(sa.alpn, "h2");
    tls::add_alpn(sa.alpn, "http/1.1");
    var c2 = tls::client(ca);
    var s2 = tls::server(sa);
    to_server.clear();
    tls::client_start(c2, ca, to_server);
    pump(c2, ca, s2, sa, to_server, capp, sapp);
    check("alpn", tls::connected(c2) && c2.alpn == "h2" && s2.alpn == "h2");
    var sn = server_cfg("ed25519");
    tls::add_alpn(sn.alpn, "spdy/3");
    let ca1, sa1 = handshake_alert(ca, sn);
    check("alpn mismatch", sa1 == tls::ALERT_NO_APPLICATION_PROTOCOL);
}

// Failures the client must catch, and roots.
// A handshake message longer than MAX_HANDSHAKE (64 KB) is refused with
// decode_error, its length being wrong (RFC 8446 §6.2), as soon as its
// header says so.
fn oversized_handshake() {
    let sc = server_cfg("p256");
    var s = tls::server(sc);
    // A ClientHello whose header announces 70000 bytes, in one record.
    var rec: u8[>..] = [22, 3, 1, 0, 8, 1, 0x01, 0x11, 0x70, 3, 3, 0, 0];
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    let r = tls::server_feed(s, sc, rec, out, app);
    check("oversized handshake message: decode_error", r == -1 && s.alert == tls::ALERT_DECODE_ERROR);
}

fn client_failures() {
    // Failures the client must catch.
    var wrong_root = client_cfg();
    wrong_root.roots = x509::new_pool();
    let okw = x509::pool_add(wrong_root.roots, field("p256", 2));   // a leaf is no root for the others
    let srv_wrong_root = server_cfg("ed25519");
    let a1, b1 = handshake_alert(wrong_root, srv_wrong_root);
    check("unknown ca", a1 == tls::ALERT_UNKNOWN_CA);
    // Roots: the system's when none are given (which do not include the
    // test root), a pool from the root's file, from a directory of
    // certificates, and an empty pool.
    var sys_cfg = tls::client_config("example.com", "");
    sys_cfg.now = NOW;
    check("system roots by default", sys_cfg.system_roots);
    let a0, b0 = handshake_alert(sys_cfg, srv_wrong_root);
    check("system roots: unknown ca", a0 == tls::ALERT_UNKNOWN_CA);
    var from_file = x509::new_pool();
    check("root file", x509::pool_add_file(from_file, "vectors/hs_root.pem") == 1);
    var file_cfg = tls::client_config_pool("example.com", from_file);
    file_cfg.now = NOW;
    check("pool from a file", !file_cfg.system_roots && handshake_ok("ed25519", file_cfg, srv_wrong_root));
    var from_dir = x509::new_pool();
    check("root directory", x509::pool_add_dir(from_dir, "vectors") > 1);
    var dir_cfg = tls::client_config_pool("example.com", from_dir);
    dir_cfg.now = NOW;
    check("pool from a directory", handshake_ok("ed25519", dir_cfg, srv_wrong_root));
    let none = x509::new_pool();
    var none_cfg = tls::client_config_pool("example.com", none);
    none_cfg.now = NOW;
    let a00, b00 = handshake_alert(none_cfg, srv_wrong_root);
    check("empty pool: unknown ca", a00 == tls::ALERT_UNKNOWN_CA);
    var wrong_name = client_cfg();
    wrong_name.server_name.clear();
    wrong_name.server_name.append("other.org");
    let srv_wrong_name = server_cfg("p256");
    let a2, b2 = handshake_alert(wrong_name, srv_wrong_name);
    check("wrong name", a2 == tls::ALERT_BAD_CERTIFICATE);
    var later = client_cfg();
    later.now = 2900000000;
    let srv_later = server_cfg("p256");
    let a3, b3 = handshake_alert(later, srv_later);
    check("expired", a3 == tls::ALERT_CERTIFICATE_EXPIRED);
    var no_suite = client_cfg();
    no_suite.suites.clear();
    no_suite.suites.push(tls::TLS_CHACHA20_POLY1305_SHA256);
    var only_aes = server_cfg("p256");
    only_aes.suites.clear();
    only_aes.suites.push(tls::TLS_AES_128_GCM_SHA256);
    let a4, b4 = handshake_alert(no_suite, only_aes);
    check("no suite", b4 == tls::ALERT_HANDSHAKE_FAILURE && a4 == tls::ALERT_HANDSHAKE_FAILURE);
    var no_group = client_cfg();
    no_group.groups.clear();
    no_group.groups.push(tls::GROUP_X25519);
    var only_p384 = server_cfg("p256");
    only_p384.groups.clear();
    only_p384.groups.push(tls::GROUP_SECP384R1);
    let a5, b5 = handshake_alert(no_group, only_p384);
    check("no group", b5 == tls::ALERT_HANDSHAKE_FAILURE);
    // Unverified mode connects to anything.
    var lax = wrong_name;
    lax.verify = false;
    let srv_lax = server_cfg("p256");
    let a6, b6 = handshake_alert(lax, srv_lax);
    check("verify off", a6 == 0 && b6 == 0);
}

// Changed records, and bytes one at a time.
fn records() {
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    // A changed record ends the connection with bad_record_mac.
    var cc3 = client_cfg();
    let sc3 = server_cfg("p384");
    var c3 = tls::client(cc3);
    var s3 = tls::server(sc3);
    to_server.clear();
    tls::client_start(c3, cc3, to_server);
    pump(c3, cc3, s3, sc3, to_server, capp, sapp);
    var to_client: u8[>..] = [];
    check("send", tls::send(s3, "secret", to_client));
    to_client[to_client.len - 3] ^= 1;
    capp.clear();
    let r = tls::client_feed(c3, cc3, to_client, to_server, capp);
    check("bad record", r == -1 && tls::failed(c3) && c3.alert == tls::ALERT_BAD_RECORD_MAC && capp.len == 0);
    // Bytes fed one at a time still assemble into records.
    var cc4 = client_cfg();
    let sc4 = server_cfg("ed25519");
    var c4 = tls::client(cc4);
    var s4 = tls::server(sc4);
    var hello: u8[>..] = [];
    tls::client_start(c4, cc4, hello);
    var reply: u8[>..] = [];
    for i in hello.len { let rr = tls::server_feed(s4, sc4, hello[i..i + 1], reply, sapp); }
    var fin: u8[>..] = [];
    for i in reply.len { let rr = tls::client_feed(c4, cc4, reply[i..i + 1], fin, capp); }
    let rr = tls::server_feed(s4, sc4, fin, reply, sapp);
    check("byte at a time", tls::connected(c4) && tls::connected(s4));
}

fn main() {
    suites_and_groups();
    mlkem_groups();
    hybrid_defaults();
    hrr_and_alpn();
    client_failures();
    oversized_handshake();
    records();
    print("handshake: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}