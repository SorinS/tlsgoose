// Handshakes a second and bulk throughput of this package's client and
// server, both in this process and in memory, so that only the TLS work is
// timed: no sockets, no system calls but the OS's entropy. One line each,
// "name value unit"; scripts/bench_openssl.py builds this natively and
// sets each line against tools/bench_openssl.c, which does the same with
// OpenSSL. A handshake is both sides' work: the client verifies the
// server's chain (to test/vectors' P-256 root) and its name, and no
// session tickets are sent except to resume. A name given as an argument
// runs only the lines it prefixes; a second argument is the time for each,
// in milliseconds (1000).
//
//   goose build -o bench tools/bench.goose && ./bench [prefix] [ms]
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import tls.session;

var secs: f64 = 1.0;
var only: u8[>..] = [];

fn wanted(name: const u8[:]) -> bool {
    only.len == 0 || (name.len >= only.len && name[..only.len] == only)
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// The root's certificate, or a server's certificate (1) or key (2).
fn field(kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("../test/vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 { continue; }
        if w[0] == "root" && kind == "root" { return unhex(w[1]); }
        if w[0] == "server" && w[1] == kind { return unhex(w[1 + idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

// Runs until secs have passed: n counts the rounds, t0 when it started.
struct Timer { t0: f64, n: i64 }

fn timer() -> Timer { Timer { t0: clock(), n: 0 } }

fn more(t: Timer&) -> bool {
    if t.n > 0 && clock() - t.t0 >= secs { return false; }
    t.n++;
    return true;
}

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

// One handshake; the client's session if the server sent a ticket.
fn handshake(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> bool, tls::Session {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    let sess, has = tls::session(c);
    return tls::connected(c) && tls::connected(s) && (cc.session.psk.len == 0 || tls::resumed(c)), sess;
}

// The configurations for a server key, a group, a TLS 1.3 suite or, for
// TLS 1.2, a TLS 1.2 one, with no tickets.
fn configs(kind: const u8[:], group: u16, suite: u16, tls12: bool) -> tls::ClientConfig, tls::ServerConfig {
    var cc = tls::client_config("example.com", field("root", 0));
    var sc, ok = tls::server_config(field(kind, 1), field(kind, 2));
    assert(ok);
    sc.tickets = 0;
    cc.groups.clear(); cc.groups.push(group);
    sc.groups.clear(); sc.groups.push(group);
    if tls12 {
        // TLS 1.2's groups cover the ECDSA certificate's curve too, so
        // P-256 follows (as for OpenSSL, which requires it).
        cc.groups.push(tls::GROUP_SECP256R1);
        sc.groups.push(tls::GROUP_SECP256R1);
        cc.max_version = tls::VERSION_TLS12; sc.max_version = tls::VERSION_TLS12;
        cc.suites12.clear(); cc.suites12.push(suite);
        sc.suites12.clear(); sc.suites12.push(suite);
    } else {
        cc.min_version = tls::VERSION_TLS13; sc.min_version = tls::VERSION_TLS13;
        cc.suites.clear(); cc.suites.push(suite);
        sc.suites.clear(); sc.suites.push(suite);
    }
    return cc, sc;
}

fn handshakes(name: const u8[:], kind: const u8[:], group: u16, suite: u16, tls12: bool) {
    if !wanted(name) { return; }
    let cc, sc = configs(kind, group, suite, tls12);
    var t = timer();
    while more(t) { let ok, sess = handshake(cc, sc); assert(ok); }
    print(name, " ", t.n / (clock() - t.t0), " hs/s");
}

// TLS 1.3 resumption (psk_dhe_ke): the server sends one ticket after each
// handshake, and the next connection resumes with it (OpenSSL's client
// uses a ticket once).
fn resumptions(name: const u8[:]) {
    if !wanted(name) { return; }
    var cc, sc = configs("p256", tls::GROUP_X25519, tls::TLS_AES_128_GCM_SHA256, false);
    sc.tickets = 1;
    let ok, sess = handshake(cc, sc);
    assert(ok && sess.psk.len > 0);
    cc.session = sess;
    var t = timer();
    while more(t) {
        let ok2, s2 = handshake(cc, sc);
        assert(ok2 && s2.psk.len > 0);
        cc.session = s2;
    }
    print(name, " ", t.n / (clock() - t.t0), " hs/s");
}

// Application data from the client to the server in 16 KiB writes: the
// client seals each record and the server opens it.
fn bulk(name: const u8[:], suite: u16, tls12: bool) {
    if !wanted(name) { return; }
    let cc, sc = configs("p256", tls::GROUP_X25519, suite, tls12);
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    assert(tls::connected(c) && tls::connected(s));
    var buf: u8[>..] = [];
    for i in 16384 { buf.push(((i * 131 + 7) % 251) as! u8); }
    var to_client: u8[>..] = [];
    var got = 0;
    var t = timer();
    while more(t) {
        to_server.clear();
        let sent = tls::send(c, buf, to_server);
        let rs = tls::server_feed(s, sc, to_server, to_client, sapp);
        got += sapp.len;
        sapp.clear();
    }
    let elapsed = clock() - t.t0;
    assert(got == t.n * 16384);
    print(name, " ", got / elapsed / 1000000.0, " MB/s");
}

fn main() {
    let a = args();
    if a.len > 1 { only.append(a[1]); }
    if a.len > 2 { let v, ok = parse_int(a[2]); if ok { secs = v / 1000.0; } }
    handshakes("tls13-x25519-ed25519", "ed25519", tls::GROUP_X25519, tls::TLS_AES_128_GCM_SHA256, false);
    handshakes("tls13-x25519-p256", "p256", tls::GROUP_X25519, tls::TLS_AES_128_GCM_SHA256, false);
    handshakes("tls13-x25519-rsa2048", "rsa", tls::GROUP_X25519, tls::TLS_AES_128_GCM_SHA256, false);
    handshakes("tls13-p256-p256", "p256", tls::GROUP_SECP256R1, tls::TLS_AES_128_GCM_SHA256, false);
    handshakes("tls13-p384-p384", "p384", tls::GROUP_SECP384R1, tls::TLS_AES_256_GCM_SHA384, false);
    handshakes("tls13-x25519mlkem768-p256", "p256", tls::GROUP_X25519MLKEM768, tls::TLS_AES_128_GCM_SHA256, false);
    handshakes("tls13-x25519mlkem768-mldsa65", "mldsa65", tls::GROUP_X25519MLKEM768, tls::TLS_AES_128_GCM_SHA256, false);
    resumptions("tls13-resume-x25519");
    handshakes("tls12-ecdhe-ecdsa-p256", "p256", tls::GROUP_X25519, tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true);
    handshakes("tls12-ecdhe-rsa2048", "rsa", tls::GROUP_X25519, tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true);
    bulk("bulk-tls13-aes128gcm", tls::TLS_AES_128_GCM_SHA256, false);
    bulk("bulk-tls13-aes256gcm", tls::TLS_AES_256_GCM_SHA384, false);
    bulk("bulk-tls13-chacha20", tls::TLS_CHACHA20_POLY1305_SHA256, false);
    bulk("bulk-tls12-aes128gcm", tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true);
    bulk("bulk-tls12-chacha20", tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, true);
}
