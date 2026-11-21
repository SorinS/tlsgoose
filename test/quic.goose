// TLS 1.3 in QUIC's mode (RFC 9001 §4), between this package's client
// and server in memory: handshake messages pass as CRYPTO data tagged with
// their encryption level, no records, no change_cipher_spec. Both sides
// must reach the same handshake and application secrets, agree on ALPN
// and get each other's transport parameters; with a HelloRetryRequest and
// with resumption too. Refused: a server without the client's transport
// parameters or without ALPN, data at the wrong level, a KeyUpdate, a
// ClientHello with a legacy_session_id, and a client offering no ALPN.
import std;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
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
        if w[0] == kind && kind == "root" { return unhex(w[idx - 1]); }
        if w[0] == "server" && w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;

fn server_cfg() -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("p256", 2), field("p256", 3));
    check("load key", ok);
    sc.now = NOW;
    tls::add_alpn(sc.alpn, "h3");
    return sc;
}

fn client_cfg() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", 2));
    cc.now = NOW;
    tls::add_alpn(cc.alpn, "h3");
    return cc;
}

// Feeds every chunk in `chunks` to the other side at its level; what that
// side sends back goes into `back`. -1 when a side failed; whether any
// record-layer bytes appeared (none must).
fn deliver(c: tls::Conn&, cfg, chunks: const u8[:], back: u8[>..]&) -> i64 {
    var at = 0;
    loop {
        let level, off, n, next, ok = tls::quic_next_chunk(chunks, at);
        if !ok { break; }
        let r = tls::feed_crypto(c, cfg, level, chunks[off..off + n], back);
        if r != 0 { return r; }
        at = next;
    }
    return if at == chunks.len { 0 } else { -2 };
}

// Runs the handshake; whether both connected.
fn handshake(c: tls::Conn&, cc: const tls::ClientConfig&, s: tls::Conn&, sc: const tls::ServerConfig&) -> bool {
    var to_server: u8[>..] = [];
    tls::quic_start(c, cc, to_server);
    for round in 10 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        if deliver(s, sc, to_server, to_client) != 0 { return false; }
        to_server.clear();
        if to_client.len == 0 { break; }
        if deliver(c, cc, to_client, to_server) != 0 { return false; }
    }
    return tls::connected(c) && tls::connected(s);
}

fn same_secrets(c: const tls::Conn&, s: const tls::Conn&) -> bool {
    let a = tls::quic_secret(c, tls::QUIC_HANDSHAKE, true);
    let b = tls::quic_secret(s, tls::QUIC_HANDSHAKE, false);
    let d = tls::quic_secret(c, tls::QUIC_APPLICATION, true);
    let e = tls::quic_secret(s, tls::QUIC_APPLICATION, false);
    let f = tls::quic_secret(s, tls::QUIC_APPLICATION, true);
    let g = tls::quic_secret(c, tls::QUIC_APPLICATION, false);
    return a.len == 32 && a == b && d.len == 32 && d == e && f == g && d != f;
}

fn basic() {
    let cc = client_cfg();
    let sc = server_cfg();
    var c = tls::quic_client(cc, "client params");
    var s = tls::quic_server(sc, "server params");
    check("handshake", handshake(c, cc, s, sc));
    check("the same secrets on both sides", same_secrets(c, s));
    let cp, chas = tls::quic_peer_params(c);
    let sp, shas = tls::quic_peer_params(s);
    check("transport parameters exchanged", chas && shas && cp == "server params" && sp == "client params");
    check("ALPN h3", tls::alpn(c) == "h3" && tls::alpn(s) == "h3");
    check("levels at the end", tls::quic_read_level(c) == tls::QUIC_APPLICATION && tls::quic_write_level(s) == tls::QUIC_APPLICATION);
    var out: u8[>..] = [];
    check("no application data through TLS", !tls::send(c, "x", out) && out.len == 0);
    check("no KeyUpdate through TLS", !tls::key_update(c, true, out) && out.len == 0);
    // A KeyUpdate from the peer, at the 1-RTT level, is refused.
    let ku: u8[5] = [24, 0, 0, 1, 0];
    let r = tls::feed_crypto(s, sc, tls::QUIC_APPLICATION, ku, out);
    check("a KeyUpdate received is unexpected_message", r == -1 && s.alert == tls::ALERT_UNEXPECTED_MESSAGE && out.len == 0);
}

fn levels() {
    let cc = client_cfg();
    let sc = server_cfg();
    var c = tls::quic_client(cc, "p");
    var s = tls::quic_server(sc, "q");
    var ch: u8[>..] = [];
    tls::quic_start(c, cc, ch);
    let level, off, n, next, ok = tls::quic_next_chunk(ch, 0);
    check("the ClientHello at the Initial level, alone", ok && level == tls::QUIC_INITIAL && next == ch.len);
    check("no session ID (no compatibility mode)", ch[off + 4 + 2 + 32] == 0);
    var back: u8[>..] = [];
    let r = tls::feed_crypto(s, sc, tls::QUIC_HANDSHAKE, ch[off..off + n], back);
    check("a ClientHello at the Handshake level refused", r == -1 && s.alert == tls::ALERT_UNEXPECTED_MESSAGE);
    // The server's flight: ServerHello at Initial, the rest at Handshake.
    var s2 = tls::quic_server(sc, "q");
    var flight: u8[>..] = [];
    let r2 = tls::feed_crypto(s2, sc, tls::QUIC_INITIAL, ch[off..off + n], flight);
    var at = 0;
    var seen: u8[>..] = [];
    loop {
        let lv, o, m, nx, okc = tls::quic_next_chunk(flight, at);
        if !okc { break; }
        seen.push(lv);
        at = nx;
    }
    check("the server's flight: Initial, then Handshake", r2 == 0 && seen.len >= 3 && seen[0] == tls::QUIC_INITIAL &&
          seen[1] == tls::QUIC_HANDSHAKE && seen[seen.len - 1] == tls::QUIC_HANDSHAKE);
}

fn refusals() {
    let sc = server_cfg();
    // A client offering no ALPN does not start.
    var nc = client_cfg();
    nc.alpn.clear();
    var c1 = tls::quic_client(nc, "p");
    var out: u8[>..] = [];
    tls::quic_start(c1, nc, out);
    check("no ALPN: the client does not start", tls::failed(c1) && out.len == 0);
    // A server without the protocol the client offers.
    let cc = client_cfg();
    var other = server_cfg();
    other.alpn.clear();
    tls::add_alpn(other.alpn, "hq-interop");
    var c2 = tls::quic_client(cc, "p");
    var s2 = tls::quic_server(other, "q");
    check("no common protocol", !handshake(c2, cc, s2, other) && s2.alert == tls::ALERT_NO_APPLICATION_PROTOCOL);
    var none = server_cfg();
    none.alpn.clear();
    var c3 = tls::quic_client(cc, "p");
    var s3 = tls::quic_server(none, "q");
    check("a server without ALPN", !handshake(c3, cc, s3, none) && s3.alert == tls::ALERT_NO_APPLICATION_PROTOCOL);
    // A ClientHello from a TLS (not QUIC) client: no transport parameters,
    // a legacy_session_id.
    var c4 = tls::client(cc);
    var rec: u8[>..] = [];
    tls::client_start(c4, cc, rec);
    var s4 = tls::quic_server(sc, "q");
    var back: u8[>..] = [];
    let r4 = tls::feed_crypto(s4, sc, tls::QUIC_INITIAL, rec[5..], back);
    check("a ClientHello without transport parameters", r4 == -1 && s4.alert == tls::ALERT_MISSING_EXTENSION);
    // feed_crypto on a TLS connection.
    var s5 = tls::server(sc);
    let r5 = tls::feed_crypto(s5, sc, tls::QUIC_INITIAL, rec[5..], back);
    check("not a QUIC connection", r5 == -1);
}

fn retry_and_resume() {
    // A HelloRetryRequest: the client's share is of a group the server
    // does not take first.
    var cc = client_cfg();
    var sc = server_cfg();
    sc.groups.clear();
    sc.groups.push(tls::GROUP_SECP256R1);
    var c = tls::quic_client(cc, "p");
    var s = tls::quic_server(sc, "q");
    check("after a HelloRetryRequest", handshake(c, cc, s, sc) && c.hrr && same_secrets(c, s));
    // Resumption: the server sends a ticket at the 1-RTT level.
    var sc2 = server_cfg();
    sc2.tickets = 1;
    var c2 = tls::quic_client(cc, "p");
    var s2 = tls::quic_server(sc2, "q");
    check("a full handshake with a ticket", handshake(c2, cc, s2, sc2));
    let sess, has = tls::session(c2);
    check("the ticket came at the 1-RTT level", has);
    var cc3 = client_cfg();
    cc3.session = sess;
    var c3 = tls::quic_client(cc3, "p");
    var s3 = tls::quic_server(sc2, "q");
    check("resumed", handshake(c3, cc3, s3, sc2) && tls::resumed(c3) && tls::resumed(s3) && same_secrets(c3, s3));
}

fn main() {
    basic();
    levels();
    refusals();
    retry_and_resume();
    print("quic: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
