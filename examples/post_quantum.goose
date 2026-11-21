// post_quantum: post-quantum TLS 1.3. The key exchange is the hybrid
// X25519MLKEM768 by default; cfg.groups picks others (SecP256r1MLKEM768,
// SecP384r1MLKEM1024, MLKEM1024 alone, or the classic curves), and a
// server preferring a group the client sent no share for asks for one
// with a HelloRetryRequest. The certificates can be ML-DSA too, signing
// CertificateVerify with a post-quantum signature.
//
//   goose examples/post_quantum.goose

import std;
import os;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
import tls.handshake;
import x509.create;
import x509.keys;

// A root and a leaf for example.com, both on keys of `kind`.
fn make_pki(kind: i64) -> u8[>..], u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(kind);
    var rt, ok1 = x509::template("CN=Example Root CA", now - 3600, now + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, e1 = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    let key = x509::generate_key(kind);
    var lt, ok2 = x509::template("CN=example.com", now - 3600, now + 86400);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt.san, "example.com");
    let leaf, e2 = x509::create_certificate(lt, x509::marshal_public_key(key), root, root_key);
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("post_quantum: cannot make the certificates"); exit(1); }
    return root, leaf, x509::marshal_pkcs8(key);
}

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

// A handshake and a message; the group used and whether it took a retry.
fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> u16, bool {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) && tls::peer_verified(c) else { print("post_quantum: failed, alerts ", c.alert, " ", s.alert); exit(1); }
    let sent = tls::send(c, "hello", to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard sent && sapp == "hello" else { print("post_quantum: data lost"); exit(1); }
    guard c.group == s.group else { print("post_quantum: the sides disagree on the group"); exit(1); }
    return c.group, c.hrr;
}

fn hex_u16(v: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, v, 16, 4, '0');
    return o;
}

fn run() {
    // An ML-DSA-65 root and server certificate.
    let root, chain, key = make_pki(x509::KEY_MLDSA65);
    var sc, ok = tls::server_config(chain, key);
    guard ok else { print("post_quantum: bad server key"); exit(1); }
    var cc = tls::client_config("example.com", root);

    // The defaults: X25519MLKEM768 at once.
    let g1, hrr1 = connect(cc, sc);
    guard g1 == tls::GROUP_X25519MLKEM768 && !hrr1 else { print("post_quantum: expected X25519MLKEM768"); exit(1); }
    print("defaults:          group 0x", hex_u16(g1), " (X25519MLKEM768), ML-DSA-65 certificate");

    // ML-KEM-1024 alone, on both sides.
    var cc2 = copy(cc);
    cc2.groups.clear();
    cc2.groups.push(tls::GROUP_MLKEM1024);
    var sc2 = copy(sc);
    sc2.groups.clear();
    sc2.groups.push(tls::GROUP_MLKEM1024);
    let g2, hrr2 = connect(cc2, sc2);
    guard g2 == tls::GROUP_MLKEM1024 else { print("post_quantum: expected MLKEM1024"); exit(1); }
    print("ML-KEM alone:      group 0x", hex_u16(g2), " (MLKEM1024)");

    // A server that wants SecP384r1MLKEM1024: the client's first share is
    // for X25519MLKEM768, so the server asks again.
    var sc3 = copy(sc);
    sc3.groups.clear();
    sc3.groups.push(tls::GROUP_SECP384R1MLKEM1024);
    let g3, hrr3 = connect(cc, sc3);
    guard g3 == tls::GROUP_SECP384R1MLKEM1024 && hrr3 else { print("post_quantum: expected a retry"); exit(1); }
    print("server's choice:   group 0x", hex_u16(g3), " (SecP384r1MLKEM1024) after a HelloRetryRequest");
}

fn main() {
    run();
}
