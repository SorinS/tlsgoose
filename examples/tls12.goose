// tls12: TLS 1.2. By default both sides take TLS 1.2 and 1.3 and settle on
// 1.3; a server that stops at 1.2 (min_version / max_version) gets 1.2
// from the same client, under the TLS 1.2 suite the two prefer
// (cfg.suites12). Data then flows as in TLS 1.3.
//
//   goose examples/tls12.goose

import std;
import os;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.handshake;
import x509.create;
import x509.keys;

// A root CA and a leaf for example.com under it (ECDSA P-256, so the
// ECDHE-ECDSA suites): the root's DER, the leaf's DER and its PKCS #8 key.
fn make_pki() -> u8[>..], u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    var rt, ok1 = x509::template("CN=Example Root CA", now - 3600, now + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, e1 = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    let key = x509::generate_key(x509::KEY_EC_P256);
    var lt, ok2 = x509::template("CN=example.com", now - 3600, now + 86400);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt.san, "example.com");
    let leaf, e2 = x509::create_certificate(lt, x509::marshal_public_key(key), root, root_key);
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("tls12: cannot make the certificates"); exit(1); }
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

// One connection with a request and a reply; the version and suite.
fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> u16, u16 {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else { print("tls12: failed, alerts ", c.alert, " ", s.alert); exit(1); }
    let sent = tls::send(c, "ping", to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var to_client: u8[>..] = [];
    let sent2 = tls::send(s, "pong", to_client);
    let r = tls::client_feed(c, cc, to_client, to_server, capp);
    guard sent && sent2 && sapp == "ping" && capp == "pong" else { print("tls12: data lost"); exit(1); }
    tls::close(c, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    return tls::version(c), c.suite.id;
}

fn hex_u16(v: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, v, 16, 4, '0');
    return o;
}

fn run() {
    let root, chain, key = make_pki();
    var sc, ok = tls::server_config(chain, key);
    guard ok else { print("tls12: bad server key"); exit(1); }
    var cc = tls::client_config("example.com", root);

    // The defaults: TLS 1.3.
    let v1, s1 = connect(cc, sc);
    guard v1 == tls::VERSION_TLS13 else { print("tls12: expected TLS 1.3"); exit(1); }
    print("both sides by default: version 0x", hex_u16(v1), ", suite 0x", hex_u16(s1));

    // A server that stops at TLS 1.2, ChaCha20-Poly1305 first.
    sc.max_version = tls::VERSION_TLS12;
    sc.suites12.clear();
    sc.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    sc.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    let v2, s2 = connect(cc, sc);
    guard v2 == tls::VERSION_TLS12 && s2 == tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 else { print("tls12: expected TLS 1.2 ChaCha20"); exit(1); }
    print("server at 1.2:       version 0x", hex_u16(v2), ", suite 0x", hex_u16(s2));

    // A client that takes only TLS 1.2 and only AES-256-GCM.
    cc.max_version = tls::VERSION_TLS12;
    cc.suites12.clear();
    cc.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    sc.suites12.push(tls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    let v3, s3 = connect(cc, sc);
    guard v3 == tls::VERSION_TLS12 && s3 == tls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 else { print("tls12: expected AES-256-GCM"); exit(1); }
    print("client at 1.2:       version 0x", hex_u16(v3), ", suite 0x", hex_u16(s3));
}

fn main() {
    run();
}
