// client_cert: mutual TLS. The server requires a client certificate and
// checks it against its client CAs (cfg.client_cas); the client sets its
// certificate and key with set_client_certificate. Once connected, the
// server reads the client's chain with peer_certificates. A client
// without a certificate is refused with certificate_required.
//
//   goose examples/client_cert.goose

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
import x509.pool;

// A certificate under the root for `subject`, on a new key: its DER and
// the key's PKCS #8. `dns` is its DNS name, if any; `eku` what it may do.
fn issue(root: const u8[:], root_key: const x509::PrivateKey&, subject: const u8[:], dns: const u8[:], eku: u32) -> u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let key = x509::generate_key(x509::KEY_ED25519);
    var t, ok = x509::template(subject, now - 3600, now + 86400);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = eku;
    if dns.len > 0 { x509::add_dns(t.san, dns); }
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), root, root_key);
    guard ok && e == x509::OK else { print("client_cert: cannot make ", subject); exit(1); }
    return der, x509::marshal_pkcs8(key);
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

fn run() {
    // One root issues both the server's certificate and the client's.
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_ED25519);
    var rt, okr = x509::template("CN=Example Root CA", now - 3600, now + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    guard okr && er == x509::OK else { print("client_cert: cannot make the root"); exit(1); }
    let server_cert, server_key = issue(root, root_key, "CN=example.com", "example.com", x509::EKU_SERVER_AUTH);
    let client_cert, client_key = issue(root, root_key, "CN=alice", "", x509::EKU_CLIENT_AUTH);

    // The server asks for a certificate and checks it.
    var sc, ok = tls::server_config(server_cert, server_key);
    guard ok else { print("client_cert: bad server key"); exit(1); }
    sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    guard x509::pool_add(sc.client_cas, root) else { print("client_cert: bad CA"); exit(1); }

    var cc = tls::client_config("example.com", root);
    guard tls::set_client_certificate(cc, client_cert, client_key) else { print("client_cert: bad client key"); exit(1); }

    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else { print("client_cert: failed, alerts ", c.alert, " ", s.alert); exit(1); }
    let seen = tls::peer_certificates(s);
    guard tls::peer_verified(s) && seen == client_cert else { print("client_cert: the server did not check the client"); exit(1); }
    let cert, e = x509::parse(seen);
    guard e == x509::OK else { print("client_cert: the client's certificate does not parse"); exit(1); }
    print("server accepted the client certificate of ", x509::subject_text(cert), ", verified");

    // Without a certificate the server refuses.
    let anonymous = tls::client_config("example.com", root);
    var c2 = tls::client(anonymous);
    var s2 = tls::server(sc);
    to_server.clear();
    tls::client_start(c2, anonymous, to_server);
    pump(c2, anonymous, s2, sc, to_server, capp, sapp);
    guard !tls::connected(s2) && s2.alert == tls::ALERT_CERTIFICATE_REQUIRED else { print("client_cert: an anonymous client got in"); exit(1); }
    print("a client without a certificate: refused with certificate_required");
}

fn main() {
    run();
}
