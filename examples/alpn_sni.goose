// alpn_sni: application protocol negotiation (ALPN) and the server name
// (SNI). The client names the server it wants in client_config and offers
// protocols with add_alpn; the server picks its first protocol the client
// offered. After the handshake c.alpn holds the protocol on both sides and
// the server's c.sni the name the client asked for. With no protocol in
// common the server refuses with no_application_protocol.
//
//   goose examples/alpn_sni.goose

import std;
import os;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.handshake;
import x509.create;
import x509.keys;

// A root, and a leaf valid for two names.
fn make_pki() -> u8[>..], u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_ED25519);
    var rt, ok1 = x509::template("CN=Example Root CA", now - 3600, now + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, e1 = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    let key = x509::generate_key(x509::KEY_ED25519);
    var lt, ok2 = x509::template("CN=example.com", now - 3600, now + 86400);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt.san, "example.com");
    x509::add_dns(lt.san, "www.example.com");
    let leaf, e2 = x509::create_certificate(lt, x509::marshal_public_key(key), root, root_key);
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("alpn_sni: cannot make the certificates"); exit(1); }
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

fn run() {
    let root, chain, key = make_pki();
    var sc, ok = tls::server_config(chain, key);
    guard ok else { print("alpn_sni: bad server key"); exit(1); }
    tls::add_alpn(sc.alpn, "h2");                    // the server's order of preference
    tls::add_alpn(sc.alpn, "http/1.1");

    var cc = tls::client_config("www.example.com", root);
    tls::add_alpn(cc.alpn, "http/1.1");
    tls::add_alpn(cc.alpn, "h2");

    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else { print("alpn_sni: failed, alerts ", c.alert, " ", s.alert); exit(1); }
    guard c.alpn == "h2" && s.alpn == "h2" && s.sni == "www.example.com" else { print("alpn_sni: wrong protocol or name"); exit(1); }
    print("server name ", s.sni, ", protocol ", c.alpn);

    // Nothing in common: the server refuses.
    var cc2 = tls::client_config("example.com", root);
    tls::add_alpn(cc2.alpn, "imap");
    var c2 = tls::client(cc2);
    var s2 = tls::server(sc);
    to_server.clear();
    tls::client_start(c2, cc2, to_server);
    pump(c2, cc2, s2, sc, to_server, capp, sapp);
    guard tls::failed(c2) && c2.alert == tls::ALERT_NO_APPLICATION_PROTOCOL else { print("alpn_sni: expected no_application_protocol"); exit(1); }
    print("offering only imap: refused with no_application_protocol");

    // A name the certificate does not cover: the client refuses it.
    let cc3 = tls::client_config("other.example.org", root);
    var c3 = tls::client(cc3);
    var s3 = tls::server(sc);
    to_server.clear();
    tls::client_start(c3, cc3, to_server);
    pump(c3, cc3, s3, sc, to_server, capp, sapp);
    guard tls::failed(c3) && c3.alert == tls::ALERT_BAD_CERTIFICATE else { print("alpn_sni: a wrong name was taken, alert ", c3.alert); exit(1); }
    print("asking for other.example.org: the certificate is refused");
}

fn main() {
    run();
}
