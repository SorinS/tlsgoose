// new_curves: TLS with X448, the Brainpool curves and Ed448, in process.
// A brainpoolP384r1 CA issues a server certificate for an Ed448 key and a
// client certificate for a brainpoolP256r1 key. The client asks for X448
// (0x001e) with its first share and gets it; a server that takes only
// brainpoolP512r1tls13 (0x0021, RFC 8734) asks the default client for it
// with a HelloRetryRequest; the server signs CertificateVerify with ed448
// (0x0808) and the client with ecdsa_brainpoolP256r1tls13_sha256
// (0x081a), which the server checks against its client CA. Then TLS 1.2:
// X448 again, the Ed448 certificate signing the ServerKeyExchange, and
// the Brainpool client certificate signing with ecdsa_secp256r1_sha256,
// which in TLS 1.2 names only the hash (RFC 8422).
//
//   goose examples/new_curves.goose

import std;
import os;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.handshake;
import x509.create;
import x509.keys;

fn fail(what: const u8[:]) { print("new_curves: ", what); exit(1); }

// A certificate for `key` from the CA (self-signed when ca is empty, and
// ca_key then unused).
fn issue(subject: const u8[:], key: const x509::PrivateKey&, ca: const u8[:], ca_key: const x509::PrivateKey&,
         eku: u32) -> u8[>..] {
    let now = time_ns() / 1000000000;
    var t, ok = x509::template(subject, now - 3600, now + 86400);
    if ca.len == 0 {
        t.is_ca = true;
        t.key_usage = x509::KU_KEY_CERT_SIGN;
    } else {
        t.key_usage = x509::KU_DIGITAL_SIGNATURE;
        t.ext_key_usage = eku;
        if eku == x509::EKU_SERVER_AUTH { x509::add_dns(t.san, "example.com"); }
    }
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), ca, if ca.len == 0 { key } else { ca_key });
    guard ok && e == x509::OK else { fail("cannot make a certificate"); }
    return der;
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

fn hex_u16(v: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, v, 16, 4, '0');
    return o;
}

// A handshake and a message each way, both sides' certificates checked;
// the group, whether it took a retry, and the client's CertificateVerify
// scheme.
fn connect(label: const u8[:], cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> u16, bool, u16 {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else { print(label, ": alerts ", c.alert, " ", s.alert); exit(1); }
    guard tls::peer_verified(c) && tls::peer_verified(s) else { fail("a certificate was not checked"); }
    let sent = tls::send(c, "hello", to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var to_client: u8[>..] = [];
    let sent2 = tls::send(s, "hi", to_client);
    let r = tls::client_feed(c, cc, to_client, to_server, capp);
    guard sent && sent2 && sapp == "hello" && capp == "hi" else { fail("data lost"); }
    guard c.group == s.group else { fail("the sides disagree on the group"); }
    print(label, ": TLS ", if tls::version(c) == tls::VERSION_TLS13 { "1.3" } else { "1.2" }, ", group 0x",
          hex_u16(c.group), if c.hrr { " after a HelloRetryRequest" } else { "" }, ", client signs with 0x",
          hex_u16(c.cert_scheme));
    return c.group, c.hrr, c.cert_scheme;
}

fn main() {
    let ca_key = x509::generate_key(x509::KEY_EC_BP384);
    let none = x509::empty_key();
    let ca = issue("CN=Example Brainpool CA", ca_key, "", none, 0);
    let server_key = x509::generate_key(x509::KEY_ED448);
    let server_cert = issue("CN=example.com", server_key, ca, ca_key, x509::EKU_SERVER_AUTH);
    let client_key = x509::generate_key(x509::KEY_EC_BP256);
    let client_cert = issue("CN=Example Client", client_key, ca, ca_key, x509::EKU_CLIENT_AUTH);

    var sc, ok = tls::server_config(server_cert, x509::marshal_pkcs8(server_key));
    guard ok else { fail("bad server key"); }
    sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    guard x509::pool_add(sc.client_cas, ca) else { fail("bad client CA"); }
    var cc = tls::client_config("example.com", ca);
    guard tls::set_client_certificate(cc, client_cert, x509::marshal_pkcs8(client_key)) else { fail("bad client key"); }

    // X448 first: the client's share is for it, and the server's defaults
    // take it.
    var cx = copy(cc);
    cx.groups.clear();
    cx.groups.push(tls::GROUP_X448);
    cx.groups.push(tls::GROUP_X25519);
    let g1, hrr1, s1 = connect("x448 share   ", cx, sc);
    guard g1 == tls::GROUP_X448 && !hrr1 && s1 == x509::ECDSA_BRAINPOOLP256R1TLS13_SHA256 else { fail("expected X448"); }

    // The client's defaults name the new groups without a share; a server
    // that takes only brainpoolP512r1tls13 asks for it.
    var sb = copy(sc);
    sb.groups.clear();
    sb.groups.push(tls::GROUP_BRAINPOOLP512R1TLS13);
    let g2, hrr2, s2 = connect("brainpool    ", cc, sb);
    guard g2 == tls::GROUP_BRAINPOOLP512R1TLS13 && hrr2 else { fail("expected a retry to brainpoolP512r1tls13"); }

    // TLS 1.2: X448 (the client's only group, as the server picks by its
    // own order), Ed448 signing the ServerKeyExchange, the Brainpool client
    // key signing with the generic ECDSA scheme.
    var c12 = copy(cc);
    c12.max_version = tls::VERSION_TLS12;
    c12.groups.clear();
    c12.groups.push(tls::GROUP_X448);
    let g3, hrr3, s3 = connect("tls 1.2      ", c12, sc);
    guard g3 == tls::GROUP_X448 && s3 == x509::ECDSA_SECP256R1_SHA256 else { fail("expected X448 in TLS 1.2"); }
    print("new_curves: ok");
}
