// handshake: a TLS 1.3 client and server in one process. A root CA and a
// server certificate for example.com are made with x509, the two sides
// shake hands by passing bytes back and forth (no sockets: the package
// does no I/O), then exchange data, update their keys and close.
//
//   goose examples/handshake.goose

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

// A root CA and a leaf for example.com under it, on Ed25519 keys: the
// root's DER, and the leaf's chain (DER) and PKCS #8 key for the server.
fn make_pki() -> u8[>..], u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_ED25519);
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
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("handshake: cannot make the certificates"); exit(1); }
    return root, leaf, x509::marshal_pkcs8(key);
}

// Hands each side's output to the other until neither has more to say.
// capp and sapp collect the application data each side receives.
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
    let sc, ok = tls::server_config(chain, key);
    guard ok else { print("handshake: bad server key"); exit(1); }
    let cc = tls::client_config("example.com", root);   // trust our root only

    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);                 // the ClientHello
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else {
        print("handshake: failed, client alert ", c.alert, ", server alert ", s.alert);
        exit(1);
    }
    guard tls::version(c) == tls::VERSION_TLS13 && tls::peer_verified(c) else { print("handshake: not TLS 1.3, or not verified"); exit(1); }
    print("connected: TLS 1.3, suite 0x", hex_u16(c.suite.id), ", group 0x", hex_u16(c.group));

    // A request one way, a reply the other.
    guard tls::send(c, "GET / HTTP/1.0\r\n\r\n", to_server) else { print("handshake: send failed"); exit(1); }
    pump(c, cc, s, sc, to_server, capp, sapp);
    var to_client: u8[>..] = [];
    guard tls::send(s, "HTTP/1.0 200 OK\r\n\r\nhello", to_client) else { print("handshake: send failed"); exit(1); }
    let r = tls::client_feed(c, cc, to_client, to_server, capp);
    guard sapp == "GET / HTTP/1.0\r\n\r\n" && capp == "HTTP/1.0 200 OK\r\n\r\nhello" else { print("handshake: data lost"); exit(1); }
    print("server got ", sapp.len, " bytes, client got ", capp.len);

    // New traffic keys, the server asked to update its own too.
    guard tls::key_update(c, true, to_server) else { print("handshake: key update failed"); exit(1); }
    tls::send(c, "after the update", to_server);
    sapp.clear();
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard sapp == "after the update" && c.key_updates == 1 && s.key_updates == 1 else { print("handshake: key update lost"); exit(1); }
    print("keys updated both ways");

    // close_notify.
    tls::close(c, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::closed(s) && s.alert == tls::ALERT_CLOSE_NOTIFY else { print("handshake: no close_notify"); exit(1); }
    print("closed");
}

fn hex_u16(v: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, v, 16, 4, '0');
    return o;
}

fn main() {
    run();   // the connections live in run's frame, not main's
}
