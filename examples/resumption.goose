// resumption: session tickets. After a full handshake the server sends a
// ticket; the client keeps it as a tls::Session, which can be saved as
// bytes (session_bytes) and read back (parse_session), say across runs.
// The next connection offers it and resumes: no certificate is sent, and
// the server keeps nothing, as the ticket is sealed under its ticket_key.
//
//   goose examples/resumption.goose

import std;
import os;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
import tls.handshake;
import tls.session;
import x509.create;
import x509.keys;

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
    let leaf, e2 = x509::create_certificate(lt, x509::marshal_public_key(key), root, root_key);
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("resumption: cannot make the certificates"); exit(1); }
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

// One connection: whether it resumed, and the session the client holds
// after it (the server's ticket arrives right after the handshake).
fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> bool, tls::Session {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    guard tls::connected(c) && tls::connected(s) else { print("resumption: failed, alerts ", c.alert, " ", s.alert); exit(1); }
    guard tls::resumed(c) == tls::resumed(s) else { print("resumption: the sides disagree"); exit(1); }
    let sess, has = tls::session(c);
    guard has else { print("resumption: no ticket"); exit(1); }
    return tls::resumed(c), sess;
}

fn run() {
    let root, chain, key = make_pki();
    let sc, ok = tls::server_config(chain, key);   // one ticket per handshake, as Go
    guard ok else { print("resumption: bad server key"); exit(1); }
    var cc = tls::client_config("example.com", root);

    let r1, sess = connect(cc, sc);
    guard !r1 else { print("resumption: the first connection cannot resume"); exit(1); }
    print("first connection: full handshake, ticket for ", sess.server_name, ", lifetime ", sess.lifetime, " s");

    // Kept as bytes, read back.
    let saved = tls::session_bytes(sess);
    let back, okp = tls::parse_session(saved);
    guard okp else { print("resumption: the saved session does not parse"); exit(1); }
    print("session saved as ", saved.len, " bytes");

    cc.session = back;
    let r2, sess2 = connect(cc, sc);
    guard r2 else { print("resumption: the second connection did not resume"); exit(1); }
    print("second connection: resumed");

    // A server with another ticket key cannot open the ticket: a full
    // handshake instead, not an error.
    var other = copy(sc);
    other.ticket_key[0] ^= 1;
    cc.session = sess2;
    let r3, sess3 = connect(cc, other);
    guard !r3 else { print("resumption: resumed under another ticket key"); exit(1); }
    print("another ticket key: full handshake");
}

fn main() {
    run();
}
