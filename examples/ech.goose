// ech: Encrypted Client Hello. The server makes an ECH key and publishes
// its ECHConfigList (in DNS, say); a client with that list hides the real
// server name inside an outer ClientHello that names only the public
// name. A client with a stale config is not accepted: it fails with
// ech_required and gets the server's retry configs, which work.
//
//   goose examples/ech.goose

import std;
import os;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.handshake;
import tls.ech;
import x509.create;
import x509.keys;

// A root, and a leaf for the hidden name and the public name: when ECH
// is not accepted the client checks the certificate against the public one.
fn make_pki() -> u8[>..], u8[>..], u8[>..] {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_ED25519);
    var rt, ok1 = x509::template("CN=Example Root CA", now - 3600, now + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, e1 = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    let key = x509::generate_key(x509::KEY_ED25519);
    var lt, ok2 = x509::template("CN=secret.example.com", now - 3600, now + 86400);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt.san, "secret.example.com");
    x509::add_dns(lt.san, "public.example.com");
    let leaf, e2 = x509::create_certificate(lt, x509::marshal_public_key(key), root, root_key);
    guard ok1 && ok2 && e1 == x509::OK && e2 == x509::OK else { print("ech: cannot make the certificates"); exit(1); }
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

// A connection offering ECH under `list`: whether it connected, whether
// ECH was accepted, the name the server saw, and any retry configs.
fn connect(root: const u8[:], list: const u8[:], sc: const tls::ServerConfig&) -> bool, bool, u8[>..], u8[>..] {
    var cc = tls::client_config("secret.example.com", root);
    cc.ech_config_list.append(list);
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp:      u8[>..] = [];
    var sapp:      u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var sni: u8[>..] = [];
    sni.append(s.sni);
    return tls::connected(c) && tls::connected(s), tls::ech_accepted(c) && tls::ech_accepted(s), sni,
           tls::ech_retry_configs(c);
}

fn run() {
    let root, chain, key = make_pki();
    var sc, ok = tls::server_config(chain, key);
    guard ok else { print("ech: bad server key"); exit(1); }

    // The server's ECH key (config id 1, X25519), sent as a retry config too.
    let config, sk = tls::generate_ech_key(1, bignum::HPKE_DHKEM_X25519, "public.example.com");
    guard tls::add_ech_key(sc, config, sk, true) else { print("ech: bad ECH key"); exit(1); }
    let published = tls::ech_config_list(config);
    print("ECHConfigList: ", published.len, " bytes, public name public.example.com");

    let ok1, accepted, sni, retry = connect(root, published, sc);
    guard ok1 && accepted && sni == "secret.example.com" else { print("ech: not accepted"); exit(1); }
    print("accepted: the server saw ", sni, ", the network only public.example.com");

    // A config for a key the server no longer has.
    let old_config, old_sk = tls::generate_ech_key(2, bignum::HPKE_DHKEM_X25519, "public.example.com");
    let ok2, accepted2, sni2, retry2 = connect(root, tls::ech_config_list(old_config), sc);
    guard !ok2 && !accepted2 && retry2 == published else { print("ech: a stale config was taken"); exit(1); }
    print("a stale config: ech_required, with ", retry2.len, " bytes of retry configs");

    let ok3, accepted3, sni3, retry3 = connect(root, retry2, sc);
    guard ok3 && accepted3 else { print("ech: the retry configs did not work"); exit(1); }
    print("retried with them: accepted");
}

fn main() {
    run();
}
