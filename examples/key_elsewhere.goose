// key_elsewhere: a TLS server whose private key the TLS code never sees,
// as with a key in a TPM, on a PKCS#11 token or in a remote service. The
// server's configuration holds only its certificate (tls::server_config
// with the chain alone), and every signature the handshake needs is asked
// of a signer passed to feed: here a block that signs with a key kept
// apart, standing in for tpm2::sign_data or p11::sign_data. The handshake
// runs in memory, and the signer says what it was asked.
//
//   goose examples/key_elsewhere.goose

import std;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
import x509.keys;
import x509.create;
import tls.handshake;

fn main() {
    // The key "held elsewhere", and a certificate for it.
    let held = x509::generate_key(x509::KEY_EC_P256);
    var t, okt = x509::template("CN=elsewhere.example.com", time_ns() / 1000000000 - 60, time_ns() / 1000000000 + 86400);
    t.is_ca = true;
    t.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_CERT_SIGN;
    x509::add_dns(t.san, "elsewhere.example.com");
    let cert, e = x509::create_certificate(t, x509::marshal_public_key(held), "", held);
    guard okt && e == x509::OK else { print("key_elsewhere: no certificate"); exit(1); }

    // The server knows the certificate only.
    var sc, oks = tls::server_config(cert);
    print("server key held elsewhere: ", x509::is_external(sc.key));
    var cc = tls::client_config("elsewhere.example.com", cert);

    var asked = 0;
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    for round in 20 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        // The signer: asked for x509's algorithm and hash and given the
        // digest; a TPM's would be { k, alg, h, data => tpm2::sign_data(tpm, key, session, alg, h, data) }.
        let rs = tls::server_feed(s, sc, to_server, to_client, sapp) { k, alg, h, data =>
            asked++;
            print("signer asked: ", if alg == x509::SIG_ECDSA { "ECDSA" } else { "another algorithm" },
                  " with SHA-", h, " over a digest of ", data.len, " bytes");
            x509::sign_data(held, alg, h, data)
        };
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::client_feed(c, cc, to_client, to_server, capp);
    }
    print("connected: ", tls::connected(c) && tls::connected(s), ", TLS 1.", if c.version == tls::VERSION_TLS13 { 3 } else { 2 },
          ", the signer asked ", asked, " time", if asked == 1 { "" } else { "s" });
}
