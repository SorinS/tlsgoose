// Keys held elsewhere: a server and a client whose configuration has only
// the certificate (x509::external_key of its leaf), their signatures made
// by a signer passed to feed, as a TPM's or a PKCS#11 token's would be.
// The signer here holds the private key the configuration never sees and
// counts what it is asked: for each key type, TLS 1.3 and 1.2, the
// server's and a client's certificate; then a signer that fails, a key held
// elsewhere fed without a signer, and the RSA key exchange left out.
import std;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
import tls.handshake;

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

// Field `idx` of the line `tag kind ...` of vectors/hs_certs.txt (root and
// clientca lines have no kind).
fn field(tag: const u8[:], kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 || w[0] != tag { continue; }
        if tag == "root" || tag == "clientca" { return unhex(w[idx - 1]); }
        if w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;

// What a signer was asked.
struct Asked { calls: i64, alg: i64, h: i64, len: i64, external: bool }

fn no_asked() -> Asked { Asked { calls: 0, alg: 0, h: 0, len: 0, external: false } }

// One handshake between a server of `kind` whose key is held elsewhere and
// a client (with a client certificate held elsewhere too when client_kind
// is given), up to max_version; fail_server makes the server's signer
// return nothing. Whether both sides connected and data crossed, and what
// each signer was asked.
fn run(kind: const u8[:], client_kind: const u8[:], max_version: u16, fail_server: bool) -> bool, Asked, Asked, u8 {
    var sc, oks = tls::server_config(field("server", kind, 2));
    check(str(kind, ": server_config from the chain alone"), oks && x509::is_external(sc.key));
    sc.now = NOW;
    sc.max_version = max_version;
    let server_real, okr = x509::parse_private_key(field("server", kind, 3));
    check("the real key", okr);
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    cc.max_version = max_version;
    var client_real = x509::empty_key();
    if client_kind.len > 0 {
        sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
        check("client CA", x509::pool_add(sc.client_cas, field("clientca", "", 2)));
        check(str(client_kind, ": client certificate from the chain alone"),
              tls::set_client_certificate(cc, field("client", client_kind, 2)) && x509::is_external(cc.cert_key));
        let k, okc = x509::parse_private_key(field("client", client_kind, 3));
        client_real = k;
    }

    var sa = no_asked();
    var ca = no_asked();
    // The signers: what a TPM's or a token's would do with the key it holds.
    fn server_signer(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        sa = Asked { calls: sa.calls + 1, alg: alg, h: h, len: data.len, external: x509::is_external(k) };
        if fail_server { return []; }
        return x509::sign_data(server_real, alg, h, data);
    }
    fn client_signer(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        ca = Asked { calls: ca.calls + 1, alg: alg, h: h, len: data.len, external: x509::is_external(k) };
        return x509::sign_data(client_real, alg, h, data);
    }

    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    for round in 20 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        let rs = tls::server_feed(s, sc, to_server, to_client, sapp, server_signer);
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::client_feed(c, cc, to_client, to_server, capp, client_signer);
    }
    var ok = tls::connected(c) && tls::connected(s);
    if ok {
        var to_client: u8[>..] = [];
        ok = tls::send(s, "pong", to_client) && tls::client_feed(c, cc, to_client, to_server, capp) == 0 && capp == "pong";
    }
    return ok, sa, ca, s.alert;
}

// The digest length of h, for the algorithms that sign one.
fn digest_len(h: i64) -> i64 { h / 8 }

fn main() {
    // TLS 1.3: each key type the server may hold elsewhere. Ed25519, Ed448
    // and ML-DSA sign the message itself, the others a digest of it.
    let kinds13: const u8[:][8] = ["p256", "p384", "p521", "rsa", "ed25519", "ed448", "mldsa44", "bp256"];
    for kind in kinds13 {
        let ok, sa, ca, alert = run(kind, "", tls::VERSION_TLS13, false);
        check(str(kind, " TLS 1.3: connected through the signer"), ok);
        check(str(kind, " TLS 1.3: the signer asked once, for the key held elsewhere"), sa.calls == 1 && sa.external && ca.calls == 0);
        let msg = sa.alg == x509::SIG_ED25519 || sa.alg == x509::SIG_ED448 || sa.alg == x509::SIG_MLDSA;
        check(str(kind, " TLS 1.3: a digest, or the message for the algorithms that sign one"),
              if msg { sa.len > 64 } else { sa.len == digest_len(sa.h) });
        if kind == "rsa" { check("rsa TLS 1.3: RSA-PSS", sa.alg == x509::SIG_RSA_PSS); }
        if kind == "p256" { check("p256 TLS 1.3: ECDSA with SHA-256", sa.alg == x509::SIG_ECDSA && sa.h == 256); }
    }

    // TLS 1.2: ECDHE's ServerKeyExchange is signed through the signer.
    let kinds12: const u8[:][2] = ["p256", "rsa"];
    for kind in kinds12 {
        let ok, sa, ca, alert = run(kind, "", tls::VERSION_TLS12, false);
        check(str(kind, " TLS 1.2: connected through the signer"), ok && sa.calls == 1 && sa.external);
    }

    // Client certificates held elsewhere: TLS 1.3's CertificateVerify and
    // TLS 1.2's, which signs a digest of the handshake.
    let versions: u16[2] = [tls::VERSION_TLS13, tls::VERSION_TLS12];
    for v in versions {
        let ok, sa, ca, alert = run("p256", "p256", v, false);
        check(str("client p256 ", v, ": connected, both signers asked once"), ok && sa.calls == 1 && ca.calls == 1 && ca.external);
    }
    let ok_ed, sa_ed, ca_ed, alert_ed = run("p256", "ed25519", tls::VERSION_TLS13, false);
    check("client ed25519 TLS 1.3: the message signed", ok_ed && ca_ed.calls == 1 && ca_ed.alg == x509::SIG_ED25519);

    // A signer that fails ends the handshake with internal_error, as Go's.
    let okf, saf, caf, alertf = run("p256", "", tls::VERSION_TLS13, true);
    check("a failing signer: no connection, internal_error", !okf && saf.calls == 1 && alertf == tls::ALERT_INTERNAL_ERROR);

    // A key held elsewhere fed without a signer cannot sign: sign_data
    // refuses it.
    var sc, oks = tls::server_config(field("server", "p256", 2));
    sc.now = NOW;
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var app: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    let r = tls::server_feed(s, sc, to_server, to_client, app);
    check("no signer: the handshake fails with internal_error", r < 0 && s.alert == tls::ALERT_INTERNAL_ERROR);

    // The RSA key exchange, which decrypts with the key, is not chosen for
    // a key held elsewhere: an RSA-only TLS 1.2 client gets no suite.
    var sr, okrs = tls::server_config(field("server", "rsa", 2));
    sr.now = NOW;
    sr.max_version = tls::VERSION_TLS12;
    sr.suites12.clear();
    sr.suites12.push(tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    var cr = tls::client_config("example.com", field("root", "", 2));
    cr.now = NOW;
    cr.max_version = tls::VERSION_TLS12;
    cr.suites12.clear();
    cr.suites12.push(tls::TLS_RSA_WITH_AES_128_GCM_SHA256);
    var c2 = tls::client(cr);
    var s2 = tls::server(sr);
    to_server.clear();
    to_client.clear();
    tls::client_start(c2, cr, to_server);
    let r2 = tls::server_feed(s2, sr, to_server, to_client, app) { k, alg, h, data => x509::sign_data(k, alg, h, data) };
    check("RSA key exchange: not chosen for a key held elsewhere", r2 < 0 && s2.alert == tls::ALERT_HANDSHAKE_FAILURE);

    print("signer: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
