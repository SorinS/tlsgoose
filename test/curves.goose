// X448 and the Brainpool curves, Ed448 and Brainpool certificates, between
// this package's client and server, in memory:
// - the groups x448 (0x001e, both versions), brainpoolP256r1tls13,
//   P384r1tls13 and P512r1tls13 (0x001f-0x0021, TLS 1.3, RFC 8734) and
//   brainpoolP256r1, P384r1, P512r1 (26-28, TLS 1.2, RFC 7027), each
//   alone, by HelloRetryRequest, and the TLS 1.2 code points refused in
//   TLS 1.3 (and the other way round);
// - the defaults: no share for them, named last in supported_groups, and
//   taken by a server from a client that offers only them;
// - Ed448 (0x0808) and Brainpool server certificates, under RFC 8734's
//   schemes in TLS 1.3 and the generic ECDSA ones in TLS 1.2, and the
//   schemes' rules: each bound to its curve, refused when not offered;
// - Ed448 and Brainpool client certificates (Ed448's not in TLS 1.2,
//   whose CertificateVerify this package signs over hashes).
// The certificates are in vectors/hs_certs.txt (scripts/gen_handshake.py).
import std;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.handshake;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// Field `idx` of the line `tag kind ...` (root and clientca lines have no
// kind).
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

fn server_cfg(kind: const u8[:]) -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("server", kind, 2), field("server", kind, 3));
    check(str("load key ", kind), ok);
    sc.now = NOW;
    return sc;
}

fn client_cfg() -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    return cc;
}

fn one_group(groups: u16[..16]&, g: u16) {
    groups.clear();
    groups.push(g);
}

// What a connection came to: both sides connected with data both ways, the
// version, both sides' group, whether there was a retry, the alerts, the
// client's CertificateVerify scheme and whether the server checked the
// client's certificate.
struct Outcome { ok: bool, version: u16, cgroup: u16, sgroup: u16, hrr: bool, client_alert: u8, server_alert: u8,
                 cert_scheme: u16, verified: bool, peer: i64 }

fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&) -> Outcome {
    var c = tls::client(cc);
    var s = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    pump(c, cc, s, sc, to_server, capp, sapp);
    var ok = tls::connected(c) && tls::connected(s);
    if ok {
        let sent = tls::send(c, "ping", to_server);
        pump(c, cc, s, sc, to_server, capp, sapp);
        var to_client: u8[>..] = [];
        let sent2 = tls::send(s, "pong", to_client);
        let r = tls::client_feed(c, cc, to_client, to_server, capp);
        ok = sent && sent2 && sapp == "ping" && capp == "pong";
    }
    return Outcome { ok: ok, version: tls::version(c), cgroup: c.group, sgroup: s.group, hrr: c.hrr, client_alert: c.alert,
                     server_alert: s.alert, cert_scheme: c.cert_scheme, verified: tls::peer_verified(s),
                     peer: tls::peer_certificates(s).len };
}

// Each group alone on both sides: TLS 1.3's, X448 in TLS 1.2 too, and the
// TLS 1.2 Brainpool code points in TLS 1.2.
fn groups_alone() {
    let g13: u16[4] = [tls::GROUP_X448, tls::GROUP_BRAINPOOLP256R1TLS13, tls::GROUP_BRAINPOOLP384R1TLS13,
                       tls::GROUP_BRAINPOOLP512R1TLS13];
    let kinds = ["ed448", "bp256", "bp384", "bp512"];
    for i in 4 {
        var cc = client_cfg();
        one_group(cc.groups, g13[i]);
        var sc = server_cfg(kinds[i]);
        one_group(sc.groups, g13[i]);
        let o = connect(cc, sc);
        check(str("tls 1.3 group ", g13[i], " with ", kinds[i]), o.ok && o.version == tls::VERSION_TLS13 &&
              o.cgroup == g13[i] && o.sgroup == g13[i] && !o.hrr);
    }
    let g12: u16[4] = [tls::GROUP_X448, tls::GROUP_BRAINPOOLP256R1, tls::GROUP_BRAINPOOLP384R1, tls::GROUP_BRAINPOOLP512R1];
    let kinds12 = ["p256", "bp256", "ed448", "rsa"];
    for i in 4 {
        var cc = client_cfg();
        cc.max_version = tls::VERSION_TLS12;
        one_group(cc.groups, g12[i]);
        var sc = server_cfg(kinds12[i]);
        one_group(sc.groups, g12[i]);
        let o = connect(cc, sc);
        check(str("tls 1.2 group ", g12[i], " with ", kinds12[i]), o.ok && o.version == tls::VERSION_TLS12 &&
              o.cgroup == g12[i] && o.sgroup == g12[i]);
    }
}

// A retry: the client's share is X25519, the server takes only the new
// group.
fn retries() {
    let g13: u16[4] = [tls::GROUP_X448, tls::GROUP_BRAINPOOLP256R1TLS13, tls::GROUP_BRAINPOOLP384R1TLS13,
                       tls::GROUP_BRAINPOOLP512R1TLS13];
    for g in g13 {
        var cc = client_cfg();
        one_group(cc.groups, tls::GROUP_X25519);
        cc.groups.push(g);
        var sc = server_cfg("p256");
        one_group(sc.groups, g);
        let o = connect(cc, sc);
        check(str("hello retry to ", g), o.ok && o.hrr && o.cgroup == g && o.sgroup == g);
    }
    // The client's defaults name them, so a server that wants only one
    // gets it by a retry.
    var sx = server_cfg("rsa");
    one_group(sx.groups, tls::GROUP_BRAINPOOLP384R1TLS13);
    let cx = client_cfg();
    let ox = connect(cx, sx);
    check("defaults: retry to brainpoolP384r1tls13", ox.ok && ox.hrr && ox.cgroup == tls::GROUP_BRAINPOOLP384R1TLS13);
}

// The defaults: no share for the new groups, which come last in
// supported_groups; the TLS 1.2 Brainpool code points not at all. The
// server's defaults take them from a client that has only them.
fn defaults() {
    let cc = client_cfg();
    var c = tls::client(cc);
    var out: u8[>..] = [];
    tls::client_start(c, cc, out);
    let m = out[5..];
    let h, ok = tls::parse_hello(m);
    check("hello parses", ok);
    let n = cc.groups.len;
    check("defaults end in the new groups", n >= 4 && cc.groups[n - 4] == tls::GROUP_X448 &&
          cc.groups[n - 1] == tls::GROUP_BRAINPOOLP512R1TLS13);
    for g in [tls::GROUP_X448, tls::GROUP_BRAINPOOLP256R1TLS13, tls::GROUP_BRAINPOOLP384R1TLS13,
              tls::GROUP_BRAINPOOLP512R1TLS13] {
        check(str("default names ", g), tls::in_u16_list(m, h.groups, g));
        let k, found = tls::find_share(h, m, g);
        check(str("default has no share for ", g), !found);
    }
    for g in [tls::GROUP_BRAINPOOLP256R1, tls::GROUP_BRAINPOOLP384R1, tls::GROUP_BRAINPOOLP512R1] {
        check(str("default leaves out ", g), !tls::in_u16_list(m, h.groups, g));
    }
    let k0, f0 = tls::find_share(h, m, tls::GROUP_X25519MLKEM768);
    check("default share is the hybrid", f0);
    // A client with only X448 (or a Brainpool group) and the server's
    // defaults.
    for g in [tls::GROUP_X448, tls::GROUP_BRAINPOOLP512R1TLS13] {
        var co = client_cfg();
        one_group(co.groups, g);
        let sp = server_cfg("p256");
        let o = connect(co, sp);
        check(str("default server takes ", g), o.ok && o.sgroup == g && !o.hrr);
    }
    // TLS 1.2 by default: X448 taken, the TLS 1.2 Brainpool ones only if
    // added.
    var c12 = client_cfg();
    c12.max_version = tls::VERSION_TLS12;
    one_group(c12.groups, tls::GROUP_X448);
    let s384 = server_cfg("p384");
    let o12 = connect(c12, s384);
    check("default server takes x448 in tls 1.2", o12.ok && o12.sgroup == tls::GROUP_X448);
    one_group(c12.groups, tls::GROUP_BRAINPOOLP256R1);
    let ob = connect(c12, s384);
    check("default server lacks brainpoolP256r1 in tls 1.2", !ob.ok && ob.server_alert == tls::ALERT_HANDSHAKE_FAILURE);
    var s12 = server_cfg("p384");
    s12.groups.push(tls::GROUP_BRAINPOOLP256R1);
    let ob2 = connect(c12, s12);
    check("server with brainpoolP256r1 added", ob2.ok && ob2.sgroup == tls::GROUP_BRAINPOOLP256R1);
}

// Each version's code points stay in it: TLS 1.3 never takes 26-28, TLS
// 1.2 never 0x001f-0x0021; a client offering only TLS 1.3 names no TLS
// 1.2 Brainpool group, and one offering only TLS 1.2 no TLS 1.3 one.
fn version_code_points() {
    var cc = client_cfg();
    one_group(cc.groups, tls::GROUP_X25519);
    cc.groups.push(tls::GROUP_BRAINPOOLP256R1);
    var sc = server_cfg("bp256");
    one_group(sc.groups, tls::GROUP_BRAINPOOLP256R1);
    let o = connect(cc, sc);
    check("tls 1.3 refuses brainpoolP256r1 (26)", !o.ok && o.server_alert == tls::ALERT_HANDSHAKE_FAILURE);
    sc.max_version = tls::VERSION_TLS12;
    let o2 = connect(cc, sc);
    check("tls 1.2 takes it", o2.ok && o2.version == tls::VERSION_TLS12 && o2.sgroup == tls::GROUP_BRAINPOOLP256R1);
    var c12 = client_cfg();
    c12.max_version = tls::VERSION_TLS12;
    one_group(c12.groups, tls::GROUP_BRAINPOOLP256R1TLS13);
    c12.groups.push(tls::GROUP_SECP256R1);
    var s12 = server_cfg("p256");
    one_group(s12.groups, tls::GROUP_BRAINPOOLP256R1TLS13);
    s12.groups.push(tls::GROUP_SECP256R1);
    let o3 = connect(c12, s12);
    check("tls 1.2 skips brainpoolP256r1tls13", o3.ok && o3.sgroup == tls::GROUP_SECP256R1);
    // What each hello names.
    var c13 = client_cfg();
    c13.min_version = tls::VERSION_TLS13;
    one_group(c13.groups, tls::GROUP_BRAINPOOLP256R1);
    c13.groups.push(tls::GROUP_BRAINPOOLP256R1TLS13);
    var c = tls::client(c13);
    var out: u8[>..] = [];
    tls::client_start(c, c13, out);
    let h, ok = tls::parse_hello(out[5..]);
    check("tls 1.3 hello: share for the tls 1.3 group, not the first",
          ok && !tls::in_u16_list(out[5..], h.groups, tls::GROUP_BRAINPOOLP256R1) &&
          tls::in_u16_list(out[5..], h.groups, tls::GROUP_BRAINPOOLP256R1TLS13) && c.group == tls::GROUP_BRAINPOOLP256R1TLS13);
    var c2 = tls::client(c12);
    var out2: u8[>..] = [];
    tls::client_start(c2, c12, out2);
    let h2, ok2 = tls::parse_hello(out2[5..]);
    check("tls 1.2 hello leaves out brainpoolP256r1tls13",
          ok2 && !tls::in_u16_list(out2[5..], h2.groups, tls::GROUP_BRAINPOOLP256R1TLS13) &&
          tls::in_u16_list(out2[5..], h2.groups, tls::GROUP_SECP256R1));
    // A client with no TLS 1.3 group fails before it sends anything.
    var cn = client_cfg();
    cn.min_version = tls::VERSION_TLS13;
    one_group(cn.groups, tls::GROUP_BRAINPOOLP384R1);
    var cnc = tls::client(cn);
    var none: u8[>..] = [];
    tls::client_start(cnc, cn, none);
    check("no tls 1.3 group", tls::failed(cnc) && none.len == 0);
}

// Ed448 and Brainpool server certificates, both versions and with every
// TLS 1.2 ECDSA suite's hash.
fn server_certificates() {
    let kinds = ["ed448", "bp256", "bp384", "bp512"];
    for kind in kinds {
        let cc = client_cfg();
        let sc = server_cfg(kind);
        let o = connect(cc, sc);
        check(str("tls 1.3 server ", kind), o.ok && o.version == tls::VERSION_TLS13 && o.sgroup == tls::GROUP_X25519MLKEM768);
        var c12 = client_cfg();
        c12.max_version = tls::VERSION_TLS12;
        for sid in [tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256] {
            c12.suites12.clear();
            c12.suites12.push(sid);
            let o12 = connect(c12, sc);
            check(str("tls 1.2 server ", kind, " suite ", sid), o12.ok && o12.version == tls::VERSION_TLS12);
        }
        // Not an RSA suite's key.
        c12.suites12.clear();
        c12.suites12.push(tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        let orsa = connect(c12, sc);
        check(str("tls 1.2 server ", kind, " not for ECDHE_RSA"), !orsa.ok && orsa.server_alert == tls::ALERT_HANDSHAKE_FAILURE);
    }
}

// The signature schemes' rules.
fn scheme_rules() {
    // TLS 1.3: each Brainpool scheme with its curve's key only; the NIST
    // ones not with a Brainpool key; Ed448 with Ed448.
    check("0x081a with bp256", tls::scheme_fits13(x509::KEY_EC_BP256, 0x081a));
    check("0x081a not with p256", !tls::scheme_fits13(x509::KEY_EC_P256, 0x081a));
    check("0x081b not with bp256", !tls::scheme_fits13(x509::KEY_EC_BP256, 0x081b));
    check("0x081c with bp512", tls::scheme_fits13(x509::KEY_EC_BP512, 0x081c));
    check("0x0403 not with bp256 in tls 1.3", !tls::scheme_fits13(x509::KEY_EC_BP256, 0x0403));
    check("0x0808 with ed448", tls::scheme_fits13(x509::KEY_ED448, 0x0808));
    check("0x0807 not with ed448", !tls::scheme_fits13(x509::KEY_ED448, 0x0807));
    check("0x0808 not with ed25519", !tls::scheme_fits13(x509::KEY_ED25519, 0x0808));
    // TLS 1.2: a Brainpool key with the ECDSA codes (any hash), not RFC
    // 8734's; Ed448 with its own; the schemes each version offers.
    check("tls 1.2: bp384 with 0x0403", tls::scheme_fits12(x509::KEY_EC_BP384, 0x0403));
    check("tls 1.2: bp384 not with 0x081b", !tls::scheme_fits12(x509::KEY_EC_BP384, 0x081b));
    check("tls 1.2: ed448", tls::scheme_fits12(x509::KEY_ED448, 0x0808));
    check("tls 1.3 offers 0x081a-0x081c and 0x0808", tls::offered_scheme(tls::SIG_SCHEMES, 0x081a) &&
          tls::offered_scheme(tls::SIG_SCHEMES, 0x081b) && tls::offered_scheme(tls::SIG_SCHEMES, 0x081c) &&
          tls::offered_scheme(tls::SIG_SCHEMES, 0x0808));
    check("tls 1.2 offers 0x0808, not 0x081a", tls::offered_scheme(tls::SIG_SCHEMES12, 0x0808) &&
          !tls::offered_scheme(tls::SIG_SCHEMES12, 0x081a));
    check("tls 1.2 CertificateVerify: no ed448", !tls::offered_scheme(tls::CV_SCHEMES12, 0x0808));
    // The scheme picked for a key from a peer's list.
    let peer: u16[4] = [0x0403, 0x081b, 0x0808, 0x0807];
    var k = x509::empty_key();
    k.kind = x509::KEY_EC_BP384;
    check("pick 0x081b for bp384", tls::pick_scheme(k, peer) == 0x081b);
    k.kind = x509::KEY_EC_BP256;
    check("pick none for bp256", tls::pick_scheme(k, peer) == 0);
    k.kind = x509::KEY_ED448;
    check("pick 0x0808 for ed448", tls::pick_scheme(k, peer) == 0x0808);
    check("tls 1.2: pick 0x0403 for bp256", tls::pick_scheme12(x509::KEY_EC_BP256, peer, tls::SIG_SCHEMES12) == 0x0403);
}

// A ClientHello's signature_algorithms without RFC 8734's schemes (or
// Ed448's): a server whose key needs one has no scheme to sign with.
fn scheme_not_offered() {
    let kinds = ["bp256", "ed448"];
    for kind in kinds {
        let cc = client_cfg();
        var c = tls::client(cc);
        var out: u8[>..] = [];
        tls::client_start(c, cc, out);
        // The schemes are 0x081a, 0x081b, 0x081c, 0x0807, 0x0808 in a row:
        // made unknown ones.
        var at = -1;
        let want: u8[10] = [0x08, 0x1a, 0x08, 0x1b, 0x08, 0x1c, 0x08, 0x07, 0x08, 0x08];
        for i in out.len - 10 { if at < 0 && out[i..i + 10] == want[..] { at = i; } }
        check("schemes found", at > 0);
        if at < 0 { continue; }
        for i in 10 { if i != 6 && i != 7 { out[at + i] = 0xfe; } }
        let sc = server_cfg(kind);
        var s = tls::server(sc);
        var back: u8[>..] = [];
        var app: u8[>..] = [];
        let r = tls::server_feed(s, sc, out, back, app);
        check(str("no scheme for ", kind), tls::failed(s) && s.alert == tls::ALERT_HANDSHAKE_FAILURE);
        // The same hello is fine for an Ed25519 server.
        let se = server_cfg("ed25519");
        var s2 = tls::server(se);
        back.clear();
        let r2 = tls::server_feed(s2, se, out, back, app);
        check("ed25519 server takes it", !tls::failed(s2) && back.len > 0);
    }
}

// Client certificates: Ed448 and Brainpool, checked by the server, in TLS
// 1.3; Brainpool in TLS 1.2 (ECDSA with SHA-256); Ed448 not in TLS 1.2.
fn client_certificates() {
    let kinds = ["ed448", "bp256"];
    for kind in kinds {
        var cc = client_cfg();
        check(str("client key ", kind), tls::set_client_certificate(cc, field("client", kind, 2), field("client", kind, 3)));
        var sc = server_cfg("bp384");
        sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
        check("client CA", x509::pool_add(sc.client_cas, field("clientca", "", 2)));
        let o = connect(cc, sc);
        let want: u16 = if kind == "ed448" { 0x0808 } else { 0x081a };
        check(str("tls 1.3 client certificate ", kind), o.ok && o.verified && o.cert_scheme == want &&
              o.peer == field("client", kind, 2).len);
        cc.max_version = tls::VERSION_TLS12;
        let o12 = connect(cc, sc);
        if kind == "ed448" {
            check("tls 1.2: no ed448 client certificate", !o12.ok && o12.cert_scheme == 0 &&
                  o12.server_alert == tls::ALERT_BAD_CERTIFICATE);
        } else {
            check("tls 1.2 client certificate bp256", o12.ok && o12.verified && o12.version == tls::VERSION_TLS12 &&
                  o12.cert_scheme == 0x0403);
        }
    }
}

fn main() {
    groups_alone();
    retries();
    defaults();
    version_code_points();
    server_certificates();
    scheme_rules();
    scheme_not_offered();
    client_certificates();
    print("curves: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
