// Encrypted Client Hello (tls.ech) between this package's client and
// server, in memory. The client asks for "localhost" inside an outer
// ClientHello for the public name "example.com" (the test certificates
// have both names).
// - Accepted: with each HPKE KEM, after a HelloRetryRequest, with ALPN,
//   with resumption, with a client certificate; the server sees the inner
//   name.
// - Not accepted: a server without keys, or with another key (whose retry
//   configs then work), or a changed payload. The client finishes the
//   handshake with the public name and fails with ech_required, a
//   certificate request answered with none. A certificate not valid for
//   the public name fails sooner.
// - Configs: picking the first usable one, and refusing lists without one;
//   decoding of EncodedClientHelloInner.
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import tls.session;
import tls.ech;

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

fn server_cfg() -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("server", "p256", 2), field("server", "p256", 3));
    check("load key", ok);
    sc.now = NOW;
    return sc;
}

fn client_cfg(list: const u8[:]) -> tls::ClientConfig {
    var cc = tls::client_config("localhost", field("root", "", 2));
    cc.now = NOW;
    cc.ech_config_list.append(list);
    return cc;
}

struct Outcome {
    ok: bool, client_accepted: bool, server_accepted: bool, resumed: bool, client_alert: u8, server_alert: u8,
    client_state: i64, sni: u8[..255], hrr: bool, retry: u8[..8192], session: tls::Session, has_session: bool,
    peer: i64,
}

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
    let sess, has = tls::session(c);
    var o = Outcome { ok: ok, client_accepted: tls::ech_accepted(c), server_accepted: tls::ech_accepted(s),
                      resumed: tls::resumed(c) && tls::resumed(s), client_alert: c.alert, server_alert: s.alert,
                      client_state: c.state, sni: [], hrr: c.hrr, retry: [], session: sess, has_session: has,
                      peer: tls::peer_certificates(s).len };
    o.sni.append(s.sni);
    o.retry.append(tls::ech_retry_configs(c));
    return o;
}

fn accepted(o: const Outcome&) -> bool { o.ok && o.client_accepted && o.server_accepted && o.sni == "localhost" }

// A client and server with a fresh key of `kem`; whether ECH was accepted.
fn with_kem(kem: i64) -> bool {
    let config, sk = tls::generate_ech_key(3, kem, "example.com");
    var sc = server_cfg();
    let added = tls::add_ech_key(sc, config, sk, true);
    let cc = client_cfg(tls::ech_config_list(config));
    let o = connect(cc, sc);
    return added && accepted(o);
}

fn main() {
    let config, sk = tls::generate_ech_key(7, bignum::HPKE_DHKEM_X25519, "example.com", 32);
    let list = tls::ech_config_list(config);
    var sc = server_cfg();
    check("add key", tls::add_ech_key(sc, config, sk, true));
    check("junk key refused", !tls::add_ech_key(sc, "junk", sk, true));
    let cc = client_cfg(list);

    // Accepted.
    let o1 = connect(cc, sc);
    check("accepted", accepted(o1));
    check("accepted: X25519", with_kem(bignum::HPKE_DHKEM_X25519));
    check("accepted: P-256", with_kem(bignum::HPKE_DHKEM_P256));
    check("accepted: P-384", with_kem(bignum::HPKE_DHKEM_P384));
    check("accepted: P-521", with_kem(bignum::HPKE_DHKEM_P521));
    check("accepted: ML-KEM-768", with_kem(bignum::HPKE_MLKEM768));
    check("accepted: ML-KEM-1024", with_kem(bignum::HPKE_MLKEM1024));
    check("accepted: MLKEM768-X25519", with_kem(bignum::HPKE_MLKEM768_X25519));
    check("accepted: MLKEM768-P256", with_kem(bignum::HPKE_MLKEM768_P256));
    check("accepted: MLKEM1024-P384", with_kem(bignum::HPKE_MLKEM1024_P384));
    // After a HelloRetryRequest: the client's first share is for P-384,
    // which this server does not take.
    var cc_hrr = client_cfg(list);
    cc_hrr.groups.clear();
    cc_hrr.groups.push(tls::GROUP_SECP384R1);
    cc_hrr.groups.push(tls::GROUP_X25519);
    var sc_hrr = server_cfg();
    check("add key", tls::add_ech_key(sc_hrr, config, sk, true));
    sc_hrr.groups.clear();
    sc_hrr.groups.push(tls::GROUP_X25519);
    let o2 = connect(cc_hrr, sc_hrr);
    check("accepted after HelloRetryRequest", accepted(o2) && o2.hrr);
    // ALPN, inside.
    var cc_alpn = client_cfg(list);
    tls::add_alpn(cc_alpn.alpn, "h2");
    var sc_alpn = server_cfg();
    check("add key", tls::add_ech_key(sc_alpn, config, sk, true));
    tls::add_alpn(sc_alpn.alpn, "h2");
    let o3 = connect(cc_alpn, sc_alpn);
    check("accepted with ALPN", accepted(o3));
    // Resumption: the session of an ECH connection, offered inside ECH.
    check("ticket", o1.has_session && o1.session.server_name == "localhost");
    var cc_res = client_cfg(list);
    cc_res.session = o1.session;
    let o4 = connect(cc_res, sc);
    check("accepted and resumed", accepted(o4) && o4.resumed);
    var cc_res_hrr = client_cfg(list);
    cc_res_hrr.session = o1.session;
    cc_res_hrr.groups.clear();
    cc_res_hrr.groups.push(tls::GROUP_SECP384R1);
    cc_res_hrr.groups.push(tls::GROUP_X25519);
    var sc_res_hrr = server_cfg();
    check("add key", tls::add_ech_key(sc_res_hrr, config, sk, true));
    sc_res_hrr.ticket_key = sc.ticket_key;
    sc_res_hrr.groups.clear();
    sc_res_hrr.groups.push(tls::GROUP_X25519);
    let o5 = connect(cc_res_hrr, sc_res_hrr);
    check("accepted and resumed after HelloRetryRequest", accepted(o5) && o5.resumed && o5.hrr);
    // A client certificate, inside.
    var cc_cert = client_cfg(list);
    check("client key", tls::set_client_certificate(cc_cert, field("client", "p256", 2), field("client", "p256", 3)));
    var sc_cert = server_cfg();
    check("add key", tls::add_ech_key(sc_cert, config, sk, true));
    sc_cert.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    check("client CA", x509::pool_add(sc_cert.client_cas, field("clientca", "", 2)));
    let o6 = connect(cc_cert, sc_cert);
    check("accepted with a client certificate", accepted(o6) && o6.peer > 0);

    // Not accepted: the handshake with the public name completes, then the
    // client fails with ech_required.
    let plain = server_cfg();
    let r1 = connect(cc, plain);
    check("no keys: ech_required", !r1.ok && !r1.client_accepted && !r1.server_accepted &&
          r1.client_alert == tls::ALERT_ECH_REQUIRED && r1.server_alert == tls::ALERT_ECH_REQUIRED &&
          r1.sni == "example.com" && r1.retry.len == 0);
    let config2, sk2 = tls::generate_ech_key(9, bignum::HPKE_DHKEM_X25519, "example.com");
    var other = server_cfg();
    check("add key", tls::add_ech_key(other, config2, sk2, true));
    let r2 = connect(cc, other);
    check("other key: retry configs", !r2.ok && r2.client_alert == tls::ALERT_ECH_REQUIRED &&
          r2.retry == tls::ech_config_list(config2));
    let cc_retry = client_cfg(r2.retry);
    let r3 = connect(cc_retry, other);
    check("retry configs accepted", accepted(r3));
    var other_quiet = server_cfg();
    check("add key", tls::add_ech_key(other_quiet, config2, sk2, false));
    let r4 = connect(cc, other_quiet);
    check("no retry configs", !r4.ok && r4.client_alert == tls::ALERT_ECH_REQUIRED && r4.retry.len == 0);
    // A certificate request when not accepted is answered with none.
    var cc_cert2 = client_cfg(list);
    check("client key", tls::set_client_certificate(cc_cert2, field("client", "p256", 2), field("client", "p256", 3)));
    var plain_req = server_cfg();
    plain_req.client_auth = tls::REQUEST_CLIENT_CERT;
    let r5 = connect(cc_cert2, plain_req);
    check("not accepted: no client certificate", !r5.ok && r5.client_alert == tls::ALERT_ECH_REQUIRED && r5.peer == 0);
    // A public name the certificate is not for.
    let config3, sk3 = tls::generate_ech_key(1, bignum::HPKE_DHKEM_X25519, "other.org");
    let cc_other_name = client_cfg(tls::ech_config_list(config3));
    let r6 = connect(cc_other_name, plain);
    check("public name not in the certificate", !r6.ok && r6.client_alert == tls::ALERT_BAD_CERTIFICATE);
    // A changed payload: the server cannot open it, and goes on with the
    // outer ClientHello.
    var c7 = tls::client(cc);
    var s7 = tls::server(sc);
    var hello: u8[>..] = [];
    tls::client_start(c7, cc, hello);
    hello[hello.len - 20] ^= 1;
    var reply: u8[>..] = [];
    var app: u8[>..] = [];
    let rr = tls::server_feed(s7, sc, hello, reply, app);
    check("changed payload: outer ClientHello", rr == 0 && !tls::ech_accepted(s7) && s7.sni == "example.com");

    // Configs.
    let junk: u8[6] = [0, 5, 'j', 'u', 'n', 'k'];
    let ecj, okj = tls::pick_ech_config(junk);
    check("malformed list", !okj);
    let short: u8[4] = [0, 2, 'a', 'b'];
    let cc8 = client_cfg(short);
    var c8 = tls::client(cc8);
    var out8: u8[>..] = [];
    tls::client_start(c8, cc8, out8);
    check("no usable config: no ClientHello", tls::failed(c8) && out8.len == 0);
    // An unknown version, a mandatory extension and a one-label name are
    // skipped for the config after them.
    var configs: u8[>..] = [];
    let unknown: u8[6] = [0xfe, 0x0e, 0, 2, 'a', 'b'];
    configs.append(unknown);
    let bad_name = tls::ech_config(2, bignum::HPKE_DHKEM_X25519, sk[..], "localhost");
    configs.append(bad_name);
    var mandatory = tls::ech_config(4, bignum::HPKE_DHKEM_X25519, sk[..], "example.com");
    mandatory[mandatory.len - 2] = 0;
    mandatory[mandatory.len - 1] = 4;
    let ext: u8[4] = [0x80, 1, 0, 0];
    mandatory.append(ext);
    mandatory[3] = (mandatory[3] as i64 + 4) as! u8;
    configs.append(mandatory);
    configs.append(config);
    let ec, okp = tls::pick_ech_config(tls::ech_config_list(configs));
    check("first usable config", okp && ec.config_id == 7 && ec.public_name == "example.com" && ec.max_name_len == 32 &&
          ec.kdf == bignum::HPKE_HKDF_SHA256 && ec.aead == bignum::HPKE_AES128GCM);
    let ec2, okp2 = tls::pick_ech_config(tls::ech_config_list(bad_name));
    check("only an unusable config", !okp2);
    check("public names", tls::ech_valid_name("a.example") && !tls::ech_valid_name("localhost") &&
          !tls::ech_valid_name("-a.example") && !tls::ech_valid_name("a..example") && !tls::ech_valid_name("a_b.example"));
    check("padding", tls::ech_padding(100, 9, 32) == 28 && tls::ech_padding(100, 0, 0) == 28 &&
          (tls::ech_padding(77, 5, 40) + 77) % 32 == 0);

    print("ech: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
