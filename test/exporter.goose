// The exporter of a connection (tls::export_keys): for TLS 1.3 and 1.2, a
// client and a server that ran a handshake in memory export the same bytes
// for the same label and context, and different ones for another label,
// context or none; nothing before the handshake is done or after close.
// EAP-TLS's labels stand in for any: RFC 5216's "client EAP encryption"
// (TLS 1.2, no context) and RFC 9190's EXPORTER_EAP_TLS_Key_Material with
// the type byte as context.
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

fn field(tag: const u8[:], kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 || w[0] != tag { continue; }
        if tag == "root" { return unhex(w[idx - 1]); }
        if w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;

fn run(version: u16, kind: const u8[:]) {
    let name = if version == tls::VERSION_TLS13 { "TLS 1.3" } else { "TLS 1.2" };
    var sc, okk = tls::server_config(field("server", kind, 2), field("server", kind, 3));
    sc.now = NOW;
    sc.max_version = version;
    var cc = tls::client_config("example.com", field("root", "", 2));
    cc.now = NOW;
    cc.max_version = version;
    var c = tls::client(cc);
    var s = tls::server(sc);
    check(str(name, ": nothing before the handshake"), tls::export_keys(c, "EXPORTER-x", "", false, 32).len == 0);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    for round in 20 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        let rs = tls::feed(s, sc, to_server, to_client, sapp);
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::feed(c, cc, to_client, to_server, capp);
    }
    check(str(name, ": connected"), okk && tls::connected(c) && tls::connected(s) && tls::version(c) == version);

    let a = tls::export_keys(c, "client EAP encryption", "", false, 128);
    let b = tls::export_keys(s, "client EAP encryption", "", false, 128);
    check(str(name, ": both ends export the same"), a.len == 128 && a == b);
    let ctx: u8[1] = [13];
    let a2 = tls::export_keys(c, "EXPORTER_EAP_TLS_Key_Material", ctx, true, 128);
    let b2 = tls::export_keys(s, "EXPORTER_EAP_TLS_Key_Material", ctx, true, 128);
    check(str(name, ": with a context, the same"), a2.len == 128 && a2 == b2);
    check(str(name, ": another label, other bytes"), a2 != a);
    let ctx2: u8[1] = [25];
    let a3 = tls::export_keys(c, "EXPORTER_EAP_TLS_Key_Material", ctx2, true, 128);
    check(str(name, ": another context, other bytes"), a3 != a2);
    let a4 = tls::export_keys(c, "EXPORTER_EAP_TLS_Key_Material", "", true, 128);
    let a5 = tls::export_keys(c, "EXPORTER_EAP_TLS_Key_Material", "", false, 128);
    if version == tls::VERSION_TLS12 {
        check(str(name, ": an empty context is not none"), a4 != a5);
    } else {
        check(str(name, ": an absent context is an empty one"), a4 == a5);
    }
    let short = tls::export_keys(c, "client EAP encryption", "", false, 64);
    // TLS 1.2's PRF streams; TLS 1.3's HKDF-Expand-Label binds the length.
    if version == tls::VERSION_TLS12 {
        check(str(name, ": a shorter export is a prefix"), short[..] == a[..64]);
    } else {
        check(str(name, ": a shorter export is not a prefix"), short.len == 64 && short[..] != a[..64]);
    }

    var out: u8[>..] = [];
    tls::close(c, out);
    check(str(name, ": nothing after close"), tls::export_keys(c, "client EAP encryption", "", false, 128).len == 0);
}

fn main() {
    run(tls::VERSION_TLS13, "p256");
    run(tls::VERSION_TLS12, "p256");
    run(tls::VERSION_TLS12, "rsa");
    print("exporter: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
