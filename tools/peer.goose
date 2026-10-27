// A TLS peer driven over stdin and stdout, for scripts/live_interop.py:
// the script relays the bytes between this program and OpenSSL.
//
//   peer client <host> <roots.pem | roots directory | system> [--suite 1301] [--group 001d] [--alpn h2] [--now N]
//               [--cert chain.pem --key key.pem]
//   peer server <chain.pem> <key.pem> [--suite ...] [--group ...] [--alpn ...]
//               [--client-auth 0-4] [--client-cas cas.pem]
//   peer echkey <kem, hex> <public name>   prints "CONFIG <ECHConfig hex>" and "KEY <private key hex>"
//
// --ech <ECHConfigList hex> has the client offer ECH, --ech-key
// <config hex>:<private key hex> gives the server a key (sent as retry).
//
// Commands, one per line: "IN <hex>" (bytes from the network), "SEND
// <hex>" (application data), "KEYUPDATE", "CLOSE", "SESSION" (the
// client's latest session, as tls::session_bytes). After the client's
// start and after each command the peer prints "OUT <hex>" if it has bytes
// to send, "APP <hex>" if it received data, "SESSION <hex|->" when asked,
// then "STATE <state> <alert> <alpn> <group> <resumed> <peer certificate
// bytes> <peer verified> <ECH accepted>" and "END"; "RETRY <hex>" with
// the client's retry configs, if it got any. --session <hex> gives the client a
// session to resume, --ticket-key <hex> the server its ticket key; --cert
// and --key the client a certificate, --client-auth (tls::NO_CLIENT_CERT
// ...) and --client-cas the server what it asks of clients.
import std;
import os;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.handshake;
import tls.session;
import x509.pool;

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_uint(o, x, 16, 2, '0'); }
    return o;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { write_stderr("cannot read file\n"); assert(false); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    return out;
}

fn report(c: const tls::Conn&, out: const u8[:], app: const u8[:]) {
    if out.len > 0 { print("OUT ", hex(out)); }
    if app.len > 0 { print("APP ", hex(app)); }
    if c.ech_retry.len > 0 { print("RETRY ", hex(c.ech_retry)); }
    print("STATE ", c.state, " ", c.alert, " ", if c.alpn.len > 0 { c.alpn[..] } else { "-" }, " ", c.group, " ",
          if tls::resumed(c) { 1 } else { 0 }, " ", c.chain.len, " ", if tls::peer_verified(c) { 1 } else { 0 }, " ",
          if tls::ech_accepted(c) { 1 } else { 0 });
    print("END");
    flush_stdout();
}

fn main() {
    let a = args();
    if a[1] == "echkey" {
        let k = unhex(a[2]);
        let config, sk = tls::generate_ech_key(1, (k[0] as i64) << 8 | k[1], a[3]);
        print("CONFIG ", hex(config));
        print("KEY ", hex(sk));
        return;
    }
    let is_server = a[1] == "server";
    var cc = tls::client_config(if is_server { "" } else { a[2] }, "");
    var key_der: u8[>..] = [];
    var chain: u8[>..] = [];
    if is_server {
        chain = pem_der(a[2], "CERTIFICATE");
        key_der = pem_der(a[3], "PRIVATE KEY");
    } else {
        // Roots from a PEM file or a directory of them, or the system's.
        if a[3] != "system" {
            cc.system_roots = false;
            if is_dir(a[3]) { let n = x509::pool_add_dir(cc.roots, a[3]); }
            else { let n = x509::pool_add_file(cc.roots, a[3]); }
        }
    }
    var sc, okk = tls::server_config(chain, key_der);
    if is_server && !okk { write_stderr("bad key\n"); assert(false); }
    var i = 4;
    var cert_path: u8[>..] = [];
    var suites_set = false;
    var groups_set = false;
    while i + 1 < a.len {
        if a[i] == "--suite" || a[i] == "--group" {
            let v = unhex(a[i + 1]);
            let id: u16 = (v[0] as u16) << 8 | v[1];
            if a[i] == "--suite" {
                if !suites_set { cc.suites.clear(); sc.suites.clear(); suites_set = true; }
                cc.suites.push(id);
                sc.suites.push(id);
            } else {
                if !groups_set { cc.groups.clear(); sc.groups.clear(); groups_set = true; }
                cc.groups.push(id);
                sc.groups.push(id);
            }
        } else if a[i] == "--alpn" {
            tls::add_alpn(cc.alpn, a[i + 1]);
            tls::add_alpn(sc.alpn, a[i + 1]);
        } else if a[i] == "--session" {
            let sess, ok = tls::parse_session(unhex(a[i + 1]));
            if !ok { write_stderr("bad session\n"); assert(false); }
            cc.session = sess;
        } else if a[i] == "--ticket-key" {
            let k = unhex(a[i + 1]);
            for j in 32 { sc.ticket_key[j] = k[j]; }
        } else if a[i] == "--cert" {
            cert_path.append(a[i + 1]);
        } else if a[i] == "--key" {
            if !tls::set_client_certificate(cc, pem_der(cert_path, "CERTIFICATE"), pem_der(a[i + 1], "PRIVATE KEY")) {
                write_stderr("bad client key\n");
                assert(false);
            }
        } else if a[i] == "--client-auth" {
            let v, ok = parse_int(a[i + 1], 10);
            sc.client_auth = v;
        } else if a[i] == "--client-cas" {
            let n = x509::pool_add_file(sc.client_cas, a[i + 1]);
        } else if a[i] == "--ech" {
            cc.ech_config_list.append(unhex(a[i + 1]));
        } else if a[i] == "--ech-key" {
            let parts = split(a[i + 1], ':');
            if !tls::add_ech_key(sc, unhex(parts[0]), unhex(parts[1]), true) { write_stderr("bad ECH key\n"); assert(false); }
        } else if a[i] == "--now" {
            let v, ok = parse_int(a[i + 1], 10);
            cc.now = v;
        }
        i += 2;
    }
    var c = if is_server { tls::server(sc) } else { tls::client(cc) };
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    if !is_server {
        tls::client_start(c, cc, out);
        report(c, out, app);
    }
    var line: u8[>..] = [];
    while read_line(line) {
        out.clear();
        app.clear();
        if line.len > 3 && line[..3] == "IN " {
            let data = unhex(line[3..]);
            let r = if is_server { tls::server_feed(c, sc, data, out, app) } else { tls::client_feed(c, cc, data, out, app) };
        } else if line.len > 5 && line[..5] == "SEND " {
            let ok = tls::send(c, unhex(line[5..]), out);
        } else if line == "KEYUPDATE" {
            let ok = tls::key_update(c, true, out);
        } else if line == "CLOSE" {
            tls::close(c, out);
        } else if line == "SESSION" {
            let sess, has = tls::session(c);
            let text: u8[>..] = if has { hex(tls::session_bytes(sess)) } else { "-" };
            print("SESSION ", text);
        }
        report(c, out, app);
        line.clear();
    }
}
