// https_get: a TLS client over a real socket. The package does no I/O, so
// the program moves the bytes: what the connection hands back goes to the
// socket, what the socket gives is fed to the connection. The sockets are
// gslib's net module's (net::dial and the rest). The server's certificate is checked
// against the system's roots. It sends an HTTP/1.1 GET and prints the
// status line and how much came back.
//
//   goose examples/https_get.goose -- HOST [PORT [PATH]]

import std;
import tls from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import net from "SorinS/netgoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509 from "SorinS/x509goose@v0.9.1";
import tls.handshake;

// Writes `out` to the socket and empties it.
fn flush(fd: i64, out: u8[>..]&) {
    if out.len == 0 { return; }
    guard net::write(fd, out, 10000) >= 0 else { print("https_get: write failed"); exit(1); }
    out.clear();
}

fn run(host: const u8[:], port: i64, path: const u8[:]) {
    var cc = tls::client_config(host, "");             // no roots given: the system's
    tls::add_alpn(cc.alpn, "http/1.1");
    var c = tls::client(cc);

    let fd = net::dial(host, port as! i32, 10000);
    guard fd >= 0 else { print("https_get: cannot connect to ", host, ":", port); exit(1); }

    var out: u8[>..] = [];
    var app: u8[>..] = [];
    var buf: u8[>..] = [];
    buf.resize(16384, 0);
    tls::client_start(c, cc, out);                        // the ClientHello
    var sent = false;
    loop {
        flush(fd, out);
        if tls::connected(c) && !sent {
            print("connected: version 0x", hex_u16(tls::version(c)), ", suite 0x", hex_u16(c.suite.id),
                  ", group 0x", hex_u16(c.group));
            let req = str("GET ", path, " HTTP/1.1\r\nHost: ", host, "\r\nConnection: close\r\n\r\n");
            guard tls::send(c, req, out) else { print("https_get: send failed"); exit(1); }
            sent = true;
            continue;
        }
        if tls::failed(c) || tls::closed(c) { break; }
        let n = net::read(fd, buf, 10000);
        if n <= 0 { break; }                              // the end of the stream, a timeout or an error
        let r = tls::client_feed(c, cc, buf[..n], out, app);
    }
    flush(fd, out);
    net::close(fd);
    guard sent else { print("https_get: handshake failed, alert ", c.alert, ", x509 error ", c.error); exit(1); }

    var end = 0;
    while end < app.len && app[end] != '\r' { end++; }
    print(app[..end]);
    print(app.len, " bytes received");
}

fn hex_u16(v: u16) -> u8[>..] {
    var o: u8[>..] = [];
    format_uint(o, v, 16, 4, '0');
    return o;
}

fn main() {
    let a = args();
    guard a.len >= 2 else { print("usage: https_get HOST [PORT [PATH]]"); exit(2); }
    var port: i64 = 443;
    if a.len > 2 {
        let p, ok = parse_int(a[2]);
        guard ok && p > 0 && p < 65536 else { print("https_get: bad port ", a[2]); exit(2); }
        port = p;
    }
    let path: const u8[:] = if a.len > 3 { a[3] } else { "/" };
    run(a[1], port, path);
}
