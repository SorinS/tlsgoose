// Interop with OpenSSL: real TLS 1.3 connections, one per cipher suite,
// captured by scripts/openssl_interop.py with their key logs. From the
// logged traffic secrets this test derives the record keys, opens every
// record both sides sent, follows the handshake messages through the
// transcript, checks both Finished messages, and recovers the application
// data. Every record it opens it also seals again, which must give
// OpenSSL's bytes exactly.
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.schedule;
import tls.record;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
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

// The hex after `key` (and `sub`, for secrets) in a capture.
fn field(text: const u8[:], key: const u8[:], sub: const u8[:]) -> u8[>..] {
    for line in split(text, '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == key && sub.len == 0 { return unhex(w[1]); }
        if w.len == 3 && w[0] == key && w[1] == sub { return unhex(w[2]); }
    }
    print("missing ", key, " ", sub);
    assert(false);
    var none: u8[>..] = [];
    return none;
}

// Opens a record with r, then seals its contents with w (a twin of r at
// the same sequence number) and compares the bytes.
fn open_and_reseal(r: tls::RecordKeys&, w: tls::RecordKeys&, rec: const u8[:]) -> u8, u8[>..] {
    let t, p, alert = tls::open_record(r, rec);
    check("open", alert == 0);
    check("fragment size", p.len <= tls::MAX_FRAGMENT);
    let again = tls::seal_record(w, t, p);
    check("reseal", again == rec);
    return t, p;
}

fn run(name: const u8[:], text: const u8[:]) {
    let id = field(text, "suite", "");
    let s, oks = tls::suite((id[0] as u16) << 8 | id[1]);
    check(name, oks);
    let c2s = field(text, "c2s", "");
    let s2c = field(text, "s2c", "");
    let c_hs = field(text, "secret", "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
    let s_hs = field(text, "secret", "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    let c_ap = field(text, "secret", "CLIENT_TRAFFIC_SECRET_0");
    let s_ap = field(text, "secret", "SERVER_TRAFFIC_SECRET_0");
    var th = tls::transcript(s.hash);

    // The ClientHello, in the client's first record.
    var coff = tls::record_length(c2s);
    check("client hello record", coff > 0 && c2s[0] == tls::CT_HANDSHAKE);
    let ch = c2s[5..coff];
    check("client hello", ch[0] == tls::HS_CLIENT_HELLO && tls::handshake_length(ch) == ch.len);
    tls::transcript_add(th, ch);

    // The server's side: ServerHello, change_cipher_spec for middleboxes,
    // then the encrypted flight up to Finished, then tickets and data.
    var r = tls::record_keys(s, s_hs);
    var w = tls::record_keys(s, s_hs);
    var hs: u8[>..] = [];
    var app: u8[>..] = [];
    var phase = 0;                                       // 0 hello, 1 handshake, 2 application
    var th_sf: u8[>..] = [];
    var tickets = 0;
    var off = 0;
    while off < s2c.len {
        let n = tls::record_length(s2c[off..]);
        check("server record", n > 0);
        if n <= 0 { return; }
        let rec = s2c[off..off + n];
        off += n;
        if rec[0] == tls::CT_HANDSHAKE && phase == 0 {
            let sh = rec[5..];
            check("server hello", sh[0] == tls::HS_SERVER_HELLO && tls::handshake_length(sh) == sh.len);
            // legacy_version, random, session id, then the suite.
            let sid = sh[38] as i64;
            check("suite chosen", sh[39 + sid] == id[0] && sh[40 + sid] == id[1]);
            tls::transcript_add(th, sh);
            phase = 1;
            continue;
        }
        if rec[0] == tls::CT_CHANGE_CIPHER_SPEC {
            check("ccs", rec.len == 6 && rec[5] == 1);
            continue;
        }
        let t, p = open_and_reseal(r, w, rec);
        if t == tls::CT_APPLICATION_DATA {
            check("data after handshake", phase == 2);
            app.append(p);
            continue;
        }
        check("server content type", t == tls::CT_HANDSHAKE);
        hs.append(p);
        loop {
            let m = tls::handshake_length(hs);
            if m == 0 { break; }
            var msg: u8[>..] = [];
            msg.append(hs[..m]);
            var rest: u8[>..] = [];
            rest.append(hs[m..]);
            hs = copy(rest);
            if phase == 2 {
                check("ticket", msg[0] == tls::HS_NEW_SESSION_TICKET);
                tickets++;
                continue;
            }
            if msg[0] == tls::HS_FINISHED {
                check("server finished", tls::finished_ok(s.hash, s_hs, tls::transcript_hash(th), msg[4..]));
                tls::transcript_add(th, msg);
                th_sf = tls::transcript_hash(th);
                r = tls::record_keys(s, s_ap);
                w = tls::record_keys(s, s_ap);
                phase = 2;
            } else {
                tls::transcript_add(th, msg);
            }
        }
    }
    check("server finished seen", phase == 2 && tickets >= 1);
    check("server data", app == field(text, "app_s2c", ""));

    // The client's side: its Finished under the handshake keys, then data.
    var cr = tls::record_keys(s, c_hs);
    var cw = tls::record_keys(s, c_hs);
    var capp: u8[>..] = [];
    var finished = false;
    var records = 0;
    while coff < c2s.len {
        let n = tls::record_length(c2s[coff..]);
        check("client record", n > 0);
        if n <= 0 { return; }
        let rec = c2s[coff..coff + n];
        coff += n;
        if rec[0] == tls::CT_CHANGE_CIPHER_SPEC { continue; }
        let t, p = open_and_reseal(cr, cw, rec);
        if !finished {
            check("client finished", t == tls::CT_HANDSHAKE && p[0] == tls::HS_FINISHED
                  && tls::finished_ok(s.hash, c_hs, th_sf, p[4..]));
            finished = true;
            cr = tls::record_keys(s, c_ap);
            cw = tls::record_keys(s, c_ap);
            continue;
        }
        check("client content type", t == tls::CT_APPLICATION_DATA);
        capp.append(p);
        records++;
    }
    check("client data", capp == field(text, "app_c2s", ""));
    check("data in several records", records >= 2);
    print(name, ": ", records, " client data records, ", tickets, " tickets");
}

fn main() {
    run("TLS_AES_128_GCM_SHA256", embed_file("vectors/openssl_1301.txt"));
    run("TLS_AES_256_GCM_SHA384", embed_file("vectors/openssl_1302.txt"));
    run("TLS_CHACHA20_POLY1305_SHA256", embed_file("vectors/openssl_1303.txt"));
    print("openssl interop: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
