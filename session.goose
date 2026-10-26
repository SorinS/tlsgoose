// tls.session: TLS 1.3 resumption state (RFC 8446 §4.6.1, §2.2). A client
// keeps a Session from the server's NewSessionTicket and offers it in a
// later ClientHello as a PSK; a server issues tickets that carry its own
// state sealed under a ticket key, so it remembers nothing (as Go's
// crypto/tls does). Sessions can be saved as bytes and restored.

namespace tls;

import std;
import tls;
import bignum;
import bignum.chacha20;

// Tickets live at most seven days (§4.6.1), and so do sessions.
let MAX_TICKET_LIFETIME: i64 = 604800;

// What a client needs to resume: the suite and PSK, the ticket and its
// age_add, when it arrived (milliseconds since 1970) and for how long it is
// good, the server name and ALPN protocol of the connection that got it,
// and its certificate's notAfter (0 when unchecked).
struct Session {
    suite: u16, psk: u8[..48], age_add: u32, lifetime: i64, received_ms: i64,
    server_name: u8[..255], alpn: u8[..255], not_after: i64, max_early_data: u32,
    ticket: u8[..4096],
}

fn no_session() -> Session {
    Session { suite: 0, psk: [], age_add: 0, lifetime: 0, received_ms: 0, server_name: [], alpn: [],
              not_after: 0, max_early_data: 0, ticket: [] }
}

// Whether a session may be offered at `now_ms` to `server_name`: not
// expired, by its ticket's lifetime or its certificate, and for that name.
fn session_usable(s: const Session&, server_name: const u8[:], now_ms: i64) -> bool {
    if s.ticket.len == 0 || s.psk.len == 0 { return false; }
    if s.server_name[..] != server_name { return false; }
    if now_ms < s.received_ms || now_ms - s.received_ms >= s.lifetime * 1000 { return false; }
    if s.not_after != 0 && now_ms / 1000 > s.not_after { return false; }
    return true;
}

// The obfuscated_ticket_age of a session at `now_ms` (§4.2.11.1).
fn obfuscated_age(s: const Session&, now_ms: i64) -> u32 {
    ((now_ms - s.received_ms) as! u32) + s.age_add
}

// --- Bytes ---------------------------------------------------------------------

fn sess_put(out: u8[>..]&, v: u64, n: i64) {
    for i in n { out.push((v >> (8 * (n - 1 - i))) as! u8); }
}

fn sess_vec(out: u8[>..]&, b: const u8[:], n: i64) {
    sess_put(out, b.len as! u64, n);
    out.append(b);
}

// A cursor over bytes being read back.
struct SessRd { pos: i64, bad: bool }

fn sess_get(r: SessRd&, b: const u8[:], n: i64) -> u64 {
    if r.bad || r.pos + n > b.len { r.bad = true; return 0; }
    var v: u64 = 0;
    for i in n { v = v << 8 | b[r.pos + i]; }
    r.pos += n;
    return v;
}

fn sess_get_vec(r: SessRd&, b: const u8[:], n: i64, max: i64) -> u8[>..] {
    var out: u8[>..] = [];
    let len = sess_get(r, b, n) as! i64;
    if r.bad || len > max || r.pos + len > b.len { r.bad = true; return out; }
    out.append(b[r.pos..r.pos + len]);
    r.pos += len;
    return out;
}

// A session as bytes, to keep across runs (Go's ClientSessionState with
// ResumptionState); `parse_session` reads them back.
fn session_bytes(s: const Session&) -> u8[>..] {
    var out: u8[>..] = [];
    out.push(1);                                    // format version
    sess_put(out, s.suite, 2);
    sess_vec(out, s.psk, 1);
    sess_put(out, s.age_add, 4);
    sess_put(out, s.lifetime as! u64, 4);
    sess_put(out, s.received_ms as! u64, 8);
    sess_vec(out, s.server_name, 1);
    sess_vec(out, s.alpn, 1);
    sess_put(out, s.not_after as! u64, 8);
    sess_put(out, s.max_early_data, 4);
    sess_vec(out, s.ticket, 2);
    return out;
}

fn parse_session(b: const u8[:]) -> Session, bool {
    var s = no_session();
    var r = SessRd { pos: 0, bad: false };
    if sess_get(r, b, 1) != 1 { return s, false; }
    s.suite = sess_get(r, b, 2) as! u16;
    s.psk.append(sess_get_vec(r, b, 1, 48));
    s.age_add = sess_get(r, b, 4) as! u32;
    s.lifetime = sess_get(r, b, 4) as! i64;
    s.received_ms = sess_get(r, b, 8) as! i64;
    s.server_name.append(sess_get_vec(r, b, 1, 255));
    s.alpn.append(sess_get_vec(r, b, 1, 255));
    s.not_after = sess_get(r, b, 8) as! i64;
    s.max_early_data = sess_get(r, b, 4) as! u32;
    s.ticket.append(sess_get_vec(r, b, 2, 4096));
    let st, oks = suite(s.suite);
    if r.bad || r.pos != b.len || !oks || s.psk.len != hash_len(st) || s.lifetime > MAX_TICKET_LIFETIME {
        return no_session(), false;
    }
    return s, true;
}

// --- Tickets -------------------------------------------------------------------

// What a server's ticket carries, sealed: the suite, the PSK, when it was
// made (seconds), its age_add and lifetime, and the ALPN protocol and server
// name of the connection.
struct TicketState {
    suite: u16, psk: u8[..48], created: i64, age_add: u32, lifetime: i64, alpn: u8[..255], sni: u8[..255],
}

let TICKET_AAD: const u8[:] = "goose tls 1.3 ticket v1";

// A ticket: a 12-byte nonce, then the state sealed with ChaCha20-Poly1305
// under the server's 32-byte ticket key.
fn seal_ticket(key: const u8[:], nonce: const u8[:], t: const TicketState&) -> u8[>..] {
    assert(key.len == 32 && nonce.len == 12);
    var plain: u8[>..] = [];
    sess_put(plain, t.suite, 2);
    sess_vec(plain, t.psk, 1);
    sess_put(plain, t.created as! u64, 8);
    sess_put(plain, t.age_add, 4);
    sess_put(plain, t.lifetime as! u64, 4);
    sess_vec(plain, t.alpn, 1);
    sess_vec(plain, t.sni, 1);
    var out: u8[>..] = [];
    out.append(nonce);
    out.append(bignum::chacha20_poly1305_seal(key, nonce, TICKET_AAD, plain));
    return out;
}

// The state of a ticket this key sealed; false for any other bytes.
fn open_ticket(key: const u8[:], ticket: const u8[:]) -> TicketState, bool {
    var t = TicketState { suite: 0, psk: [], created: 0, age_add: 0, lifetime: 0, alpn: [], sni: [] };
    if ticket.len < 12 + 16 { return t, false; }
    let plain, ok = bignum::chacha20_poly1305_open(key, ticket[..12], TICKET_AAD, ticket[12..]);
    if !ok { return t, false; }
    var r = SessRd { pos: 0, bad: false };
    t.suite = sess_get(r, plain, 2) as! u16;
    t.psk.append(sess_get_vec(r, plain, 1, 48));
    t.created = sess_get(r, plain, 8) as! i64;
    t.age_add = sess_get(r, plain, 4) as! u32;
    t.lifetime = sess_get(r, plain, 4) as! i64;
    t.alpn.append(sess_get_vec(r, plain, 1, 255));
    t.sni.append(sess_get_vec(r, plain, 1, 255));
    let st, oks = suite(t.suite);
    if r.bad || r.pos != plain.len || !oks || t.psk.len != hash_len(st) { return t, false; }
    return t, true;
}
