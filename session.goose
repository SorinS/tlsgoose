// tls.session: resumption state, TLS 1.3's (RFC 8446 §4.6.1, §2.2) and
// TLS 1.2's session tickets (RFC 5077). A client keeps a Session from the
// server's NewSessionTicket and offers it in a later ClientHello, as a PSK
// in TLS 1.3, in session_ticket in TLS 1.2; a server issues tickets that
// carry its own state sealed under a ticket key, so it remembers nothing
// (as Go's crypto/tls does). Sessions can be saved as bytes and restored.

namespace tls;

import std;
import tls;
import bignum;
import bignum.chacha20;

// Tickets live at most seven days (§4.6.1), and so do sessions.
let MAX_TICKET_LIFETIME: i64 = 604800;

// What a client needs to resume: the version and suite, the PSK (TLS
// 1.2's master secret, and whether it is an extended one), the ticket and
// its age_add, when it arrived (milliseconds since 1970) and for how long
// it is good, the server name and ALPN protocol of the connection that got
// it, and its certificate's notAfter (0 when unchecked).
struct Session {
    version: u16, suite: u16, psk: u8[..48], ems: bool, age_add: u32, lifetime: i64, received_ms: i64,
    server_name: u8[..255], alpn: u8[..255], not_after: i64, max_early_data: u32,
    ticket: u8[..16384],
}

fn no_session() -> Session {
    Session { version: VERSION_TLS13, suite: 0, psk: [], ems: false, age_add: 0, lifetime: 0, received_ms: 0, server_name: [], alpn: [],
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
    out.push(2);                                    // format version
    sess_put(out, s.version, 2);
    sess_put(out, s.suite, 2);
    sess_vec(out, s.psk, 1);
    sess_put(out, if s.ems { 1 } else { 0 }, 1);
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
    let format = sess_get(r, b, 1);
    if format != 1 && format != 2 { return s, false; }
    if format == 2 { s.version = sess_get(r, b, 2) as! u16; }
    s.suite = sess_get(r, b, 2) as! u16;
    s.psk.append(sess_get_vec(r, b, 1, 48));
    var ems: u64 = 0;
    if format == 2 { ems = sess_get(r, b, 1); }
    s.ems = ems == 1;
    s.age_add = sess_get(r, b, 4) as! u32;
    s.lifetime = sess_get(r, b, 4) as! i64;
    s.received_ms = sess_get(r, b, 8) as! i64;
    s.server_name.append(sess_get_vec(r, b, 1, 255));
    s.alpn.append(sess_get_vec(r, b, 1, 255));
    s.not_after = sess_get(r, b, 8) as! i64;
    s.max_early_data = sess_get(r, b, 4) as! u32;
    s.ticket.append(sess_get_vec(r, b, 2, 16384));
    if r.bad || r.pos != b.len || ems > 1 || !state_ok(s.version, s.suite, s.psk) || s.lifetime > MAX_TICKET_LIFETIME {
        return no_session(), false;
    }
    return s, true;
}

// Whether a version, suite and PSK go together: a TLS 1.3 suite and a PSK
// of its hash's length, or a TLS 1.2 suite and a 48-byte master secret.
fn state_ok(version: u16, id: u16, psk: const u8[:]) -> bool {
    let st, oks = suite(id);
    if !oks { return false; }
    if version == VERSION_TLS13 { return !is_tls12_suite(st) && psk.len == hash_len(st); }
    return version == VERSION_TLS12 && is_tls12_suite(st) && psk.len == 48;
}

// --- Tickets -------------------------------------------------------------------

// What a server's ticket carries, sealed: the version and suite, the PSK
// (TLS 1.2's master secret, and whether it is extended), when it was made
// (seconds), its age_add and lifetime, the ALPN protocol and server name
// of the connection, and the client's certificates (none when empty),
// whether they were checked, and the leaf's notAfter.
struct TicketState {
    version: u16, suite: u16, psk: u8[..48], ems: bool, created: i64, age_add: u32, lifetime: i64, alpn: u8[..255], sni: u8[..255],
    client_not_after: i64, client_verified: bool, client_chain: u8[..12288],
}

let TICKET_AAD: const u8[:] = "goose tls ticket v3";

// A ticket: a 12-byte nonce, then the state sealed with ChaCha20-Poly1305
// under the server's 32-byte ticket key.
fn seal_ticket(key: const u8[:], nonce: const u8[:], t: const TicketState&) -> u8[>..] {
    assert(key.len == 32 && nonce.len == 12);
    var plain: u8[>..] = [];
    sess_put(plain, t.version, 2);
    sess_put(plain, t.suite, 2);
    sess_vec(plain, t.psk, 1);
    sess_put(plain, if t.ems { 1 } else { 0 }, 1);
    sess_put(plain, t.created as! u64, 8);
    sess_put(plain, t.age_add, 4);
    sess_put(plain, t.lifetime as! u64, 4);
    sess_vec(plain, t.alpn, 1);
    sess_vec(plain, t.sni, 1);
    sess_put(plain, t.client_not_after as! u64, 8);
    sess_put(plain, if t.client_verified { 1 } else { 0 }, 1);
    sess_vec(plain, t.client_chain, 2);
    var out: u8[>..] = [];
    out.append(nonce);
    out.append(bignum::chacha20_poly1305_seal(key, nonce, TICKET_AAD, plain));
    return out;
}

// The state of a ticket this key sealed; false for any other bytes.
fn open_ticket(key: const u8[:], ticket: const u8[:]) -> TicketState, bool {
    var t = TicketState { version: 0, suite: 0, psk: [], ems: false, created: 0, age_add: 0, lifetime: 0, alpn: [], sni: [],
                          client_not_after: 0, client_verified: false, client_chain: [] };
    if ticket.len < 12 + 16 { return t, false; }
    let plain, ok = bignum::chacha20_poly1305_open(key, ticket[..12], TICKET_AAD, ticket[12..]);
    if !ok { return t, false; }
    var r = SessRd { pos: 0, bad: false };
    t.version = sess_get(r, plain, 2) as! u16;
    t.suite = sess_get(r, plain, 2) as! u16;
    t.psk.append(sess_get_vec(r, plain, 1, 48));
    let ems = sess_get(r, plain, 1);
    t.ems = ems == 1;
    t.created = sess_get(r, plain, 8) as! i64;
    t.age_add = sess_get(r, plain, 4) as! u32;
    t.lifetime = sess_get(r, plain, 4) as! i64;
    t.alpn.append(sess_get_vec(r, plain, 1, 255));
    t.sni.append(sess_get_vec(r, plain, 1, 255));
    t.client_not_after = sess_get(r, plain, 8) as! i64;
    let verified = sess_get(r, plain, 1);
    t.client_verified = verified == 1;
    t.client_chain.append(sess_get_vec(r, plain, 2, 12288));
    if r.bad || r.pos != plain.len || verified > 1 || ems > 1 || !state_ok(t.version, t.suite, t.psk) { return t, false; }
    return t, true;
}
