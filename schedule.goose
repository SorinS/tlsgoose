// tls.schedule: the TLS 1.3 key schedule (RFC 8446 §7.1): HKDF-Expand-Label,
// Derive-Secret, the early, handshake and master secrets with the traffic
// secrets derived from them, traffic keys, Finished, KeyUpdate, exporters,
// resumption PSKs, and a running transcript hash.

namespace tls;

import std;
import tls;
import bignum;
import bignum.ct;
import bignum.hmac;
import bignum.sha256;
import bignum.sha512;

// HKDF-Expand-Label(secret, label, context, len), with the "tls13 " prefix
// added here: struct { u16 length; opaque label<7..255>; opaque context<0..255> }.
fn hkdf_expand_label(hash: i64, secret: const u8[:], label: const u8[:], context: const u8[:],
                     len: i64) -> u8[>..] {
    assert(len >= 0 && len < 65536 && label.len + 6 <= 255 && context.len <= 255);
    var info: u8[>..] = [];
    info.push((len >> 8) as! u8);
    info.push(len as! u8);
    info.push((label.len + 6) as! u8);
    info.append("tls13 ");
    info.append(label);
    info.push(context.len as! u8);
    info.append(context);
    return bignum::hkdf_expand(hash, secret, info, len);
}

// Derive-Secret(secret, label, transcript hash).
fn derive_secret(hash: i64, secret: const u8[:], label: const u8[:], th: const u8[:]) -> u8[>..] {
    hkdf_expand_label(hash, secret, label, th, hash / 8)
}

// The hash of the empty string, the transcript of "derived".
fn empty_hash(hash: i64) -> u8[>..] { bignum::hash_bits(hash, "") }

// The running transcript hash over the handshake messages (§4.4.1).
struct Transcript { hash: i64, s256: bignum::Sha256, s512: bignum::Sha512 }

fn transcript(hash: i64) -> Transcript {
    assert(hash == 256 || hash == 384);
    Transcript { hash: hash, s256: bignum::sha256_init(), s512: bignum::sha384_init() }
}

// Adds whole handshake messages (header included).
fn transcript_add(t: Transcript&, msg: const u8[:]) {
    if t.hash == 256 { bignum::sha256_update(t.s256, msg); } else { bignum::sha512_update(t.s512, msg); }
}

// The hash so far; the transcript goes on.
fn transcript_hash(t: const Transcript&) -> u8[>..] {
    var out: u8[>..] = [];
    if t.hash == 256 {
        var c = t.s256;
        out.append(bignum::sha256_final(c));
    } else {
        var c = t.s512;
        out = bignum::sha512_final(c);
    }
    return out;
}

// After a HelloRetryRequest the transcript restarts from message_hash(CH1)
// (§4.4.1).
fn transcript_restart_hrr(t: Transcript&) {
    let h1 = transcript_hash(t);
    t = transcript(t.hash);
    let hdr: u8[4] = [HS_MESSAGE_HASH, 0, 0, h1.len as! u8];
    transcript_add(t, hdr);
    transcript_add(t, h1);
}

// The secrets of one connection, each as long as the hash.
struct Schedule {
    hash: i64,
    early: u8[..48], handshake: u8[..48], master: u8[..48],
    c_hs: u8[..48], s_hs: u8[..48], c_ap: u8[..48], s_ap: u8[..48],
    exporter: u8[..48], resumption: u8[..48],
}

fn set48(dst: u8[..48]&, v: const u8[:]) {
    dst.clear();
    dst.append(v);
}

// Starts the schedule: the early secret from a PSK, or from zeros without
// one (an empty psk).
fn schedule(hash: i64, psk: const u8[:]) -> Schedule {
    var s = Schedule {
        hash: hash, early: [], handshake: [], master: [], c_hs: [], s_hs: [],
        c_ap: [], s_ap: [], exporter: [], resumption: [],
    };
    var zeros: u8[48] = [0; 48];
    let ikm = if psk.len == 0 { zeros[..hash / 8] } else { psk };
    set48(s.early, bignum::hkdf_extract(hash, zeros[..hash / 8], ikm));
    return s;
}

// The binder key for a resumption PSK (§4.2.11), from the early secret.
fn binder_key(s: const Schedule&, external: bool) -> u8[>..] {
    derive_secret(s.hash, s.early, if external { "ext binder" } else { "res binder" }, empty_hash(s.hash))
}

// The handshake secret from the (EC)DHE shared secret, and the handshake
// traffic secrets for the transcript through ServerHello.
fn schedule_handshake(s: Schedule&, shared: const u8[:], th_hello: const u8[:]) {
    let salt = derive_secret(s.hash, s.early, "derived", empty_hash(s.hash));
    set48(s.handshake, bignum::hkdf_extract(s.hash, salt, shared));
    set48(s.c_hs, derive_secret(s.hash, s.handshake, "c hs traffic", th_hello));
    set48(s.s_hs, derive_secret(s.hash, s.handshake, "s hs traffic", th_hello));
}

// The master secret, and the application traffic and exporter secrets for
// the transcript through the server's Finished.
fn schedule_master(s: Schedule&, th_server_finished: const u8[:]) {
    let salt = derive_secret(s.hash, s.handshake, "derived", empty_hash(s.hash));
    var zeros: u8[48] = [0; 48];
    set48(s.master, bignum::hkdf_extract(s.hash, salt, zeros[..s.hash / 8]));
    set48(s.c_ap, derive_secret(s.hash, s.master, "c ap traffic", th_server_finished));
    set48(s.s_ap, derive_secret(s.hash, s.master, "s ap traffic", th_server_finished));
    set48(s.exporter, derive_secret(s.hash, s.master, "exp master", th_server_finished));
}

// The resumption master secret, for the transcript through the client's
// Finished.
fn schedule_resumption(s: Schedule&, th_client_finished: const u8[:]) {
    set48(s.resumption, derive_secret(s.hash, s.master, "res master", th_client_finished));
}

// The PSK that a NewSessionTicket with this nonce offers (§4.6.1).
fn resumption_psk(hash: i64, resumption: const u8[:], nonce: const u8[:]) -> u8[>..] {
    hkdf_expand_label(hash, resumption, "resumption", nonce, hash / 8)
}

// The write key and IV of a traffic secret (§7.3).
fn traffic_key(s: Suite, secret: const u8[:]) -> u8[>..] { hkdf_expand_label(s.hash, secret, "key", "", s.key_len) }
fn traffic_iv(s: Suite, secret: const u8[:]) -> u8[>..] { hkdf_expand_label(s.hash, secret, "iv", "", 12) }

// The next generation of a traffic secret, after a KeyUpdate (§7.2).
fn next_traffic_secret(hash: i64, secret: const u8[:]) -> u8[>..] {
    hkdf_expand_label(hash, secret, "traffic upd", "", hash / 8)
}

// Finished.verify_data for a handshake traffic secret and the transcript
// so far (§4.4.4).
fn finished_data(hash: i64, base: const u8[:], th: const u8[:]) -> u8[>..] {
    let key = hkdf_expand_label(hash, base, "finished", "", hash / 8);
    return bignum::hmac(hash, key, th);
}

// Compares received verify_data in constant time.
fn finished_ok(hash: i64, base: const u8[:], th: const u8[:], got: const u8[:]) -> bool {
    let want = finished_data(hash, base, th);
    return got.len == want.len && bignum::ct_eq_bytes(want, got) == 1;
}

// TLS-Exporter(label, context, len) from the exporter master secret (§7.5).
fn export_keying_material(hash: i64, exporter: const u8[:], label: const u8[:], context: const u8[:],
                          len: i64) -> u8[>..] {
    let s = derive_secret(hash, exporter, label, empty_hash(hash));
    return hkdf_expand_label(hash, s, "exporter", bignum::hash_bits(hash, context), len);
}
