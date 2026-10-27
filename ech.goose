// tls.ech: Encrypted Client Hello (RFC 9849), the parts both sides share:
// ECHConfig and ECHConfigList encoding, picking a config as Go does, key
// generation for servers, the acceptance confirmation, and rebuilding a
// ClientHelloInner from its encoding and the ClientHelloOuter.
//
// A client with an ECHConfigList sends the real ClientHello (the inner one,
// with the real server name) encrypted under the config's HPKE key inside
// an outer ClientHello that names the config's public name. A server with
// the matching private key decrypts it and goes on with the inner one,
// which it confirms in the ServerHello's random; one without falls back to
// the outer one and may send retry configs.

namespace tls;

import std;
import tls;
import schedule;
import record;
import bignum;
import bignum.hmac;
import bignum.hpke;

let EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
let EXT_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;
let ECH_VERSION: u16 = 0xfe0d;
let ECH_OUTER: u8 = 0;
let ECH_INNER: u8 = 1;

// One ECHConfig as a client uses it: the HPKE suite it picked, the
// config's id, maximum name length and public name, its public key, and
// the whole ECHConfig (the HPKE info).
struct EchConfig {
    config_id: u8, kem: i64, kdf: i64, aead: i64, max_name_len: i64,
    public_name: u8[..255], public_key: u8[..2048], raw: u8[..4096],
}

fn no_ech_config() -> EchConfig {
    EchConfig { config_id: 0, kem: 0, kdf: 0, aead: 0, max_name_len: 0, public_name: [], public_key: [], raw: [] }
}

fn ech_put16(out: u8[>..]&, v: i64) { out.push((v >> 8) as! u8); out.push(v as! u8); }

// An ECHConfig (§4) for a KEM's public key, offering HKDF-SHA256 with
// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, without extensions.
fn ech_config(config_id: u8, kem: i64, public_key: const u8[:], public_name: const u8[:],
              max_name_len: i64 = 0) -> u8[>..] {
    assert(public_name.len > 0 && public_name.len < 256 && max_name_len >= 0 && max_name_len < 256);
    var body: u8[>..] = [];
    body.push(config_id);
    ech_put16(body, kem);
    ech_put16(body, public_key.len);
    body.append(public_key);
    ech_put16(body, 12);
    for aead in [bignum::HPKE_AES128GCM, bignum::HPKE_AES256GCM, bignum::HPKE_CHACHA20POLY1305] {
        ech_put16(body, bignum::HPKE_HKDF_SHA256);
        ech_put16(body, aead);
    }
    body.push(max_name_len as! u8);
    body.push(public_name.len as! u8);
    body.append(public_name);
    ech_put16(body, 0);
    var out: u8[>..] = [];
    ech_put16(out, ECH_VERSION);
    ech_put16(out, body.len);
    out.append(body);
    return out;
}

// An ECHConfigList of ECHConfigs given back to back.
fn ech_config_list(configs: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    ech_put16(out, configs.len);
    out.append(configs);
    return out;
}

// A fresh key for a server: its ECHConfig and HPKE private key, for
// ServerConfig (add_ech_key) and, in an ECHConfigList, for clients.
fn generate_ech_key(config_id: u8, kem: i64, public_name: const u8[:], max_name_len: i64 = 0) -> u8[>..], u8[>..] {
    let sk, pk = bignum::hpke_keygen(kem);
    return ech_config(config_id, kem, pk, public_name, max_name_len), sk;
}

// A host name as Go accepts for a public name: at most 253 bytes, two or
// more labels of letters, digits and inner hyphens.
fn ech_valid_name(name: const u8[:]) -> bool {
    if name.len > 253 { return false; }
    var labels = 0;
    var start = 0;
    for i in name.len + 1 {
        if i < name.len && name[i] != '.' { continue; }
        let n = i - start;
        if n == 0 { return false; }
        for j in start..i {
            let b = name[j];
            let alnum = (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
            if b == '-' && (j == start || j == i - 1) { return false; }
            if !alnum && b != '-' { return false; }
        }
        labels++;
        start = i + 1;
    }
    return labels > 1;
}

struct EchRd { pos: i64, end: i64, bad: bool }

fn ech_u8(r: EchRd&, b: const u8[:]) -> i64 {
    if r.bad || r.pos + 1 > r.end { r.bad = true; return 0; }
    r.pos++;
    return b[r.pos - 1];
}

fn ech_u16(r: EchRd&, b: const u8[:]) -> i64 { let a = ech_u8(r, b); return a << 8 | ech_u8(r, b); }

fn ech_vec(r: EchRd&, b: const u8[:], n: i64) -> EchRd {
    let len = if n == 1 { ech_u8(r, b) } else { ech_u16(r, b) };
    if r.bad || r.pos + len > r.end { r.bad = true; return EchRd { pos: 0, end: 0, bad: true }; }
    let v = EchRd { pos: r.pos, end: r.pos + len, bad: false };
    r.pos += len;
    return v;
}

fn ech_kdf_ok(kdf: i64) -> bool { kdf >= bignum::HPKE_HKDF_SHA256 && kdf <= bignum::HPKE_HKDF_SHA512 }

fn ech_aead_ok(aead: i64) -> bool { aead >= bignum::HPKE_AES128GCM && aead <= bignum::HPKE_CHACHA20POLY1305 }

// One ECHConfig at the reader: whether it parsed, and whether it is one of
// this version that a client can use (Go's parseECHConfig and
// pickECHConfig): a valid public name, no mandatory extension, a KEM this
// package has with a key of its size, and a suite of HKDF and a sealing
// AEAD, the first such picked. The reader moves past it.
fn ech_parse_config(r: EchRd&, b: const u8[:]) -> EchConfig, bool, bool {
    var ec = no_ech_config();
    let start = r.pos;
    let version = ech_u16(r, b);
    var body = ech_vec(r, b, 2);
    if r.bad { return ec, false, false; }
    if version != ECH_VERSION { return ec, true, false; }
    if r.pos - start > ec.raw.cap { return ec, true, false; }
    ec.raw.append(b[start..r.pos]);
    ec.config_id = ech_u8(body, b) as! u8;
    ec.kem = ech_u16(body, b);
    let pk = ech_vec(body, b, 2);
    var suites = ech_vec(body, b, 2);
    ec.max_name_len = ech_u8(body, b);
    let name = ech_vec(body, b, 1);
    var exts = ech_vec(body, b, 2);
    if body.bad || body.pos != body.end { return ec, false, false; }
    var usable = ech_valid_name(b[name.pos..name.end]) && bignum::hpke_kem_ok(ec.kem) &&
                 pk.end - pk.pos == bignum::hpke_npk(ec.kem) && pk.end - pk.pos <= ec.public_key.cap;
    while exts.pos < exts.end {
        let ty = ech_u16(exts, b);
        let data = ech_vec(exts, b, 2);
        if exts.bad { return ec, false, false; }
        if ty & 0x8000 != 0 { usable = false; }       // mandatory, and none is known
    }
    while suites.pos < suites.end {
        let kdf = ech_u16(suites, b);
        let aead = ech_u16(suites, b);
        if suites.bad { return ec, false, false; }
        if ec.kdf == 0 && ech_kdf_ok(kdf) && ech_aead_ok(aead) { ec.kdf = kdf; ec.aead = aead; }
    }
    if !usable || ec.kdf == 0 { return ec, true, false; }
    ec.public_name.append(b[name.pos..name.end]);
    ec.public_key.append(b[pk.pos..pk.end]);
    return ec, true, true;
}

// The first usable config of an ECHConfigList; false if the list is
// malformed or has none.
fn pick_ech_config(list: const u8[:]) -> EchConfig, bool {
    var r = EchRd { pos: 0, end: list.len, bad: false };
    var configs = ech_vec(r, list, 2);
    if r.bad || r.pos != list.len { return no_ech_config(), false; }
    while configs.pos < configs.end {
        let ec, ok, usable = ech_parse_config(configs, list);
        if !ok { return no_ech_config(), false; }
        if usable { return ec, true; }
    }
    return no_ech_config(), false;
}

// One ECHConfig alone, as a server's key holds it: whether it parsed and
// is of this version, with its KEM and config id.
fn ech_server_config(config: const u8[:]) -> i64, u8, bool {
    var r = EchRd { pos: 0, end: config.len, bad: false };
    let version = ech_u16(r, config);
    var body = ech_vec(r, config, 2);
    let id = ech_u8(body, config);
    let kem = ech_u16(body, config);
    if r.bad || body.bad || r.pos != config.len || version != ECH_VERSION { return 0, 0, false; }
    return kem, id as! u8, true;
}

// The HPKE info for a config (§6.1).
fn ech_info(config: const u8[:]) -> u8[>..] {
    var info: u8[>..] = [];
    info.append("tls ech");
    info.push(0);
    info.append(config);
    return info;
}

// An accept confirmation (§7.2): eight bytes from the inner ClientHello's
// random and a transcript hash, under "ech accept confirmation" for a
// ServerHello and "hrr ech accept confirmation" for a HelloRetryRequest.
fn ech_confirmation(hash: i64, inner_random: const u8[:], label: const u8[:], th: const u8[:]) -> u8[>..] {
    var zeros: u8[48] = [0; 48];
    let prk = bignum::hkdf_extract(hash, zeros[..hash / 8], inner_random);
    return hkdf_expand_label(hash, prk, label, th, 8);
}

// EncodedClientHelloInner's padding (§6.1.3, as Go pads): the server name
// up to the config's maximum, then the whole to a multiple of 32.
fn ech_padding(encoded_len: i64, server_name_len: i64, max_name_len: i64) -> i64 {
    var n = if server_name_len > 0 { ::max(0, max_name_len - server_name_len) } else { max_name_len + 9 };
    n += 31 - ((encoded_len + n - 1) % 32);
    return n;
}

// The extensions of a ClientHello (a handshake message): where each type's
// data is, in order.
fn ech_hello_extensions(m: const u8[:]) -> EchRd, bool {
    var r = EchRd { pos: 4 + 2 + 32, end: m.len, bad: false };
    let sid = ech_vec(r, m, 1);
    let suites = ech_vec(r, m, 2);
    let comp = ech_vec(r, m, 1);
    let exts = ech_vec(r, m, 2);
    return exts, !r.bad;
}

// ClientHelloInner from EncodedClientHelloInner (§5.1): the outer
// ClientHello's session id, and each extension ech_outer_extensions names
// copied from the outer one, in its order there. The padding must be zeros.
// False if malformed, or if it names encrypted_client_hello or an
// extension the outer one lacks (after the ones already taken).
fn ech_decode_inner(outer: const u8[:], encoded: const u8[:]) -> u8[>..], bool {
    var none: u8[>..] = [];
    var r = EchRd { pos: 0, end: encoded.len, bad: false };
    r.pos = 34;
    if encoded.len < 34 { return none, false; }
    let sid = ech_vec(r, encoded, 1);
    let suites = ech_vec(r, encoded, 2);
    let comp = ech_vec(r, encoded, 1);
    var exts = ech_vec(r, encoded, 2);
    if r.bad || sid.end != sid.pos { return none, false; }
    for i in r.pos..encoded.len { if encoded[i] != 0 { return none, false; } }
    var outer_exts, ok = ech_hello_extensions(outer);
    if !ok { return none, false; }
    var osid = EchRd { pos: 4 + 34, end: outer.len, bad: false };
    let outer_sid = ech_vec(osid, outer, 1);
    var b: u8[>..] = [];
    b.append(encoded[..34]);
    b.push((outer_sid.end - outer_sid.pos) as! u8);
    b.append(outer[outer_sid.pos..outer_sid.end]);
    b.append(encoded[suites.pos - 2..comp.end]);
    let ext_mark = b.len;
    ech_put16(b, 0);
    while exts.pos < exts.end {
        let ty = ech_u16(exts, encoded);
        var data = ech_vec(exts, encoded, 2);
        if exts.bad { return none, false; }
        if ty != EXT_ECH_OUTER_EXTENSIONS {
            ech_put16(b, ty);
            ech_put16(b, data.end - data.pos);
            b.append(encoded[data.pos..data.end]);
            continue;
        }
        var list = ech_vec(data, encoded, 1);
        if data.bad || data.pos != data.end || list.end == list.pos { return none, false; }
        while list.pos < list.end {
            let want = ech_u16(list, encoded);
            if list.bad || want == EXT_ENCRYPTED_CLIENT_HELLO { return none, false; }
            var found = false;
            while outer_exts.pos < outer_exts.end && !found {
                let oty = ech_u16(outer_exts, outer);
                let od = ech_vec(outer_exts, outer, 2);
                if outer_exts.bad { return none, false; }
                if oty == want {
                    ech_put16(b, oty);
                    ech_put16(b, od.end - od.pos);
                    b.append(outer[od.pos..od.end]);
                    found = true;
                }
            }
            if !found { return none, false; }
        }
    }
    let n = b.len - ext_mark - 2;
    if n > 0xffff { return none, false; }
    b[ext_mark] = (n >> 8) as! u8;
    b[ext_mark + 1] = n as! u8;
    return handshake_message(HS_CLIENT_HELLO, b), true;
}

// Whether a ClientHelloInner is one: encrypted_client_hello of the inner
// type, and TLS 1.3 offered with nothing older (GREASE aside).
fn ech_inner_ok(m: const u8[:]) -> bool {
    var exts, ok = ech_hello_extensions(m);
    if !ok { return false; }
    var inner = false;
    var tls13 = false;
    while exts.pos < exts.end {
        let ty = ech_u16(exts, m);
        var d = ech_vec(exts, m, 2);
        if exts.bad { return false; }
        if ty == EXT_ENCRYPTED_CLIENT_HELLO {
            inner = d.end - d.pos == 1 && m[d.pos] == ECH_INNER;
        } else if ty == 43 {
            var l = ech_vec(d, m, 1);
            while l.pos < l.end {
                let v = ech_u16(l, m);
                if v & 0x0f0f == 0x0a0a && v & 0xff == v >> 8 { continue; }
                if v == 0x0304 { tls13 = true; } else if v < 0x0304 { return false; }
            }
            if l.bad { return false; }
        }
    }
    return inner && tls13;
}

// The outer ClientHello as the AAD of its payload (§5.2): without its
// handshake header, the payload at [pos, end) zeroed.
fn ech_aad(m: const u8[:], pos: i64, end: i64) -> u8[>..] {
    var aad: u8[>..] = [];
    aad.append(m[4..]);
    for i in pos - 4..end - 4 { aad[i] = 0; }
    return aad;
}
