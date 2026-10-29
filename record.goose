// tls.record: the TLS 1.3 record layer (RFC 8446 §5): plaintext records,
// protected records with any of the three AEADs, the per-record nonce from
// the sequence number, content-type hiding and padding, size limits, and
// splitting a byte stream into records and handshake messages; and TLS
// 1.2's protection (RFC 5246 §6.2.3): AES-GCM with an explicit nonce
// (RFC 5288), ChaCha20-Poly1305 (RFC 7905), and AES-CBC with HMAC,
// MAC-then-encrypt, its padding checked in constant time.

namespace tls;

import std;
import tls;
import schedule;
import bignum;
import bignum.gcm;
import bignum.chacha20;
import bignum.aes;
import bignum.modes;
import bignum.hmac;
import bignum.ct;
import bignum.entropy;

// The largest plaintext fragment, and the most a protected record may
// add to it (§5.1, §5.2).
let MAX_FRAGMENT: i64 = 16384;
let MAX_CIPHERTEXT: i64 = 16384 + 256;
let MAX_CIPHERTEXT12: i64 = 16384 + 2048;

// One direction's protection: the AEAD's key (expanded once for AES), the
// static IV, and the sequence number of the next record; for TLS 1.2
// (v12), the IV is AES-GCM's 4-byte salt or ChaCha20-Poly1305's 12 bytes,
// and CBC has a MAC key (the cipher's key is gcm.aes).
struct RecordKeys { suite: Suite, key: u8[..32], iv: u8[12], seq: u64, gcm: bignum::AesGcm, v12: bool, mac_key: u8[..32] }

// The keys for a traffic secret, at sequence number 0.
fn record_keys(s: Suite, secret: const u8[:]) -> RecordKeys {
    let key = traffic_key(s, secret);
    let iv = traffic_iv(s, secret);
    var k = RecordKeys { suite: s, key: [], iv: [0; 12], seq: 0, gcm: bignum::gcm_init(key), v12: false, mac_key: [] };
    k.key.append(key);
    for i in 12 { k.iv[i] = iv[i]; }
    return k;
}

// TLS 1.2 keys from the key block's parts, at sequence number 0.
fn record_keys12(s: Suite, key: const u8[:], mac_key: const u8[:], iv: const u8[:]) -> RecordKeys {
    var k = RecordKeys { suite: s, key: [], iv: [0; 12], seq: 0, gcm: bignum::gcm_init(key), v12: true, mac_key: [] };
    k.key.append(key);
    k.mac_key.append(mac_key);
    for i in iv.len { k.iv[i] = iv[i]; }
    return k;
}

// TLS 1.2's additional data, and CBC's MAC input before the fragment:
// seq_num, type, version, length (§6.2.3.1, §6.2.3.3).
fn aad12(k: const RecordKeys&, ctype: u8, len: i64) -> u8[13] {
    var a: u8[13] = [0; 13];
    for i in 8 { a[i] = (k.seq >> (56 - 8 * i)) as! u8; }
    a[8] = ctype;
    a[9] = 3;
    a[10] = 3;
    a[11] = (len >> 8) as! u8;
    a[12] = len as! u8;
    return a;
}

fn mac12(k: const RecordKeys&, ctype: u8, data: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append(aad12(k, ctype, data.len));
    m.append(data);
    return bignum::hmac(k.suite.mac, k.mac_key, m);
}

// A TLS 1.2 protected record of type ctype. AES-GCM's explicit nonce is
// the sequence number, as Go and OpenSSL send it; CBC's explicit IV is
// random (§6.2.3.2).
fn seal_record12(k: RecordKeys&, ctype: u8, payload: const u8[:]) -> u8[>..] {
    assert(payload.len <= MAX_FRAGMENT && k.seq != 0xffffffffffffffff);
    var out: u8[>..] = [];
    out.append(header(ctype, 0x0303, 0));
    if k.suite.aead == AEAD_AES_CBC {
        let mac = mac12(k, ctype, payload);
        var iv: u8[16] = [0; 16];
        bignum::random_bytes(iv);
        var body: u8[>..] = [];
        body.append(payload);
        body.append(mac);
        let npad = 16 - body.len % 16;              // 1 to 16 bytes, each npad - 1
        for i in npad { body.push((npad - 1) as! u8); }
        bignum::cbc_encrypt(k.gcm.aes, iv, body);
        out.append(iv);
        out.append(body);
    } else {
        let aad = aad12(k, ctype, payload.len);
        var nonce: u8[12] = [0; 12];
        if k.suite.aead == AEAD_AES_GCM {
            for i in 4 { nonce[i] = k.iv[i]; }
            for i in 8 { nonce[4 + i] = aad[i]; }
            out.append(nonce[4..]);
        } else {
            nonce = record_nonce(k);
        }
        var body: u8[>..] = [];
        body.append(payload);
        let tag = if k.suite.aead == AEAD_AES_GCM { bignum::gcm_encrypt(k.gcm, nonce, aad, body) }
                  else { bignum::chacha20_poly1305_encrypt(k.key, nonce, aad, body) };
        out.append(body);
        out.append(tag);
    }
    let n = out.len - 5;
    out[3] = (n >> 8) as! u8;
    out[4] = n as! u8;
    k.seq++;
    return out;
}

// CBC padding in constant time, as Go's extractPadding: how many bytes to
// remove (the padding and its length byte), and all ones when it is well
// formed. A bad padding removes one byte, so that the MAC still covers
// the rest.
fn cbc_padding(p: const u8[:]) -> i64, u32 {
    let n: u32 = p[p.len - 1];
    var good: u32 = 1 ^ bignum::ct_lt_u32((p.len - 1) as! u32, n);
    let check = ::min(256, p.len);
    for i in check {
        let in_pad = 1 ^ bignum::ct_lt_u32(n, i as! u32);         // i <= n
        let b: u32 = p[p.len - 1 - i];
        good &= 1 ^ (in_pad & (1 ^ bignum::ct_eq_u32(b, n)));
    }
    let mask = bignum::ct_mask(good);
    let remove: i64 = (n & mask) + 1;
    return remove, mask;
}

// The ml-byte MAC at p[dlen..], read without an address that depends on
// dlen: every byte where it could be (the last 256 + ml) is read, and
// kept where it lines up.
fn cbc_mac_at(p: const u8[:], dlen: i64, ml: i64) -> u8[>..] {
    var mac: u8[>..] = [];
    mac.resize(ml, 0);
    for i in ::max(0, p.len - ml - 256)..p.len {
        let b: u32 = p[i];
        for j in ml {
            let m = bignum::ct_mask(bignum::ct_eq_u32(i as! u32, (dlen + j) as! u32));
            mac[j] |= (b & m) as! u8;
        }
    }
    return mac;
}

// Opens a TLS 1.2 record: its type, the plaintext, and the alert when it
// fails (0 for none). For CBC, a bad padding and a bad MAC look the same,
// and cost the same, against Lucky13 (AlFardan and Paterson, 2013): the
// MAC is computed in constant time over the length the padding gives
// (bignum::hmac_prefix_ct; the padding is at most 256 bytes, so that
// length is one of the last 256), and read in constant time.
fn open_record12(k: RecordKeys&, rec: const u8[:]) -> u8, u8[>..], u8 {
    var out: u8[>..] = [];
    if rec.len < 5 || rec[1] != 3 || rec[2] != 3 { return 0, out, ALERT_PROTOCOL_VERSION; }
    let ctype = rec[0];
    let n = (rec[3] as i64) << 8 | rec[4];
    if n != rec.len - 5 { return 0, out, ALERT_DECODE_ERROR; }
    if n > MAX_CIPHERTEXT12 { return 0, out, ALERT_RECORD_OVERFLOW; }
    if k.suite.aead == AEAD_AES_CBC {
        let ml = k.suite.mac / 8;
        if n % 16 != 0 || n < 16 + (ml + 16) / 16 * 16 { return 0, out, ALERT_BAD_RECORD_MAC; }
        out.append(rec[21..]);
        bignum::cbc_decrypt(k.gcm.aes, rec[5..21], out);
        let remove, good = cbc_padding(out);
        var dlen = out.len - ml - remove;
        let neg = ((dlen as! u64) >> 63) as! u32;
        dlen = bignum::ct_select_u32(bignum::ct_mask(neg), 0, dlen as! u32);
        let dmax = out.len - ml;
        let want = bignum::hmac_prefix_ct(k.suite.mac, k.mac_key, aad12(k, ctype, dlen), out[..dmax], dlen,
                                          ::max(0, dmax - 256));
        let got = cbc_mac_at(out, dlen, ml);
        let ok = bignum::ct_eq_bytes(want, got) & good & 1;
        if ok != 1 { out.clear(); return 0, out, ALERT_BAD_RECORD_MAC; }
        out.resize(dlen);
    } else {
        let explicit = if k.suite.aead == AEAD_AES_GCM { 8 } else { 0 };
        if n < explicit + 16 { return 0, out, ALERT_BAD_RECORD_MAC; }
        out.append(rec[5 + explicit..rec.len - 16]);
        let aad = aad12(k, ctype, out.len);
        var nonce: u8[12] = [0; 12];
        if explicit > 0 {
            for i in 4 { nonce[i] = k.iv[i]; }
            for i in 8 { nonce[4 + i] = rec[5 + i]; }
        } else {
            nonce = record_nonce(k);
        }
        let tag = rec[rec.len - 16..];
        let ok = if k.suite.aead == AEAD_AES_GCM { bignum::gcm_decrypt(k.gcm, nonce, aad, out, tag) }
                 else { bignum::chacha20_poly1305_decrypt(k.key, nonce, aad, out, tag) };
        if !ok { out.clear(); return 0, out, ALERT_BAD_RECORD_MAC; }
    }
    if out.len > MAX_FRAGMENT { out.clear(); return 0, out, ALERT_RECORD_OVERFLOW; }
    k.seq++;
    return ctype, out, 0;
}

// The per-record nonce: the IV xor the 64-bit sequence number, right-aligned.
fn record_nonce(k: const RecordKeys&) -> u8[12] {
    var n = k.iv;
    for i in 8 { n[4 + i] ^= (k.seq >> (56 - 8 * i)) as! u8; }
    return n;
}

fn header(ctype: u8, version: u16, len: i64) -> u8[5] {
    [ctype, (version >> 8) as! u8, version as! u8, (len >> 8) as! u8, len as! u8]
}

// A plaintext record (TLSPlaintext): the ClientHello, ServerHello and
// alerts before keys exist, and change_cipher_spec. The first ClientHello
// may say version 0x0301; everything else says 0x0303.
fn plain_record(ctype: u8, payload: const u8[:], version: u16 = 0x0303) -> u8[>..] {
    assert(payload.len <= MAX_FRAGMENT);
    var out: u8[>..] = [];
    out.append(header(ctype, version, payload.len));
    out.append(payload);
    return out;
}

// Protects one record (TLSCiphertext): payload, its real content type and
// `padding` zero bytes are encrypted under an outer type of
// application_data, with the record header as additional data.
fn seal_record(k: RecordKeys&, ctype: u8, payload: const u8[:], padding: i64 = 0) -> u8[>..] {
    if k.v12 { return seal_record12(k, ctype, payload); }
    assert(k.seq != 0xffffffffffffffff);                  // the keys must be updated first
    let inner_len = payload.len + 1 + padding;
    assert(payload.len <= MAX_FRAGMENT && inner_len <= MAX_FRAGMENT + 1 && padding >= 0);
    var out: u8[>..] = [];
    out.append(header(CT_APPLICATION_DATA, 0x0303, inner_len + 16));
    out.append(payload);
    out.push(ctype);
    for i in padding { out.push(0); }
    let nonce = record_nonce(k);
    let aad = out[..5];
    let body = out[5..];
    let tag = if k.suite.aead == AEAD_AES_GCM {
        bignum::gcm_encrypt(k.gcm, nonce, aad, body)
    } else {
        bignum::chacha20_poly1305_encrypt(k.key, nonce, aad, body)
    };
    out.append(tag);
    k.seq++;
    return out;
}

// Seals data of any length as records of at most MAX_FRAGMENT bytes.
fn seal_records(k: RecordKeys&, ctype: u8, data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var off = 0;
    loop {
        let n = ::min(MAX_FRAGMENT, data.len - off);
        out.append(seal_record(k, ctype, data[off..off + n]));
        off += n;
        if off >= data.len { break; }
    }
    return out;
}

// Opens one protected record: the inner content type, the plaintext, and
// the alert to send when it fails (0 for none). The sequence number moves
// on only for a record that opened.
fn open_record(k: RecordKeys&, rec: const u8[:]) -> u8, u8[>..], u8 {
    if k.v12 { return open_record12(k, rec); }
    var out: u8[>..] = [];
    if rec.len < 5 || rec[0] != CT_APPLICATION_DATA || rec[1] != 3 || rec[2] != 3 {
        return 0, out, ALERT_UNEXPECTED_MESSAGE;
    }
    let n = (rec[3] as i64) << 8 | rec[4];
    if n != rec.len - 5 { return 0, out, ALERT_DECODE_ERROR; }
    if n > MAX_CIPHERTEXT { return 0, out, ALERT_RECORD_OVERFLOW; }
    if n < 17 { return 0, out, ALERT_BAD_RECORD_MAC; }
    out.append(rec[5..rec.len - 16]);
    let nonce = record_nonce(k);
    let tag = rec[rec.len - 16..];
    let ok = if k.suite.aead == AEAD_AES_GCM {
        bignum::gcm_decrypt(k.gcm, nonce, rec[..5], out, tag)
    } else {
        bignum::chacha20_poly1305_decrypt(k.key, nonce, rec[..5], out, tag)
    };
    if !ok { out.clear(); return 0, out, ALERT_BAD_RECORD_MAC; }
    k.seq++;
    // TLSInnerPlaintext, padding and all, is at most 2^14 + 1 bytes (§5.4).
    if out.len > MAX_FRAGMENT + 1 { out.clear(); return 0, out, ALERT_RECORD_OVERFLOW; }
    // The content type is the last non-zero byte; zeros after it are padding.
    var end = out.len;
    while end > 0 && out[end - 1] == 0 { end--; }
    if end == 0 { out.clear(); return 0, out, ALERT_UNEXPECTED_MESSAGE; }
    let ctype = out[end - 1];
    out.resize(end - 1);
    if out.len > MAX_FRAGMENT { out.clear(); return 0, out, ALERT_RECORD_OVERFLOW; }
    return ctype, out, 0;
}

// The length of the first whole record in buf: 0 while more bytes are
// needed, -1 for a header no peer sends (an unknown type, a major version
// other than 3, or a length past the limit; record_alert says which).
// The minor version is not checked: a first ClientHello's record may say
// 0x0300, and TLS 1.3 ignores it (RFC 8446 §5.1), as Go does until the
// version is agreed. With tls12, any record may be as long as a TLS 1.2
// ciphertext.
fn record_length(buf: const u8[:], tls12: bool = false) -> i64 {
    if buf.len < 5 { return 0; }
    if record_alert(buf, tls12) != 0 { return -1; }
    let n = (buf[3] as i64) << 8 | buf[4];
    if buf.len < 5 + n { return 0; }
    return 5 + n;
}

// The alert for a header record_length refuses, 0 for one it takes:
// unexpected_message for an unknown type, protocol_version for a major
// version other than 3, record_overflow for a length past the limit.
fn record_alert(buf: const u8[:], tls12: bool = false) -> u8 {
    let t = buf[0];
    if t < CT_CHANGE_CIPHER_SPEC || t > CT_APPLICATION_DATA { return ALERT_UNEXPECTED_MESSAGE; }
    if buf[1] != 3 { return ALERT_PROTOCOL_VERSION; }
    let n = (buf[3] as i64) << 8 | buf[4];
    if tls12 { if n > MAX_CIPHERTEXT12 { return ALERT_RECORD_OVERFLOW; } }
    else if n > MAX_CIPHERTEXT || (t != CT_APPLICATION_DATA && n > MAX_FRAGMENT) { return ALERT_RECORD_OVERFLOW; }
    return 0;
}

// A handshake message: type, 24-bit length, body.
fn handshake_message(msg_type: u8, body: const u8[:]) -> u8[>..] {
    assert(body.len < 1 << 24);
    var out: u8[>..] = [];
    out.push(msg_type);
    out.push((body.len >> 16) as! u8);
    out.push((body.len >> 8) as! u8);
    out.push(body.len as! u8);
    out.append(body);
    return out;
}

// The length of the first whole handshake message in buf (header
// included), or 0 while more bytes are needed. Messages may span records,
// so the caller collects handshake records' plaintexts in one buffer.
fn handshake_length(buf: const u8[:]) -> i64 {
    if buf.len < 4 { return 0; }
    let n = (buf[1] as i64) << 16 | (buf[2] as i64) << 8 | buf[3];
    if buf.len < 4 + n { return 0; }
    return 4 + n;
}

// An alert's two bytes.
fn alert(level: u8, desc: u8) -> u8[2] { [level, desc] }
