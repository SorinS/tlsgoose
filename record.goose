// tls.record: the TLS 1.3 record layer (RFC 8446 §5): plaintext records,
// protected records with any of the three AEADs, the per-record nonce from
// the sequence number, content-type hiding and padding, size limits, and
// splitting a byte stream into records and handshake messages.

namespace tls;

import std;
import tls;
import schedule;
import bignum;
import bignum.gcm;
import bignum.chacha20;

// The largest plaintext fragment, and the most a protected record may
// add to it (§5.1, §5.2).
let MAX_FRAGMENT: i64 = 16384;
let MAX_CIPHERTEXT: i64 = 16384 + 256;

// One direction's protection: the AEAD's key (expanded once for AES), the
// static IV, and the sequence number of the next record.
struct RecordKeys { suite: Suite, key: u8[..32], iv: u8[12], seq: u64, gcm: bignum::AesGcm }

// The keys for a traffic secret, at sequence number 0.
fn record_keys(s: Suite, secret: const u8[:]) -> RecordKeys {
    let key = traffic_key(s, secret);
    let iv = traffic_iv(s, secret);
    var k = RecordKeys { suite: s, key: [], iv: [0; 12], seq: 0, gcm: bignum::gcm_init(key) };
    k.key.append(key);
    for i in 12 { k.iv[i] = iv[i]; }
    return k;
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
// needed, -1 for a header no TLS 1.3 peer sends (an unknown type, a
// version other than 0x0301 or 0x0303, or a length past the limit).
fn record_length(buf: const u8[:]) -> i64 {
    if buf.len < 5 { return 0; }
    let t = buf[0];
    if t < CT_CHANGE_CIPHER_SPEC || t > CT_APPLICATION_DATA { return -1; }
    if buf[1] != 3 || (buf[2] != 1 && buf[2] != 3) { return -1; }
    let n = (buf[3] as i64) << 8 | buf[4];
    if n > MAX_CIPHERTEXT || (t != CT_APPLICATION_DATA && n > MAX_FRAGMENT) { return -1; }
    if buf.len < 5 + n { return 0; }
    return 5 + n;
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
