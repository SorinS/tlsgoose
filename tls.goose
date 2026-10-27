// tls: TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246) on bignum's primitives.
// This module holds the cipher suites and the wire constants;
// tls.schedule is the key schedule (HKDF-Expand-Label, Derive-Secret,
// traffic keys, Finished, and TLS 1.2's PRF), and tls.record protects and
// frames records. No sockets: everything works on
// byte strings, so the caller owns the I/O.

namespace tls;

import std;
import bignum from "../bigmongoose.git";
import asn1 from "../asn1goose.git";
import x509 from "../x509goose.git";

// Record content types (RFC 8446 §5.1).
let CT_CHANGE_CIPHER_SPEC: u8 = 20;
let CT_ALERT: u8 = 21;
let CT_HANDSHAKE: u8 = 22;
let CT_APPLICATION_DATA: u8 = 23;

// Handshake message types (§4).
let HS_HELLO_REQUEST: u8 = 0;            // TLS 1.2
let HS_CLIENT_HELLO: u8 = 1;
let HS_SERVER_HELLO: u8 = 2;
let HS_NEW_SESSION_TICKET: u8 = 4;
let HS_END_OF_EARLY_DATA: u8 = 5;
let HS_ENCRYPTED_EXTENSIONS: u8 = 8;
let HS_CERTIFICATE: u8 = 11;
let HS_SERVER_KEY_EXCHANGE: u8 = 12;     // TLS 1.2
let HS_CERTIFICATE_REQUEST: u8 = 13;
let HS_SERVER_HELLO_DONE: u8 = 14;       // TLS 1.2
let HS_CERTIFICATE_VERIFY: u8 = 15;
let HS_CLIENT_KEY_EXCHANGE: u8 = 16;     // TLS 1.2
let HS_FINISHED: u8 = 20;
let HS_KEY_UPDATE: u8 = 24;
let HS_MESSAGE_HASH: u8 = 254;

// Alert levels and the descriptions a TLS 1.3 stack sends (§6).
let ALERT_WARNING: u8 = 1;
let ALERT_FATAL: u8 = 2;
let ALERT_CLOSE_NOTIFY: u8 = 0;
let ALERT_UNEXPECTED_MESSAGE: u8 = 10;
let ALERT_BAD_RECORD_MAC: u8 = 20;
let ALERT_RECORD_OVERFLOW: u8 = 22;
let ALERT_HANDSHAKE_FAILURE: u8 = 40;
let ALERT_BAD_CERTIFICATE: u8 = 42;
let ALERT_CERTIFICATE_EXPIRED: u8 = 45;
let ALERT_ILLEGAL_PARAMETER: u8 = 47;
let ALERT_UNKNOWN_CA: u8 = 48;
let ALERT_DECODE_ERROR: u8 = 50;
let ALERT_DECRYPT_ERROR: u8 = 51;
let ALERT_PROTOCOL_VERSION: u8 = 70;
let ALERT_INAPPROPRIATE_FALLBACK: u8 = 86;
let ALERT_INTERNAL_ERROR: u8 = 80;
let ALERT_NO_RENEGOTIATION: u8 = 100;
let ALERT_MISSING_EXTENSION: u8 = 109;
let ALERT_UNRECOGNIZED_NAME: u8 = 112;
let ALERT_CERTIFICATE_REQUIRED: u8 = 116;
let ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;
let ALERT_ECH_REQUIRED: u8 = 121;

// Protocol versions.
let VERSION_TLS12: u16 = 0x0303;
let VERSION_TLS13: u16 = 0x0304;

// The cipher suites of TLS 1.3 (§B.4) this package implements.
let TLS_AES_128_GCM_SHA256: u16 = 0x1301;
let TLS_AES_256_GCM_SHA384: u16 = 0x1302;
let TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// The TLS 1.2 suites, as Go has them: ECDHE with ECDSA or RSA signatures
// and AES-GCM (RFC 5289), ChaCha20-Poly1305 (RFC 7905) or AES-CBC with
// HMAC (RFC 4492, 5246); and RSA key exchange, which Go no longer enables
// by default and neither does this package.
let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
let TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
let TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
let TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
let TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
let TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
let TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
let TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
let TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
let TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
let TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
let TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
// Signals (as suites): a client that falls back to a lower version than
// it supports (RFC 7507), and one that supports secure renegotiation
// without the extension (RFC 5746).
let TLS_FALLBACK_SCSV: u16 = 0x5600;
let TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

let AEAD_AES_GCM: i64 = 0;
let AEAD_CHACHA20_POLY1305: i64 = 1;
let AEAD_AES_CBC: i64 = 2;            // TLS 1.2: AES-CBC with HMAC, not an AEAD

// TLS 1.2 key exchanges: none (a TLS 1.3 suite), ECDHE signed with ECDSA
// (or Ed25519) or RSA, or RSA encryption.
let KX_NONE: i64 = 0;
let KX_ECDHE_ECDSA: i64 = 1;
let KX_ECDHE_RSA: i64 = 2;
let KX_RSA: i64 = 3;

// A suite's hash (256 or 384, as bignum.hmac takes it: TLS 1.3's HKDF
// hash, TLS 1.2's PRF hash), its AEAD and key length; for TLS 1.2 its key
// exchange and, for CBC, its HMAC hash (160 or 256).
struct Suite { id: u16, hash: i64, aead: i64, key_len: i64, kx: i64, mac: i64 }

fn suite_of(id: u16, hash: i64, aead: i64, key_len: i64, kx: i64, mac: i64) -> Suite, bool {
    return Suite { id: id, hash: hash, aead: aead, key_len: key_len, kx: kx, mac: mac }, true;
}

// The suite for an id, and false for one this package does not know.
fn suite(id: u16) -> Suite, bool {
    if id == TLS_AES_128_GCM_SHA256 { return suite_of(id, 256, AEAD_AES_GCM, 16, KX_NONE, 0); }
    if id == TLS_AES_256_GCM_SHA384 { return suite_of(id, 384, AEAD_AES_GCM, 32, KX_NONE, 0); }
    if id == TLS_CHACHA20_POLY1305_SHA256 { return suite_of(id, 256, AEAD_CHACHA20_POLY1305, 32, KX_NONE, 0); }
    if id == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 { return suite_of(id, 256, AEAD_AES_GCM, 16, KX_ECDHE_ECDSA, 0); }
    if id == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 { return suite_of(id, 384, AEAD_AES_GCM, 32, KX_ECDHE_ECDSA, 0); }
    if id == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 { return suite_of(id, 256, AEAD_AES_GCM, 16, KX_ECDHE_RSA, 0); }
    if id == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 { return suite_of(id, 384, AEAD_AES_GCM, 32, KX_ECDHE_RSA, 0); }
    if id == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
        return suite_of(id, 256, AEAD_CHACHA20_POLY1305, 32, KX_ECDHE_RSA, 0);
    }
    if id == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
        return suite_of(id, 256, AEAD_CHACHA20_POLY1305, 32, KX_ECDHE_ECDSA, 0);
    }
    if id == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_ECDHE_ECDSA, 160); }
    if id == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 32, KX_ECDHE_ECDSA, 160); }
    if id == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_ECDHE_RSA, 160); }
    if id == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 32, KX_ECDHE_RSA, 160); }
    if id == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_ECDHE_ECDSA, 256); }
    if id == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_ECDHE_RSA, 256); }
    if id == TLS_RSA_WITH_AES_128_GCM_SHA256 { return suite_of(id, 256, AEAD_AES_GCM, 16, KX_RSA, 0); }
    if id == TLS_RSA_WITH_AES_256_GCM_SHA384 { return suite_of(id, 384, AEAD_AES_GCM, 32, KX_RSA, 0); }
    if id == TLS_RSA_WITH_AES_128_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_RSA, 160); }
    if id == TLS_RSA_WITH_AES_256_CBC_SHA { return suite_of(id, 256, AEAD_AES_CBC, 32, KX_RSA, 160); }
    if id == TLS_RSA_WITH_AES_128_CBC_SHA256 { return suite_of(id, 256, AEAD_AES_CBC, 16, KX_RSA, 256); }
    let s, ok = suite_of(0, 256, AEAD_AES_GCM, 16, KX_NONE, 0);
    return s, false;
}

// Whether a suite is one of TLS 1.2's (else TLS 1.3's).
fn is_tls12_suite(s: Suite) -> bool { s.kx != KX_NONE }

fn hash_len(s: Suite) -> i64 { s.hash / 8 }

// Go's default TLS 1.2 suites, in its order.
let DEFAULT_SUITES12: u16[10] = [
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014,
];
