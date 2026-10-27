// tls: TLS 1.3 (RFC 8446) on bignum's primitives. This module holds the
// cipher suites and the wire constants; tls.schedule is the key schedule
// (HKDF-Expand-Label, Derive-Secret, traffic keys, Finished), and
// tls.record protects and frames records. No sockets: everything works on
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
let HS_CLIENT_HELLO: u8 = 1;
let HS_SERVER_HELLO: u8 = 2;
let HS_NEW_SESSION_TICKET: u8 = 4;
let HS_END_OF_EARLY_DATA: u8 = 5;
let HS_ENCRYPTED_EXTENSIONS: u8 = 8;
let HS_CERTIFICATE: u8 = 11;
let HS_CERTIFICATE_REQUEST: u8 = 13;
let HS_CERTIFICATE_VERIFY: u8 = 15;
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
let ALERT_INTERNAL_ERROR: u8 = 80;
let ALERT_MISSING_EXTENSION: u8 = 109;
let ALERT_UNRECOGNIZED_NAME: u8 = 112;
let ALERT_CERTIFICATE_REQUIRED: u8 = 116;
let ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;
let ALERT_ECH_REQUIRED: u8 = 121;

// The cipher suites of TLS 1.3 (§B.4) this package implements.
let TLS_AES_128_GCM_SHA256: u16 = 0x1301;
let TLS_AES_256_GCM_SHA384: u16 = 0x1302;
let TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

let AEAD_AES_GCM: i64 = 0;
let AEAD_CHACHA20_POLY1305: i64 = 1;

// A suite's hash (256 or 384, as bignum.hmac takes it), its AEAD and key length.
struct Suite { id: u16, hash: i64, aead: i64, key_len: i64 }

// The suite for an id, and false for one this package does not know.
fn suite(id: u16) -> Suite, bool {
    if id == TLS_AES_128_GCM_SHA256 { return Suite { id: id, hash: 256, aead: AEAD_AES_GCM, key_len: 16 }, true; }
    if id == TLS_AES_256_GCM_SHA384 { return Suite { id: id, hash: 384, aead: AEAD_AES_GCM, key_len: 32 }, true; }
    if id == TLS_CHACHA20_POLY1305_SHA256 {
        return Suite { id: id, hash: 256, aead: AEAD_CHACHA20_POLY1305, key_len: 32 }, true;
    }
    return Suite { id: 0, hash: 256, aead: AEAD_AES_GCM, key_len: 16 }, false;
}

fn hash_len(s: Suite) -> i64 { s.hash / 8 }
