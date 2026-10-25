// tls.record's checks and edge cases: headers record_length refuses,
// records open_record refuses (each with its alert), padding, records with
// no content type, fragmenting long data, the nonce for large sequence
// numbers, KeyUpdate, and the HelloRetryRequest transcript.
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
    if !ok { failures++; print("FAIL ", what); }
}

fn alert_of(k: tls::RecordKeys&, rec: const u8[:]) -> u8 {
    let t, p, a = tls::open_record(k, rec);
    return a;
}

fn main() {
    var secret: u8[48] = [7; 48];
    for id in [tls::TLS_AES_128_GCM_SHA256, tls::TLS_AES_256_GCM_SHA384, tls::TLS_CHACHA20_POLY1305_SHA256] {
        let s, ok = tls::suite(id);
        check("suite", ok);
        var w = tls::record_keys(s, secret[..tls::hash_len(s)]);
        var r = tls::record_keys(s, secret[..tls::hash_len(s)]);

        // Padding hides the length; the type survives it.
        let padded = tls::seal_record(w, tls::CT_APPLICATION_DATA, "abc", 200);
        check("padded size", padded.len == 5 + 3 + 1 + 200 + 16);
        let t, p, a = tls::open_record(r, padded);
        check("padded open", a == 0 && t == tls::CT_APPLICATION_DATA && p == "abc");

        // An inner plaintext of only zeros has no content type.
        let typeless = tls::seal_record(w, 0, "", 5);
        check("no type", alert_of(r, typeless) == tls::ALERT_UNEXPECTED_MESSAGE);

        // Records refused before decryption.
        var rec = tls::seal_record(w, tls::CT_HANDSHAKE, "x");
        var wrong_type = copy(rec);
        wrong_type[0] = tls::CT_HANDSHAKE;
        check("outer type", alert_of(r, wrong_type) == tls::ALERT_UNEXPECTED_MESSAGE);
        var wrong_version = copy(rec);
        wrong_version[2] = 1;
        check("version", alert_of(r, wrong_version) == tls::ALERT_UNEXPECTED_MESSAGE);
        check("truncated", alert_of(r, rec[..rec.len - 1]) == tls::ALERT_DECODE_ERROR);
        var short: u8[>..] = [];
        short.append(rec[..5]);
        short[3] = 0;
        short[4] = 16;
        for i in 16 { short.push(0); }
        check("too short", alert_of(r, short) == tls::ALERT_BAD_RECORD_MAC);
        var big: u8[>..] = [];
        big.append(rec[..5]);
        big[3] = 0x41;
        big[4] = 1;                                      // 2^14 + 257
        big.resize(5 + 16641, 0);
        check("overflow", alert_of(r, big) == tls::ALERT_RECORD_OVERFLOW);
        let tt, pp, aa = tls::open_record(r, rec);
        check("still in step", aa == 0 && pp == "x");

        // Long data goes out as several records of at most 2^14 bytes.
        var data: u8[>..] = [];
        data.resize(40000, 0x5a);
        let recs = tls::seal_records(w, tls::CT_APPLICATION_DATA, data);
        var off = 0;
        var n = 0;
        var back: u8[>..] = [];
        while off < recs.len {
            let len = tls::record_length(recs[off..]);
            check("framed", len > 0 && len <= 5 + tls::MAX_CIPHERTEXT);
            let t2, p2, a2 = tls::open_record(r, recs[off..off + len]);
            check("fragment", a2 == 0 && p2.len <= tls::MAX_FRAGMENT);
            back.append(p2);
            off += len;
            n++;
        }
        check("fragments", n == 3 && back == data);
        let empty = tls::seal_records(w, tls::CT_APPLICATION_DATA, "");
        let t3, p3, a3 = tls::open_record(r, empty);
        check("empty data", a3 == 0 && p3.len == 0);

        // KeyUpdate: the next secret's keys cannot open the old keys' records.
        let next = tls::next_traffic_secret(s.hash, secret[..tls::hash_len(s)]);
        check("next secret", next.len == tls::hash_len(s) && next != secret[..tls::hash_len(s)]);
        var w2 = tls::record_keys(s, next);
        var r2 = tls::record_keys(s, next);
        let rec2 = tls::seal_record(w2, tls::CT_APPLICATION_DATA, "after update");
        check("old keys", alert_of(r, rec2) == tls::ALERT_BAD_RECORD_MAC);
        let t4, p4, a4 = tls::open_record(r2, rec2);
        check("new keys", a4 == 0 && p4 == "after update");
    }

    // The nonce: the IV xor the sequence number in its last 8 bytes.
    let s, ok = tls::suite(tls::TLS_AES_128_GCM_SHA256);
    var k = tls::record_keys(s, secret[..32]);
    let iv = k.iv;
    k.seq = 0x0102030405060708;
    let nonce = tls::record_nonce(k);
    check("nonce head", nonce[0] == iv[0] && nonce[3] == iv[3]);
    check("nonce tail", nonce[4] == iv[4] ^ 1 && nonce[11] == iv[11] ^ 8);

    // Headers record_length refuses.
    let ok_hdr: u8[5] = [23, 3, 3, 0, 0];
    check("empty record", tls::record_length(ok_hdr) == 5);
    let bad_type: u8[5] = [24, 3, 3, 0, 0];
    check("unknown type", tls::record_length(bad_type) == -1);
    let bad_ver: u8[5] = [22, 3, 2, 0, 0];
    check("tls 1.1", tls::record_length(bad_ver) == -1);
    let too_big: u8[5] = [22, 3, 3, 0x40, 1];
    check("plaintext over 2^14", tls::record_length(too_big) == -1);
    let partial: u8[3] = [22, 3, 3];
    check("partial header", tls::record_length(partial) == 0);

    // After a HelloRetryRequest the transcript starts again from
    // message_hash(hash of ClientHello1).
    var th = tls::transcript(256);
    tls::transcript_add(th, "client hello 1");
    tls::transcript_restart_hrr(th);
    var manual = tls::transcript(256);
    let h1 = bignum::sha256("client hello 1");
    let hdr: u8[4] = [254, 0, 0, 32];
    tls::transcript_add(manual, hdr);
    tls::transcript_add(manual, h1);
    check("hrr transcript", tls::transcript_hash(th) == tls::transcript_hash(manual));

    // The exporter depends on its label and context.
    let e1 = tls::export_keying_material(256, secret[..32], "EXPORTER-test", "", 32);
    let e2 = tls::export_keying_material(256, secret[..32], "EXPORTER-test", "ctx", 32);
    check("exporter", e1.len == 32 && e1 != e2);

    print("record api: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
