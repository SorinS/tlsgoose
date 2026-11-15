// records: the TLS 1.3 key schedule and record layer on their own, for a
// protocol that runs its own handshake (as QUIC or DTLS do) or a test
// harness. Two sides agree on an X25519 secret, run the schedule over a
// transcript, protect records under the traffic keys, check Finished,
// update keys and export keying material.
//
//   goose examples/records.goose

import std;
import tls from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.schedule;
import tls.record;

fn run() {
    let s, ok = tls::suite(tls::TLS_AES_128_GCM_SHA256);
    guard ok else { print("records: unknown suite"); exit(1); }

    // The (EC)DHE secret: X25519 between the two sides.
    let c_sk, c_pk = bignum::x25519_keypair();
    let s_sk, s_pk = bignum::x25519_keypair();
    let shared, ok1 = bignum::x25519_shared(c_sk, s_pk);
    let shared2, ok2 = bignum::x25519_shared(s_sk, c_pk);
    guard ok1 && ok2 && shared == shared2 else { print("records: X25519 failed"); exit(1); }

    // The transcript through the hellos (here stand-in messages), then
    // the handshake secrets.
    var th = tls::transcript(s.hash);
    tls::transcript_add(th, tls::handshake_message(tls::HS_CLIENT_HELLO, c_pk));
    tls::transcript_add(th, tls::handshake_message(tls::HS_SERVER_HELLO, s_pk));
    var sch = tls::schedule(s.hash, "");                         // no PSK
    tls::schedule_handshake(sch, shared, tls::transcript_hash(th));

    // The server writes under s_hs, the client reads with the same secret.
    var out = tls::record_keys(s, sch.s_hs);
    var inn = tls::record_keys(s, sch.s_hs);
    let ee = tls::handshake_message(tls::HS_ENCRYPTED_EXTENSIONS, "\x00\x00");
    let rec = tls::seal_record(out, tls::CT_HANDSHAKE, ee, 32);   // 32 bytes of padding hide the length
    guard tls::record_length(rec) == rec.len else { print("records: framing"); exit(1); }
    let ctype, plain, alert = tls::open_record(inn, rec);
    guard alert == 0 && ctype == tls::CT_HANDSHAKE && plain == ee else { print("records: open failed"); exit(1); }
    print("handshake record: ", ee.len, " bytes sealed into ", rec.len);

    // A changed byte: refused with bad_record_mac, and the sequence number
    // stays where it was.
    let rec2 = tls::seal_record(out, tls::CT_HANDSHAKE, "more");
    var bad = copy(rec2);
    bad[bad.len - 1] ^= 1;
    let t2, p2, a2 = tls::open_record(inn, bad);
    guard a2 == tls::ALERT_BAD_RECORD_MAC else { print("records: a changed record opened"); exit(1); }
    let t3, p3, a3 = tls::open_record(inn, rec2);
    guard a3 == 0 && p3 == "more" else { print("records: the good record did not open"); exit(1); }
    print("a changed record: bad_record_mac");

    // Finished over the transcript, then the application secrets.
    tls::transcript_add(th, ee);
    let fin = tls::finished_data(s.hash, sch.s_hs, tls::transcript_hash(th));
    guard tls::finished_ok(s.hash, sch.s_hs, tls::transcript_hash(th), fin) else { print("records: Finished"); exit(1); }
    tls::transcript_add(th, tls::handshake_message(tls::HS_FINISHED, fin));
    tls::schedule_master(sch, tls::transcript_hash(th));

    // Long data is cut into records of at most 16 KiB.
    var app_out = tls::record_keys(s, sch.c_ap);
    var app_in = tls::record_keys(s, sch.c_ap);
    var data: u8[>..] = [];
    data.resize(40000, 'x');
    let stream = tls::seal_records(app_out, tls::CT_APPLICATION_DATA, data);
    var got: u8[>..] = [];
    var pos = 0;
    var count = 0;
    while pos < stream.len {
        let n = tls::record_length(stream[pos..]);           // 0 while a record is incomplete
        guard n > 0 else { print("records: a cut record"); exit(1); }
        let t, p, a = tls::open_record(app_in, stream[pos..pos + n]);
        guard a == 0 && t == tls::CT_APPLICATION_DATA else { print("records: open failed"); exit(1); }
        got.append(p);
        pos += n;
        count++;
    }
    guard got == data else { print("records: data lost"); exit(1); }
    print(data.len, " bytes of application data in ", count, " records");

    // KeyUpdate: both sides move to the next secret.
    let next = tls::next_traffic_secret(s.hash, sch.c_ap);
    var upd_out = tls::record_keys(s, next);
    var upd_in = tls::record_keys(s, next);
    let t4, p4, a4 = tls::open_record(upd_in, tls::seal_record(upd_out, tls::CT_APPLICATION_DATA, "new keys"));
    guard a4 == 0 && p4 == "new keys" else { print("records: key update"); exit(1); }

    // Keying material for another protocol, bound to this handshake.
    let ekm = tls::export_keying_material(s.hash, sch.exporter, "EXPERIMENTAL example", "", 32);
    guard ekm.len == 32 else { print("records: exporter"); exit(1); }
    print("key update and exporter: done");
}

fn main() {
    run();
}
