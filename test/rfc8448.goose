// The simple 1-RTT handshake of RFC 8448 §3, end to end: from the two
// X25519 key pairs through the key schedule, the Finished messages, and
// every record of the trace. Records sealed here must come out byte for
// byte as the RFC prints them, open again to the same plaintext, and fail
// when changed. Values come from vectors/rfc8448.txt (scripts/rfc8448.py).
import std;
import tls from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls.schedule;
import tls.record;
import bignum.x25519;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// The value the trace prints under a label.
fn rfc(label: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/rfc8448.txt"), '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == label { return unhex(w[1]); }
    }
    print("no such label: ", label);
    assert(false);
    var none: u8[>..] = [];
    return none;
}

// Opens a record and checks it gives this type and payload, then that a
// changed copy is refused without moving the sequence number.
fn check_open(what: const u8[:], k: tls::RecordKeys&, rec: const u8[:], ctype: u8, payload: const u8[:]) {
    var bad: u8[>..] = [];
    bad.append(rec);
    bad[bad.len / 2] ^= 1;
    let seq = k.seq;
    let t0, p0, a0 = tls::open_record(k, bad);
    check(what, a0 == tls::ALERT_BAD_RECORD_MAC && k.seq == seq);
    let t, p, a = tls::open_record(k, rec);
    check(what, a == 0 && t == ctype && p == payload);
}

fn main() {
    let s, oks = tls::suite(tls::TLS_AES_128_GCM_SHA256);
    check("suite", oks && s.hash == 256 && s.key_len == 16);

    // Key exchange.
    let c_sk = rfc("client.create_an_ephemeral_x25519_key_pair.private_key");
    let c_pk = rfc("client.create_an_ephemeral_x25519_key_pair.public_key");
    let s_sk = rfc("server.create_an_ephemeral_x25519_key_pair.private_key");
    let s_pk = rfc("server.create_an_ephemeral_x25519_key_pair.public_key");
    check("client public", bignum::x25519_base(c_sk) == c_pk);
    check("server public", bignum::x25519_base(s_sk) == s_pk);
    let shared, okx = bignum::x25519_shared(c_sk, s_pk);
    let shared2, okx2 = bignum::x25519_shared(s_sk, c_pk);
    check("shared", okx && okx2 && shared == shared2 && shared == rfc("server.extract_secret_handshake.ikm"));

    // The hellos travel in plaintext records.
    let ch = rfc("client.construct_a_clienthello_handshake_message.clienthello");
    let sh = rfc("server.construct_a_serverhello_handshake_message.serverhello");
    let ch_rec = rfc("client.send_handshake_record.complete_record");
    check("ClientHello record", tls::plain_record(tls::CT_HANDSHAKE, ch, 0x0301) == ch_rec);
    check("ServerHello record", tls::plain_record(tls::CT_HANDSHAKE, sh) == rfc("server.send_handshake_record.complete_record"));
    check("record length", tls::record_length(ch_rec) == ch_rec.len && tls::record_length(ch_rec[..100]) == 0);
    check("handshake length", tls::handshake_length(ch) == ch.len && tls::handshake_length(ch[..3]) == 0);

    // The schedule through the handshake secrets.
    var sch = tls::schedule(256, "");
    check("early", sch.early == rfc("server.extract_secret_early.secret"));
    var th = tls::transcript(256);
    tls::transcript_add(th, ch);
    tls::transcript_add(th, sh);
    let th_hello = tls::transcript_hash(th);
    check("hello hash", th_hello == rfc("server.derive_secret_tls13_c_hs_traffic.hash"));
    check("expand label", tls::hkdf_expand_label(256, sch.early, "derived", tls::empty_hash(256), 32)
          == rfc("server.derive_secret_for_handshake_tls13_derived.expanded"));
    tls::schedule_handshake(sch, shared, th_hello);
    check("handshake secret", sch.handshake == rfc("server.extract_secret_handshake.secret"));
    check("c hs traffic", sch.c_hs == rfc("server.derive_secret_tls13_c_hs_traffic.expanded"));
    check("s hs traffic", sch.s_hs == rfc("server.derive_secret_tls13_s_hs_traffic.expanded"));
    check("s hs key", tls::traffic_key(s, sch.s_hs) == rfc("server.derive_write_traffic_keys_for_handshake_data.key_expanded"));
    check("s hs iv", tls::traffic_iv(s, sch.s_hs) == rfc("server.derive_write_traffic_keys_for_handshake_data.iv_expanded"));
    check("c hs key", tls::traffic_key(s, sch.c_hs) == rfc("server.derive_read_traffic_keys_for_handshake_data.key_expanded"));
    check("c hs iv", tls::traffic_iv(s, sch.c_hs) == rfc("server.derive_read_traffic_keys_for_handshake_data.iv_expanded"));

    // The server's encrypted flight, ending in its Finished.
    let ee = rfc("server.construct_an_encryptedextensions_handshake_message.encryptedextensions");
    let cert = rfc("server.construct_a_certificate_handshake_message.certificate");
    let cv = rfc("server.construct_a_certificateverify_handshake_message.certificateverify");
    tls::transcript_add(th, ee);
    tls::transcript_add(th, cert);
    tls::transcript_add(th, cv);
    let s_fin = tls::finished_data(256, sch.s_hs, tls::transcript_hash(th));
    check("server finished", s_fin == rfc("server.calculate_finished_tls13_finished.finished"));
    let s_fin_msg = tls::handshake_message(tls::HS_FINISHED, s_fin);
    check("server finished message", s_fin_msg == rfc("server.construct_a_finished_handshake_message.finished"));
    check("finished check", tls::finished_ok(256, sch.s_hs, tls::transcript_hash(th), s_fin));
    var flight: u8[>..] = [];
    flight.append(ee);
    flight.append(cert);
    flight.append(cv);
    flight.append(s_fin_msg);
    check("flight", flight == rfc("server.send_handshake_record.payload.2"));
    var s_hs_w = tls::record_keys(s, sch.s_hs);
    let flight_rec = tls::seal_record(s_hs_w, tls::CT_HANDSHAKE, flight);
    check("server flight record", flight_rec == rfc("server.send_handshake_record.complete_record.2"));
    var s_hs_r = tls::record_keys(s, sch.s_hs);
    check_open("server flight open", s_hs_r, flight_rec, tls::CT_HANDSHAKE, flight);
    // The flight splits back into its four messages.
    var off = 0;
    var count = 0;
    while off < flight.len {
        let n = tls::handshake_length(flight[off..]);
        assert(n > 0);
        off += n;
        count++;
    }
    check("four messages", count == 4 && off == flight.len);

    // Application secrets, then the client's Finished.
    tls::transcript_add(th, s_fin_msg);
    let th_sf = tls::transcript_hash(th);
    check("server finished hash", th_sf == rfc("server.derive_secret_tls13_c_ap_traffic.hash"));
    tls::schedule_master(sch, th_sf);
    check("master", sch.master == rfc("server.extract_secret_master.secret"));
    check("c ap traffic", sch.c_ap == rfc("server.derive_secret_tls13_c_ap_traffic.expanded"));
    check("s ap traffic", sch.s_ap == rfc("server.derive_secret_tls13_s_ap_traffic.expanded"));
    check("exporter", sch.exporter == rfc("server.derive_secret_tls13_exp_master.expanded"));
    check("s ap key", tls::traffic_key(s, sch.s_ap) == rfc("server.derive_write_traffic_keys_for_application_data.key_expanded"));
    check("c ap key", tls::traffic_key(s, sch.c_ap) == rfc("client.derive_write_traffic_keys_for_application_data.key_expanded"));
    check("c ap iv", tls::traffic_iv(s, sch.c_ap) == rfc("client.derive_write_traffic_keys_for_application_data.iv_expanded"));
    let c_fin = tls::finished_data(256, sch.c_hs, th_sf);
    check("client finished", c_fin == rfc("client.calculate_finished_tls13_finished.finished"));
    let c_fin_msg = tls::handshake_message(tls::HS_FINISHED, c_fin);
    var c_hs_w = tls::record_keys(s, sch.c_hs);
    let c_fin_rec = tls::seal_record(c_hs_w, tls::CT_HANDSHAKE, c_fin_msg);
    check("client finished record", c_fin_rec == rfc("client.send_handshake_record.complete_record.2"));
    var c_hs_r = tls::record_keys(s, sch.c_hs);
    check_open("client finished open", c_hs_r, c_fin_rec, tls::CT_HANDSHAKE, c_fin_msg);
    var wrong = copy(c_fin);
    wrong[0] ^= 1;
    check("wrong finished", !tls::finished_ok(256, sch.c_hs, th_sf, wrong));

    // Resumption.
    tls::transcript_add(th, c_fin_msg);
    let th_cf = tls::transcript_hash(th);
    check("client finished hash", th_cf == rfc("client.derive_secret_tls13_res_master.hash"));
    tls::schedule_resumption(sch, th_cf);
    check("res master", sch.resumption == rfc("client.derive_secret_tls13_res_master.expanded"));
    let nonce: u8[2] = [0, 0];
    check("resumption psk", tls::resumption_psk(256, sch.resumption, nonce)
          == rfc("server.generate_resumption_secret_tls13_resumption.expanded"));

    // Application records: the server's ticket and data, the client's
    // data, and both close_notify alerts, each under its sequence number.
    var s_ap_w = tls::record_keys(s, sch.s_ap);
    var c_ap_w = tls::record_keys(s, sch.c_ap);
    var s_ap_r = tls::record_keys(s, sch.s_ap);
    var c_ap_r = tls::record_keys(s, sch.c_ap);
    let nst = rfc("server.send_handshake_record.payload.3");
    let nst_rec = tls::seal_record(s_ap_w, tls::CT_HANDSHAKE, nst);
    check("ticket record", nst_rec == rfc("server.send_handshake_record.complete_record.3"));
    check_open("ticket open", s_ap_r, nst_rec, tls::CT_HANDSHAKE, nst);
    let c_data = rfc("client.send_application_data_record.payload");
    let c_data_rec = tls::seal_record(c_ap_w, tls::CT_APPLICATION_DATA, c_data);
    check("client data record", c_data_rec == rfc("client.send_application_data_record.complete_record"));
    check_open("client data open", c_ap_r, c_data_rec, tls::CT_APPLICATION_DATA, c_data);
    let s_data = rfc("server.send_application_data_record.payload");
    let s_data_rec = tls::seal_record(s_ap_w, tls::CT_APPLICATION_DATA, s_data);
    check("server data record", s_data_rec == rfc("server.send_application_data_record.complete_record"));
    check_open("server data open", s_ap_r, s_data_rec, tls::CT_APPLICATION_DATA, s_data);
    let close = tls::alert(tls::ALERT_WARNING, tls::ALERT_CLOSE_NOTIFY);
    let c_alert = tls::seal_record(c_ap_w, tls::CT_ALERT, close);
    check("client alert record", c_alert == rfc("client.send_alert_record.complete_record"));
    check_open("client alert open", c_ap_r, c_alert, tls::CT_ALERT, close);
    let s_alert = tls::seal_record(s_ap_w, tls::CT_ALERT, close);
    check("server alert record", s_alert == rfc("server.send_alert_record.complete_record"));
    check_open("server alert open", s_ap_r, s_alert, tls::CT_ALERT, close);
    // A replayed record no longer opens: its sequence number has passed.
    let tr, pr, ar = tls::open_record(s_ap_r, s_data_rec);
    check("replay", ar == tls::ALERT_BAD_RECORD_MAC);

    print("rfc 8448: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
