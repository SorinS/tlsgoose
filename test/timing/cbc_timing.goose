// Timing test of TLS 1.2's CBC records against Lucky13 (AlFardan and
// Paterson, 2013), as bignum's ct_timing (after dudect): records of
// one length whose padding is valid and 1 byte long (class 0) or of a
// random length up to 256 (class 1), every MAC wrong, opened with
// open_record12; Welch's t-test compares the classes' times, over all of
// them and below the 50th to 99th percentile. A |t| above 10 says they
// differ. The control, the MAC as it was before hmac_prefix_ct (a
// separate hash of the padding), must be caught.
//
//	python3 scripts/cbc_timing.py [scale]
//
// Built natively at -O2. Not part of run_tests.py: it wants a quiet
// machine.

import std;
import os;
import math;
import tls from "../..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls.record;

let LIMIT = 10.0;
let LEN: i64 = 1024;                 // plaintext, MAC and padding

var failures = 0;

// A test's runs, each its time in nanoseconds times 2 plus its class.
fn sample(s: i64[>..]&, class: u8, ns: i64) { s.push(2 * ns + class); }

// Welch's t for the runs that took `cut` nanoseconds or less.
fn welch(s: const i64[:], cut: i64) -> f64 {
    var n: f64[2] = [0.0, 0.0];
    var sum: f64[2] = [0.0, 0.0];
    for x in s {
        if x / 2 > cut { continue; }
        n[x & 1] += 1.0;
        sum[x & 1] += x / 2;
    }
    if n[0] < 2.0 || n[1] < 2.0 { return 0.0; }
    let m0 = sum[0] / n[0];
    let m1 = sum[1] / n[1];
    var v: f64[2] = [0.0, 0.0];
    for x in s {
        if x / 2 > cut { continue; }
        let d = x / 2 - (if (x & 1) == 0 { m0 } else { m1 });
        v[x & 1] += d * d;
    }
    let se = sqrt(v[0] / (n[0] - 1.0) / n[0] + v[1] / (n[1] - 1.0) / n[1]);
    if se == 0.0 { return 0.0; }
    return (m0 - m1) / se;
}

// The largest |t| over all the times and the percentile crops.
fn max_t(s: const i64[:]) -> f64 {
    var sorted: i64[>..] = [];
    sorted.append(s);
    sort(sorted);
    var worst = abs(welch(s, sorted[sorted.len - 1] / 2));
    for pct in [50, 60, 70, 80, 90, 95, 99] {
        worst = max(worst, abs(welch(s, sorted[sorted.len * pct / 100] / 2)));
    }
    return worst;
}

// Reports a test; a leak is a failure unless one is expected (the control).
fn report(name: const u8[:], s: const i64[:], leaky: bool) {
    let t = max_t(s);
    let leak = t > LIMIT;
    let ok = leak == leaky;
    if !ok { failures++; }
    let verdict = if leak { "differs" } else { "same" };
    // How far apart the classes are, in time: the medians' difference, and
    // the median itself, so a |t| can be read against the work.
    var c0: i64[>..] = [];
    var c1: i64[>..] = [];
    for x in s { if (x & 1) == 0 { c0.push(x / 2); } else { c1.push(x / 2); } }
    sort(c0);
    sort(c1);
    let m0 = c0[c0.len / 2];
    let m1 = c1[c1.len / 2];
    print(if ok { "ok    " } else { "FAIL  " }, name, ": max |t| = ", t, " over ", s.len,
          " runs (", verdict, if leaky { ", a leak expected" } else { "" }, "); medians ", m0, " and ", m1, " ns");
}

fn random_bytes_into(r: rng&, out: u8[:]) {
    for &b in out { b = r.rand_u64() as! u8; }
}

// Keys for a CBC suite, at random.
fn cbc_keys(r: rng&, id: u16) -> tls::RecordKeys {
    let st, ok = tls::suite(id);
    assert(ok);
    var key: u8[16] = [0; 16];
    var mac_key: u8[>..] = [];
    mac_key.resize(st.mac / 8, 0);
    random_bytes_into(r, key);
    random_bytes_into(r, mac_key);
    let none: u8[0] = [];
    return tls::record_keys12(st, key, mac_key, none);
}

// An application_data record of LEN bytes, encrypted, whose padding is
// valid and padlen + 1 bytes long, and whose MAC is wrong.
fn record(k: const tls::RecordKeys&, r: rng&, padlen: i64) -> u8[>..] {
    var body: u8[>..] = [];
    body.resize(LEN, 0);
    random_bytes_into(r, body);
    // The same 256 writes whatever the padding (the bytes past it kept),
    // so that the classes differ only in the record, not in the work done
    // before it is timed.
    for i in 256 {
        let keep = bignum::ct_mask(bignum::ct_lt_u32(padlen as! u32, i as! u32));
        let old: u32 = body[LEN - 1 - i];
        body[LEN - 1 - i] = bignum::ct_select_u32(keep, old, padlen as! u32) as! u8;
    }
    var iv: u8[16] = [0; 16];
    random_bytes_into(r, iv);
    bignum::cbc_encrypt(k.gcm.aes, iv, body);
    var rec: u8[>..] = [];
    rec.append(tls::header(23, 0x0303, 16 + LEN));
    rec.append(iv);
    rec.append(body);
    return rec;
}

// The CBC open as it was before hmac_prefix_ct: the MAC over the data,
// then a hash of its own over the padding, which does not even out the
// first's work.
fn old_open(k: const tls::RecordKeys&, rec: const u8[:]) -> u32 {
    let ml = k.suite.mac / 8;
    var out: u8[>..] = [];
    out.append(rec[21..]);
    bignum::cbc_decrypt(k.gcm.aes, rec[5..21], out);
    let remove, good = tls::cbc_padding(out);
    var dlen = out.len - ml - remove;
    let neg = ((dlen as! u64) >> 63) as! u32;
    dlen = bignum::ct_select_u32(bignum::ct_mask(neg), 0, dlen as! u32);
    let want = tls::mac12(k, rec[0], out[..dlen]);
    let extra = bignum::hash_bits(k.suite.mac, out[dlen + ml..]);
    return bignum::ct_eq_bytes(want, out[dlen..dlen + ml]) & good & (extra[0] | 1);
}

fn run(name: const u8[:], r: rng&, id: u16, runs: i64, control: bool) {
    var k = cbc_keys(r, id);
    var s: i64[>..] = [];
    var sink: u32 = 0;
    for i in runs {
        let c = (r.rand_u64() & 1) as! u8;
        let padlen = if c == 0 { 0 } else { (r.rand_u64() % 256) as! i64 };
        let rec = record(k, r, padlen);
        let t0 = clock_ns();
        if control {
            sink ^= old_open(k, rec);
        } else {
            let ctype, plain, alert = tls::open_record12(k, rec);
            assert(alert == tls::ALERT_BAD_RECORD_MAC);
        }
        sample(s, c, clock_ns() - t0);
    }
    report(name, s, control);
    if sink == 0xffffffff { print(""); }
}

fn main() {
    let args = args();
    var scale = 1;
    if args.len > 1 {
        let v, ok = parse_int(args[1]);
        if !ok || v < 1 { print("usage: cbc_timing [scale]"); exit(2); }
        scale = v;
    }
    var r = rng { 2026 };
    run("open_record12, AES-CBC with HMAC-SHA-1", r, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 40000 * scale, false);
    run("open_record12, AES-CBC with HMAC-SHA-256", r, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 40000 * scale, false);
    run("the MAC as it was, a hash of its own over the padding (the control)", r, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 40000 * scale, true);
    print(if failures == 0 { "cbc timing: no leak found" } else { "cbc timing: FAILED" });
    exit(if failures == 0 { 0 } else { 1 });
}
