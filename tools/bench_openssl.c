/* tools/bench.goose's measurements made with OpenSSL: its client and
 * server in this process, joined by memory BIOs, the same certificates and
 * keys (test/vectors/hs_certs.txt as PEM, written by
 * scripts/bench_openssl.py), the client verifying the chain and the name,
 * no session tickets except to resume. Prints "name value unit" lines, as
 * bench.goose does.
 *
 *   cc -O2 -o bench_openssl tools/bench_openssl.c $(pkg-config --cflags --libs openssl)
 *   ./bench_openssl -d pemdir [-ms 1000] [prefix]
 */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *version = "bench_openssl 1";
static const char *dir = NULL;
static const char *only = "";
static double secs = 1.0;

static void die(const char *what) {
    fprintf(stderr, "bench_openssl: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int wanted(const char *name) { return strncmp(name, only, strlen(only)) == 0; }

static const char *path(const char *file) {
    static char buf[4096];
    snprintf(buf, sizeof buf, "%s/%s", dir, file);
    return buf;
}

struct cfg {
    const char *kind;   /* server key: ed25519, p256, p384, rsa, mldsa65 */
    const char *group;  /* OpenSSL's group list (TLS 1.2: X25519, then the
                         * ECDSA certificate's P-256, which it must cover) */
    const char *suite;  /* a TLS 1.3 suite, or a TLS 1.2 cipher list */
    int tls12;
    int tickets;
};

static void configure(const struct cfg *c, SSL_CTX **cctx, SSL_CTX **sctx) {
    *cctx = SSL_CTX_new(TLS_client_method());
    *sctx = SSL_CTX_new(TLS_server_method());
    if (!*cctx || !*sctx) die("SSL_CTX_new");
    char file[256];
    snprintf(file, sizeof file, "%s.crt", c->kind);
    if (SSL_CTX_use_certificate_file(*sctx, path(file), SSL_FILETYPE_PEM) != 1) die(file);
    snprintf(file, sizeof file, "%s.key", c->kind);
    if (SSL_CTX_use_PrivateKey_file(*sctx, path(file), SSL_FILETYPE_PEM) != 1) die(file);
    if (SSL_CTX_load_verify_locations(*cctx, path("root.crt"), NULL) != 1) die("root.crt");
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);
    for (int i = 0; i < 2; i++) {
        SSL_CTX *x = i ? *sctx : *cctx;
        int v = c->tls12 ? TLS1_2_VERSION : TLS1_3_VERSION;
        SSL_CTX_set_min_proto_version(x, v);
        SSL_CTX_set_max_proto_version(x, v);
        if (SSL_CTX_set1_groups_list(x, c->group) != 1) die(c->group);
        if (c->tls12 ? SSL_CTX_set_cipher_list(x, c->suite) != 1 : SSL_CTX_set_ciphersuites(x, c->suite) != 1)
            die(c->suite);
        SSL_CTX_set_session_cache_mode(x, !c->tickets ? SSL_SESS_CACHE_OFF : i ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT);
    }
    SSL_CTX_set_num_tickets(*sctx, c->tickets);
    if (!c->tickets) SSL_CTX_set_options(*sctx, SSL_OP_NO_TICKET);
}

/* Moves what one side wrote to the other's input. */
static int move(BIO *from, BIO *to) {
    char buf[16384 + 512];
    int moved = 0, n;
    while ((n = BIO_read(from, buf, sizeof buf)) > 0) {
        BIO_write(to, buf, n);
        moved += n;
    }
    return moved;
}

struct pair { SSL *c, *s; BIO *c_out, *s_out; };

static struct pair join(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *sess) {
    struct pair p;
    p.c = SSL_new(cctx);
    p.s = SSL_new(sctx);
    BIO *c_in = BIO_new(BIO_s_mem()), *s_in = BIO_new(BIO_s_mem());
    p.c_out = BIO_new(BIO_s_mem());
    p.s_out = BIO_new(BIO_s_mem());
    SSL_set_bio(p.c, c_in, p.c_out);
    SSL_set_bio(p.s, s_in, p.s_out);
    SSL_set_tlsext_host_name(p.c, "example.com");
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(p.c), "example.com", 0);
    if (sess) SSL_set_session(p.c, sess);
    SSL_set_connect_state(p.c);
    SSL_set_accept_state(p.s);
    for (int round = 0; round < 20; round++) {
        int rc = SSL_do_handshake(p.c);
        if (rc != 1 && SSL_get_error(p.c, rc) != SSL_ERROR_WANT_READ) die("client handshake");
        int moved = move(p.c_out, s_in);
        int rs = SSL_do_handshake(p.s);
        if (rs != 1 && SSL_get_error(p.s, rs) != SSL_ERROR_WANT_READ) die("server handshake");
        moved += move(p.s_out, c_in);
        if (rc == 1 && rs == 1 && moved == 0) break;
    }
    if (!SSL_is_init_finished(p.c) || !SSL_is_init_finished(p.s)) die("no handshake");
    if (SSL_get_verify_result(p.c) != X509_V_OK) die("not verified");
    /* The client reads what came after its Finished (tickets). */
    char b[1];
    if (SSL_read(p.c, b, 1) > 0) die("unexpected data");
    if (sess && !SSL_session_reused(p.c)) die("not resumed");
    return p;
}

/* Freed as if closed (no close_notify is timed, as in bench.goose): a
 * connection freed open marks its session not resumable. */
static void done(struct pair *p) {
    SSL_set_shutdown(p->c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(p->s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(p->c);
    SSL_free(p->s);
}

static void handshakes(const char *name, struct cfg c) {
    if (!wanted(name)) return;
    SSL_CTX *cctx, *sctx;
    configure(&c, &cctx, &sctx);
    long n = 0;
    double t0 = now();
    while (n == 0 || now() - t0 < secs) {
        struct pair p = join(cctx, sctx, NULL);
        done(&p);
        n++;
    }
    printf("%s %f hs/s\n", name, n / (now() - t0));
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void resumptions(const char *name) {
    if (!wanted(name)) return;
    struct cfg c = {"p256", "X25519", "TLS_AES_128_GCM_SHA256", 0, 1};
    SSL_CTX *cctx, *sctx;
    configure(&c, &cctx, &sctx);
    struct pair first = join(cctx, sctx, NULL);
    SSL_SESSION *sess = SSL_get1_session(first.c);
    if (!sess || !SSL_SESSION_is_resumable(sess)) die("no ticket");
    done(&first);
    long n = 0;
    double t0 = now();
    while (n == 0 || now() - t0 < secs) {
        struct pair p = join(cctx, sctx, sess);
        SSL_SESSION_free(sess);
        sess = SSL_get1_session(p.c);
        done(&p);
        n++;
    }
    printf("%s %f hs/s\n", name, n / (now() - t0));
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void bulk(const char *name, const char *suite, int tls12) {
    if (!wanted(name)) return;
    struct cfg c = {"p256", tls12 ? "X25519:P-256" : "X25519", suite, tls12, 0};
    SSL_CTX *cctx, *sctx;
    configure(&c, &cctx, &sctx);
    struct pair p = join(cctx, sctx, NULL);
    static unsigned char buf[16384], in[16384];
    for (int i = 0; i < 16384; i++) buf[i] = (i * 131 + 7) % 251;
    BIO *s_in = SSL_get_rbio(p.s);
    long n = 0, got = 0;
    double t0 = now();
    while (n == 0 || now() - t0 < secs) {
        if (SSL_write(p.c, buf, sizeof buf) != sizeof buf) die("SSL_write");
        move(p.c_out, s_in);
        int r;
        while ((r = SSL_read(p.s, in, sizeof in)) > 0) got += r;
        n++;
    }
    double elapsed = now() - t0;
    if (got != n * 16384) die("short read");
    printf("%s %f MB/s\n", name, got / elapsed / 1e6);
    done(&p);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-version")) { puts(version); return 0; }
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "-ms") && i + 1 < argc) secs = atof(argv[++i]) / 1000;
        else if (argv[i][0] == '-') { fprintf(stderr, "usage: bench_openssl -d pemdir [-ms 1000] [prefix]\n"); return 2; }
        else only = argv[i];
    }
    if (!dir) { fprintf(stderr, "bench_openssl: -d pemdir is required\n"); return 2; }
    handshakes("tls13-x25519-ed25519", (struct cfg){"ed25519", "X25519", "TLS_AES_128_GCM_SHA256", 0, 0});
    handshakes("tls13-x25519-p256", (struct cfg){"p256", "X25519", "TLS_AES_128_GCM_SHA256", 0, 0});
    handshakes("tls13-x25519-rsa2048", (struct cfg){"rsa", "X25519", "TLS_AES_128_GCM_SHA256", 0, 0});
    handshakes("tls13-p256-p256", (struct cfg){"p256", "P-256", "TLS_AES_128_GCM_SHA256", 0, 0});
    handshakes("tls13-p384-p384", (struct cfg){"p384", "P-384", "TLS_AES_256_GCM_SHA384", 0, 0});
    handshakes("tls13-x25519mlkem768-p256", (struct cfg){"p256", "X25519MLKEM768", "TLS_AES_128_GCM_SHA256", 0, 0});
    handshakes("tls13-x25519mlkem768-mldsa65", (struct cfg){"mldsa65", "X25519MLKEM768", "TLS_AES_128_GCM_SHA256", 0, 0});
    resumptions("tls13-resume-x25519");
    handshakes("tls12-ecdhe-ecdsa-p256", (struct cfg){"p256", "X25519:P-256", "ECDHE-ECDSA-AES128-GCM-SHA256", 1, 0});
    handshakes("tls12-ecdhe-rsa2048", (struct cfg){"rsa", "X25519:P-256", "ECDHE-RSA-AES128-GCM-SHA256", 1, 0});
    bulk("bulk-tls13-aes128gcm", "TLS_AES_128_GCM_SHA256", 0);
    bulk("bulk-tls13-aes256gcm", "TLS_AES_256_GCM_SHA384", 0);
    bulk("bulk-tls13-chacha20", "TLS_CHACHA20_POLY1305_SHA256", 0);
    bulk("bulk-tls12-aes128gcm", "ECDHE-ECDSA-AES128-GCM-SHA256", 1);
    bulk("bulk-tls12-chacha20", "ECDHE-ECDSA-CHACHA20-POLY1305", 1);
    return 0;
}
