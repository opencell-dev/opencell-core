#define _GNU_SOURCE
/* oc_tls (portal spec §7): which clients the admin API's TLS lets in.
 * Server and client run in this process over a socket pair, both
 * non-blocking, stepped in turn. The certificates are the test PKI that
 * test_oc_ca.sh makes (argv[1], the ctest fixture "pki"). */
#include "unity.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "oc_tls.h"

void setUp(void) {}
void tearDown(void) {}

static const char *PKI = "build/pki";

/* PKI/name, in a buffer of its own for each of the few names used. */
static const char *f(const char *name)
{
    static char path[16][256];
    static const char *names[16];
    int i = 0;
    while (i < 15 && names[i] != NULL && strcmp(names[i], name) != 0) i++;
    names[i] = name;
    snprintf(path[i], sizeof(path[i]), "%s/%s", PKI, name);
    return path[i];
}

static void read_fpr(const char *name, uint8_t out[32])
{
    char hex[80] = "";
    FILE *fp = fopen(f(name), "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(fp, f(name));
    TEST_ASSERT_NOT_NULL(fgets(hex, sizeof(hex), fp));
    fclose(fp);
    hex[strcspn(hex, "\n")] = '\0';
    TEST_ASSERT_EQUAL_INT(0, oc_tls_fpr_parse(hex, out));
}

static oc_tls_cfg_t server_cfg(void)
{
    oc_tls_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.cert = f("core.crt");
    c.key = f("core.key");
    c.ca = f("ca.crt");
    c.alpn = "oc-admin/1";
    c.role = OC_TLS_ROLE_PORTAL;
    read_fpr("portal.fpr", c.pin[0]);
    c.npin = 1;
    return c;
}

typedef struct {
    const char *cert, *key; /* NULL: no client certificate */
    const char *alpn;       /* NULL: none offered */
    int         max_version;
} client_t;

/* A handshake between a server on cfg and this client: the server's
 * result (1 in, -1 refused) and, if refused, why. When let in, one frame
 * goes each way. */
static int handshake(const oc_tls_cfg_t *cfg, const client_t *cl, char *why, size_t cap)
{
    char err[256];
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    oc_tls_t *t = oc_tls_new(cfg, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(t, err);
    oc_tls_conn_t c;
    TEST_ASSERT_EQUAL_INT(0, oc_tls_conn_start(t, &c, sv[0]));

    SSL_CTX *cx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(cx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(cx, cl->max_version);
    TEST_ASSERT_EQUAL_INT(1, SSL_CTX_load_verify_locations(cx, f("ca.crt"), NULL));
    SSL_CTX_set_verify(cx, SSL_VERIFY_PEER, NULL);
    if (cl->cert != NULL) {
        TEST_ASSERT_EQUAL_INT(1, SSL_CTX_use_certificate_file(cx, f(cl->cert), SSL_FILETYPE_PEM));
        TEST_ASSERT_EQUAL_INT(1, SSL_CTX_use_PrivateKey_file(cx, f(cl->key), SSL_FILETYPE_PEM));
    }
    if (cl->alpn != NULL) {
        unsigned char w[64];
        w[0] = (unsigned char)strlen(cl->alpn);
        memcpy(w + 1, cl->alpn, w[0]);
        TEST_ASSERT_EQUAL_INT(0, SSL_CTX_set_alpn_protos(cx, w, 1u + w[0]));
    }
    SSL *s = SSL_new(cx);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    SSL_set_fd(s, sv[1]);
    SSL_set1_host(s, "localhost");
    SSL_set_connect_state(s);

    int srv = 0, cli = 0;
    for (int i = 0; i < 200 && srv == 0; i++) {
        if (cli == 0) {
            int r = SSL_do_handshake(s);
            if (r == 1) cli = 1;
            else if (SSL_get_error(s, r) != SSL_ERROR_WANT_READ && SSL_get_error(s, r) != SSL_ERROR_WANT_WRITE) cli = -1;
        }
        srv = oc_tls_conn_handshake(&c);
    }
    snprintf(why, cap, "%s", c.why);
    if (srv == 1) {
        /* TLS 1.3: the client's side ends before the server's; one frame each way */
        uint8_t ping[3] = { 0, 1, 0x0e }, got[8];
        long n = 0;
        for (int i = 0; i < 200 && n <= 0; i++) {
            if (i == 0) TEST_ASSERT_EQUAL_INT(3, SSL_write(s, ping, 3));
            n = oc_tls_conn_read(&c, got, sizeof(got));
        }
        TEST_ASSERT_EQUAL_INT(3, n);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(ping, got, 3);
        TEST_ASSERT_EQUAL_INT(3, oc_tls_conn_write(&c, ping, 3));
        int r = -1;
        for (int i = 0; i < 200 && r <= 0; i++) r = SSL_read(s, got, sizeof(got));
        TEST_ASSERT_EQUAL_INT(3, r);
        TEST_ASSERT_EQUAL_UINT(64, strlen(c.peer));
    }
    SSL_free(s);
    SSL_CTX_free(cx);
    close(sv[1]);
    oc_tls_conn_close(&c);
    oc_tls_conn_close(&c); /* twice: harmless */
    oc_tls_free(t);
    ERR_clear_error();
    return srv;
}

static const client_t PORTAL = { "portal.crt", "portal.key", "oc-admin/1", TLS1_3_VERSION };

static void test_the_pinned_portal_gets_in(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    char why[160];
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, handshake(&cfg, &PORTAL, why, sizeof(why)), why);
}

static void test_no_client_certificate_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.cert = cl.key = NULL;
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
}

static void test_another_roots_certificate_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.cert = "rogue.crt";
    cl.key = "rogue.key";
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "client certificate refused"), why);
}

static void test_a_good_certificate_not_pinned_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.cert = "other.crt";
    cl.key = "other.key";
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "is not pinned"), why);
    memset(cfg.pin[0], 0, 32); /* a rotation: the old pin and the new one */
    read_fpr("portal.fpr", cfg.pin[1]);
    cfg.npin = 2;
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, handshake(&cfg, &PORTAL, why, sizeof(why)), why);
}

static void test_a_pinned_certificate_without_the_portal_role_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    read_fpr("cell.fpr", cfg.pin[1]);
    cfg.npin = 2;
    cl.cert = "cell.crt";
    cl.key = "cell.key";
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "lacks the role"), why);
    read_fpr("core-client.fpr", cfg.pin[1]); /* a server certificate: not for clients */
    cl.cert = "core.crt";
    cl.key = "core.key";
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "client certificate refused"), why);
}

/* An expired certificate is refused by the chain check, even pinned (a
 * forgotten pin outlives its certificate). */
static void test_an_expired_certificate_is_refused_even_pinned(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.cert = "expired.crt";
    cl.key = "expired.key";
    read_fpr("expired.fpr", cfg.pin[1]);
    cfg.npin = 2;
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "expired"), why);
}

static void test_the_wrong_alpn_or_none_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.alpn = "oc-cell/1";
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "does not speak oc-admin/1"), why);
    cl.alpn = NULL;
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(why, "no ALPN"), why);
}

static void test_tls_1_2_is_refused(void)
{
    oc_tls_cfg_t cfg = server_cfg();
    client_t cl = PORTAL;
    char why[160];
    cl.max_version = TLS1_2_VERSION;
    TEST_ASSERT_EQUAL_INT(-1, handshake(&cfg, &cl, why, sizeof(why)));
}

static void test_a_server_that_cant_start_says_why(void)
{
    char err[256];
    oc_tls_cfg_t cfg = server_cfg();
    cfg.key = f("portal.key"); /* not core.crt's */
    TEST_ASSERT_NULL(oc_tls_new(&cfg, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "not the key of"), err);
    cfg = server_cfg();
    cfg.cert = f("missing.crt");
    TEST_ASSERT_NULL(oc_tls_new(&cfg, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "missing.crt"), err);
    cfg = server_cfg();
    cfg.npin = 0;
    TEST_ASSERT_NULL(oc_tls_new(&cfg, err, sizeof(err)));
    uint8_t b[32];
    TEST_ASSERT_EQUAL_INT(0, oc_tls_fpr_parse("00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff", b));
    TEST_ASSERT_EQUAL_HEX8(0xAA, b[10]);
    TEST_ASSERT_EQUAL_INT(-1, oc_tls_fpr_parse("0011", b));
    TEST_ASSERT_EQUAL_INT(-1, oc_tls_fpr_parse("zz112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff", b));
}

int main(int argc, char **argv)
{
    if (argc > 1) PKI = argv[1];
    signal(SIGPIPE, SIG_IGN); /* as oc-core: a refused peer's socket is closed under a write */
    UNITY_BEGIN();
    RUN_TEST(test_the_pinned_portal_gets_in);
    RUN_TEST(test_no_client_certificate_is_refused);
    RUN_TEST(test_another_roots_certificate_is_refused);
    RUN_TEST(test_a_good_certificate_not_pinned_is_refused);
    RUN_TEST(test_a_pinned_certificate_without_the_portal_role_is_refused);
    RUN_TEST(test_an_expired_certificate_is_refused_even_pinned);
    RUN_TEST(test_the_wrong_alpn_or_none_is_refused);
    RUN_TEST(test_tls_1_2_is_refused);
    RUN_TEST(test_a_server_that_cant_start_says_why);
    return UNITY_END();
}
