#define _GNU_SOURCE
/* oc_cellsrv (network-core spec §6, single-board cell spec §5): the cells'
 * TLS listener: a finished handshake is handed on with the peer's
 * fingerprint; a refused one is not; at most OC_CELLSRV_PENDING
 * handshakes at once; a handshake older than OC_CELLSRV_HANDSHAKE_S is
 * closed. argv[1]: the test PKI. */
#include "unity.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "oc_cellsrv.h"

void setUp(void) {}
void tearDown(void) {}

static const char *PKI = "build/pki";
static uint64_t NOW;
static uint64_t now_us(void) { return NOW; }
static char path_buf[8][256];
static const char *f(int i, const char *name)
{
    snprintf(path_buf[i], sizeof(path_buf[i]), "%s/%s", PKI, name);
    return path_buf[i];
}

static int nready;
static oc_tls_conn_t got;
static void on_ready(void *ctx, oc_tls_conn_t *tls, const char *addr)
{
    (void)ctx;
    (void)addr;
    nready++;
    oc_tls_conn_move(&got, tls);
}

static oc_tls_t *server(void)
{
    char err[256];
    oc_tls_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.cert = f(0, "core.crt");
    c.key = f(1, "core.key");
    c.ca = f(2, "ca.crt");
    c.alpn = "oc-cell/1";
    c.role = OC_TLS_ROLE_CELL;
    c.pin_by_caller = 1;
    oc_tls_t *t = oc_tls_new(&c, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(t, err);
    return t;
}

static int dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    TEST_ASSERT_EQUAL_INT(0, connect(fd, (struct sockaddr *)&a, sizeof(a)));
    return fd;
}

static void turn(oc_cellsrv_t *s)
{
    struct pollfd p[1 + OC_CELLSRV_PENDING];
    unsigned n = oc_cellsrv_fds(s, p);
    poll(p, n, 20);
    oc_cellsrv_serve(s, p, n, on_ready, NULL);
}

static uint16_t PORT;
static char LISTEN[32];

static void test_a_cell_handshake_is_handed_on(void)
{
    char err[256];
    oc_cellsrv_t s;
    oc_tls_t *t = server();
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_cellsrv_open(&s, LISTEN, t, now_us, err, sizeof(err)), err);
    TEST_ASSERT_EQUAL_UINT16(PORT, oc_cellsrv_port(&s));
    oc_tls_client_cfg_t cc = { f(3, "cell.crt"), f(4, "cell.key"), f(5, "ca.crt"), "oc-cell/1", OC_TLS_ROLE_CORE,
                               "localhost" };
    oc_tls_t *k = oc_tls_client_new(&cc, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(k, err);
    oc_tls_conn_t c;
    TEST_ASSERT_EQUAL_INT(0, oc_tls_conn_start(k, &c, dial(PORT)));
    nready = 0;
    int r = 0;
    for (int i = 0; i < 300 && (nready == 0 || r == 0); i++) {
        if (r == 0) r = oc_tls_conn_handshake(&c);
        turn(&s);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, r, c.why);
    TEST_ASSERT_EQUAL_INT(1, nready);
    TEST_ASSERT_EQUAL_UINT(64, strlen(got.peer));
    oc_tls_conn_close(&got);
    oc_tls_conn_close(&c);
    oc_cellsrv_close(&s);
    oc_tls_free(k);
    oc_tls_free(t);
}

static void test_a_portal_certificate_is_not_handed_on(void)
{
    char err[256];
    oc_cellsrv_t s;
    oc_tls_t *t = server();
    TEST_ASSERT_EQUAL_INT(0, oc_cellsrv_open(&s, LISTEN, t, now_us, err, sizeof(err)));
    oc_tls_client_cfg_t cc = { f(3, "portal.crt"), f(4, "portal.key"), f(5, "ca.crt"), "oc-cell/1", OC_TLS_ROLE_CORE,
                               "localhost" };
    oc_tls_t *k = oc_tls_client_new(&cc, err, sizeof(err));
    oc_tls_conn_t c;
    TEST_ASSERT_EQUAL_INT(0, oc_tls_conn_start(k, &c, dial(PORT)));
    nready = 0;
    for (int i = 0; i < 100; i++) {
        oc_tls_conn_handshake(&c);
        turn(&s);
    }
    TEST_ASSERT_EQUAL_INT(0, nready);
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) TEST_ASSERT_FALSE(s.hs[i].used); /* its slot is free again */
    oc_tls_conn_close(&c);
    oc_cellsrv_close(&s);
    oc_tls_free(k);
    oc_tls_free(t);
}

static void test_at_most_four_handshakes_and_each_has_a_deadline(void)
{
    char err[256];
    oc_cellsrv_t s;
    oc_tls_t *t = server();
    TEST_ASSERT_EQUAL_INT(0, oc_cellsrv_open(&s, LISTEN, t, now_us, err, sizeof(err)));
    NOW = 1000000;
    int fd[OC_CELLSRV_PENDING + 1];
    for (unsigned i = 0; i <= OC_CELLSRV_PENDING; i++) {
        fd[i] = dial(PORT); /* TCP only: no ClientHello */
        turn(&s);
        turn(&s);
    }
    unsigned used = 0;
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) used += s.hs[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(OC_CELLSRV_PENDING, used);
    char b;
    struct pollfd p = { fd[OC_CELLSRV_PENDING], POLLIN, 0 };
    TEST_ASSERT_EQUAL_INT(1, poll(&p, 1, 500));
    TEST_ASSERT_EQUAL_INT(0, (int)recv(fd[OC_CELLSRV_PENDING], &b, 1, 0)); /* the fifth: closed at once */
    NOW += (uint64_t)OC_CELLSRV_HANDSHAKE_S * 1000000u - 1u;
    turn(&s);
    used = 0;
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) used += s.hs[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(OC_CELLSRV_PENDING, used);
    NOW += 1u;
    turn(&s);
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) TEST_ASSERT_FALSE(s.hs[i].used);
    for (unsigned i = 0; i <= OC_CELLSRV_PENDING; i++) close(fd[i]);
    oc_cellsrv_close(&s);
    oc_cellsrv_close(&s); /* twice: harmless */
    oc_tls_free(t);
}

static int count(const char *buf, const char *needle)
{
    int n = 0;
    for (const char *p = strstr(buf, needle); p != NULL; p = strstr(p + 1, needle)) n++;
    return n;
}

/* A public port: an internet host can fail handshakes as fast as it can
 * connect. Per 10 s, 5 failures are logged one by one; the rest are
 * counted, and one line says how many once the 10 s are over. Captured from
 * stderr, oc_log's only destination. */
static void test_failed_handshakes_are_logged_5_per_10_s(void)
{
    char err[256];
    oc_cellsrv_t s;
    oc_tls_t *t = server();
    TEST_ASSERT_EQUAL_INT(0, oc_cellsrv_open(&s, LISTEN, t, now_us, err, sizeof(err)));
    NOW = 50000000;
    char tmp[] = "/tmp/oc_cellsrv_log_XXXXXX";
    int lf = mkstemp(tmp);
    TEST_ASSERT_TRUE(lf >= 0);
    unlink(tmp);
    fflush(stderr);
    int saved = dup(2);
    TEST_ASSERT_TRUE(saved >= 0);
    dup2(lf, 2);
    for (int k = 0; k < 20; k++) {
        int fd = dial(PORT);
        static const char junk[] = "GET / HTTP/1.0\r\n\r\n"; /* not a ClientHello: the handshake fails */
        TEST_ASSERT_EQUAL_INT((int)sizeof(junk) - 1, (int)send(fd, junk, sizeof(junk) - 1u, 0));
        turn(&s); /* the accept */
        for (int i = 0; i < 50 && (s.hs[0].used || s.hs[1].used || s.hs[2].used || s.hs[3].used); i++) turn(&s);
        close(fd);
    }
    turn(&s);
    fflush(stderr);
    char buf[16384] = { 0 };
    ssize_t n = pread(lf, buf, sizeof(buf) - 1u, 0);
    int one_by_one = count(buf, ": closed: "), summary = count(buf, "more refusals in the last 10 s");
    NOW += (uint64_t)10 * 1000000u + 1u;
    turn(&s);
    fflush(stderr);
    char buf2[16384] = { 0 };
    ssize_t n2 = pread(lf, buf2, sizeof(buf2) - 1u, 0);
    dup2(saved, 2);
    close(saved);
    close(lf);
    TEST_ASSERT_TRUE(n > 0 && n2 > 0);
    for (unsigned i = 0; i < OC_CELLSRV_PENDING; i++) TEST_ASSERT_FALSE(s.hs[i].used);
    TEST_ASSERT_EQUAL_INT_MESSAGE(5, one_by_one, buf);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, summary, buf);
    TEST_ASSERT_EQUAL_INT_MESSAGE(5, count(buf2, ": closed: "), buf2);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, count(buf2, "cell TLS: 15 more refusals in the last 10 s (not logged one by one)"),
                                  buf2);
    oc_cellsrv_close(&s);
    oc_tls_free(t);
}

int main(int argc, char **argv)
{
    if (argc > 1) PKI = argv[1];
    signal(SIGPIPE, SIG_IGN);
    PORT = (uint16_t)(20000 + getpid() % 20000);
    snprintf(LISTEN, sizeof(LISTEN), "127.0.0.1:%u", PORT);
    UNITY_BEGIN();
    RUN_TEST(test_a_cell_handshake_is_handed_on);
    RUN_TEST(test_a_portal_certificate_is_not_handed_on);
    RUN_TEST(test_at_most_four_handshakes_and_each_has_a_deadline);
    RUN_TEST(test_failed_handshakes_are_logged_5_per_10_s);
    return UNITY_END();
}
