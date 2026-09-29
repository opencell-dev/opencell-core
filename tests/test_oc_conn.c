#define _GNU_SOURCE
/* oc_conn: frames over a socket pair, as the daemons use them, and the
 * Unix-socket helpers; oc_kv: the configuration files. */
#include "unity.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oc_conn.h"
#include "oc_kv.h"

void setUp(void) {}
void tearDown(void) {}

static oc_core_msg_t got[64];
static int ngot;
static oc_conn_t *close_on_rx;

static void on_rx(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    got[ngot++ % 64] = *m;
    if (close_on_rx != NULL) oc_conn_close(close_on_rx);
}

static void pair(oc_conn_t *a, int *raw)
{
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    oc_conn_init(a, sv[0]);
    *raw = sv[1];
    ngot = 0;
    close_on_rx = NULL;
}

static oc_core_msg_t ping(void)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_PING;
    return m;
}

static void test_frames_cross_both_ways(void)
{
    oc_conn_t a, b;
    int raw;
    pair(&a, &raw);
    oc_conn_init(&b, raw);
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = 7;
    h.u.hello.boot_id = 0x1122334455667788ull;
    TEST_ASSERT_EQUAL_INT(0, oc_conn_send(&a, &h));
    oc_core_msg_t p = ping();
    TEST_ASSERT_EQUAL_INT(0, oc_conn_send(&a, &p));
    TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&b, on_rx, NULL));
    TEST_ASSERT_EQUAL_INT(2, ngot);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_HELLO, got[0].type);
    TEST_ASSERT_EQUAL_UINT32(7, got[0].u.hello.cell_id);
    TEST_ASSERT_EQUAL_UINT64(0x1122334455667788ull, got[0].u.hello.boot_id);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PING, got[1].type);
    oc_conn_close(&a);
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&b, on_rx, NULL)); /* the peer closed */
    oc_conn_close(&b);
    oc_conn_close(&b); /* twice is fine */
}

/* A frame split across reads is whole when its last byte arrives. */
static void test_a_frame_in_pieces(void)
{
    oc_conn_t a;
    int raw;
    uint8_t f[OC_CORE_FRAME_MAX];
    pair(&a, &raw);
    oc_core_msg_t p = ping();
    size_t n = oc_core_encode(&p, f, sizeof(f));
    TEST_ASSERT_EQUAL_INT(3, (int)n);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_EQUAL_INT(1, (int)write(raw, f + i, 1));
        TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&a, on_rx, NULL));
        TEST_ASSERT_EQUAL_INT(i + 1 == n ? 1 : 0, ngot);
    }
    oc_conn_close(&a);
    close(raw);
}

/* An unknown type is dropped and counted; the link stays up. */
static void test_an_undecodable_frame_is_dropped(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t junk[] = { 0x00, 0x03, 0x7F, 0x01, 0x02, 0x00, 0x01, OC_CORE_PING };
    TEST_ASSERT_EQUAL_INT((int)sizeof(junk), (int)write(raw, junk, sizeof(junk)));
    TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&a, on_rx, NULL));
    TEST_ASSERT_EQUAL_UINT32(1, a.bad);
    TEST_ASSERT_EQUAL_INT(1, ngot);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PING, got[0].type);
    oc_conn_close(&a);
    close(raw);
}

/* A length no frame can have breaks the stream. */
static void test_an_impossible_length_breaks_the_link(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t zero[] = { 0x00, 0x00 };
    TEST_ASSERT_EQUAL_INT(2, (int)write(raw, zero, 2));
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    oc_conn_close(&a);
    close(raw);
    pair(&a, &raw);
    const uint8_t big[] = { 0x01, 0xFF, 0x04 }; /* 511 + 2 > 512 */
    TEST_ASSERT_EQUAL_INT(3, (int)write(raw, big, 3));
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    oc_conn_close(&a);
    close(raw);
}

/* The callback may close the connection (the core drops a link); reading
 * stops there. */
static void test_rx_callback_may_close(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t two[] = { 0x00, 0x01, OC_CORE_PING, 0x00, 0x01, OC_CORE_PING };
    TEST_ASSERT_EQUAL_INT(6, (int)write(raw, two, 6));
    close_on_rx = &a;
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    TEST_ASSERT_EQUAL_INT(1, ngot);
    TEST_ASSERT_EQUAL_INT(-1, a.fd);
    close(raw);
}

/* A peer that reads nothing fills the queue: send then fails, so the
 * caller drops the link instead of blocking the daemon. */
static void test_a_full_queue_refuses(void)
{
    oc_conn_t a;
    int raw, rc = 0;
    pair(&a, &raw);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.len = OC_SIG_APP_MAX;
    for (int i = 0; i < 100000 && rc == 0; i++) rc = oc_conn_send(&a, &m);
    TEST_ASSERT_EQUAL_INT(-1, rc);
    TEST_ASSERT_TRUE(a.tn > OC_CONN_TX - 40u);
    oc_conn_close(&a);
    close(raw);
}

static void test_unix_listen_and_connect(void)
{
    char path[] = "/tmp/oc_conn_test_XXXXXX";
    int tmp = mkstemp(path);
    TEST_ASSERT_TRUE(tmp >= 0);
    close(tmp);
    errno = 0;
    TEST_ASSERT_EQUAL_INT(-1, oc_unix_listen(path, 0600, NULL)); /* a regular file is not removed */
    TEST_ASSERT_EQUAL_INT(EEXIST, errno);
    unlink(path);
    int l = oc_unix_listen(path, 0600, NULL);
    TEST_ASSERT_TRUE(l >= 0);
    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(path, &st));
    TEST_ASSERT_EQUAL_UINT(0600, st.st_mode & 0777);
    int c = oc_unix_connect(path);
    TEST_ASSERT_TRUE(c >= 0);
    int s = accept(l, NULL, NULL);
    TEST_ASSERT_TRUE(s >= 0);
    close(s);
    close(c);
    close(l);
    l = oc_unix_listen(path, 0660, NULL); /* the stale socket is replaced */
    TEST_ASSERT_TRUE(l >= 0);
    close(l);
    unlink(path);
    TEST_ASSERT_EQUAL_INT(-1, oc_unix_connect(path));
    TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

static void test_backoff(void)
{
    uint32_t d = oc_backoff_next(0);
    TEST_ASSERT_EQUAL_UINT32(1000, d);
    d = oc_backoff_next(d);
    TEST_ASSERT_EQUAL_UINT32(2000, d);
    for (int i = 0; i < 10; i++) d = oc_backoff_next(d);
    TEST_ASSERT_EQUAL_UINT32(30000, d);
}

static void test_kv(void)
{
    oc_kv_t kv;
    long long v;
    static const char *const known[] = { "cell_id", "block", "name", NULL };
    TEST_ASSERT_EQUAL_INT(0, oc_kv_parse(&kv,
                                         "# comment\n cell_id = 0x2A \n\nblock = 8831606 1\nblock=8831859 2 # two\n"
                                         "name = bench A\n",
                                         "t"));
    TEST_ASSERT_EQUAL_UINT(4, kv.n);
    TEST_ASSERT_EQUAL_INT(0, oc_kv_num(&kv, "cell_id", 1, 100, 0, &v));
    TEST_ASSERT_EQUAL_INT64(42, v);
    TEST_ASSERT_EQUAL_STRING("8831859 2", oc_kv_nth(&kv, "block", 1));
    TEST_ASSERT_NULL(oc_kv_nth(&kv, "block", 2));
    TEST_ASSERT_EQUAL_STRING("bench A", oc_kv_get(&kv, "name"));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_num(&kv, "missing", 0, 5, 3, &v));
    TEST_ASSERT_EQUAL_INT64(3, v);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_num(&kv, "cell_id", 1, 10, 0, &v));
    TEST_ASSERT_EQUAL_STRING("cell_id = '0x2A': a number 1-10", kv.err);
    TEST_ASSERT_EQUAL_INT(1, oc_kv_known(&kv, known));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_parse(&kv, "cel_id = 1\n", "t"));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_known(&kv, known));
    TEST_ASSERT_EQUAL_STRING("line 1: unknown key 'cel_id'", kv.err);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_parse(&kv, "a = 1\nnonsense\n", "f.conf"));
    TEST_ASSERT_EQUAL_STRING("f.conf:2: expected key = value", kv.err);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_load(&kv, "/nonexistent/oc.conf"));
    TEST_ASSERT_EQUAL_STRING("/nonexistent/oc.conf: No such file or directory", kv.err);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_frames_cross_both_ways);
    RUN_TEST(test_a_frame_in_pieces);
    RUN_TEST(test_an_undecodable_frame_is_dropped);
    RUN_TEST(test_an_impossible_length_breaks_the_link);
    RUN_TEST(test_rx_callback_may_close);
    RUN_TEST(test_a_full_queue_refuses);
    RUN_TEST(test_unix_listen_and_connect);
    RUN_TEST(test_backoff);
    RUN_TEST(test_kv);
    return UNITY_END();
}
