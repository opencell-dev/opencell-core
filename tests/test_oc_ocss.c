#define _GNU_SOURCE
/* oc_ocss (core test services spec §6): two cores in this process, each an
 * oc_core on an in-memory store with its oc_ocss, over TCP on 127.0.0.1
 * with the test PKI (argv[1]): core 1 dials core 2, HELLO brings the link
 * up, a call from a cell on core 1 reaches core 2's echo service and its
 * media comes back; a core that has not pinned the other is refused; a link
 * whose peer goes away is reported down and dialled again. The clock is
 * fake (NOW, advanced every turn): the sockets are real. */
#include "unity.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>

#include "oc_core_mem.h"
#include "oc_ocss.h"

void setUp(void) {}
void tearDown(void) {}

#define UNIX0 1790000000u
#define CELL  10u
#define LEG   7u

static const char *PKI = "build/pki";
static uint64_t    NOW;
static uint32_t    NEXT_LINK = 1000;

typedef struct {
    oc_core_mem_t   mem;
    oc_core_store_t st;
    oc_core_route_t rt;
    oc_core_t       k;
    oc_ocss_t       o;
} core_t;

static core_t        C1, C2;
static oc_core_msg_t CELL_RX[64];
static int           NCELL;

static uint64_t now_us(void) { return NOW; }
static uint32_t new_link(void *ctx)
{
    (void)ctx;
    return ++NEXT_LINK;
}
static int send_any(core_t *c, uint32_t link, const oc_core_msg_t *m)
{
    if (oc_ocss_owns(&c->o, link)) return oc_ocss_send(&c->o, link, m);
    if (c == &C1 && link == CELL) CELL_RX[NCELL++ % 64] = *m;
    return 0;
}
static int send1(void *x, uint32_t l, const oc_core_msg_t *m) { (void)x; return send_any(&C1, l, m); }
static int send2(void *x, uint32_t l, const oc_core_msg_t *m) { (void)x; return send_any(&C2, l, m); }
static void close1(void *x, uint32_t l) { (void)x; oc_ocss_drop(&C1.o, l); }
static void close2(void *x, uint32_t l) { (void)x; oc_ocss_drop(&C2.o, l); }
static void rnd(void *x, uint8_t *out, size_t n)
{
    (void)x;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(i * 13u + 5u);
}
static uint32_t unix_now(void *x)
{
    (void)x;
    return UNIX0 + (uint32_t)(NOW / 1000000u);
}

static const char *f(const char *name)
{
    static char path[8][256];
    static int i;
    i = (i + 1) % 8;
    snprintf(path[i], sizeof(path[i]), "%s/%s", PKI, name);
    return path[i];
}

static void fpr(const char *name, uint8_t out[32])
{
    char hex[80] = "";
    FILE *fp = fopen(f(name), "r");
    TEST_ASSERT_NOT_NULL(fp);
    TEST_ASSERT_NOT_NULL(fgets(hex, sizeof(hex), fp));
    fclose(fp);
    hex[strcspn(hex, "\n")] = '\0';
    TEST_ASSERT_EQUAL_INT(0, oc_tls_fpr_parse(hex, out));
}

static void make_core(core_t *c, uint16_t id, const oc_core_io_t *io)
{
    uint8_t r[32];
    memset(r, 0x22 * id, 32);
    oc_core_mem_init(&c->mem);
    c->st = oc_core_mem_store(&c->mem);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&c->st, id, 1800, r, UNIX0));
    oc_core_route_init(&c->rt, id);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&c->rt, "8831606", 1, 1));
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&c->rt, "8831503", 2, 2));
    oc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = id;
    cfg.key_id = id;
    const char *echo = id == 1 ? "+883160655500100" : "+883150355500100";
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(echo, strlen(echo), cfg.echo_number));
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&c->k, io, &c->st, &c->rt, &cfg));
}

/* Core 2 listens on a free port and pins core2_pins; core 1 dials it,
 * pinning core 2's certificate. */
static void world(const char *core2_pins)
{
    static const oc_core_io_t IO1 = { NULL, send1, close1, rnd, unix_now, NULL };
    static const oc_core_io_t IO2 = { NULL, send2, close2, rnd, unix_now, NULL };
    char err[300];
    memset(&C1, 0, sizeof(C1));
    memset(&C2, 0, sizeof(C2));
    NOW = 1000000u;
    NCELL = 0;
    make_core(&C1, 1, &IO1);
    make_core(&C2, 2, &IO2);
    oc_ocss_cfg_t c2 = { "127.0.0.1:0", f("core2.crt"), f("core2.key"), f("ca.crt"), { { 0 } }, 1,
                         &C2.k,         now_us,          new_link,        NULL };
    c2.peer[0].core_id = 1;
    fpr(core2_pins, c2.peer[0].fpr);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C2.o, &c2, err, sizeof(err)), err);
    oc_ocss_cfg_t c1 = { NULL, f("core.crt"), f("core.key"), f("ca.crt"), { { 0 } }, 1, &C1.k, now_us, new_link, NULL };
    c1.peer[0].core_id = 2;
    snprintf(c1.peer[0].addr, sizeof(c1.peer[0].addr), "127.0.0.1:%u", C2.o.port);
    fpr("core2.fpr", c1.peer[0].fpr);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C1.o, &c1, err, sizeof(err)), err);
}

/* One loop turn of both daemons: poll, serve, tick; the clock moves on. */
static void turn(uint64_t step_us)
{
    struct pollfd p[2][1 + OC_OCSS_CONNS];
    int t = 5;
    unsigned n1 = oc_ocss_fds(&C1.o, p[0], &t), n2 = oc_ocss_fds(&C2.o, p[1], &t);
    struct pollfd all[2 * (1 + OC_OCSS_CONNS)];
    memcpy(all, p[0], n1 * sizeof(all[0]));
    memcpy(all + n1, p[1], n2 * sizeof(all[0]));
    poll(all, n1 + n2, t < 5 ? t : 5);
    oc_ocss_serve(&C1.o, all, n1);
    oc_ocss_serve(&C2.o, all + n1, n2);
    NOW += step_us;
    oc_core_tick(&C1.k, NOW);
    oc_core_tick(&C2.k, NOW);
}

static int linked_within(int turns)
{
    for (int i = 0; i < turns; i++) {
        if (oc_core_peer_linked(&C1.k, 2) && oc_core_peer_linked(&C2.k, 1)) return 1;
        turn(1000u);
    }
    return 0;
}

static void done(void)
{
    oc_ocss_close(&C1.o);
    oc_ocss_close(&C2.o);
    ERR_clear_error();
}

static void test_core_1_dials_and_the_link_comes_up(void)
{
    world("core.fpr");
    TEST_ASSERT_TRUE(linked_within(400));
    for (int i = 0; i < 40; i++) turn(1000000u); /* 40 s of PING/PONG over TLS */
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C1.k, 2));
    TEST_ASSERT_TRUE(oc_core_peer_linked(&C2.k, 1));
    done();
}

static void test_a_call_from_core_1_reaches_core_2s_echo(void)
{
    world("core.fpr");
    TEST_ASSERT_TRUE(linked_within(400));
    /* cell 1 on core 1, with A registered */
    uint8_t na[OC_SIG_NUMBER_LEN], echo2[OC_SIG_NUMBER_LEN], got[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd("+883160655501234", 16, na);
    oc_sig_number_to_bcd("+883150355500100", 16, echo2);
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&C1.k, 1, "A", OC_SIG_MODE_PART15, 0));
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO;
    m.u.hello.cell_id = 1;
    m.u.hello.boot_id = 1;
    oc_core_link_up(&C1.k, CELL, NOW);
    oc_core_rx(&C1.k, CELL, &m, NOW);
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&C1.k, na, got));
    TEST_ASSERT_EQUAL_INT(0, C1.st.sub_get(C1.st.ctx, na, &s));
    s.activated = 1;
    s.tmid = 0xaaaa;
    TEST_ASSERT_EQUAL_INT(0, C1.st.sub_put(C1.st.ctx, &s));
    oc_core_loc_t l = { { 0 }, 1, 0xaaaa, UNIX0 + 3600u, 0, { 0 } };
    memcpy(l.number, na, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, C1.st.loc_put(C1.st.ctx, &l));
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = LEG;
    memcpy(m.u.call_route.caller, na, OC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, echo2, OC_SIG_NUMBER_LEN);
    oc_core_rx(&C1.k, CELL, &m, NOW);
    int answered = 0, echoed = 0;
    for (int i = 0; i < 400 && !echoed; i++) {
        turn(20000u);
        for (int j = 0; j < NCELL; j++) {
            if (CELL_RX[j].type == OC_CORE_CALL_ANSWER && !answered) {
                answered = 1;
                memset(&m, 0, sizeof(m));
                m.type = OC_CORE_MEDIA;
                m.u.media.ref = LEG;
                m.u.media.len = 5;
                memcpy(m.u.media.data, "HELLO", 5);
                oc_core_rx(&C1.k, CELL, &m, NOW);
            }
            if (CELL_RX[j].type == OC_CORE_MEDIA && memcmp(CELL_RX[j].u.media.data, "HELLO", 5) == 0) echoed = 1;
        }
    }
    TEST_ASSERT_TRUE(answered);
    TEST_ASSERT_TRUE(echoed);
    done();
}

static void test_a_core_that_has_not_pinned_the_other_refuses_it(void)
{
    world("portal.fpr"); /* core 2 expects someone else */
    TEST_ASSERT_FALSE(linked_within(400));
    TEST_ASSERT_TRUE(C1.o.dial_at[0] > NOW); /* core 1 waits before it dials again */
    done();
}

static void test_a_link_whose_peer_goes_is_reported_and_dialled_again(void)
{
    world("core.fpr");
    TEST_ASSERT_TRUE(linked_within(400));
    uint16_t port = C2.o.port;
    oc_ocss_close(&C2.o); /* core 2 stops */
    for (int i = 0; i < 50 && oc_core_peer_linked(&C1.k, 2); i++) turn(1000u);
    TEST_ASSERT_FALSE(oc_core_peer_linked(&C1.k, 2));
    char err[300];
    oc_ocss_cfg_t c2 = C2.o.cfg; /* core 2 starts again on the same port */
    char listen[32];
    snprintf(listen, sizeof(listen), "127.0.0.1:%u", port);
    c2.listen = listen;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C2.o, &c2, err, sizeof(err)), err);
    TEST_ASSERT_TRUE(linked_within(40000)); /* after core 1's wait (1 s, then 2 s ...) */
    done();
}

/* Review M2: "the lower core_id dials" (spec §7.1) means core 2, told it
 * dials core 1 (an address for a lower core_id), must not instead accept
 * an inbound link claiming to be core 1 - that connection should have
 * come from core 2 dialling out, not core 1 dialling in. */
static void test_a_peer_configured_to_be_dialled_refuses_an_inbound_link(void)
{
    static const oc_core_io_t IO1 = { NULL, send1, close1, rnd, unix_now, NULL };
    static const oc_core_io_t IO2 = { NULL, send2, close2, rnd, unix_now, NULL };
    char err[300];
    memset(&C1, 0, sizeof(C1));
    memset(&C2, 0, sizeof(C2));
    NOW = 1000000u;
    NCELL = 0;
    make_core(&C1, 1, &IO1);
    make_core(&C2, 2, &IO2);
    oc_ocss_cfg_t c2 = { "127.0.0.1:0", f("core2.crt"), f("core2.key"), f("ca.crt"), { { 0 } }, 1,
                         &C2.k,         now_us,          new_link,        NULL };
    c2.peer[0].core_id = 1;
    snprintf(c2.peer[0].addr, sizeof(c2.peer[0].addr), "127.0.0.1:1"); /* core 2 thinks it dials core 1 */
    fpr("core.fpr", c2.peer[0].fpr);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C2.o, &c2, err, sizeof(err)), err);
    oc_ocss_cfg_t c1 = { NULL, f("core.crt"), f("core.key"), f("ca.crt"), { { 0 } }, 1, &C1.k, now_us, new_link, NULL };
    c1.peer[0].core_id = 2;
    snprintf(c1.peer[0].addr, sizeof(c1.peer[0].addr), "127.0.0.1:%u", C2.o.port);
    fpr("core2.fpr", c1.peer[0].fpr);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C1.o, &c1, err, sizeof(err)), err);
    TEST_ASSERT_FALSE(linked_within(400)); /* core 1 dials in, but core 2 refuses the accept */
    done();
}

/* Review M4: OC_OCSS_CONNS is shared by every connection in handshake, with
 * no per-source limit, so a second TCP connection from the same address
 * while the first is still handshaking (never finishing one) could hold
 * every slot. At most one handshake per address at once. */
static void test_a_second_handshake_from_the_same_address_is_refused(void)
{
    world("core.fpr");
    int a = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int b = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    TEST_ASSERT_TRUE(a >= 0 && b >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(C2.o.port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    connect(a, (struct sockaddr *)&sa, sizeof(sa)); /* non-blocking: EINPROGRESS, fine */
    connect(b, (struct sockaddr *)&sa, sizeof(sa));
    for (int i = 0; i < 20; i++) turn(50000u); /* give core 2's listener a chance to accept both */
    char buf[4];
    TEST_ASSERT_TRUE(recv(a, buf, sizeof(buf), MSG_DONTWAIT) < 0); /* a: still in handshake, not closed */
    TEST_ASSERT_EQUAL_INT(0, recv(b, buf, sizeof(buf), MSG_DONTWAIT)); /* b: refused, closed at once (EOF) */
    close(a);
    close(b);
    done();
}

/* Review M5: an IPv6 ocss_listen takes IPV6_FREEBIND too (not IPv4 only),
 * so it can bind an address that is not up yet (the header already
 * documents IPv6 listen addresses). [::1]:0 is always up, so this only
 * exercises the AF_INET6 bind path without a not-yet-configured address
 * to prove FREEBIND's benefit; that needs a netns this sandbox lacks. */
static void test_an_ipv6_listen_address_binds_too(void)
{
    char err[300];
    static const oc_core_io_t IO2 = { NULL, send2, close2, rnd, unix_now, NULL };
    memset(&C2, 0, sizeof(C2));
    make_core(&C2, 2, &IO2);
    oc_ocss_cfg_t c2 = { "[::1]:0", f("core2.crt"), f("core2.key"), f("ca.crt"), { { 0 } }, 1, &C2.k, now_us, new_link,
                         NULL };
    c2.peer[0].core_id = 1;
    fpr("core.fpr", c2.peer[0].fpr);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_ocss_open(&C2.o, &c2, err, sizeof(err)), err);
    TEST_ASSERT_NOT_EQUAL(0, C2.o.port);
    oc_ocss_close(&C2.o);
}

/* Review M6: a frame that does not decode (a version-skewed peer, say) was
 * only ever counted (c->bad), never logged - it would vanish silently.
 * Writes the frame straight past oc_core's own framing, over the open
 * link's TLS connection (state 3, the header's documented "open"), and
 * checks stderr (oc_log's only destination) for a line naming it. */
static void test_an_undecodable_frame_is_logged(void)
{
    world("core.fpr");
    TEST_ASSERT_TRUE(linked_within(400));
    oc_ocss_conn_t *c = NULL;
    for (unsigned i = 0; i < OC_OCSS_CONNS && c == NULL; i++) {
        if (C1.o.c[i].state == 3) c = &C1.o.c[i];
    }
    TEST_ASSERT_NOT_NULL(c);
    char tmp[] = "/tmp/oc_ocss_log_XXXXXX";
    int fd = mkstemp(tmp);
    TEST_ASSERT_TRUE(fd >= 0);
    fflush(stderr);
    int saved = dup(2);
    TEST_ASSERT_TRUE(saved >= 0);
    dup2(fd, 2);
    uint8_t bad[] = { 0x00, 0x01, 0xFF }; /* len 1, type 0xFF: not a frame oc_core_decode knows */
    long wn = oc_tls_conn_write(&c->tls, bad, sizeof(bad));
    for (int i = 0; i < 20; i++) turn(50000u);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    char buf[4096] = { 0 };
    off_t end = lseek(fd, 0, SEEK_CUR);
    lseek(fd, 0, SEEK_SET);
    ssize_t n = end > 0 ? read(fd, buf, sizeof(buf) - 1) : 0;
    close(fd);
    unlink(tmp);
    TEST_ASSERT_EQUAL_INT((long)sizeof(bad), wn);
    TEST_ASSERT_TRUE_MESSAGE(n > 0 && strstr(buf, "frame type ff") != NULL, buf);
    done();
}

int main(int argc, char **argv)
{
    if (argc > 1) PKI = argv[1];
    signal(SIGPIPE, SIG_IGN);
    UNITY_BEGIN();
    RUN_TEST(test_core_1_dials_and_the_link_comes_up);
    RUN_TEST(test_a_call_from_core_1_reaches_core_2s_echo);
    RUN_TEST(test_a_core_that_has_not_pinned_the_other_refuses_it);
    RUN_TEST(test_a_link_whose_peer_goes_is_reported_and_dialled_again);
    RUN_TEST(test_a_peer_configured_to_be_dialled_refuses_an_inbound_link);
    RUN_TEST(test_a_second_handshake_from_the_same_address_is_refused);
    RUN_TEST(test_an_ipv6_listen_address_binds_too);
    RUN_TEST(test_an_undecodable_frame_is_logged);
    return UNITY_END();
}
