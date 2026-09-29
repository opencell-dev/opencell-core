/* A core on the in-memory store, with cells as bare message endpoints: every
 * message the core sends is recorded per link, and tests feed it messages
 * as a cell would. Block 1 (+883 1 606) is at home; cells 1 and 2 exist. */
#ifndef CORE_FIXTURE_H
#define CORE_FIXTURE_H

#include <string.h>

#include "oc_core.h"
#include "oc_core_mem.h"
#include "unity.h"

#define UNIX0    1790000000u
#define ECHO_NUM "+883160655500100"

typedef struct {
    uint32_t      link;
    oc_core_msg_t m;
} sent_t;

static oc_core_mem_t   MEM;
static oc_core_store_t ST;
static oc_core_route_t RT;
static oc_core_t       K;
static sent_t          SENT[128];
static int             NSENT;
static uint32_t        CLOSED[8];
static int             NCLOSED;
static uint64_t        NOW;
static uint32_t        RNG = 1;

static int f_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    SENT[NSENT % 128].link = link;
    SENT[NSENT % 128].m = *m;
    NSENT++;
    return 0;
}
static void f_close(void *c, uint32_t link)
{
    (void)c;
    CLOSED[NCLOSED++ % 8] = link;
}
static void f_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((RNG = RNG * 1103515245u + 12345u) >> 16);
}
static uint32_t f_unix(void *c)
{
    (void)c;
    return UNIX0 + (uint32_t)(NOW / 1000000u);
}
static const oc_core_io_t CORE_IO = { NULL, f_send, f_close, f_random, f_unix, NULL };

static inline void number(const char *text, uint8_t out[OC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_sig_number_to_bcd(text, strlen(text), out), text);
}

static inline oc_core_cfg_t core_cfg(void)
{
    oc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    number(ECHO_NUM, cfg.echo_number);
    return cfg;
}

/* A fresh store with the network key, block and cells; a core on it. */
static inline void core_world(void)
{
    uint8_t r[32];
    memset(r, 0x11, 32);
    oc_core_mem_init(&MEM);
    ST = oc_core_mem_store(&MEM);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&ST, 1, 1800, r, UNIX0));
    oc_core_route_init(&RT, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&RT, "8831606", 1, 1));
    oc_core_cfg_t cfg = core_cfg();
    NOW = 1000000u;
    NSENT = NCLOSED = 0;
    RNG = 1;
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 1, "A", OC_SIG_MODE_PART15, 0));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 2, "B", OC_SIG_MODE_PART97, 0));
}

/* The core restarts on the same store: links and calls are gone. */
static inline void core_restart(void)
{
    oc_core_cfg_t cfg = core_cfg();
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
}

static inline void rx(uint32_t link, const oc_core_msg_t *m)
{
    oc_core_rx(&K, link, m, NOW);
}

/* Link `link` connects and says HELLO as cell_id. */
static inline void hello(uint32_t link, uint32_t cell_id, uint64_t boot_id)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO;
    m.u.hello.cell_id = cell_id;
    m.u.hello.boot_id = boot_id;
    oc_core_link_up(&K, link, NOW);
    rx(link, &m);
}

/* The newest message of type sent on link (NULL if none since index from). */
static inline const oc_core_msg_t *sent_since(int from, uint32_t link, uint8_t type)
{
    for (int i = NSENT - 1; i >= from && i >= NSENT - 128; i--) {
        if (SENT[i % 128].link == link && SENT[i % 128].m.type == type) return &SENT[i % 128].m;
    }
    return NULL;
}
static inline const oc_core_msg_t *sent(uint32_t link, uint8_t type) { return sent_since(0, link, type); }

static inline void advance(uint64_t us)
{
    NOW += us;
    oc_core_tick(&K, NOW);
}

#endif
