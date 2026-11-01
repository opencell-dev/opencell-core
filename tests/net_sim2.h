/* The two-core simulation (OCSS spec 2026-11-01 §8): net_sim.h's world
 * with two oc_cores joined by an OCSS link. Core 1 (CORE[0]) is home for
 * +883 1 606 and serves cells 0 and 1 (cell ids 1 and 2); core 2 (CORE[1])
 * is home for +883 1 503 and serves cell 2 (cell id 1 there too, so a cell
 * id alone never names a cell). Terminals 0 and 2 have core-1 numbers
 * (+883 1 606 555 0123<i>), 1 and 3 core-2 numbers (+883 1 503 555 0123<i>).
 * Every frame goes through the wire codec with a one-way delay; the OCSS
 * link can be cut. */
#ifndef NET_SIM2_H
#define NET_SIM2_H

#include <stdio.h>
#include <string.h>

#include "oc_cell.h"
#include "oc_core.h"
#include "oc_core_mem.h"
#include "oc_sig_crypto.h"
#include "oc_sig_term.h"
#include "unity.h"

#define S2_CORES  2
#define S2_CELLS  3
#define S2_TERMS  4
#define S2_FRAME  120000u
#define S2_DELAY  20000u /* every hop, one way */
#define S2_WIRE   1024
#define S2_PEER_LINK(i) (1000u + (uint32_t)(i)) /* core i's handle for its OCSS link */

typedef struct {
    uint8_t p[32][OC_SIG_LINK_MAX], n[32];
    int     head, count;
} s2_q_t;

typedef struct {
    uint32_t       tmid;
    uint8_t        number[OC_SIG_NUMBER_LEN];
    oc_sig_ident_t id;
    oc_sig_term_t  t;
    int            cell; /* -1: none */
    s2_q_t         ul, dl;
    uint8_t        ev[64][16];
    int            nev;
    uint8_t        app[OC_SIG_APP_MAX], app_n;
} s2_term_t;

typedef struct {
    oc_cell_t c;
    int       core; /* 0 or 1 */
    uint32_t  id;   /* its cell id on that core */
    uint32_t  link;
    uint32_t  boots;
} s2_cell_t;

typedef struct {
    oc_core_mem_t   mem;
    oc_core_store_t st;
    oc_core_route_t rt;
    oc_core_t       k;
    int             peer_up;
} s2_core_t;

/* kind 0: to a core from a cell; 1: to a cell; 2: to a core over OCSS */
typedef struct {
    uint64_t at;
    int      kind, core, cell;
    uint32_t link;
    uint8_t  f[OC_CORE_FRAME_MAX];
    size_t   n;
} s2_frame_t;

static s2_core_t  CORE2[S2_CORES];
static s2_cell_t  CELL2[S2_CELLS];
static s2_term_t  TERM2[S2_TERMS];
static s2_frame_t WIRE2[S2_WIRE], DUE2[S2_WIRE];
static int        NWIRE2;
static uint64_t   now2;
static uint32_t   next_link2;
static int        CUT2;                 /* OCSS frames are lost */
static unsigned   ocss_sent[S2_CORES][256]; /* by type, what each core sent its peer */

static inline void s2_push(int kind, int core, int cell, uint32_t link, const oc_core_msg_t *m)
{
    TEST_ASSERT_TRUE_MESSAGE(NWIRE2 < S2_WIRE, "wire full");
    s2_frame_t *w = &WIRE2[NWIRE2++];
    w->at = now2 + S2_DELAY;
    w->kind = kind;
    w->core = core;
    w->cell = cell;
    w->link = link;
    w->n = oc_core_encode(m, w->f, sizeof(w->f));
    TEST_ASSERT_TRUE_MESSAGE(w->n > 0, "encode");
}

static inline int s2_qpush(s2_q_t *q, const uint8_t *p, uint8_t n)
{
    if (q->count == 32) return -1;
    int i = (q->head + q->count++) % 32;
    memcpy(q->p[i], p, n);
    q->n[i] = n;
    return 0;
}

static inline int s2_qpop(s2_q_t *q, uint8_t *p, uint8_t *n)
{
    if (q->count == 0) return -1;
    memcpy(p, q->p[q->head], q->n[q->head]);
    *n = q->n[q->head];
    q->head = (q->head + 1) % 32;
    q->count--;
    return 0;
}

/* ---- the cores' transport ---- */

static int s2_k_send(void *ctx, uint32_t link, const oc_core_msg_t *m)
{
    int ci = (int)((s2_core_t *)ctx - CORE2);
    if (link == S2_PEER_LINK(ci)) {
        ocss_sent[ci][m->type]++;
        if (!CUT2) s2_push(2, 1 - ci, -1, S2_PEER_LINK(1 - ci), m);
        return 0;
    }
    for (int i = 0; i < S2_CELLS; i++) {
        if (CELL2[i].link == link && link != 0) {
            s2_push(1, ci, i, link, m);
            return 0;
        }
    }
    return -1;
}

static void s2_k_close(void *ctx, uint32_t link)
{
    (void)ctx;
    for (int i = 0; i < S2_CELLS; i++) {
        if (CELL2[i].link == link && link != 0) {
            CELL2[i].link = 0;
            oc_cell_core_down(&CELL2[i].c, now2);
        }
    }
}

static uint32_t s2_rng = 9;
static void s2_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((s2_rng = s2_rng * 1103515245u + 12345u) >> 16);
}
static uint32_t s2_unix(void *c)
{
    (void)c;
    return 1790000000u + (uint32_t)(now2 / 1000000u);
}

/* ---- the cells' transport and radio ---- */

static int s2_c_send(void *ctx, const oc_core_msg_t *m)
{
    s2_cell_t *s = ctx;
    if (s->link == 0) return -1;
    s2_push(0, s->core, (int)(s - CELL2), s->link, m);
    return 0;
}

static void s2_c_close(void *ctx)
{
    s2_cell_t *s = ctx;
    if (s->link == 0) return;
    oc_core_link_down(&CORE2[s->core].k, s->link, now2);
    s->link = 0;
}

static int s2_c_radio(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    s2_cell_t *s = ctx;
    for (int i = 0; i < S2_TERMS; i++) {
        if (TERM2[i].tmid == tmid && TERM2[i].cell == (int)(s - CELL2)) return s2_qpush(&TERM2[i].dl, p, n);
    }
    return 0;
}

static int s2_t_send(void *c, const uint8_t *p, uint8_t n) { return s2_qpush(&((s2_term_t *)c)->ul, p, n); }
static int s2_t_svc(void *c, uint8_t cause)
{
    s2_term_t *t = c;
    uint8_t p = (uint8_t)(OC_SIG_KIND_SVC | cause);
    if (t->cell >= 0) oc_cell_upper(&CELL2[t->cell].c, t->tmid, &p, 1, now2);
    return 0;
}
static void s2_t_event(void *c, const uint8_t *e, uint8_t n)
{
    s2_term_t *t = c;
    memcpy(t->ev[t->nev % 64], e, n);
    t->nev++;
}

/* ---- the world ---- */

static inline void s2_peer_link_up(void)
{
    CORE2[0].peer_up = CORE2[1].peer_up = 1;
    oc_core_peer_up(&CORE2[1].k, S2_PEER_LINK(1), 1, 0, now2); /* core 1 (lower id) dials */
    oc_core_peer_up(&CORE2[0].k, S2_PEER_LINK(0), 2, 1, now2);
}

static inline void s2_peer_link_down(void)
{
    CORE2[0].peer_up = CORE2[1].peer_up = 0;
    oc_core_peer_down(&CORE2[0].k, S2_PEER_LINK(0), now2);
    oc_core_peer_down(&CORE2[1].k, S2_PEER_LINK(1), now2);
}

static inline void s2_deliver(void)
{
    int nd = 0, k = 0;
    for (int i = 0; i < NWIRE2; i++) {
        if (WIRE2[i].at <= now2) {
            DUE2[nd++] = WIRE2[i];
        } else {
            WIRE2[k++] = WIRE2[i];
        }
    }
    NWIRE2 = k;
    for (int i = 0; i < nd; i++) {
        oc_core_msg_t m;
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_core_decode(DUE2[i].f, DUE2[i].n, &m), "decode");
        s2_frame_t *f = &DUE2[i];
        if (f->kind == 2) {
            if (CORE2[f->core].peer_up && !CUT2) oc_core_peer_rx(&CORE2[f->core].k, f->link, &m, now2);
        } else if (CELL2[f->cell].link == f->link) {
            if (f->kind == 0) {
                oc_core_rx(&CORE2[f->core].k, f->link, &m, now2);
            } else {
                oc_cell_core_rx(&CELL2[f->cell].c, &m, now2);
            }
        }
    }
}

static inline void s2_frame(void)
{
    uint8_t p[OC_SIG_LINK_MAX], n;
    now2 += S2_FRAME;
    s2_deliver();
    for (int i = 0; i < S2_TERMS; i++) {
        s2_term_t *t = &TERM2[i];
        int on = t->cell >= 0;
        oc_sig_term_link(&t->t, on, on, now2);
        if (on) oc_cell_radio_link(&CELL2[t->cell].c, t->tmid, 1, now2);
        oc_sig_term_tick(&t->t, now2);
    }
    for (int i = 0; i < S2_CELLS; i++) oc_cell_tick(&CELL2[i].c, now2);
    for (int c = 0; c < S2_CORES; c++) oc_core_tick(&CORE2[c].k, now2);
    for (int i = 0; i < S2_TERMS; i++) {
        s2_term_t *t = &TERM2[i];
        if (t->cell < 0) continue;
        oc_cell_t *c = &CELL2[t->cell].c;
        if (s2_qpop(&t->ul, p, &n) == 0) {
            oc_cell_ul(c, t->tmid, p, n, now2);
        } else {
            oc_cell_ul(c, t->tmid, NULL, 0, now2);
        }
        if (s2_qpop(&t->dl, p, &n) == 0) {
            if ((p[0] & 0xF0u) == OC_SIG_KIND_SIG) {
                oc_sig_term_rx(&t->t, p, n, now2);
            } else if (p[0] == OC_SIG_KIND_DATA) {
                oc_sig_term_data_in(&t->t, p, n, t->app, &t->app_n);
            }
        }
    }
}

static inline void s2_run_ms(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += S2_FRAME / 1000u) s2_frame();
}

static inline void s2_cell_connect(int i)
{
    CELL2[i].link = ++next_link2;
    oc_core_link_up(&CORE2[CELL2[i].core].k, CELL2[i].link, now2);
    oc_cell_core_up(&CELL2[i].c, now2);
}

static inline void s2_number(int i, uint8_t out[OC_SIG_NUMBER_LEN])
{
    char num[] = "+883160655501230";
    if (i % 2 == 1) memcpy(num + 5, "503", 3);
    num[15] = (char)('0' + i);
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(num, strlen(num), out));
}

static inline void s2_world(void)
{
    static const oc_core_io_t io0 = { &CORE2[0], s2_k_send, s2_k_close, s2_random, s2_unix, NULL, NULL };
    static const oc_core_io_t io1 = { &CORE2[1], s2_k_send, s2_k_close, s2_random, s2_unix, NULL, NULL };
    uint8_t r[32];
    memset(CELL2, 0, sizeof(CELL2));
    memset(TERM2, 0, sizeof(TERM2));
    memset(ocss_sent, 0, sizeof(ocss_sent));
    NWIRE2 = 0;
    now2 = 0;
    next_link2 = 0;
    CUT2 = 0;
    s2_rng = 9;
    for (int c = 0; c < S2_CORES; c++) {
        s2_core_t *x = &CORE2[c];
        oc_core_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.core_id = (uint16_t)(c + 1);
        cfg.key_id = (uint16_t)(c + 1);
        const char *echo = c == 0 ? "+883160655500100" : "+883150355500100";
        oc_sig_number_to_bcd(echo, strlen(echo), cfg.echo_number);
        oc_core_mem_init(&x->mem);
        x->st = oc_core_mem_store(&x->mem);
        memset(r, 0x21 + c, 32);
        TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&x->st, cfg.key_id, 1800, r, 1790000000u));
        oc_core_route_init(&x->rt, cfg.core_id);
        TEST_ASSERT_EQUAL_INT(0, oc_core_route_add_ex(&x->rt, "8831606", 1, 1, 2, 1, "US-KY"));
        TEST_ASSERT_EQUAL_INT(0, oc_core_route_add_ex(&x->rt, "8831503", 2, 2, 1, 1, "US-OR"));
        TEST_ASSERT_EQUAL_INT(0, oc_core_init(&x->k, c == 0 ? &io0 : &io1, &x->st, &x->rt, &cfg));
    }
    for (int i = 0; i < S2_CELLS; i++) {
        s2_cell_t *s = &CELL2[i];
        s->core = i < 2 ? 0 : 1;
        s->id = i < 2 ? (uint32_t)(i + 1) : 1u;
        char name[] = "cell ?";
        name[5] = (char)('0' + i);
        TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&CORE2[s->core].k, s->id, name, OC_SIG_MODE_PART15, 0));
        oc_cell_io_t io = { s, s2_c_send, s2_c_close, s2_c_radio, NULL, NULL };
        oc_cell_cfg_t cfg = { s->id, 0, { 0, 7, 0 }, OC_SIG_MODE_PART15, 1800 };
        cfg.boot_id = 0xB0070000ull + (uint64_t)(i + 1) * 0x100u + ++s->boots;
        oc_cell_init(&s->c, &io, &cfg);
        s2_cell_connect(i);
    }
    for (int i = 0; i < S2_TERMS; i++) {
        s2_term_t *t = &TERM2[i];
        uint8_t got[OC_SIG_NUMBER_LEN];
        s2_number(i, t->number);
        TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&CORE2[i % 2].k, t->number, got));
        t->tmid = 0x77000000u + (uint32_t)i;
        t->cell = -1;
        memset(r, 0x50 + i, 32);
        oc_sig_ident_new(&t->id, r);
        const oc_sig_term_io_t tio = { t, s2_t_send, s2_t_svc, NULL, s2_t_event };
        oc_sig_term_init(&t->t, &tio, &t->id, t->tmid, now2);
    }
    s2_peer_link_up();
    s2_run_ms(500);
    for (int i = 0; i < S2_CELLS; i++) TEST_ASSERT_TRUE(CELL2[i].c.ready);
    TEST_ASSERT_TRUE(oc_core_peer_mob(&CORE2[0].k, 2));
    TEST_ASSERT_TRUE(oc_core_peer_mob(&CORE2[1].k, 1));
}

static inline uint8_t s2_state(int i) { return oc_sig_term_state(&TERM2[i].t); }

static inline void s2_command(int i, const uint8_t *cmd, size_t n)
{
    TEST_ASSERT_EQUAL_UINT8(0, oc_sig_term_command(&TERM2[i].t, cmd, n, now2));
}

/* A QR from the number's home core, scanned on terminal i on cell. */
static inline void s2_activate(int i, int cell, const uint8_t number[OC_SIG_NUMBER_LEN], int home)
{
    oc_sig_qr_t qr;
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    TERM2[i].cell = cell;
    TEST_ASSERT_EQUAL_INT(0, oc_core_token_issue(&CORE2[home].k, number, 3600, &qr));
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&qr, (char *)cmd + 1, sizeof(cmd) - 1);
    s2_command(i, cmd, 1 + n);
}

static inline void s2_registered_on(int i, int cell)
{
    s2_activate(i, cell, TERM2[i].number, i % 2);
    s2_run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(OC_SIG_ST_REGISTERED, s2_state(i), "registered");
}

static inline void s2_dial(int i, const char *number)
{
    uint8_t cmd[1 + 24];
    size_t n = strlen(number);
    cmd[0] = OC_SIG_CMD_DIAL;
    memcpy(cmd + 1, number, n);
    s2_command(i, cmd, 1 + n);
}

static inline void s2_press(int i, uint8_t cmd) { s2_command(i, &cmd, 1); }

static inline void s2_talk(int i, const char *s)
{
    uint8_t out[OC_SIG_LINK_MAX], on;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_term_data_out(&TERM2[i].t, (const uint8_t *)s, (uint8_t)strlen(s), out, &on));
    s2_qpush(&TERM2[i].ul, out, on);
}

static inline const uint8_t *s2_event(const s2_term_t *t, uint8_t code)
{
    for (int i = t->nev - 1; i >= 0 && i >= t->nev - 64; i--) {
        if (t->ev[i % 64][0] == code) return t->ev[i % 64];
    }
    return NULL;
}

static inline int s2_ended(int i)
{
    const uint8_t *e = s2_event(&TERM2[i], OC_SIG_EV_ENDED);
    return e != NULL ? e[5] : -1;
}

static inline void s2_forget(void)
{
    for (int i = 0; i < S2_TERMS; i++) TERM2[i].nev = 0;
}

/* core c's location row for terminal i's number: 1 found (into l), 0 none */
static inline int s2_loc(int c, int i, oc_core_loc_t *l)
{
    return CORE2[c].st.loc_get(CORE2[c].st.ctx, TERM2[i].number, l) == 0;
}

static inline const oc_core_cdr_t *s2_last_cdr(int c)
{
    const oc_core_mem_t *m = &CORE2[c].mem;
    return m->d.ncdr == 0 ? NULL : &m->d.cdr[(m->d.ncdr - 1u) % OC_CORE_MEM_LOG];
}

#endif
