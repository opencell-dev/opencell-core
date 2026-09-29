/* The multi-cell simulation (network-core spec §9.2): SIM_CELLS cells
 * (oc_cell: oc_sig_net and the core client), SIM_TERMS oc_sig_term
 * terminals on fake radio links (one UL and one DL payload per 120 ms frame,
 * always granted, as test_sig_local.c), and one oc_core on the in-memory
 * store. Cells and core talk through an in-memory transport that carries
 * encoded frames (oc_core_encode/decode) with a one-way delay; tests can
 * disconnect a cell, mute it, restart it, or restart the core. */
#ifndef NET_SIM_H
#define NET_SIM_H

#include <stdio.h>
#include <string.h>

#include "oc_cell.h"
#include "oc_core.h"
#include "oc_core_mem.h"
#include "oc_sig_crypto.h"
#include "oc_sig_term.h"
#include "unity.h"

#define SIM_CELLS    3
#define SIM_TERMS    5
#define SIM_FRAME    120000u
#define SIM_DELAY_US 20000u /* cell <-> core, one way */
#define SIM_WIRE     512
#define SIM_ECHO     "+883160655500100"

typedef struct {
    uint8_t p[32][OC_SIG_LINK_MAX], n[32];
    int     head, count;
} sim_q_t;

typedef struct {
    uint32_t       tmid;
    uint8_t        number[OC_SIG_NUMBER_LEN]; /* its subscriber */
    oc_sig_ident_t id;
    oc_sig_term_t  t;
    int            cell; /* the cell it is attached to; -1: none */
    sim_q_t        ul, dl;
    uint8_t        ev[64][16];
    int            nev;
    uint8_t        app[OC_SIG_APP_MAX], app_n; /* the last app data it received */
    int            ul_lost;                     /* test hook: its UL payloads are not heard */
    int            rec;                         /* test hook: record its UL payloads (an eavesdropper) */
    uint8_t        rp[16][OC_SIG_LINK_MAX], rn[16];
    int            nrp;
} sim_term_t;

typedef struct {
    oc_cell_t c;
    int       up;    /* the process runs: its beacon is on the air */
    uint32_t  link;  /* its link to the core; 0: none */
    int       mute;  /* test hook: its frames to the core are lost */
    uint32_t  boots;
} sim_cell_t;

typedef struct {
    uint64_t at;
    int      to_core;
    int      cell;
    uint32_t link;
    uint8_t  f[OC_CORE_FRAME_MAX];
    size_t   n;
} sim_frame_t;

static sim_cell_t      CELL[SIM_CELLS];
static sim_term_t      TERM[SIM_TERMS];
static sim_frame_t     WIRE[SIM_WIRE];
static int             NWIRE;
static oc_core_mem_t   SMEM;
static oc_core_store_t SST;
static oc_core_route_t SRT;
static oc_core_t       CORE;
static uint64_t        now;
static uint32_t        next_link;
static oc_core_msg_t   last_loc_update[SIM_CELLS]; /* what each cell last claimed (the rogue-cell test replays it) */
static unsigned        to_core[SIM_CELLS][256];    /* what each cell sent the core, by type */
static oc_core_msg_t   last_loc_cancel[SIM_CELLS]; /* the last LOC_CANCEL the core sent each cell */

static inline int sim_qpush(sim_q_t *q, const uint8_t *p, uint8_t n)
{
    if (q->count == 32) return -1;
    int i = (q->head + q->count++) % 32;
    memcpy(q->p[i], p, n);
    q->n[i] = n;
    return 0;
}

static inline int sim_qpop(sim_q_t *q, uint8_t *p, uint8_t *n)
{
    if (q->count == 0) return -1;
    memcpy(p, q->p[q->head], q->n[q->head]);
    *n = q->n[q->head];
    q->head = (q->head + 1) % 32;
    q->count--;
    return 0;
}

static inline int cell_of_link(uint32_t link)
{
    for (int i = 0; i < SIM_CELLS; i++) {
        if (CELL[i].link == link && link != 0) return i;
    }
    return -1;
}

static inline void wire_push(int to_core, int cell, uint32_t link, const oc_core_msg_t *m)
{
    TEST_ASSERT_TRUE_MESSAGE(NWIRE < SIM_WIRE, "wire full");
    sim_frame_t *w = &WIRE[NWIRE++];
    w->at = now + SIM_DELAY_US;
    w->to_core = to_core;
    w->cell = cell;
    w->link = link;
    w->n = oc_core_encode(m, w->f, sizeof(w->f));
    TEST_ASSERT_TRUE_MESSAGE(w->n > 0, "encode");
}

static inline void wire_forget(uint32_t link)
{
    int k = 0;
    for (int i = 0; i < NWIRE; i++) {
        if (WIRE[i].link != link) WIRE[k++] = WIRE[i];
    }
    NWIRE = k;
}

/* ---- the core's transport ---- */

static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    int i = cell_of_link(link);
    if (i < 0) return -1;
    if (m->type == OC_CORE_LOC_CANCEL) last_loc_cancel[i] = *m;
    wire_push(0, i, link, m);
    return 0;
}

static void k_close(void *c, uint32_t link) /* the core dropped it: the cell sees its connection close */
{
    (void)c;
    int i = cell_of_link(link);
    if (i < 0) return;
    CELL[i].link = 0;
    wire_forget(link);
    oc_cell_core_down(&CELL[i].c, now);
}

static uint32_t sim_rng = 5;
static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((sim_rng = sim_rng * 1103515245u + 12345u) >> 16);
}
static uint32_t k_unix(void *c)
{
    (void)c;
    return 1790000000u + (uint32_t)(now / 1000000u);
}
static const oc_core_io_t SIM_CORE_IO = { NULL, k_send, k_close, k_random, k_unix, NULL };

/* ---- a cell's transport and radio ---- */

static int c_send(void *ctx, const oc_core_msg_t *m)
{
    sim_cell_t *s = ctx;
    int i = (int)(s - CELL);
    if (s->link == 0) return -1;
    if (m->type == OC_CORE_LOC_UPDATE) last_loc_update[i] = *m;
    to_core[i][m->type]++;
    if (!s->mute) wire_push(1, i, s->link, m);
    return 0;
}

static void c_close(void *ctx) /* the cell dropped it: the core sees the connection close */
{
    sim_cell_t *s = ctx;
    if (s->link == 0) return;
    oc_core_link_down(&CORE, s->link, now);
    wire_forget(s->link);
    s->link = 0;
}

static int c_radio(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    sim_cell_t *s = ctx;
    for (int i = 0; i < SIM_TERMS; i++) {
        if (TERM[i].tmid == tmid && TERM[i].cell == (int)(s - CELL)) return sim_qpush(&TERM[i].dl, p, n);
    }
    return 0; /* sent; nobody here to hear it */
}

static const oc_cell_io_t SIM_CELL_IO_TEMPLATE = { NULL, c_send, c_close, c_radio, NULL, NULL };

/* ---- terminals ---- */

static int t_send(void *c, const uint8_t *p, uint8_t n) { return sim_qpush(&((sim_term_t *)c)->ul, p, n); }
static int t_svc(void *c, uint8_t cause)
{
    sim_term_t *t = c;
    uint8_t p = (uint8_t)(OC_SIG_KIND_SVC | cause);
    if (t->cell >= 0 && CELL[t->cell].up) oc_cell_upper(&CELL[t->cell].c, t->tmid, &p, 1, now);
    return 0;
}
static void t_event(void *c, const uint8_t *e, uint8_t n)
{
    sim_term_t *t = c;
    memcpy(t->ev[t->nev % 64], e, n);
    t->nev++;
}

/* ---- the world ---- */

static inline void sim_connect(int i)
{
    CELL[i].link = ++next_link;
    oc_core_link_up(&CORE, CELL[i].link, now);
    oc_cell_core_up(&CELL[i].c, now);
}

static inline void sim_disconnect(int i)
{
    if (CELL[i].link == 0) return;
    oc_core_link_down(&CORE, CELL[i].link, now);
    wire_forget(CELL[i].link);
    CELL[i].link = 0;
    oc_cell_core_down(&CELL[i].c, now);
}

static inline void sim_cell_start(int i)
{
    oc_cell_io_t io = SIM_CELL_IO_TEMPLATE;
    io.ctx = &CELL[i];
    oc_cell_cfg_t cfg = { (uint32_t)(i + 1), 0, { 0, 7, 0 }, OC_SIG_MODE_PART15, 1800 };
    cfg.boot_id = 0xB0070000ull + (uint64_t)(i + 1) * 0x100u + ++CELL[i].boots; /* a new boot id every start */
    oc_cell_init(&CELL[i].c, &io, &cfg);
    CELL[i].up = 1;
}

static inline void sim_core_start(void)
{
    oc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    oc_sig_number_to_bcd(SIM_ECHO, strlen(SIM_ECHO), cfg.echo_number);
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&CORE, &SIM_CORE_IO, &SST, &SRT, &cfg));
}

static sim_frame_t DUE[SIM_WIRE];

/* Every frame whose time has come, in the order sent; a frame of a
 * connection that has closed since is lost. */
static inline void deliver(void)
{
    int nd = 0, k = 0;
    for (int i = 0; i < NWIRE; i++) {
        if (WIRE[i].at <= now) {
            DUE[nd++] = WIRE[i];
        } else {
            WIRE[k++] = WIRE[i];
        }
    }
    NWIRE = k;
    for (int i = 0; i < nd; i++) {
        oc_core_msg_t m;
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_core_decode(DUE[i].f, DUE[i].n, &m), "decode");
        if (CELL[DUE[i].cell].link != DUE[i].link) continue;
        if (DUE[i].to_core) {
            oc_core_rx(&CORE, DUE[i].link, &m, now);
        } else {
            oc_cell_core_rx(&CELL[DUE[i].cell].c, &m, now);
        }
    }
}

/* One 120 ms frame: the wire, every terminal's link state and timers, the
 * cells, the core, then one UL and one DL payload per attached terminal. */
static inline void frame(void)
{
    uint8_t p[OC_SIG_LINK_MAX], n;
    now += SIM_FRAME;
    deliver();
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        int on = t->cell >= 0 && CELL[t->cell].up;
        oc_sig_term_link(&t->t, on, on, now);
        if (on) oc_cell_radio_link(&CELL[t->cell].c, t->tmid, 1, now);
        oc_sig_term_tick(&t->t, now);
    }
    for (int i = 0; i < SIM_CELLS; i++) {
        if (CELL[i].up) oc_cell_tick(&CELL[i].c, now);
    }
    oc_core_tick(&CORE, now);
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        if (t->cell < 0 || !CELL[t->cell].up) continue;
        oc_cell_t *c = &CELL[t->cell].c;
        if (sim_qpop(&t->ul, p, &n) == 0 && !t->ul_lost) {
            if (t->rec && t->nrp < 16) {
                memcpy(t->rp[t->nrp], p, n);
                t->rn[t->nrp++] = n;
            }
            oc_cell_ul(c, t->tmid, p, n, now);
        } else {
            oc_cell_ul(c, t->tmid, NULL, 0, now); /* its UL slot was heard, empty */
        }
        if (sim_qpop(&t->dl, p, &n) == 0) {
            if ((p[0] & 0xF0u) == OC_SIG_KIND_SIG) {
                oc_sig_term_rx(&t->t, p, n, now);
            } else if (p[0] == OC_SIG_KIND_DATA) {
                oc_sig_term_data_in(&t->t, p, n, t->app, &t->app_n);
            }
        }
    }
}

static inline void run_ms(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += SIM_FRAME / 1000u) frame();
}

/* Terminal i's subscriber is +883 1 606 555 0123<i>; nobody is activated. */
static inline void sim_world(void)
{
    uint8_t r[32];
    memset(CELL, 0, sizeof(CELL));
    memset(TERM, 0, sizeof(TERM));
    memset(last_loc_update, 0, sizeof(last_loc_update));
    memset(to_core, 0, sizeof(to_core));
    memset(last_loc_cancel, 0, sizeof(last_loc_cancel));
    NWIRE = 0;
    now = 0;
    next_link = 0;
    sim_rng = 5;
    oc_core_mem_init(&SMEM);
    SST = oc_core_mem_store(&SMEM);
    memset(r, 0x11, 32);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&SST, 1, 1800, r, 1790000000u));
    oc_core_route_init(&SRT, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&SRT, "8831606", 1, 1));
    sim_core_start();
    for (int i = 0; i < SIM_CELLS; i++) {
        char name[] = "cell ?";
        name[5] = (char)('1' + i);
        /* cells 1 and 2 share channel-list group 1; cell 3 is group 2 */
        TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&CORE, (uint32_t)(i + 1), name, OC_SIG_MODE_PART15,
                                                  (uint16_t)(i < 2 ? 1 : 2)));
        sim_cell_start(i);
        sim_connect(i);
    }
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        char num[] = "+88316065550123?";
        uint8_t got[OC_SIG_NUMBER_LEN];
        num[15] = (char)('0' + i);
        TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(num, strlen(num), t->number));
        TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&CORE, t->number, got));
        t->tmid = 0x76000000u + (uint32_t)i;
        t->cell = -1;
        memset(r, 0x40 + i, 32);
        oc_sig_ident_new(&t->id, r);
        const oc_sig_term_io_t io = { t, t_send, t_svc, NULL, t_event };
        oc_sig_term_init(&t->t, &io, &t->id, t->tmid, now);
    }
    run_ms(500); /* HELLO, HELLO_ACK */
    for (int i = 0; i < SIM_CELLS; i++) TEST_ASSERT_TRUE(CELL[i].c.ready);
}

static inline const uint8_t *event(const sim_term_t *t, uint8_t code)
{
    for (int i = t->nev - 1; i >= 0 && i >= t->nev - 64; i--) {
        if (t->ev[i % 64][0] == code) return t->ev[i % 64];
    }
    return NULL;
}

static inline uint8_t state(int i) { return oc_sig_term_state(&TERM[i].t); }

static inline void command(int i, const uint8_t *cmd, size_t n)
{
    TEST_ASSERT_EQUAL_UINT8(0, oc_sig_term_command(&TERM[i].t, cmd, n, now));
}

/* A fresh QR for number, scanned on terminal i (attached to cell). */
static inline void activate_number(int i, int cell, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    oc_sig_qr_t qr;
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    TERM[i].cell = cell;
    TEST_ASSERT_EQUAL_INT(0, oc_core_token_issue(&CORE, number, 3600, &qr));
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&qr, (char *)cmd + 1, sizeof(cmd) - 1);
    command(i, cmd, 1 + n);
}

/* A fresh QR from the core for terminal i's subscriber, scanned on it. */
static inline void activate_on(int i, int cell) { activate_number(i, cell, TERM[i].number); }

/* Terminal i activated and registered on cell. */
static inline void registered_on(int i, int cell)
{
    activate_on(i, cell);
    run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(OC_SIG_ST_REGISTERED, state(i), "registered");
}

static inline void dial(int i, const char *number)
{
    uint8_t cmd[1 + 24];
    size_t n = strlen(number);
    cmd[0] = OC_SIG_CMD_DIAL;
    memcpy(cmd + 1, number, n);
    command(i, cmd, 1 + n);
}

static inline void press(int i, uint8_t cmd) { command(i, &cmd, 1); }

/* App data from terminal i, as its app would send it. */
static inline void talk(int i, const char *s)
{
    uint8_t out[OC_SIG_LINK_MAX], on;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_term_data_out(&TERM[i].t, (const uint8_t *)s, (uint8_t)strlen(s), out, &on));
    sim_qpush(&TERM[i].ul, out, on);
}

/* The cause of terminal i's last ENDED, or -1. */
static inline int ended(int i)
{
    const uint8_t *e = event(&TERM[i], OC_SIG_EV_ENDED);
    return e != NULL ? e[5] : -1;
}

static inline void forget_events(void)
{
    for (int i = 0; i < SIM_TERMS; i++) TERM[i].nev = 0;
}

/* The core's view: the cell (1-based id) number i is located on, 0 if none. */
static inline uint32_t located(int i)
{
    oc_core_loc_t l;
    return SST.loc_get(SST.ctx, TERM[i].number, &l) == 0 ? l.cell_id : 0;
}

/* Play back what terminal i's UL carried while it was recorded, as its own. */
static inline void replay_recorded(int i)
{
    for (int k = 0; k < TERM[i].nrp; k++) {
        TEST_ASSERT_EQUAL_INT(0, sim_qpush(&TERM[i].ul, TERM[i].rp[k], TERM[i].rn[k]));
    }
}

/* cell's registration record for terminal i, NULL if none. */
static inline const oc_cell_reg_t *reg_on(int cell, int i)
{
    for (unsigned k = 0; k < OC_SIG_NET_TERMS; k++) {
        const oc_cell_reg_t *r = &CELL[cell].c.regs[k];
        if (r->used && r->tmid == TERM[i].tmid) return r;
    }
    return NULL;
}

/* Terminal i's session on cell, NULL if it has none. */
static inline const oc_sig_net_sess_t *sess_on(int cell, int i)
{
    for (unsigned k = 0; k < OC_SIG_NET_TERMS; k++) {
        const oc_sig_net_sess_t *s = &CELL[cell].c.net.s[k];
        if (s->used && s->tmid == TERM[i].tmid) return s;
    }
    return NULL;
}

/* Frames until terminal i's event code, at most ms; 1 when it came. */
static inline int run_until_event(int i, uint8_t code, uint32_t ms)
{
    for (uint32_t t = 0; t < ms && event(&TERM[i], code) == NULL; t += SIM_FRAME / 1000u) frame();
    return event(&TERM[i], code) != NULL;
}

#endif
