/* The switch (network-core spec §7.4-7.6): routes a cell's CALL_ROUTE to
 * the callee's cell, to one of this core's services (the echo service, the
 * playback service: core test services spec §5), or over OCSS to the core
 * that is home for the callee's block (spec §6), and serves a peer core's
 * CALL_SETUP the same way; relays alert, answer, release and media between
 * the two legs, runs the setup timer and the playback service's clock, and
 * writes a CDR for every call attempt. */
#include "oc_core_int.h"

#include <string.h>

#include "oc_sig_keys.h" /* oc_sig_wipe */

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, OC_SIG_NUMBER_LEN) == 0; }

static int num_set(const uint8_t *a)
{
    static const uint8_t none[OC_SIG_NUMBER_LEN];
    return memcmp(a, none, OC_SIG_NUMBER_LEN) != 0;
}

static int is_service(const oc_core_leg_t *l) { return l->kind == OC_CORE_LEG_ECHO || l->kind == OC_CORE_LEG_PLAY; }

/* OC_CORE_LEG_ECHO or _PLAY if called is one of this core's services, else 0. */
static uint8_t service(const oc_core_t *k, const uint8_t *called)
{
    if (num_eq(called, k->cfg.echo_number)) return OC_CORE_LEG_ECHO;
    if (num_set(k->cfg.playback_number) && num_eq(called, k->cfg.playback_number)) return OC_CORE_LEG_PLAY;
    return 0;
}

/* A message to a leg: a cell's §6 type, or its OCSS analogue to a peer;
 * nothing to a service. 0, or -1 (logged). */
static int leg_send(oc_core_t *k, const oc_core_leg_t *leg, oc_core_msg_t *m)
{
    int r;
    if (is_service(leg)) return 0;
    if (leg->kind == OC_CORE_LEG_PEER) {
        m->type = (uint8_t)(m->type + OC_OCSS_OFFSET);
        r = oc_core_peer_send(k, leg->peer, m);
    } else {
        r = oc_core_send(k, leg->cell, m);
    }
    if (r != 0) {
        oc_core_logf(k, "%s %u: send of %02x (ref %08x) failed", leg->kind == OC_CORE_LEG_PEER ? "peer" : "cell",
                     leg->kind == OC_CORE_LEG_PEER ? (unsigned)leg->peer : (unsigned)leg->cell, (unsigned)m->type,
                     (unsigned)leg->ref);
    }
    return r;
}

static void to_leg(oc_core_t *k, const oc_core_leg_t *leg, uint8_t type, uint8_t cause)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = leg->ref;
    m.u.call.cause = cause;
    leg_send(k, leg, &m);
}

static void media_to(oc_core_t *k, const oc_core_leg_t *leg, uint16_t seq, const uint8_t *data, uint8_t len)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.ref = leg->ref;
    m.u.media.seq = seq;
    m.u.media.len = len;
    memcpy(m.u.media.data, data, len);
    leg_send(k, leg, &m);
}

static void cdr(oc_core_t *k, const oc_core_call_t *c, uint8_t cause)
{
    oc_core_cdr_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.caller, c->caller, OC_SIG_NUMBER_LEN);
    memcpy(r.called, c->called, OC_SIG_NUMBER_LEN);
    r.cell_a = c->a.cell; /* 0 for a service's or a peer's leg */
    r.cell_b = c->b.cell;
    r.setup = c->setup;
    r.answer = c->answer;
    r.end = oc_core_unix(k);
    r.cause = cause;
    if (k->st.cdr_add(k->st.ctx, &r) != 0) {
        char caller[OC_SIG_NUMBER_TEXT], called[OC_SIG_NUMBER_TEXT];
        oc_sig_number_to_text(c->caller, caller);
        oc_sig_number_to_text(c->called, called);
        oc_core_logf(k, "CDR write FAILED: %s -> %s (%08x/%08x cause %u)", caller, called, (unsigned)c->a.ref,
                     (unsigned)c->b.ref, cause);
    }
}

static void end_call(oc_core_t *k, oc_core_call_t *c, uint8_t cause)
{
    if (c->b.kind == OC_CORE_LEG_PLAY && c->answer != 0) {
        oc_core_logf(k, "call %08x: playback sent %u payloads, skipped %u", (unsigned)c->a.ref, (unsigned)c->play_sent,
                     (unsigned)c->play_skipped);
    }
    cdr(k, c, cause);
    oc_core_logf(k, "call %08x/%08x ended, cause %u", (unsigned)c->a.ref, (unsigned)c->b.ref, cause);
    c->used = 0;
}

/* The call that has a cell's leg (cell, ref); *leg is it, *other the far
 * one. Only a cell's leg has a cell id (never 0). */
static oc_core_call_t *find(oc_core_t *k, uint32_t cell, uint32_t ref, oc_core_leg_t **leg, oc_core_leg_t **other)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (!c->used) continue;
        if (c->a.cell == cell && c->a.ref == ref) {
            *leg = &c->a;
            *other = &c->b;
            return c;
        }
        if (c->b.cell == cell && c->b.ref == ref) {
            *leg = &c->b;
            *other = &c->a;
            return c;
        }
    }
    return NULL;
}

static int peer_leg(const oc_core_leg_t *l, uint16_t peer, uint32_t ref)
{
    return l->kind == OC_CORE_LEG_PEER && l->peer == peer && l->ref == ref;
}

/* The call that has a peer's leg (peer, call_ref). */
static oc_core_call_t *find_peer(oc_core_t *k, uint16_t peer, uint32_t ref, oc_core_leg_t **leg, oc_core_leg_t **other)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (!c->used) continue;
        if (peer_leg(&c->a, peer, ref)) {
            *leg = &c->a;
            *other = &c->b;
            return c;
        }
        if (peer_leg(&c->b, peer, ref)) {
            *leg = &c->b;
            *other = &c->a;
            return c;
        }
    }
    return NULL;
}

static unsigned peer_calls(const oc_core_t *k, uint16_t peer)
{
    unsigned n = 0;
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        const oc_core_call_t *c = &k->calls[i];
        n += c->used && ((c->a.kind == OC_CORE_LEG_PEER && c->a.peer == peer) ||
                         (c->b.kind == OC_CORE_LEG_PEER && c->b.peer == peer));
    }
    return n;
}

/* A free call, or full (no room: the call is refused, its CDR still
 * written), with a fresh core ref for leg b. */
static oc_core_call_t *new_call(oc_core_t *k, oc_core_call_t *full, const uint8_t *caller, const uint8_t *called)
{
    oc_core_call_t *c = NULL;
    for (unsigned i = 0; i < OC_CORE_CALLS && c == NULL; i++) {
        if (!k->calls[i].used) c = &k->calls[i];
    }
    if (c == NULL) c = full;
    memset(c, 0, sizeof(*c));
    c->used = c != full;
    k->next_ref = (k->next_ref + 1u) & ~OC_CORE_REF_CORE;
    c->b.ref = OC_CORE_REF_CORE | k->next_ref;
    memcpy(c->caller, caller, OC_SIG_NUMBER_LEN);
    memcpy(c->called, called, OC_SIG_NUMBER_LEN);
    c->setup = oc_core_unix(k);
    return c;
}

/* Where a call to `called` goes from this core (core test services spec
 * §6.3): 0 with to's kind (and its cell or peer) set, or the cause to
 * release the call with. A call that came over OCSS (from_peer) is never
 * sent on to another core: a number whose block this core is not home for
 * is unreachable then, so no call can loop between cores. */
static uint8_t resolve(oc_core_t *k, const uint8_t *called, int from_peer, oc_core_leg_t *to)
{
    oc_core_sub_t s;
    oc_core_loc_t l;
    int got;
    uint8_t why = 0;
    if ((to->kind = service(k, called)) != 0) return 0;
    const oc_core_block_t *b = oc_core_route_find(&k->route, called);
    if (b == NULL) return OC_SIG_CAUSE_UNREACHABLE; /* no route: not 883, or no block */
    if (!oc_core_route_home(&k->route, b)) {
        if (from_peer) return OC_SIG_CAUSE_UNREACHABLE;
        if (!oc_core_peer_linked(k, b->home_core)) return OC_SIG_CAUSE_NET_FAILURE; /* its home core is cut off */
        to->kind = OC_CORE_LEG_PEER;
        to->peer = b->home_core;
        return 0;
    }
    memset(&s, 0, sizeof(s));
    if ((got = k->st.sub_get(k->st.ctx, called, &s)) == OC_CORE_STORE_FAILED) {
        oc_core_logf(k, "route: callee read FAILED");
        why = OC_SIG_CAUSE_NET_FAILURE; /* a failed read is not "unknown" (oc_core_store.h) */
    } else if (got != 0 || s.state != OC_CORE_SUB_ACTIVE || !s.activated) {
        why = OC_SIG_CAUSE_UNREACHABLE; /* unknown, disabled, or not activated */
    } else if ((got = oc_core_loc_live(k, called, &l)) == OC_CORE_STORE_FAILED) {
        oc_core_logf(k, "route: callee location read FAILED");
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else if (got != 0) {
        why = OC_SIG_CAUSE_UNREACHABLE; /* registered nowhere */
    } else if (!oc_core_linked(k, l.cell_id)) {
        why = OC_SIG_CAUSE_NET_FAILURE; /* the callee's cell is cut off */
    } else {
        to->cell = l.cell_id;
    }
    oc_sig_wipe(s.k, sizeof(s.k)); /* only its state was wanted */
    oc_sig_wipe(s.opc, sizeof(s.opc));
    return why;
}

/* Leg b is resolved: a service rings at once; a cell is offered the call;
 * a peer is asked to set it up. */
static void start_b(oc_core_t *k, oc_core_call_t *c)
{
    oc_core_msg_t o;
    memset(&o, 0, sizeof(o));
    if (is_service(&c->b)) {
        c->state = OC_CORE_CALL_ALERTING;
        c->due = k->now + OC_CORE_ECHO_US;
        to_leg(k, &c->a, OC_CORE_CALL_ALERT, 0);
        return;
    }
    c->state = OC_CORE_CALL_ROUTING;
    c->due = k->now + OC_CORE_SETUP_US;
    if (c->b.kind == OC_CORE_LEG_PEER) {
        o.type = OC_OCSS_CALL_SETUP;
        o.u.setup.call_ref = c->b.ref;
        memcpy(o.u.setup.caller, c->caller, OC_SIG_NUMBER_LEN);
        memcpy(o.u.setup.called, c->called, OC_SIG_NUMBER_LEN);
        o.u.setup.hop = 0;
        if (oc_core_peer_send(k, c->b.peer, &o) != 0) oc_core_logf(k, "peer %u: CALL_SETUP failed", (unsigned)c->b.peer);
        return;
    }
    o.type = OC_CORE_CALL_OFFER;
    o.u.call_offer.call_ref = c->b.ref;
    memcpy(o.u.call_offer.callee, c->called, OC_SIG_NUMBER_LEN);
    memcpy(o.u.call_offer.caller, c->caller, OC_SIG_NUMBER_LEN);
    oc_core_send(k, c->b.cell, &o);
}

static void refused(oc_core_t *k, oc_core_call_t *c, uint8_t why)
{
    to_leg(k, &c->a, OC_CORE_CALL_RELEASE, why);
    end_call(k, c, why);
}

static void on_route(oc_core_t *k, uint32_t cell, const oc_core_msg_t *m)
{
    oc_core_leg_t *leg, *other;
    oc_core_loc_t la;
    if ((m->u.call_route.leg_ref & OC_CORE_REF_CORE) != 0 || find(k, cell, m->u.call_route.leg_ref, &leg, &other)) {
        return; /* not a cell's ref, or a leg already routed */
    }
    oc_core_call_t full, *c = new_call(k, &full, m->u.call_route.caller, m->u.call_route.called);
    c->a.cell = cell;
    c->a.ref = m->u.call_route.leg_ref;
    uint8_t why = 0;
    if (c == &full) {
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else if (oc_core_loc_live(k, c->caller, &la) != 0 || la.cell_id != cell) {
        /* a cell calls only as a subscriber registered on it */
        oc_core_logf(k, "cell %u: CALL_ROUTE from a caller not registered there", (unsigned)cell);
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else {
        why = resolve(k, c->called, 0, &c->b);
    }
    if (why != 0) {
        refused(k, c, why);
        return;
    }
    start_b(k, c);
}

/* A peer core's CALL_SETUP (core test services spec §6.3): served as a
 * cell's CALL_ROUTE is, but the caller is the peer's to vouch for (it
 * authenticated the caller's terminal; this core can't), and at most
 * OC_CORE_PEER_CALLS calls at once come from one peer. */
static void on_setup(oc_core_t *k, uint16_t peer, const oc_core_msg_t *m)
{
    oc_core_leg_t *leg, *other;
    if (find_peer(k, peer, m->u.setup.call_ref, &leg, &other) != NULL) return; /* a repeat */
    oc_core_call_t full, *c = new_call(k, &full, m->u.setup.caller, m->u.setup.called);
    c->a.kind = OC_CORE_LEG_PEER;
    c->a.peer = peer;
    c->a.ref = m->u.setup.call_ref;
    uint8_t why = 0;
    if (c == &full || peer_calls(k, peer) > OC_CORE_PEER_CALLS) {
        oc_core_logf(k, "peer %u: CALL_SETUP refused: %s", (unsigned)peer, c == &full ? "no room" : "too many calls");
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else if (m->u.setup.hop > OC_CORE_HOP_MAX) {
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else {
        why = resolve(k, c->called, 1, &c->b);
    }
    if (why != 0) {
        refused(k, c, why);
        return;
    }
    start_b(k, c);
}

/* A message about an existing leg, whoever sent it; type is the §6 type
 * (an OCSS one less OC_OCSS_OFFSET). */
static void leg_rx(oc_core_t *k, oc_core_call_t *c, oc_core_leg_t *leg, oc_core_leg_t *other, uint8_t type,
                   const oc_core_msg_t *m)
{
    switch (type) {
    case OC_CORE_CALL_ALERT:
        if (leg == &c->b && c->state == OC_CORE_CALL_ROUTING) {
            c->state = OC_CORE_CALL_ALERTING;
            to_leg(k, &c->a, OC_CORE_CALL_ALERT, 0);
        }
        break;
    case OC_CORE_CALL_ANSWER:
        if (leg == &c->b && c->state != OC_CORE_CALL_ACTIVE) {
            c->state = OC_CORE_CALL_ACTIVE;
            c->answer = oc_core_unix(k);
            to_leg(k, &c->a, OC_CORE_CALL_ANSWER, 0);
        }
        break;
    case OC_CORE_CALL_RELEASE:
        if (leg == &c->b && leg->kind == OC_CORE_LEG_CELL && c->state == OC_CORE_CALL_ROUTING &&
            m->u.call.cause == OC_SIG_CAUSE_UNREACHABLE) {
            oc_core_loc_t l; /* §7.4 step 3: no such session there, so the location was stale */
            if (k->st.loc_get(k->st.ctx, c->called, &l) == 0 && l.cell_id == c->b.cell &&
                k->st.loc_del(k->st.ctx, c->called) != 0) {
                oc_core_logf(k, "cell %u: stale location delete failed", (unsigned)c->b.cell);
            }
        }
        to_leg(k, other, OC_CORE_CALL_RELEASE, m->u.call.cause); /* the same cause on the other leg */
        end_call(k, c, m->u.call.cause);
        break;
    case OC_CORE_MEDIA:
        if (c->state != OC_CORE_CALL_ACTIVE) break;
        if (other->kind == OC_CORE_LEG_PLAY) {
            /* the caller's terminal is connected: the clip may start now */
            if (c->play_sent == 0 && c->play_next > k->now) c->play_next = k->now;
            break;
        }
        /* the echo service sends it back */
        media_to(k, other->kind == OC_CORE_LEG_ECHO ? leg : other, m->u.media.seq, m->u.media.data, m->u.media.len);
        break;
    default:
        break;
    }
}

void oc_core_sw_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    oc_core_leg_t *leg, *other;
    if (m->type == OC_CORE_CALL_ROUTE) {
        on_route(k, cell_id, m);
        return;
    }
    oc_core_call_t *c = find(k, cell_id, m->type == OC_CORE_MEDIA ? m->u.media.ref : m->u.call.ref, &leg, &other);
    if (c != NULL) leg_rx(k, c, leg, other, m->type, m);
}

void oc_core_sw_peer_rx(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m)
{
    oc_core_leg_t *leg, *other;
    if (m->type == OC_OCSS_CALL_SETUP) {
        on_setup(k, core_id, m);
        return;
    }
    uint8_t type = (uint8_t)(m->type - OC_OCSS_OFFSET);
    oc_core_call_t *c = find_peer(k, core_id, type == OC_CORE_MEDIA ? m->u.media.ref : m->u.call.ref, &leg, &other);
    if (c != NULL) leg_rx(k, c, leg, other, type, m);
}

/* The playback service's clock (core test services spec §5.3): every
 * payload that is due goes to the caller, in clip order, looping. One that
 * is OC_CORE_PLAY_LATE_US late or more (the loop stalled: a slow disk, an
 * admin command) is skipped with every other missed one, so the cell's DL
 * queue never takes a burst of more than two. */
static void play_tick(oc_core_t *k, oc_core_call_t *c)
{
    while (k->now >= c->play_next) {
        uint64_t late = k->now - c->play_next;
        if (late >= OC_CORE_PLAY_LATE_US) {
            uint64_t n = late / OC_CORE_PLAY_US;
            c->play_skipped += (uint32_t)n;
            c->play_seq = (uint16_t)(c->play_seq + n);
            c->play_at = (uint32_t)((c->play_at + n * OC_CORE_PLAY_BYTES) % k->cfg.clip_len);
            c->play_next += n * OC_CORE_PLAY_US;
            continue;
        }
        media_to(k, &c->a, c->play_seq++, k->cfg.clip + c->play_at, OC_CORE_PLAY_BYTES);
        c->play_sent++;
        c->play_at = (c->play_at + OC_CORE_PLAY_BYTES) % k->cfg.clip_len;
        c->play_next += OC_CORE_PLAY_US;
    }
}

/* When oc_core_sw_tick next has something to do for c; UINT64_MAX: nothing. */
static uint64_t call_due(const oc_core_call_t *c)
{
    if (!c->used) return UINT64_MAX;
    if (c->state == OC_CORE_CALL_ROUTING || (c->state == OC_CORE_CALL_ALERTING && is_service(&c->b))) return c->due;
    if (c->state == OC_CORE_CALL_ACTIVE && c->b.kind == OC_CORE_LEG_PLAY) {
        return c->play_next < c->due ? c->play_next : c->due;
    }
    return UINT64_MAX;
}

uint64_t oc_core_due(const oc_core_t *k)
{
    uint64_t due = UINT64_MAX;
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        uint64_t d = call_due(&k->calls[i]);
        if (d < due) due = d;
    }
    return due;
}

void oc_core_sw_tick(oc_core_t *k)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (k->now < call_due(c)) continue; /* also: not used, or nothing to do */
        if (c->state == OC_CORE_CALL_ROUTING) { /* no alert or release from the callee's side in 10 s */
            to_leg(k, &c->a, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
            to_leg(k, &c->b, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
            end_call(k, c, OC_SIG_CAUSE_NET_FAILURE);
        } else if (c->state == OC_CORE_CALL_ALERTING) { /* a service answers */
            c->state = OC_CORE_CALL_ACTIVE;
            c->answer = oc_core_unix(k);
            to_leg(k, &c->a, OC_CORE_CALL_ANSWER, 0);
            if (c->b.kind == OC_CORE_LEG_PLAY) {
                c->play_next = k->now + OC_CORE_PLAY_LEAD_US;
                c->due = k->now + OC_CORE_PLAY_MAX_US;
            }
        } else if (k->now >= c->due) { /* the playback service has played long enough */
            to_leg(k, &c->a, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NORMAL);
            end_call(k, c, OC_SIG_CAUSE_NORMAL);
        } else {
            play_tick(k, c);
        }
    }
}

/* Every call with a leg on the gone side ends, cause 5 to the other leg. */
static void gone(oc_core_t *k, int (*on)(const oc_core_leg_t *, uint32_t), uint32_t id)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (!c->used || (!on(&c->a, id) && !on(&c->b, id))) continue;
        if (!on(&c->a, id)) to_leg(k, &c->a, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
        if (!on(&c->b, id)) to_leg(k, &c->b, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
        end_call(k, c, OC_SIG_CAUSE_NET_FAILURE);
    }
}

static int on_cell(const oc_core_leg_t *l, uint32_t id) { return l->kind == OC_CORE_LEG_CELL && l->cell == id; }
static int on_peer(const oc_core_leg_t *l, uint32_t id) { return l->kind == OC_CORE_LEG_PEER && l->peer == id; }

void oc_core_sw_cell_gone(oc_core_t *k, uint32_t cell_id) { gone(k, on_cell, cell_id); }
void oc_core_sw_peer_gone(oc_core_t *k, uint16_t core_id) { gone(k, on_peer, core_id); }
