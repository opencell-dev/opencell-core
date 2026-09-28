/* The switch (network-core spec §7.4-7.6): routes a cell's CALL_ROUTE to
 * the callee's cell (or the echo service), relays alert, answer, release
 * and media between the two legs, runs the setup timer, and writes a CDR
 * for every call attempt. */
#include "lc_core_int.h"

#include <string.h>

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

static void to_leg(lc_core_t *k, const lc_core_leg_t *leg, uint8_t type, uint8_t cause)
{
    if (leg->cell == 0) return; /* the echo service */
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = leg->ref;
    m.u.call.cause = cause;
    lc_core_send(k, leg->cell, &m);
}

static void cdr(lc_core_t *k, const lc_core_call_t *c, uint8_t cause)
{
    lc_core_cdr_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.caller, c->caller, LC_SIG_NUMBER_LEN);
    memcpy(r.called, c->called, LC_SIG_NUMBER_LEN);
    r.cell_a = c->a.cell;
    r.cell_b = c->b.cell;
    r.setup = c->setup;
    r.answer = c->answer;
    r.end = lc_core_unix(k);
    r.cause = cause;
    if (k->st.cdr_add(k->st.ctx, &r) != 0) lc_core_logf(k, "CDR write FAILED");
}

static void end_call(lc_core_t *k, lc_core_call_t *c, uint8_t cause)
{
    cdr(k, c, cause);
    lc_core_logf(k, "call %08x/%08x ended, cause %u", (unsigned)c->a.ref, (unsigned)c->b.ref, cause);
    c->used = 0;
}

/* The call that has leg (cell, ref); *leg is it, *other the far one. */
static lc_core_call_t *find(lc_core_t *k, uint32_t cell, uint32_t ref, lc_core_leg_t **leg, lc_core_leg_t **other)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
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

static void on_route(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    const uint8_t *called = m->u.call_route.called;
    lc_core_leg_t *leg, *other;
    lc_core_call_t *c = NULL;
    lc_core_loc_t la, lb;
    lc_core_sub_t s;
    if ((m->u.call_route.leg_ref & LC_CORE_REF_CORE) != 0 || find(k, cell, m->u.call_route.leg_ref, &leg, &other)) {
        return; /* not a cell's ref, or a leg already routed */
    }
    for (unsigned i = 0; i < LC_CORE_CALLS && c == NULL; i++) {
        if (!k->calls[i].used) c = &k->calls[i];
    }
    lc_core_call_t full;
    if (c == NULL) c = &full; /* no room: refused below, the CDR still written */
    memset(c, 0, sizeof(*c));
    c->used = c != &full;
    c->a.cell = cell;
    c->a.ref = m->u.call_route.leg_ref;
    k->next_ref = (k->next_ref + 1u) & ~LC_CORE_REF_CORE;
    c->b.ref = LC_CORE_REF_CORE | k->next_ref;
    memcpy(c->caller, m->u.call_route.caller, LC_SIG_NUMBER_LEN);
    memcpy(c->called, called, LC_SIG_NUMBER_LEN);
    c->setup = lc_core_unix(k);
    uint8_t why = 0;
    if (c == &full) {
        why = LC_SIG_CAUSE_NET_FAILURE;
    } else if (lc_core_loc_live(k, c->caller, &la) != 0 || la.cell_id != cell) {
        /* a cell calls only as a subscriber registered on it */
        lc_core_logf(k, "cell %u: CALL_ROUTE from a caller not registered there", (unsigned)cell);
        why = LC_SIG_CAUSE_NET_FAILURE;
    } else if (num_eq(called, k->cfg.echo_number)) {
        c->state = LC_CORE_CALL_ALERTING; /* the echo service rings at once */
        c->due = k->now + LC_CORE_ECHO_US;
        to_leg(k, &c->a, LC_CORE_CALL_ALERT, 0);
        return;
    } else if (!lc_core_route_home(&k->route, lc_core_route_find(&k->route, called)) ||
               k->st.sub_get(k->st.ctx, called, &s) != 0 || s.state != LC_CORE_SUB_ACTIVE || !s.activated ||
               lc_core_loc_live(k, called, &lb) != 0) {
        why = LC_SIG_CAUSE_UNREACHABLE; /* unknown, not ours, disabled, or registered nowhere */
    } else if (!lc_core_linked(k, lb.cell_id)) {
        why = LC_SIG_CAUSE_NET_FAILURE; /* the callee's cell is cut off */
    }
    if (why != 0) {
        to_leg(k, &c->a, LC_CORE_CALL_RELEASE, why);
        end_call(k, c, why);
        return;
    }
    c->b.cell = lb.cell_id;
    c->state = LC_CORE_CALL_ROUTING;
    c->due = k->now + LC_CORE_SETUP_US;
    lc_core_msg_t o;
    memset(&o, 0, sizeof(o));
    o.type = LC_CORE_CALL_OFFER;
    o.u.call_offer.call_ref = c->b.ref;
    memcpy(o.u.call_offer.callee, called, LC_SIG_NUMBER_LEN);
    memcpy(o.u.call_offer.caller, c->caller, LC_SIG_NUMBER_LEN);
    lc_core_send(k, c->b.cell, &o);
}

void lc_core_sw_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    lc_core_leg_t *leg, *other;
    lc_core_call_t *c;
    if (m->type == LC_CORE_CALL_ROUTE) {
        on_route(k, cell_id, m);
        return;
    }
    c = find(k, cell_id, m->type == LC_CORE_MEDIA ? m->u.media.ref : m->u.call.ref, &leg, &other);
    if (c == NULL) return;
    switch (m->type) {
    case LC_CORE_CALL_ALERT:
        if (leg == &c->b && c->state == LC_CORE_CALL_ROUTING) {
            c->state = LC_CORE_CALL_ALERTING;
            to_leg(k, &c->a, LC_CORE_CALL_ALERT, 0);
        }
        break;
    case LC_CORE_CALL_ANSWER:
        if (leg == &c->b && c->state != LC_CORE_CALL_ACTIVE) {
            c->state = LC_CORE_CALL_ACTIVE;
            c->answer = lc_core_unix(k);
            to_leg(k, &c->a, LC_CORE_CALL_ANSWER, 0);
        }
        break;
    case LC_CORE_CALL_RELEASE:
        if (leg == &c->b && c->state == LC_CORE_CALL_ROUTING && m->u.call.cause == LC_SIG_CAUSE_UNREACHABLE) {
            lc_core_loc_t l; /* §7.4 step 3: no such session there, so the location was stale */
            if (k->st.loc_get(k->st.ctx, c->called, &l) == 0 && l.cell_id == c->b.cell) k->st.loc_del(k->st.ctx, c->called);
        }
        to_leg(k, other, LC_CORE_CALL_RELEASE, m->u.call.cause); /* the same cause on the other leg */
        end_call(k, c, m->u.call.cause);
        break;
    case LC_CORE_MEDIA:
        if (c->state == LC_CORE_CALL_ACTIVE) {
            lc_core_msg_t d = *m;
            const lc_core_leg_t *to = other->cell != 0 ? other : leg; /* the echo service sends it back */
            d.u.media.ref = to->ref;
            lc_core_send(k, to->cell, &d);
        }
        break;
    default:
        break;
    }
}

void lc_core_sw_tick(lc_core_t *k)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
        if (!c->used || k->now < c->due) continue;
        if (c->state == LC_CORE_CALL_ROUTING) { /* no alert or release from the callee's cell in 10 s */
            to_leg(k, &c->a, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
            to_leg(k, &c->b, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
            end_call(k, c, LC_SIG_CAUSE_NET_FAILURE);
        } else if (c->state == LC_CORE_CALL_ALERTING && c->b.cell == 0) { /* the echo service answers */
            c->state = LC_CORE_CALL_ACTIVE;
            c->answer = lc_core_unix(k);
            to_leg(k, &c->a, LC_CORE_CALL_ANSWER, 0);
        }
    }
}

void lc_core_sw_cell_gone(lc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
        if (!c->used || (c->a.cell != cell_id && c->b.cell != cell_id)) continue;
        if (c->a.cell != cell_id) to_leg(k, &c->a, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
        if (c->b.cell != cell_id) to_leg(k, &c->b, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
        end_call(k, c, LC_SIG_CAUSE_NET_FAILURE);
    }
}
