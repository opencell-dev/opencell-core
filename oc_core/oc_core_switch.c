/* The switch (network-core spec §7.4-7.6): routes a cell's CALL_ROUTE to
 * the callee's cell (or the echo service), relays alert, answer, release
 * and media between the two legs, runs the setup timer, and writes a CDR
 * for every call attempt. */
#include "oc_core_int.h"

#include <string.h>

#include "oc_sig_keys.h" /* oc_sig_wipe */

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, OC_SIG_NUMBER_LEN) == 0; }

static void to_leg(oc_core_t *k, const oc_core_leg_t *leg, uint8_t type, uint8_t cause)
{
    if (leg->cell == 0) return; /* the echo service */
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = leg->ref;
    m.u.call.cause = cause;
    if (oc_core_send(k, leg->cell, &m) != 0) {
        oc_core_logf(k, "cell %u: send of %u (ref %08x, cause %u) failed", (unsigned)leg->cell, (unsigned)type,
                     (unsigned)leg->ref, (unsigned)cause);
    }
}

static void cdr(oc_core_t *k, const oc_core_call_t *c, uint8_t cause)
{
    oc_core_cdr_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.caller, c->caller, OC_SIG_NUMBER_LEN);
    memcpy(r.called, c->called, OC_SIG_NUMBER_LEN);
    r.cell_a = c->a.cell;
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
    cdr(k, c, cause);
    oc_core_logf(k, "call %08x/%08x ended, cause %u", (unsigned)c->a.ref, (unsigned)c->b.ref, cause);
    c->used = 0;
}

/* The call that has leg (cell, ref); *leg is it, *other the far one. */
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

static void on_route(oc_core_t *k, uint32_t cell, const oc_core_msg_t *m)
{
    const uint8_t *called = m->u.call_route.called;
    oc_core_leg_t *leg, *other;
    oc_core_call_t *c = NULL;
    oc_core_loc_t la, lb;
    oc_core_sub_t s;
    if ((m->u.call_route.leg_ref & OC_CORE_REF_CORE) != 0 || find(k, cell, m->u.call_route.leg_ref, &leg, &other)) {
        return; /* not a cell's ref, or a leg already routed */
    }
    for (unsigned i = 0; i < OC_CORE_CALLS && c == NULL; i++) {
        if (!k->calls[i].used) c = &k->calls[i];
    }
    oc_core_call_t full;
    if (c == NULL) c = &full; /* no room: refused below, the CDR still written */
    memset(c, 0, sizeof(*c));
    c->used = c != &full;
    c->a.cell = cell;
    c->a.ref = m->u.call_route.leg_ref;
    k->next_ref = (k->next_ref + 1u) & ~OC_CORE_REF_CORE;
    c->b.ref = OC_CORE_REF_CORE | k->next_ref;
    memcpy(c->caller, m->u.call_route.caller, OC_SIG_NUMBER_LEN);
    memcpy(c->called, called, OC_SIG_NUMBER_LEN);
    c->setup = oc_core_unix(k);
    uint8_t why = 0;
    if (c == &full) {
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else if (oc_core_loc_live(k, c->caller, &la) != 0 || la.cell_id != cell) {
        /* a cell calls only as a subscriber registered on it */
        oc_core_logf(k, "cell %u: CALL_ROUTE from a caller not registered there", (unsigned)cell);
        why = OC_SIG_CAUSE_NET_FAILURE;
    } else if (num_eq(called, k->cfg.echo_number)) {
        c->state = OC_CORE_CALL_ALERTING; /* the echo service rings at once */
        c->due = k->now + OC_CORE_ECHO_US;
        to_leg(k, &c->a, OC_CORE_CALL_ALERT, 0);
        return;
    } else if (!oc_core_route_home(&k->route, oc_core_route_find(&k->route, called)) ||
               k->st.sub_get(k->st.ctx, called, &s) != 0 || s.state != OC_CORE_SUB_ACTIVE || !s.activated ||
               oc_core_loc_live(k, called, &lb) != 0) {
        why = OC_SIG_CAUSE_UNREACHABLE; /* unknown, not ours, disabled, or registered nowhere */
    } else if (!oc_core_linked(k, lb.cell_id)) {
        why = OC_SIG_CAUSE_NET_FAILURE; /* the callee's cell is cut off */
    }
    oc_sig_wipe(s.k, sizeof(s.k)); /* only its state was wanted */
    oc_sig_wipe(s.opc, sizeof(s.opc));
    if (why != 0) {
        to_leg(k, &c->a, OC_CORE_CALL_RELEASE, why);
        end_call(k, c, why);
        return;
    }
    c->b.cell = lb.cell_id;
    c->state = OC_CORE_CALL_ROUTING;
    c->due = k->now + OC_CORE_SETUP_US;
    oc_core_msg_t o;
    memset(&o, 0, sizeof(o));
    o.type = OC_CORE_CALL_OFFER;
    o.u.call_offer.call_ref = c->b.ref;
    memcpy(o.u.call_offer.callee, called, OC_SIG_NUMBER_LEN);
    memcpy(o.u.call_offer.caller, c->caller, OC_SIG_NUMBER_LEN);
    oc_core_send(k, c->b.cell, &o);
}

void oc_core_sw_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m)
{
    oc_core_leg_t *leg, *other;
    oc_core_call_t *c;
    if (m->type == OC_CORE_CALL_ROUTE) {
        on_route(k, cell_id, m);
        return;
    }
    c = find(k, cell_id, m->type == OC_CORE_MEDIA ? m->u.media.ref : m->u.call.ref, &leg, &other);
    if (c == NULL) return;
    switch (m->type) {
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
        if (leg == &c->b && c->state == OC_CORE_CALL_ROUTING && m->u.call.cause == OC_SIG_CAUSE_UNREACHABLE) {
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
        if (c->state == OC_CORE_CALL_ACTIVE) {
            oc_core_msg_t d = *m;
            const oc_core_leg_t *to = other->cell != 0 ? other : leg; /* the echo service sends it back */
            d.u.media.ref = to->ref;
            if (oc_core_send(k, to->cell, &d) != 0) {
                oc_core_logf(k, "cell %u: media relay (ref %08x) failed", (unsigned)to->cell, (unsigned)to->ref);
            }
        }
        break;
    default:
        break;
    }
}

void oc_core_sw_tick(oc_core_t *k)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (!c->used || k->now < c->due) continue;
        if (c->state == OC_CORE_CALL_ROUTING) { /* no alert or release from the callee's cell in 10 s */
            to_leg(k, &c->a, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
            to_leg(k, &c->b, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
            end_call(k, c, OC_SIG_CAUSE_NET_FAILURE);
        } else if (c->state == OC_CORE_CALL_ALERTING && c->b.cell == 0) { /* the echo service answers */
            c->state = OC_CORE_CALL_ACTIVE;
            c->answer = oc_core_unix(k);
            to_leg(k, &c->a, OC_CORE_CALL_ANSWER, 0);
        }
    }
}

void oc_core_sw_cell_gone(oc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < OC_CORE_CALLS; i++) {
        oc_core_call_t *c = &k->calls[i];
        if (!c->used || (c->a.cell != cell_id && c->b.cell != cell_id)) continue;
        if (c->a.cell != cell_id) to_leg(k, &c->a, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
        if (c->b.cell != cell_id) to_leg(k, &c->b, OC_CORE_CALL_RELEASE, OC_SIG_CAUSE_NET_FAILURE);
        end_call(k, c, OC_SIG_CAUSE_NET_FAILURE);
    }
}
