#include "oc_core_msg.h"

#include <string.h>

/* ---- little-endian writer and reader over one frame ---- */

typedef struct {
    uint8_t *p;
    size_t   n, cap;
    int      bad;
} wr_t;

static void w8(wr_t *w, uint8_t v)
{
    if (w->n >= w->cap) {
        w->bad = 1;
        return;
    }
    w->p[w->n++] = v;
}
static void w16(wr_t *w, uint16_t v) { w8(w, (uint8_t)v); w8(w, (uint8_t)(v >> 8)); }
static void w32(wr_t *w, uint32_t v) { w16(w, (uint16_t)v); w16(w, (uint16_t)(v >> 16)); }
static void w64(wr_t *w, uint64_t v) { w32(w, (uint32_t)v); w32(w, (uint32_t)(v >> 32)); }
static void wb(wr_t *w, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) w8(w, b[i]);
}

typedef struct {
    const uint8_t *p;
    size_t         n, at;
    int            bad;
} rd_t;

static uint8_t r8(rd_t *r)
{
    if (r->at >= r->n) {
        r->bad = 1;
        return 0;
    }
    return r->p[r->at++];
}
static uint16_t r16(rd_t *r) { uint16_t lo = r8(r); return (uint16_t)(lo | (uint16_t)(r8(r) << 8)); }
static uint32_t r32(rd_t *r) { uint32_t lo = r16(r); return lo | ((uint32_t)r16(r) << 16); }
static uint64_t r64(rd_t *r) { uint64_t lo = r32(r); return lo | ((uint64_t)r32(r) << 32); }
static void rb(rd_t *r, uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = r8(r);
}
static void rnum(rd_t *r, uint8_t num[OC_SIG_NUMBER_LEN])
{
    rb(r, num, OC_SIG_NUMBER_LEN);
    if (!oc_sig_number_valid(num)) r->bad = 1;
}

static void w_av(wr_t *w, const oc_core_av_t *av)
{
    wb(w, av->rand, 16);
    wb(w, av->autn, 16);
    wb(w, av->hxres, 16);
    wb(w, av->ck, 16);
    wb(w, av->ik, 16);
}
static void r_av(rd_t *r, oc_core_av_t *av)
{
    rb(r, av->rand, 16);
    rb(r, av->autn, 16);
    rb(r, av->hxres, 16);
    rb(r, av->ck, 16);
    rb(r, av->ik, 16);
}

size_t oc_core_encode(const oc_core_msg_t *m, uint8_t *out, size_t cap)
{
    wr_t w = { out, 0, cap < OC_CORE_FRAME_MAX ? cap : OC_CORE_FRAME_MAX, 0 };
    uint8_t sig[OC_SIG_MAX_MSG];
    size_t sn;
    w16(&w, 0); /* the length, filled in below */
    w8(&w, m->type);
    switch (m->type) {
    case OC_CORE_HELLO:
        w8(&w, m->u.hello.proto);
        w32(&w, m->u.hello.cell_id);
        w64(&w, m->u.hello.boot_id);
        wb(&w, m->u.hello.sw_version, 3);
        break;
    case OC_CORE_HELLO_ACK:
        w8(&w, m->u.hello_ack.mode);
        w16(&w, m->u.hello_ack.period_s);
        w16(&w, m->u.hello_ack.key_id);
        wb(&w, m->u.hello_ack.echo_number, OC_SIG_NUMBER_LEN);
        break;
    case OC_CORE_HELLO_NAK:
        w8(&w, m->u.hello_nak.reason);
        break;
    case OC_CORE_PING:
    case OC_CORE_PONG:
    case OC_OCSS_PING:
    case OC_OCSS_PONG:
        break;
    case OC_OCSS_HELLO:
        w8(&w, m->u.peer_hello.proto);
        /* fall through */
    case OC_OCSS_HELLO_ACK:
        w16(&w, m->u.peer_hello.core_id);
        w32(&w, m->u.peer_hello.table_ver);
        break;
    case OC_OCSS_HELLO_NAK:
        w8(&w, m->u.hello_nak.reason);
        break;
    case OC_OCSS_CALL_SETUP:
        w32(&w, m->u.setup.call_ref);
        wb(&w, m->u.setup.caller, OC_SIG_NUMBER_LEN);
        wb(&w, m->u.setup.called, OC_SIG_NUMBER_LEN);
        w8(&w, m->u.setup.hop);
        break;
    case OC_CORE_CELL_CFG: {
        oc_sig_msg_t cl;
        memset(&cl, 0, sizeof(cl));
        cl.type = OC_SIG_CHAN_LIST;
        cl.u.chan_list = m->u.cell_cfg.list;
        sn = oc_sig_body_encode(&cl, sig, sizeof(sig));
        if (sn == 0) return 0;
        wb(&w, sig, sn);
        break;
    }
    case OC_CORE_ACT_FWD:
        w16(&w, m->u.act_fwd.req);
        w32(&w, m->u.act_fwd.tmid);
        wb(&w, m->u.act_fwd.token_id, 8);
        wb(&w, m->u.act_fwd.pkt, 32);
        wb(&w, m->u.act_fwd.tag, 8);
        break;
    case OC_CORE_ACT_RES:
        if (m->u.act_res.msg.type != OC_SIG_ACT_ACK && m->u.act_res.msg.type != OC_SIG_ACT_NAK) return 0;
        sn = oc_sig_body_encode(&m->u.act_res.msg, sig, sizeof(sig));
        if (sn == 0) return 0;
        w16(&w, m->u.act_res.req);
        w32(&w, m->u.act_res.tmid);
        w8(&w, m->u.act_res.msg.type);
        wb(&w, sig, sn);
        break;
    case OC_CORE_AV_REQ:
        w16(&w, m->u.av_req.req);
        w32(&w, m->u.av_req.tmid);
        w8(&w, m->u.av_req.count);
        break;
    case OC_CORE_AV_RES:
        if (m->u.av_res.count > OC_CORE_AV_MAX) return 0;
        w16(&w, m->u.av_res.req);
        w32(&w, m->u.av_res.tmid);
        w8(&w, m->u.av_res.status);
        wb(&w, m->u.av_res.number, OC_SIG_NUMBER_LEN);
        w8(&w, m->u.av_res.count);
        for (uint8_t i = 0; i < m->u.av_res.count; i++) w_av(&w, &m->u.av_res.av[i]);
        break;
    case OC_CORE_RESYNC:
        w16(&w, m->u.resync.req);
        w32(&w, m->u.resync.tmid);
        wb(&w, m->u.resync.rand, 16);
        wb(&w, m->u.resync.auts, 14);
        break;
    case OC_CORE_LOC_UPDATE:
        w32(&w, m->u.loc_update.tmid);
        wb(&w, m->u.loc_update.number, OC_SIG_NUMBER_LEN);
        wb(&w, m->u.loc_update.rand, 16);
        wb(&w, m->u.loc_update.res, 8);
        break;
    case OC_CORE_LOC_PURGE:
        w32(&w, m->u.loc_purge.tmid);
        wb(&w, m->u.loc_purge.number, OC_SIG_NUMBER_LEN);
        break;
    case OC_CORE_LOC_CANCEL:
        w32(&w, m->u.loc_cancel.tmid);
        w8(&w, m->u.loc_cancel.cause);
        wb(&w, m->u.loc_cancel.rand, 16);
        break;
    case OC_CORE_CALL_ROUTE:
        w32(&w, m->u.call_route.leg_ref);
        wb(&w, m->u.call_route.caller, OC_SIG_NUMBER_LEN);
        wb(&w, m->u.call_route.called, OC_SIG_NUMBER_LEN);
        break;
    case OC_CORE_CALL_OFFER:
        w32(&w, m->u.call_offer.call_ref);
        wb(&w, m->u.call_offer.callee, OC_SIG_NUMBER_LEN);
        wb(&w, m->u.call_offer.caller, OC_SIG_NUMBER_LEN);
        break;
    case OC_CORE_CALL_ALERT:
    case OC_CORE_CALL_ANSWER:
    case OC_OCSS_CALL_ALERT:
    case OC_OCSS_CALL_ANSWER:
        w32(&w, m->u.call.ref);
        break;
    case OC_CORE_CALL_RELEASE:
    case OC_OCSS_CALL_RELEASE:
        w32(&w, m->u.call.ref);
        w8(&w, m->u.call.cause);
        break;
    case OC_CORE_MEDIA:
    case OC_OCSS_MEDIA:
        if (m->u.media.len > OC_SIG_APP_MAX) return 0;
        w32(&w, m->u.media.ref);
        w16(&w, m->u.media.seq);
        wb(&w, m->u.media.data, m->u.media.len);
        break;
    default:
        return 0;
    }
    if (w.bad) return 0;
    out[0] = (uint8_t)((w.n - 2u) >> 8);
    out[1] = (uint8_t)(w.n - 2u);
    return w.n;
}

int oc_core_decode(const uint8_t *in, size_t len, oc_core_msg_t *m)
{
    memset(m, 0, sizeof(*m));
    if (len < 3 || len > OC_CORE_FRAME_MAX || ((size_t)in[0] << 8 | in[1]) != len - 2u) return -1;
    rd_t r = { in, len, 3, 0 };
    m->type = in[2];
    switch (m->type) {
    case OC_CORE_HELLO:
        m->u.hello.proto = r8(&r);
        m->u.hello.cell_id = r32(&r);
        m->u.hello.boot_id = r64(&r);
        rb(&r, m->u.hello.sw_version, 3);
        break;
    case OC_CORE_HELLO_ACK:
        m->u.hello_ack.mode = r8(&r);
        m->u.hello_ack.period_s = r16(&r);
        m->u.hello_ack.key_id = r16(&r);
        rnum(&r, m->u.hello_ack.echo_number);
        break;
    case OC_CORE_HELLO_NAK:
        m->u.hello_nak.reason = r8(&r);
        break;
    case OC_CORE_PING:
    case OC_CORE_PONG:
    case OC_OCSS_PING:
    case OC_OCSS_PONG:
        break;
    case OC_OCSS_HELLO:
        m->u.peer_hello.proto = r8(&r);
        /* fall through */
    case OC_OCSS_HELLO_ACK:
        m->u.peer_hello.core_id = r16(&r);
        m->u.peer_hello.table_ver = r32(&r);
        break;
    case OC_OCSS_HELLO_NAK:
        m->u.hello_nak.reason = r8(&r);
        break;
    case OC_OCSS_CALL_SETUP:
        m->u.setup.call_ref = r32(&r);
        rnum(&r, m->u.setup.caller);
        rnum(&r, m->u.setup.called);
        m->u.setup.hop = r8(&r);
        break;
    case OC_CORE_CELL_CFG: {
        oc_sig_msg_t cl;
        if (oc_sig_body_decode(OC_SIG_CHAN_LIST, in + r.at, len - r.at, &cl) != 0) return -1;
        m->u.cell_cfg.list = cl.u.chan_list;
        r.at = len;
        break;
    }
    case OC_CORE_ACT_FWD:
        m->u.act_fwd.req = r16(&r);
        m->u.act_fwd.tmid = r32(&r);
        rb(&r, m->u.act_fwd.token_id, 8);
        rb(&r, m->u.act_fwd.pkt, 32);
        rb(&r, m->u.act_fwd.tag, 8);
        break;
    case OC_CORE_ACT_RES: {
        m->u.act_res.req = r16(&r);
        m->u.act_res.tmid = r32(&r);
        uint8_t t = r8(&r);
        if (r.bad || (t != OC_SIG_ACT_ACK && t != OC_SIG_ACT_NAK) ||
            oc_sig_body_decode(t, in + r.at, len - r.at, &m->u.act_res.msg) != 0) {
            return -1;
        }
        r.at = len;
        break;
    }
    case OC_CORE_AV_REQ:
        m->u.av_req.req = r16(&r);
        m->u.av_req.tmid = r32(&r);
        m->u.av_req.count = r8(&r);
        break;
    case OC_CORE_AV_RES:
        m->u.av_res.req = r16(&r);
        m->u.av_res.tmid = r32(&r);
        m->u.av_res.status = r8(&r);
        if (m->u.av_res.status == OC_CORE_AV_OK) {
            rnum(&r, m->u.av_res.number);
        } else {
            rb(&r, m->u.av_res.number, OC_SIG_NUMBER_LEN);
        }
        m->u.av_res.count = r8(&r);
        if (m->u.av_res.count > OC_CORE_AV_MAX) return -1;
        for (uint8_t i = 0; i < m->u.av_res.count; i++) r_av(&r, &m->u.av_res.av[i]);
        break;
    case OC_CORE_RESYNC:
        m->u.resync.req = r16(&r);
        m->u.resync.tmid = r32(&r);
        rb(&r, m->u.resync.rand, 16);
        rb(&r, m->u.resync.auts, 14);
        break;
    case OC_CORE_LOC_UPDATE:
        m->u.loc_update.tmid = r32(&r);
        rnum(&r, m->u.loc_update.number);
        rb(&r, m->u.loc_update.rand, 16);
        rb(&r, m->u.loc_update.res, 8);
        break;
    case OC_CORE_LOC_PURGE:
        m->u.loc_purge.tmid = r32(&r);
        rnum(&r, m->u.loc_purge.number);
        break;
    case OC_CORE_LOC_CANCEL:
        m->u.loc_cancel.tmid = r32(&r);
        m->u.loc_cancel.cause = r8(&r);
        rb(&r, m->u.loc_cancel.rand, 16);
        break;
    case OC_CORE_CALL_ROUTE:
        m->u.call_route.leg_ref = r32(&r);
        rnum(&r, m->u.call_route.caller);
        rnum(&r, m->u.call_route.called);
        break;
    case OC_CORE_CALL_OFFER:
        m->u.call_offer.call_ref = r32(&r);
        rnum(&r, m->u.call_offer.callee);
        rnum(&r, m->u.call_offer.caller);
        break;
    case OC_CORE_CALL_ALERT:
    case OC_CORE_CALL_ANSWER:
    case OC_OCSS_CALL_ALERT:
    case OC_OCSS_CALL_ANSWER:
        m->u.call.ref = r32(&r);
        break;
    case OC_CORE_CALL_RELEASE:
    case OC_OCSS_CALL_RELEASE:
        m->u.call.ref = r32(&r);
        m->u.call.cause = r8(&r);
        break;
    case OC_CORE_MEDIA:
    case OC_OCSS_MEDIA:
        m->u.media.ref = r32(&r);
        m->u.media.seq = r16(&r);
        if (r.bad || len - r.at > OC_SIG_APP_MAX) return -1;
        m->u.media.len = (uint8_t)(len - r.at);
        rb(&r, m->u.media.data, m->u.media.len);
        break;
    default:
        return -1;
    }
    return r.bad || r.at != len ? -1 : 0;
}
