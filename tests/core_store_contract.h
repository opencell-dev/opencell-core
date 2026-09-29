/* The oc_core_store_t contract (network-core spec §5), as one test any store
 * must pass: the in-memory store here, plan 8's SQLite store there. The
 * store must start empty. */
#ifndef CORE_STORE_CONTRACT_H
#define CORE_STORE_CONTRACT_H

#include <string.h>

#include "oc_core_store.h"
#include "unity.h"

static inline void contract_num(const char *text, uint8_t out[OC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd(text, strlen(text), out));
}

static inline void store_contract(const oc_core_store_t *st)
{
    void *c = st->ctx;
    uint8_t n1[OC_SIG_NUMBER_LEN], n2[OC_SIG_NUMBER_LEN];
    contract_num("+883160655501234", n1);
    contract_num("+883160655501235", n2);

    /* network keys and cells: get what was put, replace by key */
    oc_core_netkey_t k = { 1, { 1 }, { 2 }, 1800, 100 }, k2;
    TEST_ASSERT_EQUAL_INT(-1, st->netkey_get(c, 1, &k2));
    TEST_ASSERT_EQUAL_INT(0, st->netkey_put(c, &k));
    TEST_ASSERT_EQUAL_INT(0, st->netkey_get(c, 1, &k2));
    TEST_ASSERT_EQUAL_MEMORY(&k, &k2, sizeof(k));
    oc_core_cell_t cell, cell2;
    memset(&cell, 0, sizeof(cell));
    cell.cell_id = 7;
    strcpy(cell.name, "bench A");
    cell.mode = OC_SIG_MODE_PART15;
    cell.enabled = 1;
    TEST_ASSERT_EQUAL_INT(0, st->cell_put(c, &cell));
    cell.boot_id = 99;
    TEST_ASSERT_EQUAL_INT(0, st->cell_put(c, &cell));
    TEST_ASSERT_EQUAL_INT(0, st->cell_get(c, 7, &cell2));
    TEST_ASSERT_EQUAL_STRING("bench A", cell2.name);
    TEST_ASSERT_EQUAL_UINT64(99, cell2.boot_id);
    TEST_ASSERT_EQUAL_UINT8(1, cell2.enabled);
    TEST_ASSERT_EQUAL_INT(-1, st->cell_get(c, 8, &cell2));

    /* channel lists: one per list group, replaced by group */
    oc_sig_chan_list_t cl, cl2;
    memset(&cl, 0, sizeof(cl));
    cl.ver = 1;
    cl.count = 1;
    cl.freq_hz[0] = 917250000u;
    TEST_ASSERT_EQUAL_INT(-1, st->list_get(c, 3, &cl2));
    TEST_ASSERT_EQUAL_INT(0, st->list_put(c, 3, &cl));
    cl.ver = 2;
    cl.flags[0] = OC_SIG_CHAN_FIXED;
    TEST_ASSERT_EQUAL_INT(0, st->list_put(c, 3, &cl));
    TEST_ASSERT_EQUAL_INT(0, st->list_get(c, 3, &cl2));
    TEST_ASSERT_EQUAL_MEMORY(&cl, &cl2, sizeof(cl));
    TEST_ASSERT_EQUAL_INT(-1, st->list_get(c, 4, &cl2));

    /* subscribers: by number; by TMID only while activated */
    oc_core_sub_t s, s2;
    memset(&s, 0, sizeof(s));
    memcpy(s.number, n1, OC_SIG_NUMBER_LEN);
    s.state = OC_CORE_SUB_ACTIVE;
    s.tmid = 0x1234u;
    s.sqn = 5;
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(-1, st->sub_by_tmid(c, 0x1234u, &s2)); /* bound but not activated */
    s.activated = 1;
    s.sqn = (1ull << 40) + 3u; /* SQN is 48 bits */
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(0, st->sub_by_tmid(c, 0x1234u, &s2));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(n1, s2.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->sub_get(c, n1, &s2));
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 3u, s2.sqn);
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->sub_get(c, n2, &s2)); /* none, not failed */

    /* tokens: voiding removes only the number's unused ones */
    oc_core_token_t t1, t2, t3, tg;
    memset(&t1, 0, sizeof(t1));
    memset(t1.token_id, 0x11, 8);
    memcpy(t1.number, n1, OC_SIG_NUMBER_LEN);
    t2 = t1;
    memset(t2.token_id, 0x22, 8);
    t2.used_at = 50;
    t3 = t1;
    memset(t3.token_id, 0x33, 8);
    memcpy(t3.number, n2, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t1));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t2));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t3));
    TEST_ASSERT_EQUAL_INT(0, st->token_void(c, n1));
    TEST_ASSERT_EQUAL_INT(-1, st->token_get(c, t1.token_id, &tg));
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t2.token_id, &tg)); /* used: kept */
    TEST_ASSERT_EQUAL_UINT32(50, tg.used_at);
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t3.token_id, &tg)); /* another number: kept */

    /* issued vectors: keyed by (number, rand); drop and prune */
    oc_core_av_issued_t a1, a2, ag;
    memset(&a1, 0, sizeof(a1));
    memcpy(a1.number, n1, OC_SIG_NUMBER_LEN);
    memset(a1.rand, 0xa1, 16);
    a1.cell_id = 7;
    a1.issued = 1000;
    a2 = a1;
    memset(a2.rand, 0xa2, 16);
    a2.issued = 2000;
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a1));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a2));
    a2.confirmed = 1;
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a2)); /* replaced, not added */
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_UINT8(1, ag.confirmed);
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n2, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_drop_cell(c, 7)); /* a1 (unconfirmed) goes, a2 stays */
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a1.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_prune(c, 2000)); /* issued at 2000: not before */
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_prune(c, 2001));
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a2.rand, &ag));

    /* a number's issued vectors go all at once (re-activation, network-core
     * spec §19.3), confirmed or not, and nobody else's; SQN is kept whole */
    oc_core_av_issued_t a3 = a1, a4 = a1;
    a3.confirmed = 1;
    a3.sqn = (1ull << 40) + 1u;
    memcpy(a4.number, n2, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a1));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a2));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a3));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a4));
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a3.rand, &ag));
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 1u, ag.sqn);
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n1));
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a1.rand, &ag));
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n2, a4.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n1)); /* none left: still 0, unlike loc_del's -1 */
    uint64_t top = 0;
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->av_newest_confirmed(c, n1, 0, &top)); /* none at all */
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n2));
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n2, a4.rand, &ag));

    /* the newest confirmed vector of a number issued to any cell but one
     * (§19.2's floor for a claim from that cell) */
    oc_core_av_issued_t v1 = a1, v2 = a1, v3 = a1, v4 = a1, v5 = a1;
    memset(v1.rand, 0xb1, 16); /* cell 7, SQN 2^40 + 5, confirmed */
    v1.sqn = (1ull << 40) + 5u;
    v1.confirmed = 1;
    v2 = v1; /* cell 8, SQN 2^40 + 9, confirmed: the newest elsewhere */
    memset(v2.rand, 0xb2, 16);
    v2.cell_id = 8;
    v2.sqn = (1ull << 40) + 9u;
    v3 = v2; /* cell 8, higher, but never confirmed */
    memset(v3.rand, 0xb3, 16);
    v3.sqn = (1ull << 40) + 20u;
    v3.confirmed = 0;
    v4 = v1; /* cell 7, the highest, confirmed: excluded when asking for cell 7 */
    memset(v4.rand, 0xb4, 16);
    v4.sqn = (1ull << 40) + 30u;
    v5 = v4; /* another number */
    memcpy(v5.number, n2, OC_SIG_NUMBER_LEN);
    v5.cell_id = 9;
    v5.sqn = (1ull << 40) + 40u;
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &v1));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &v2));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &v3));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &v4));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &v5));
    TEST_ASSERT_EQUAL_INT(0, st->av_newest_confirmed(c, n1, 7, &top));
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 9u, top);
    TEST_ASSERT_EQUAL_INT(0, st->av_newest_confirmed(c, n1, 8, &top));
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 30u, top);
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->av_newest_confirmed(c, n2, 9, &top)); /* only cell 9's own */
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n1));
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n2));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->av_newest_confirmed(c, n1, 7, &top));

    /* locations: one per number; delete; purge a cell's */
    oc_core_loc_t l1 = { { 0 }, 7, 0x1234u, 5000, 0, { 0 } }, l2 = { { 0 }, 8, 0x5678u, 5000, 0, { 0 } }, lg;
    memcpy(l1.number, n1, OC_SIG_NUMBER_LEN);
    memcpy(l2.number, n2, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1));
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l2));
    l1.cell_id = 8;
    l1.sqn = (1ull << 40) + 9u; /* the SQN of the vector that proved it (§19.2), 48 bits */
    memset(l1.rand, 0xa7, 16);  /* ...and its RAND (for LOC_CANCEL, §19 follow-ups) */
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1)); /* moved */
    TEST_ASSERT_EQUAL_INT(0, st->loc_get(c, n1, &lg));
    TEST_ASSERT_EQUAL_UINT32(8, lg.cell_id);
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 9u, lg.sqn);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(l1.rand, lg.rand, 16);
    TEST_ASSERT_EQUAL_INT(0, st->loc_del(c, n1));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->loc_get(c, n1, &lg)); /* none, not failed */
    TEST_ASSERT_EQUAL_INT(-1, st->loc_del(c, n1)); /* nothing to delete: -1 (oc_core_store.h) */
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1));
    TEST_ASSERT_EQUAL_INT(0, st->loc_purge_cell(c, 8));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->loc_get(c, n1, &lg));
    TEST_ASSERT_EQUAL_INT(OC_CORE_STORE_NONE, st->loc_get(c, n2, &lg));
    TEST_ASSERT_EQUAL_INT(0, st->loc_purge_cell(c, 8)); /* a bulk delete finding nothing: 0 */

    /* the store contract (oc_core_store.h): a write that fails inside a
     * transaction dooms it, except a delete that finds nothing to delete,
     * which must not. n1 has no location at this point (purged just above),
     * so deleting it here is exactly that "nothing to delete" case, and
     * must not stop the sub_put alongside it from landing. (A delete
     * failing for a genuine reason - disk I/O, say - would still have to
     * doom the transaction, but the in-memory store has no such failure to
     * provoke through this store-agnostic test; the store that owns that
     * failure mode, e.g. plan 8's SQLite store, tests it directly.) */
    s.sqn = 7;
    TEST_ASSERT_EQUAL_INT(0, st->begin(c));
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(-1, st->loc_del(c, n1)); /* nothing there to delete */
    TEST_ASSERT_EQUAL_INT(0, st->av_del_number(c, n1)); /* nor here */
    TEST_ASSERT_EQUAL_INT(0, st->commit(c)); /* not doomed */
    TEST_ASSERT_EQUAL_INT(0, st->sub_get(c, n1, &s2));
    TEST_ASSERT_EQUAL_UINT64(7, s2.sqn);

    /* records are appended */
    oc_core_cdr_t cdr;
    oc_core_audit_t au;
    memset(&cdr, 0, sizeof(cdr));
    memset(&au, 0, sizeof(au));
    au.event = OC_CORE_AUDIT_REGISTER;
    TEST_ASSERT_EQUAL_INT(0, st->cdr_add(c, &cdr));
    TEST_ASSERT_EQUAL_INT(0, st->audit_add(c, &au));

    /* one transaction commits as a whole */
    s.sqn = 6;
    TEST_ASSERT_EQUAL_INT(0, st->begin(c));
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t1));
    TEST_ASSERT_EQUAL_INT(0, st->commit(c));
    TEST_ASSERT_EQUAL_INT(0, st->sub_get(c, n1, &s2));
    TEST_ASSERT_EQUAL_UINT64(6, s2.sqn);
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t1.token_id, &tg));
}

#endif
