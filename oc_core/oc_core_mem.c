#include "oc_core_mem.h"

#include <string.h>

#define M(c) ((oc_core_mem_t *)(c))
#define D(c) (&M(c)->d)

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, OC_SIG_NUMBER_LEN) == 0; }

/* A put that fails while a transaction is open dooms it (oc_core_store.h):
 * remember that so commit() undoes everything, even if the caller that saw
 * the put's own -1 pressed on and reached commit() anyway. */
static void fail_txn(void *c)
{
    oc_core_mem_t *m = M(c);
    if (m->in_txn) m->txn_failed = 1;
}

/* A write after a failed begin (oc_core_store.h): refused, nothing written. */
static int refuse(void *c)
{
    oc_core_mem_t *m = M(c);
    if (!m->refusing) return 0;
    m->refused++;
    return 1;
}

/* The begin failed: a transaction is open all the same, doomed, and every
 * write until its commit is refused. Inside an open transaction that is
 * the one doomed (its undo point stays where its own begin put it). */
static int begin_failed(oc_core_mem_t *m)
{
    if (!m->in_txn) m->undo = m->d;
    m->in_txn = 1;
    m->txn_failed = 1;
    m->refusing = 1;
    return -1;
}

static int begin(void *c)
{
    oc_core_mem_t *m = M(c);
    if (m->in_txn) return begin_failed(m); /* already inside a transaction */
    if (m->fail_begins > 0) {
        m->fail_begins--;
        return begin_failed(m);
    }
    m->undo = m->d;
    m->in_txn = 1;
    m->txn_failed = 0;
    return 0;
}

static int commit(void *c)
{
    oc_core_mem_t *m = M(c);
    if (!m->in_txn) return -1; /* no matching begin(): nothing to commit */
    m->in_txn = 0;
    m->refusing = 0;
    int failed = m->txn_failed;
    m->txn_failed = 0;
    if (m->fail_commits > 0) {
        m->fail_commits--;
        failed = 1;
    }
    if (failed) {
        m->d = m->undo;
        return -1;
    }
    m->commits++;
    return 0;
}

static int netkey_get(void *c, uint16_t key_id, oc_core_netkey_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_NETKEY_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->nkey; i++) {
        if (D(c)->key[i].key_id == key_id) {
            *out = D(c)->key[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int netkey_put(void *c, const oc_core_netkey_t *k)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nkey; i++) {
        if (d->key[i].key_id == k->key_id) {
            d->key[i] = *k;
            return 0;
        }
    }
    if (d->nkey >= OC_CORE_MEM_KEYS) {
        fail_txn(c);
        return -1;
    }
    d->key[d->nkey++] = *k;
    return 0;
}

static int cell_get(void *c, uint32_t cell_id, oc_core_cell_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_CELL_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->ncell; i++) {
        if (D(c)->cell[i].cell_id == cell_id) {
            *out = D(c)->cell[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int cell_put(void *c, const oc_core_cell_t *x)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ncell; i++) {
        if (d->cell[i].cell_id == x->cell_id) {
            d->cell[i] = *x;
            return 0;
        }
    }
    if (d->ncell >= OC_CORE_MEM_CELLS) {
        fail_txn(c);
        return -1;
    }
    d->cell[d->ncell++] = *x;
    return 0;
}

static int list_get(void *c, uint16_t list_id, oc_sig_chan_list_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_LIST_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->nlist; i++) {
        if (D(c)->list_id[i] == list_id) {
            *out = D(c)->list[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int list_put(void *c, uint16_t list_id, const oc_sig_chan_list_t *l)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nlist; i++) {
        if (d->list_id[i] == list_id) {
            d->list[i] = *l;
            return 0;
        }
    }
    if (d->nlist >= OC_CORE_MEM_LISTS) {
        fail_txn(c);
        return -1;
    }
    d->list_id[d->nlist] = list_id;
    d->list[d->nlist++] = *l;
    return 0;
}

static int sub_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_sub_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_SUB_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (num_eq(D(c)->sub[i].number, number)) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int sub_by_tmid(void *c, uint32_t tmid, oc_core_sub_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_SUB_BY_TMID) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (D(c)->sub[i].activated && D(c)->sub[i].tmid == tmid) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int sub_put(void *c, const oc_core_sub_t *s)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nsub; i++) {
        if (num_eq(d->sub[i].number, s->number)) {
            d->sub[i] = *s;
            return 0;
        }
    }
    if (d->nsub >= OC_CORE_MEM_SUBS) {
        fail_txn(c);
        return -1;
    }
    d->sub[d->nsub++] = *s;
    return 0;
}

static int token_get(void *c, const uint8_t token_id[8], oc_core_token_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_TOKEN_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->ntoken; i++) {
        if (memcmp(D(c)->token[i].token_id, token_id, 8) == 0) {
            *out = D(c)->token[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int token_put(void *c, const oc_core_token_t *t)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (memcmp(d->token[i].token_id, t->token_id, 8) == 0) {
            d->token[i] = *t;
            return 0;
        }
    }
    if (d->ntoken >= OC_CORE_MEM_TOKENS) {
        fail_txn(c);
        return -1;
    }
    d->token[d->ntoken++] = *t;
    return 0;
}

static int token_void(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (!(num_eq(d->token[i].number, number) && d->token[i].used_at == 0)) d->token[k++] = d->token[i];
    }
    d->ntoken = k;
    return 0;
}

static int av_find(oc_core_mem_data_t *d, const uint8_t number[OC_SIG_NUMBER_LEN], const uint8_t rand[16])
{
    for (unsigned i = 0; i < d->nav; i++) {
        if (num_eq(d->av[i].number, number) && memcmp(d->av[i].rand, rand, 16) == 0) return (int)i;
    }
    return -1;
}

static int av_put(void *c, const oc_core_av_issued_t *a)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    int i = av_find(d, a->number, a->rand);
    if (i >= 0) {
        d->av[i] = *a;
        return 0;
    }
    if (d->nav >= OC_CORE_MEM_AVS) {
        fail_txn(c);
        return -1;
    }
    d->av[d->nav++] = *a;
    return 0;
}

static int av_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], const uint8_t rand[16], oc_core_av_issued_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_AV_GET) return OC_CORE_STORE_FAILED;
    int i = av_find(D(c), number, rand);
    if (i < 0) return OC_CORE_STORE_NONE;
    *out = D(c)->av[i];
    return 0;
}

static int av_drop_cell(void *c, uint32_t cell_id)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (!(d->av[i].cell_id == cell_id && !d->av[i].confirmed)) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

/* Like the other bulk deletes: deleting none is not a failure (0). */
static int av_del_number(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (!num_eq(d->av[i].number, number)) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int av_newest_confirmed(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t not_cell, uint64_t *sqn)
{
    const oc_core_mem_data_t *d = D(c);
    int found = 0;
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_AV_NEWEST) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < d->nav; i++) {
        const oc_core_av_issued_t *a = &d->av[i];
        if (!num_eq(a->number, number) || !a->confirmed || a->cell_id == not_cell) continue;
        if (!found || a->sqn > *sqn) *sqn = a->sqn;
        found = 1;
    }
    return found ? 0 : OC_CORE_STORE_NONE;
}

static int av_prune(void *c, uint32_t issued_before)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (d->av[i].issued >= issued_before) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int loc_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out)
{
    if (M(c)->fail_reads & OC_CORE_MEM_FAIL_LOC_GET) return OC_CORE_STORE_FAILED;
    for (unsigned i = 0; i < D(c)->nloc; i++) {
        if (num_eq(D(c)->loc[i].number, number)) {
            *out = D(c)->loc[i];
            return 0;
        }
    }
    return OC_CORE_STORE_NONE;
}

static int loc_put(void *c, const oc_core_loc_t *l)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, l->number)) {
            d->loc[i] = *l;
            return 0;
        }
    }
    if (d->nloc >= OC_CORE_MEM_SUBS) {
        fail_txn(c);
        return -1;
    }
    d->loc[d->nloc++] = *l;
    return 0;
}

static int loc_del(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, number)) {
            d->loc[i] = d->loc[--d->nloc];
            return 0;
        }
    }
    /* nothing to delete: -1, but not fail_txn(c) (oc_core_store.h) - this
     * store's only way for a delete to fail is finding nothing, which the
     * contract carves out as not dooming an open transaction. */
    return -1;
}

static int loc_purge_cell(void *c, uint32_t cell_id)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nloc; i++) {
        if (d->loc[i].cell_id != cell_id) d->loc[k++] = d->loc[i];
    }
    d->nloc = k;
    return 0;
}

static int cdr_add(void *c, const oc_core_cdr_t *x)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    d->cdr[d->ncdr++ % OC_CORE_MEM_LOG] = *x;
    return 0;
}

static int audit_add(void *c, const oc_core_audit_t *a)
{
    if (refuse(c)) return -1;
    oc_core_mem_data_t *d = D(c);
    d->audit[d->naudit++ % OC_CORE_MEM_LOG] = *a;
    return 0;
}

void oc_core_mem_init(oc_core_mem_t *m)
{
    memset(m, 0, sizeof(*m));
}

oc_core_store_t oc_core_mem_store(oc_core_mem_t *m)
{
    oc_core_store_t s = {
        .ctx = m,
        .begin = begin,
        .commit = commit,
        .netkey_get = netkey_get,
        .netkey_put = netkey_put,
        .cell_get = cell_get,
        .cell_put = cell_put,
        .list_get = list_get,
        .list_put = list_put,
        .sub_get = sub_get,
        .sub_by_tmid = sub_by_tmid,
        .sub_put = sub_put,
        .token_get = token_get,
        .token_put = token_put,
        .token_void = token_void,
        .av_put = av_put,
        .av_get = av_get,
        .av_drop_cell = av_drop_cell,
        .av_del_number = av_del_number,
        .av_newest_confirmed = av_newest_confirmed,
        .av_prune = av_prune,
        .loc_get = loc_get,
        .loc_put = loc_put,
        .loc_del = loc_del,
        .loc_purge_cell = loc_purge_cell,
        .cdr_add = cdr_add,
        .audit_add = audit_add,
    };
    return s;
}

const oc_core_audit_t *oc_core_mem_audit(const oc_core_mem_t *m, uint8_t event)
{
    unsigned kept = m->d.naudit < OC_CORE_MEM_LOG ? m->d.naudit : OC_CORE_MEM_LOG;
    for (unsigned i = 0; i < kept; i++) {
        const oc_core_audit_t *a = &m->d.audit[(m->d.naudit - 1u - i) % OC_CORE_MEM_LOG];
        if (a->event == event) return a;
    }
    return NULL;
}
