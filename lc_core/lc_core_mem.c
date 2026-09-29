#include "lc_core_mem.h"

#include <string.h>

#define M(c) ((lc_core_mem_t *)(c))
#define D(c) (&M(c)->d)

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

/* A put that fails while a transaction is open dooms it (lc_core_store.h):
 * remember that so commit() undoes everything, even if the caller that saw
 * the put's own -1 pressed on and reached commit() anyway. */
static void fail_txn(void *c)
{
    lc_core_mem_t *m = M(c);
    if (m->in_txn) m->txn_failed = 1;
}

static int begin(void *c)
{
    lc_core_mem_t *m = M(c);
    if (m->in_txn) return -1; /* already inside a transaction: leave it be */
    m->undo = m->d;
    m->in_txn = 1;
    m->txn_failed = 0;
    return 0;
}

static int commit(void *c)
{
    lc_core_mem_t *m = M(c);
    if (!m->in_txn) return -1; /* no matching begin(): nothing to commit */
    m->in_txn = 0;
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

static int netkey_get(void *c, uint16_t key_id, lc_core_netkey_t *out)
{
    for (unsigned i = 0; i < D(c)->nkey; i++) {
        if (D(c)->key[i].key_id == key_id) {
            *out = D(c)->key[i];
            return 0;
        }
    }
    return -1;
}

static int netkey_put(void *c, const lc_core_netkey_t *k)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nkey; i++) {
        if (d->key[i].key_id == k->key_id) {
            d->key[i] = *k;
            return 0;
        }
    }
    if (d->nkey >= LC_CORE_MEM_KEYS) {
        fail_txn(c);
        return -1;
    }
    d->key[d->nkey++] = *k;
    return 0;
}

static int cell_get(void *c, uint32_t cell_id, lc_core_cell_t *out)
{
    for (unsigned i = 0; i < D(c)->ncell; i++) {
        if (D(c)->cell[i].cell_id == cell_id) {
            *out = D(c)->cell[i];
            return 0;
        }
    }
    return -1;
}

static int cell_put(void *c, const lc_core_cell_t *x)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ncell; i++) {
        if (d->cell[i].cell_id == x->cell_id) {
            d->cell[i] = *x;
            return 0;
        }
    }
    if (d->ncell >= LC_CORE_MEM_CELLS) {
        fail_txn(c);
        return -1;
    }
    d->cell[d->ncell++] = *x;
    return 0;
}

static int sub_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out)
{
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (num_eq(D(c)->sub[i].number, number)) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return -1;
}

static int sub_by_tmid(void *c, uint32_t tmid, lc_core_sub_t *out)
{
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (D(c)->sub[i].activated && D(c)->sub[i].tmid == tmid) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return -1;
}

static int sub_put(void *c, const lc_core_sub_t *s)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nsub; i++) {
        if (num_eq(d->sub[i].number, s->number)) {
            d->sub[i] = *s;
            return 0;
        }
    }
    if (d->nsub >= LC_CORE_MEM_SUBS) {
        fail_txn(c);
        return -1;
    }
    d->sub[d->nsub++] = *s;
    return 0;
}

static int token_get(void *c, const uint8_t token_id[8], lc_core_token_t *out)
{
    for (unsigned i = 0; i < D(c)->ntoken; i++) {
        if (memcmp(D(c)->token[i].token_id, token_id, 8) == 0) {
            *out = D(c)->token[i];
            return 0;
        }
    }
    return -1;
}

static int token_put(void *c, const lc_core_token_t *t)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (memcmp(d->token[i].token_id, t->token_id, 8) == 0) {
            d->token[i] = *t;
            return 0;
        }
    }
    if (d->ntoken >= LC_CORE_MEM_TOKENS) {
        fail_txn(c);
        return -1;
    }
    d->token[d->ntoken++] = *t;
    return 0;
}

static int token_void(void *c, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (!(num_eq(d->token[i].number, number) && d->token[i].used_at == 0)) d->token[k++] = d->token[i];
    }
    d->ntoken = k;
    return 0;
}

static int av_find(lc_core_mem_data_t *d, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16])
{
    for (unsigned i = 0; i < d->nav; i++) {
        if (num_eq(d->av[i].number, number) && memcmp(d->av[i].rand, rand, 16) == 0) return (int)i;
    }
    return -1;
}

static int av_put(void *c, const lc_core_av_issued_t *a)
{
    lc_core_mem_data_t *d = D(c);
    int i = av_find(d, a->number, a->rand);
    if (i >= 0) {
        d->av[i] = *a;
        return 0;
    }
    if (d->nav >= LC_CORE_MEM_AVS) {
        fail_txn(c);
        return -1;
    }
    d->av[d->nav++] = *a;
    return 0;
}

static int av_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16], lc_core_av_issued_t *out)
{
    int i = av_find(D(c), number, rand);
    if (i < 0) return -1;
    *out = D(c)->av[i];
    return 0;
}

static int av_drop_cell(void *c, uint32_t cell_id)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (!(d->av[i].cell_id == cell_id && !d->av[i].confirmed)) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int av_prune(void *c, uint32_t issued_before)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (d->av[i].issued >= issued_before) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int loc_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out)
{
    for (unsigned i = 0; i < D(c)->nloc; i++) {
        if (num_eq(D(c)->loc[i].number, number)) {
            *out = D(c)->loc[i];
            return 0;
        }
    }
    return -1;
}

static int loc_put(void *c, const lc_core_loc_t *l)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, l->number)) {
            d->loc[i] = *l;
            return 0;
        }
    }
    if (d->nloc >= LC_CORE_MEM_SUBS) {
        fail_txn(c);
        return -1;
    }
    d->loc[d->nloc++] = *l;
    return 0;
}

static int loc_del(void *c, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, number)) {
            d->loc[i] = d->loc[--d->nloc];
            return 0;
        }
    }
    return -1;
}

static int loc_purge_cell(void *c, uint32_t cell_id)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nloc; i++) {
        if (d->loc[i].cell_id != cell_id) d->loc[k++] = d->loc[i];
    }
    d->nloc = k;
    return 0;
}

static int cdr_add(void *c, const lc_core_cdr_t *x)
{
    lc_core_mem_data_t *d = D(c);
    d->cdr[d->ncdr++ % LC_CORE_MEM_LOG] = *x;
    return 0;
}

static int audit_add(void *c, const lc_core_audit_t *a)
{
    lc_core_mem_data_t *d = D(c);
    d->audit[d->naudit++ % LC_CORE_MEM_LOG] = *a;
    return 0;
}

void lc_core_mem_init(lc_core_mem_t *m)
{
    memset(m, 0, sizeof(*m));
}

lc_core_store_t lc_core_mem_store(lc_core_mem_t *m)
{
    lc_core_store_t s = {
        .ctx = m,
        .begin = begin,
        .commit = commit,
        .netkey_get = netkey_get,
        .netkey_put = netkey_put,
        .cell_get = cell_get,
        .cell_put = cell_put,
        .sub_get = sub_get,
        .sub_by_tmid = sub_by_tmid,
        .sub_put = sub_put,
        .token_get = token_get,
        .token_put = token_put,
        .token_void = token_void,
        .av_put = av_put,
        .av_get = av_get,
        .av_drop_cell = av_drop_cell,
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

const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event)
{
    unsigned kept = m->d.naudit < LC_CORE_MEM_LOG ? m->d.naudit : LC_CORE_MEM_LOG;
    for (unsigned i = 0; i < kept; i++) {
        const lc_core_audit_t *a = &m->d.audit[(m->d.naudit - 1u - i) % LC_CORE_MEM_LOG];
        if (a->event == event) return a;
    }
    return NULL;
}
