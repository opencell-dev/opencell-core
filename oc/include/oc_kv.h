/* key = value configuration files (oc-core.conf, oc-cell.conf): one pair
 * per line, '#' starts a comment, blank lines are skipped, spaces around
 * the key and the value are dropped. A key may repeat (block = ...);
 * oc_kv_get returns the first, oc_kv_nth the others. */
#ifndef OC_KV_H
#define OC_KV_H

#include <stddef.h>
#include <stdint.h>

#define OC_KV_MAX 64u
#define OC_KV_KEY 32u
#define OC_KV_VAL 160u

typedef struct {
    char     key[OC_KV_MAX][OC_KV_KEY];
    char     val[OC_KV_MAX][OC_KV_VAL];
    unsigned line[OC_KV_MAX];
    unsigned n;
    char     err[256]; /* why a call failed: "FILE:LINE: reason" or "KEY = 'VALUE': reason" */
} oc_kv_t;

/* 0, or -1 (unreadable file, a line without '=', a key or value too long,
 * more than OC_KV_MAX pairs): kv->err says which. */
int         oc_kv_load(oc_kv_t *kv, const char *path);
/* The same from text; name stands in for the file name in kv->err. */
int         oc_kv_parse(oc_kv_t *kv, const char *text, const char *name);
const char *oc_kv_get(const oc_kv_t *kv, const char *key);             /* NULL: not set */
const char *oc_kv_nth(const oc_kv_t *kv, const char *key, unsigned i); /* the i-th (0-based), or NULL */
/* A whole number (decimal, or 0x hex) in lo..hi, or def when not set. 0, or
 * -1 (set but not such a number: kv->err names the key). */
int         oc_kv_num(oc_kv_t *kv, const char *key, long long lo, long long hi, long long def, long long *out);
/* 1 if every key is in the NULL-terminated list; else 0, with kv->err
 * naming the first unknown key (a typo must not be ignored). */
int         oc_kv_known(oc_kv_t *kv, const char *const *keys);

#endif
