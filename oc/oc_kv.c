#define _GNU_SOURCE
#include "oc_kv.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

int oc_kv_parse(oc_kv_t *kv, const char *text, const char *name)
{
    memset(kv, 0, sizeof(*kv));
    unsigned ln = 0;
    const char *p = text;
    while (*p != '\0') {
        char line[512];
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        ln++;
        if (len >= sizeof(line)) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: line too long", name, ln);
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        p += len + (nl != NULL ? 1u : 0u);
        char *hash = strchr(line, '#');
        if (hash != NULL) *hash = '\0';
        char *s = trim(line);
        if (*s == '\0') continue;
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: expected key = value", name, ln);
            return -1;
        }
        *eq = '\0';
        char *k = trim(s), *v = trim(eq + 1);
        if (*k == '\0' || strlen(k) >= OC_KV_KEY || strlen(v) >= OC_KV_VAL || kv->n >= OC_KV_MAX) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: empty or long key, long value, or too many lines", name,
                     ln);
            return -1;
        }
        strcpy(kv->key[kv->n], k);
        strcpy(kv->val[kv->n], v);
        kv->line[kv->n++] = ln;
    }
    return 0;
}

int oc_kv_load(oc_kv_t *kv, const char *path)
{
    static char text[OC_KV_MAX * 256];
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        memset(kv, 0, sizeof(*kv));
        snprintf(kv->err, sizeof(kv->err), "%s: %s", path, strerror(errno));
        return -1;
    }
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    int big = !feof(f);
    fclose(f);
    if (big) {
        memset(kv, 0, sizeof(*kv));
        snprintf(kv->err, sizeof(kv->err), "%s: file too long", path);
        return -1;
    }
    text[n] = '\0';
    return oc_kv_parse(kv, text, path);
}

const char *oc_kv_nth(const oc_kv_t *kv, const char *key, unsigned i)
{
    for (unsigned k = 0; k < kv->n; k++) {
        if (strcmp(kv->key[k], key) == 0 && i-- == 0) return kv->val[k];
    }
    return NULL;
}

const char *oc_kv_get(const oc_kv_t *kv, const char *key) { return oc_kv_nth(kv, key, 0); }

int oc_kv_num(oc_kv_t *kv, const char *key, long long lo, long long hi, long long def, long long *out)
{
    const char *v = oc_kv_get(kv, key);
    if (v == NULL) {
        *out = def;
        return 0;
    }
    char *end;
    errno = 0;
    long long x = strtoll(v, &end, 0);
    if (errno != 0 || end == v || *end != '\0' || x < lo || x > hi) {
        snprintf(kv->err, sizeof(kv->err), "%s = '%s': a number %lld-%lld", key, v, lo, hi);
        return -1;
    }
    *out = x;
    return 0;
}

int oc_kv_known(oc_kv_t *kv, const char *const *keys)
{
    for (unsigned k = 0; k < kv->n; k++) {
        int ok = 0;
        for (const char *const *p = keys; *p != NULL && !ok; p++) ok = strcmp(*p, kv->key[k]) == 0;
        if (!ok) {
            snprintf(kv->err, sizeof(kv->err), "line %u: unknown key '%s'", kv->line[k], kv->key[k]);
            return 0;
        }
    }
    return 1;
}
