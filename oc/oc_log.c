#define _GNU_SOURCE
#include "oc_log.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

/* oc_log.h says what is kept. */
int oc_log_clean(char *s)
{
    int changed = 0;
    for (unsigned char *p = (unsigned char *)s; *p != '\0';) {
        unsigned c = *p;
        size_t len = 1;
        int ok = c >= 0x20 && c != 0x7f;
        if (ok && c >= 0x80) {
            len = c >= 0xc2 && c <= 0xdf ? 2u : c >= 0xe0 && c <= 0xef ? 3u : c >= 0xf0 && c <= 0xf4 ? 4u : 0u;
            ok = len != 0;
            for (size_t i = 1; ok && i < len; i++) ok = (p[i] & 0xc0) == 0x80;
            if (ok && c == 0xc2 && p[1] <= 0x9f) ok = 0; /* C1 */
            if (!ok) len = 1;
        }
        if (!ok) {
            *p = '?';
            changed = 1;
        }
        p += len;
    }
    return changed;
}

void oc_log(int prio, const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    oc_log_clean(line); /* one call, one journal line: nothing from a peer starts a line of its own */
    fprintf(stderr, "<%d>%s\n", prio, line);
    fflush(stderr);
}

void oc_log_line(void *ctx, const char *line)
{
    (void)ctx;
    oc_log(OC_LOG_INFO, "%s", line);
}
