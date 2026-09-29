#define _GNU_SOURCE
#include "oc_log.h"

#include <stdarg.h>
#include <stdio.h>

void oc_log(int prio, const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    fprintf(stderr, "<%d>%s\n", prio, line);
    fflush(stderr);
}

void oc_log_line(void *ctx, const char *line)
{
    (void)ctx;
    oc_log(OC_LOG_INFO, "%s", line);
}
