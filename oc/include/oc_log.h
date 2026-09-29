/* Logging for the OpenCell daemons: one line per call on stderr, with the
 * syslog priority as a "<N>" prefix, which journald reads (SyslogLevelPrefix,
 * on by default) and strips. Run by hand, the prefix shows as is. */
#ifndef OC_LOG_H
#define OC_LOG_H

#define OC_LOG_ERR     3
#define OC_LOG_WARNING 4
#define OC_LOG_NOTICE  5
#define OC_LOG_INFO    6
#define OC_LOG_DEBUG   7

/* Every line is cleaned first (oc_log_clean): a newline in a message - text
 * from a peer, say - becomes '?' and can't start a journal line of its own. */
void oc_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* An oc_* library's log line (its io.log callback): info. */
void oc_log_line(void *ctx, const char *line);
/* Text from a peer, made safe to store and print: C0 controls (newlines
 * among them), DEL, C1 controls (U+0080-U+009F as UTF-8) and bytes that are
 * not UTF-8 (a raw 0x80-0x9f among them, or a sequence cut short) become
 * '?'. Returns whether anything changed. */
int  oc_log_clean(char *s);

#endif
