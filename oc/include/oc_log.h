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

void oc_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* An oc_* library's log line (its io.log callback): info. */
void oc_log_line(void *ctx, const char *line);

#endif
