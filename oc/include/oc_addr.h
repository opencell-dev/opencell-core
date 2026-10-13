#ifndef OC_ADDR_H
#define OC_ADDR_H

#include <sys/socket.h>

/* "A.B.C.D:PORT" or "[V6]:PORT", numeric only, port 1-65535, into out. 0,
 * or -1. *priv (may be NULL): 1 for 10/8, 172.16/12, 192.168/16, 127/8,
 * 100.64/10, fc00::/7 or ::1. */
int oc_addr_parse(const char *text, struct sockaddr_storage *out, socklen_t *len, int *priv);

#endif
