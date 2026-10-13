#define _GNU_SOURCE
#include "oc_addr.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int private4(uint32_t a) /* host order */
{
    return (a >> 24) == 10 || (a >> 20) == (172u << 4 | 1u) || (a >> 16) == (192u << 8 | 168u) || (a >> 24) == 127 ||
           (a >> 22) == (100u << 2 | 1u); /* 100.64.0.0/10 */
}

int oc_addr_parse(const char *text, struct sockaddr_storage *out, socklen_t *len, int *priv)
{
    char host[64];
    const char *colon;
    memset(out, 0, sizeof(*out));
    if (text[0] == '[') {
        const char *end = strchr(text, ']');
        if (end == NULL || end[1] != ':' || (size_t)(end - text - 1) >= sizeof(host)) return -1;
        snprintf(host, sizeof(host), "%.*s", (int)(end - text - 1), text + 1);
        colon = end + 1;
    } else {
        colon = strrchr(text, ':');
        if (colon == NULL || (size_t)(colon - text) >= sizeof(host)) return -1;
        snprintf(host, sizeof(host), "%.*s", (int)(colon - text), text);
    }
    char *end;
    long port = strtol(colon + 1, &end, 10);
    if (*end != '\0' || end == colon + 1 || port < 1 || port > 65535) return -1;
    struct sockaddr_in *v4 = (struct sockaddr_in *)out;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
    if (text[0] != '[' && inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)port);
        *len = sizeof(*v4);
        if (priv != NULL) *priv = private4(ntohl(v4->sin_addr.s_addr));
        return 0;
    }
    if (text[0] == '[' && inet_pton(AF_INET6, host, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)port);
        *len = sizeof(*v6);
        if (priv != NULL) *priv = IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr) || (v6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc;
        return 0;
    }
    return -1;
}
