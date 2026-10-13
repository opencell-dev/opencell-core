/* The tools' dial: a Unix socket path, or tls:HOST:PORT:PKI:NAME (a cell
 * over TLS with PKI/NAME.crt and .key, checking the core against PKI/ca.crt
 * as HOST). Waits up to 10 s. 0 with *c ready, or -1 (printed). */
#ifndef TOOL_DIAL_H
#define TOOL_DIAL_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "oc_conn.h"
#include "oc_tls.h"

static oc_tls_conn_t tool_tls;

static int tool_dial(const char *target, oc_conn_t *c)
{
    if (strncmp(target, "tls:", 4) != 0) {
        int fd = oc_unix_connect_wait(target, 10000);
        if (fd < 0) {
            perror(target);
            return -1;
        }
        oc_conn_init(c, fd);
        return 0;
    }
    char host[64], pki[256], name[64], crt[340], key[340], ca[340], err[256];
    unsigned port;
    if (sscanf(target + 4, "%63[^:]:%u:%255[^:]:%63s", host, &port, pki, name) != 4) {
        fprintf(stderr, "%s: tls:HOST:PORT:PKI:NAME\n", target);
        return -1;
    }
    snprintf(crt, sizeof(crt), "%s/%s.crt", pki, name);
    snprintf(key, sizeof(key), "%s/%s.key", pki, name);
    snprintf(ca, sizeof(ca), "%s/ca.crt", pki);
    oc_tls_client_cfg_t cc = { crt, key, ca, "oc-cell/1", OC_TLS_ROLE_CORE, host };
    oc_tls_t *t = oc_tls_client_new(&cc, err, sizeof(err));
    if (t == NULL) {
        fprintf(stderr, "%s\n", err);
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr); /* the tests' core is local; HOST is the name checked */
    time_t end = time(NULL) + 10;
    while (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (time(NULL) > end) {
            perror("connect");
            return -1;
        }
        close(fd);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        usleep(100000);
    }
    oc_tls_conn_t h;
    if (oc_tls_conn_start(t, &h, fd) != 0) return -1;
    int r = 0;
    while (r == 0 && time(NULL) <= end) {
        r = oc_tls_conn_handshake(&h);
        struct pollfd p = { h.fd, h.want, 0 };
        if (r == 0) poll(&p, 1, 100);
    }
    /* TLS 1.3: the client is done before the core has checked its
     * certificate; a refusal comes as an alert right after. The core says
     * nothing before the cell's HELLO, so a peek that fails within 300 ms
     * is that alert. */
    char why[200] = "";
    if (r == 1) {
        struct pollfd p = { h.fd, POLLIN, 0 };
        char b;
        if (poll(&p, 1, 300) > 0) {
            ERR_clear_error();
            int k = SSL_peek(h.ssl, &b, 1);
            if (k <= 0 && SSL_get_error(h.ssl, k) != SSL_ERROR_WANT_READ) {
                const char *e = ERR_reason_error_string(ERR_peek_error());
                snprintf(why, sizeof(why), "%s", e != NULL ? e : "closed by the core");
                r = -1;
            }
        }
    }
    if (r != 1) {
        printf("TLS refused: %s\n", h.why[0] != '\0' ? h.why : why[0] != '\0' ? why : "closed by the core");
        fflush(stdout);
        oc_tls_conn_close(&h);
        return -1;
    }
    oc_tls_conn_move(&tool_tls, &h);
    oc_conn_io_t io = oc_tls_conn_io(&tool_tls);
    oc_conn_init_io(c, tool_tls.fd, &io);
    return 0; /* t lives as long as the tool */
}
#endif
