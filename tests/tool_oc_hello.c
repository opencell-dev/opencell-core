#define _GNU_SOURCE
/* A bare cell for the process tests: connects to a core's cell socket,
 * sends HELLO, prints what comes back, answers PING, and holds the link for
 * a while.
 *
 *   tool_oc_hello SOCKET CELL_ID BOOT_ID HOLD_S
 *
 * Prints "HELLO_ACK mode M period P", or "HELLO_NAK reason R", then "closed"
 * if the core drops the link while held. Exit 0 on HELLO_ACK. */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_conn.h"

static oc_conn_t C;
static int acked = -1;

static void on_rx(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    if (m->type == OC_CORE_HELLO_ACK) {
        printf("HELLO_ACK mode %u period %u\n", m->u.hello_ack.mode, m->u.hello_ack.period_s);
        acked = 1;
    } else if (m->type == OC_CORE_HELLO_NAK) {
        printf("HELLO_NAK reason %u\n", m->u.hello_nak.reason);
        acked = 0;
    } else if (m->type == OC_CORE_PING) {
        oc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = OC_CORE_PONG;
        oc_conn_send(&C, &p);
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: tool_oc_hello SOCKET CELL_ID BOOT_ID HOLD_S\n");
        return 2;
    }
    int fd = oc_unix_connect(argv[1]);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    oc_conn_init(&C, fd);
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = (uint32_t)strtoul(argv[2], NULL, 0);
    h.u.hello.boot_id = strtoull(argv[3], NULL, 0);
    oc_conn_send(&C, &h);
    time_t end = time(NULL) + atoi(argv[4]);
    while (time(NULL) < end || acked < 0) {
        struct pollfd p = { C.fd, POLLIN, 0 };
        if (poll(&p, 1, 200) > 0 && oc_conn_read(&C, on_rx, NULL) != 0) {
            printf("closed\n");
            break;
        }
        if (acked < 0 && time(NULL) > end + 5) break;
    }
    oc_conn_close(&C);
    return acked == 1 ? 0 : 1;
}
