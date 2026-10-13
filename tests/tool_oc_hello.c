#define _GNU_SOURCE
/* A bare cell for the process tests: connects to a core's cell socket,
 * sends HELLO, prints what comes back, answers PING, and holds the link for
 * a while.
 *
 *   tool_oc_hello SOCKET|tls:HOST:PORT:PKI:NAME CELL_ID BOOT_ID HOLD_S
 *
 * Prints "HELLO_ACK mode M period P", or "HELLO_NAK reason R", then "closed"
 * if the core drops the link while held, and "PONG" for each PONG. Exit 0 on
 * HELLO_ACK. BOOT_ID is a number, or a mode for the HELLO gate's tests:
 * ping-first (a PING, then HELLO boot 1), ping-none (no frame at all: hold
 * HOLD_S), hello-ping (HELLO boot 1 and a PING right behind it). */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_conn.h"
#include "tool_dial.h"

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
    } else if (m->type == OC_CORE_PONG) {
        printf("PONG\n");
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: tool_oc_hello SOCKET|tls:HOST:PORT:PKI:NAME CELL_ID BOOT_ID HOLD_S\n");
        return 2;
    }
    if (tool_dial(argv[1], &C) != 0) return 1;
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = (uint32_t)strtoul(argv[2], NULL, 0);
    if (argv[3][0] >= '0' && argv[3][0] <= '9') h.u.hello.boot_id = strtoull(argv[3], NULL, 0);
    oc_core_msg_t ping;
    memset(&ping, 0, sizeof(ping));
    ping.type = OC_CORE_PING;
    if (strcmp(argv[3], "ping-first") == 0) {        /* the gate: a first frame other than HELLO */
        oc_conn_send(&C, &ping);
        h.u.hello.boot_id = 1;
        oc_conn_send(&C, &h);
    } else if (strcmp(argv[3], "ping-none") == 0) {  /* the gate: no frame at all */
        acked = 0;
    } else if (strcmp(argv[3], "hello-ping") == 0) { /* a frame right behind HELLO, one write (one TLS record) */
        uint8_t f[2 * OC_CORE_FRAME_MAX];
        h.u.hello.boot_id = 1;
        size_t n = oc_core_encode(&h, f, OC_CORE_FRAME_MAX);
        n += oc_core_encode(&ping, f + n, OC_CORE_FRAME_MAX);
        for (size_t off = 0; off < n;) {
            long w = C.io.send(C.io.ctx, f + off, n - off);
            if (w < 0) return 1;
            off += (size_t)w;
        }
    } else {
        oc_conn_send(&C, &h);
    }
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
