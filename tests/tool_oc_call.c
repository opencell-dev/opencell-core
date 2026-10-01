#define _GNU_SOURCE
/* A cell with one registered terminal in a call, for the process tests.
 *
 *   tool_oc_call hss FILE
 *       writes an ocbench HSS file (import-ocb-hss): a network key and
 *       +883160655501234 activated on TMID 76ad0488 with this tool's K/OPc
 *   tool_oc_call SOCKET CELL_ID BOOT_ID [CALLED SECONDS]
 *       HELLO as the cell, registers that terminal as the terminal would
 *       (AV_REQ, the RES from K/OPc, LOC_UPDATE), calls the echo service
 *       (or CALLED), prints "answered" once the call is up, then holds the
 *       link until the core drops it ("closed", or "released cause N" first
 *       if the core releases the call). Gives up after 30 s. Exit 0 once
 *       answered. With SECONDS: once answered it sends an 18-byte MEDIA
 *       every 120 ms as a terminal does, counts the MEDIA that comes back,
 *       and after SECONDS hangs up and prints "media N maxgap G" (G: the
 *       longest wait between two, ms; core test services spec §5.3); a
 *       release from the core ends it at once. */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_conn.h"
#include "oc_sig_crypto.h"
#include "oc_sig_milenage.h"

#define NUMBER "+883160655501234"
#define TMID   0x76ad0488u
#define ECHO   "+883160655500100"
#define LEG    0x42u

static const char *called_text = ECHO;
static double      talk_s;    /* 0: hold, as before */
static int         media_n;   /* MEDIA received */
static double      last_rx_s, maxgap_s, answered_s;

static const uint8_t K[16] = { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                               0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60 };
static const uint8_t OPC[16] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };

static oc_conn_t C;
static uint8_t num[OC_SIG_NUMBER_LEN];
static int answered, released;

static double mono_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void hexs(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

static int write_hss(const char *path)
{
    uint8_t sk[32], pk[32];
    for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(0x40 + i);
    if (oc_sig_x25519_public(sk, pk) != 0) return 1;
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        return 1;
    }
    fprintf(f, "network key_id=1 sk=");
    hexs(f, sk, 32);
    fprintf(f, " pk=");
    hexs(f, pk, 32);
    fprintf(f, " mode=part15 period=1800\n");
    fprintf(f, "sub number=%s token_id=d5d37c57bd4ac802 token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=1 tmid=%08x activated=1 k=", NUMBER, TMID);
    hexs(f, K, 16);
    fprintf(f, " opc=");
    hexs(f, OPC, 16);
    fprintf(f, " sqn=000000000000\n");
    return fclose(f) == 0 ? 0 : 1;
}

static void send_msg(const oc_core_msg_t *m)
{
    oc_conn_send(&C, m);
    oc_conn_flush(&C);
}

static void on_rx(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    oc_core_msg_t r;
    memset(&r, 0, sizeof(r));
    switch (m->type) {
    case OC_CORE_HELLO_ACK: /* the terminal registers: a vector first */
        r.type = OC_CORE_AV_REQ;
        r.u.av_req.req = 1;
        r.u.av_req.tmid = TMID;
        r.u.av_req.count = 1;
        send_msg(&r);
        break;
    case OC_CORE_HELLO_NAK:
        printf("HELLO_NAK reason %u\n", m->u.hello_nak.reason);
        exit(1);
    case OC_CORE_AV_RES: { /* the terminal's RES proves it, then it calls */
        static const uint8_t sqn[6] = { 0 }, amf[2] = { 0x80, 0x00 };
        oc_milenage_t o;
        if (m->u.av_res.status != OC_CORE_AV_OK || m->u.av_res.count < 1 ||
            oc_milenage(K, OPC, m->u.av_res.av[0].rand, sqn, amf, &o) != 0) {
            printf("AV_RES status %u\n", m->u.av_res.status);
            exit(1);
        }
        r.type = OC_CORE_LOC_UPDATE;
        r.u.loc_update.tmid = TMID;
        memcpy(r.u.loc_update.number, num, OC_SIG_NUMBER_LEN);
        memcpy(r.u.loc_update.rand, m->u.av_res.av[0].rand, 16);
        memcpy(r.u.loc_update.res, o.res, 8);
        send_msg(&r);
        memset(&r, 0, sizeof(r));
        r.type = OC_CORE_CALL_ROUTE;
        r.u.call_route.leg_ref = LEG;
        memcpy(r.u.call_route.caller, num, OC_SIG_NUMBER_LEN);
        oc_sig_number_to_bcd(called_text, strlen(called_text), r.u.call_route.called);
        send_msg(&r);
        break;
    }
    case OC_CORE_CALL_ANSWER:
        if (m->u.call.ref == LEG) {
            printf("answered\n");
            answered = 1;
            answered_s = mono_s();
        }
        break;
    case OC_CORE_MEDIA:
        if (m->u.media.ref == LEG) {
            double t = mono_s();
            if (media_n > 0 && t - last_rx_s > maxgap_s) maxgap_s = t - last_rx_s;
            last_rx_s = t;
            media_n++;
        }
        break;
    case OC_CORE_CALL_RELEASE:
        if (m->u.call.ref == LEG) {
            printf("released cause %u\n", m->u.call.cause);
            released = 1;
        }
        break;
    case OC_CORE_PING:
        r.type = OC_CORE_PONG;
        send_msg(&r);
        break;
    default:
        break;
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "hss") == 0) return write_hss(argv[2]);
    if (argc != 4 && argc != 6) {
        fprintf(stderr, "usage: tool_oc_call hss FILE | tool_oc_call SOCKET CELL_ID BOOT_ID [CALLED SECONDS]\n");
        return 2;
    }
    if (argc == 6) {
        called_text = argv[4];
        talk_s = strtod(argv[5], NULL);
    }
    oc_sig_number_to_bcd(NUMBER, strlen(NUMBER), num);
    int fd = oc_unix_connect_wait(argv[1], 10000);
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
    send_msg(&h);
    time_t end = time(NULL) + 30;
    double next_tx = 0;
    uint16_t seq = 0;
    while (time(NULL) < end) {
        struct pollfd p = { C.fd, POLLIN, 0 };
        if (poll(&p, 1, talk_s > 0 && answered ? 5 : 200) > 0 && oc_conn_read(&C, on_rx, NULL) != 0) {
            printf("closed\n");
            break;
        }
        if (talk_s > 0 && released) break; /* talking: a released call is the end */
        if (talk_s <= 0 || !answered) continue;
        double t = mono_s();
        if (t - answered_s >= talk_s) { /* hang up, and say what came */
            oc_core_msg_t r;
            memset(&r, 0, sizeof(r));
            r.type = OC_CORE_CALL_RELEASE;
            r.u.call.ref = LEG;
            send_msg(&r);
            printf("media %d maxgap %d\n", media_n, (int)(maxgap_s * 1000.0));
            break;
        }
        if (t >= next_tx) { /* one 18-byte payload per 120 ms frame, as a terminal sends */
            oc_core_msg_t r;
            memset(&r, 0, sizeof(r));
            r.type = OC_CORE_MEDIA;
            r.u.media.ref = LEG;
            r.u.media.seq = seq++;
            r.u.media.len = 18;
            memset(r.u.media.data, 0x5a, 18);
            send_msg(&r);
            next_tx = (next_tx == 0 ? t : next_tx) + 0.12;
        }
    }
    oc_conn_close(&C);
    return answered ? 0 : 1;
}
