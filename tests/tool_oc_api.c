#define _GNU_SOURCE
/* An admin API client for the process tests (portal spec §7): TLS 1.3 with
 * a certificate from the test PKI, one request, its answer printed.
 *
 *   tool_oc_api PORT PKI CERT [--alpn P|none] [--actor N] OP [ARG]
 *
 * Connects to 127.0.0.1:PORT, checks the core against PKI/ca.crt as
 * "localhost", shows PKI/CERT.crt (key PKI/CERT.key; "none": no
 * certificate). OP:
 *   core.status                 prints "ok NAME VERSION"
 *   num.check|sub.create|sub.status|sub.release NUMBER
 *                               prints the status name ("ok", "taken", ...),
 *                               and after sub.create's ok the QR text
 *   hold S                      sends nothing; "closed after N s" when the
 *                               core closes it, or "open" after S s
 *   drip S                      sends a request's first byte only; as hold
 *   pipe N                      N sub.status calls for +883171746412345 in
 *                               one write (req 1..N), then their answers:
 *                               "answered N in M ms", or "stalled after K
 *                               of N" (an answer missing or out of order)
 * Prints "refused" when the handshake fails or the core closes the
 * connection instead of answering. Exit 0 once something was printed. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "oc_api.h"

static SSL *S;

static int read_all(uint8_t *b, size_t n)
{
    for (size_t got = 0; got < n;) {
        int r = SSL_read(S, b + got, (int)(n - got));
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* One answer frame into b: its length, or -1 (closed). */
static int answer(uint8_t *b)
{
    if (read_all(b, 2) != 0) return -1;
    size_t len = (size_t)b[0] << 8 | b[1];
    if (len < 6 || len + 2 > OC_API_FRAME_MAX || read_all(b + 2, len) != 0) return -1;
    return (int)len + 2;
}

static int wait_close(int secs)
{
    time_t t0 = time(NULL);
    uint8_t b[16];
    struct timeval tv = { secs, 0 };
    setsockopt(SSL_get_fd(S), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int r = SSL_read(S, b, sizeof(b));
    if (r <= 0 && time(NULL) - t0 < secs) printf("closed after %ld s\n", (long)(time(NULL) - t0));
    else printf("open\n");
    return 0;
}

/* N requests pipelined, their answers read in order (oc_apisrv serves at
 * most OC_APISRV_BURST per loop turn: the rest must still come at once). */
static int pipe_calls(int count)
{
    static uint8_t w[64 * 19];
    uint8_t f[OC_API_FRAME_MAX], num[OC_SIG_NUMBER_LEN];
    struct timespec t0, t1;
    if (count < 1 || count > 64 || oc_sig_number_to_bcd("+883171746412345", 16, num) != 0) return 2;
    for (int k = 0; k < count; k++) {
        uint8_t *p = w + 19 * k;
        uint32_t req = (uint32_t)k + 1u;
        p[0] = 0;
        p[1] = 17;
        p[2] = OC_API_SUB_STATUS;
        for (int j = 0; j < 4; j++) p[3 + j] = (uint8_t)(req >> (8 * j));
        memset(p + 7, 0, 4);
        memcpy(p + 11, num, OC_SIG_NUMBER_LEN);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (SSL_write(S, w, 19 * count) != 19 * count) {
        printf("refused\n");
        return 0;
    }
    int got = 0;
    const char *why = "";
    for (; got < count; got++) {
        uint32_t req;
        if (answer(f) < 0) {
            why = ", then closed";
            break;
        }
        req = (uint32_t)f[3] | (uint32_t)f[4] << 8 | (uint32_t)f[5] << 16 | (uint32_t)f[6] << 24;
        if (req != (uint32_t)got + 1u) {
            why = ", then an answer out of order";
            break;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)(t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    if (got == count) printf("answered %d in %ld ms\n", count, ms);
    else printf("stalled after %d of %d%s (%ld ms)\n", got, count, why, ms);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: tool_oc_api PORT PKI CERT [--alpn P|none] [--actor N] OP [ARG]\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN); /* a core that closes on us: "refused", not a dead tool */
    const char *pki = argv[2], *cert = argv[3], *alpn = "oc-admin/1";
    uint32_t actor = 42;
    int i = 4;
    for (; i + 1 < argc && strncmp(argv[i], "--", 2) == 0; i += 2) {
        if (strcmp(argv[i], "--alpn") == 0) alpn = argv[i + 1];
        else if (strcmp(argv[i], "--actor") == 0) actor = (uint32_t)strtoul(argv[i + 1], NULL, 10);
    }
    if (i >= argc) return 2;
    const char *op = argv[i], *arg = i + 1 < argc ? argv[i + 1] : "";
    char path[512], kpath[512];

    SSL_CTX *cx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(cx, TLS1_3_VERSION);
    snprintf(path, sizeof(path), "%s/ca.crt", pki);
    SSL_CTX_load_verify_locations(cx, path, NULL);
    SSL_CTX_set_verify(cx, SSL_VERIFY_PEER, NULL);
    if (strcmp(cert, "none") != 0) {
        snprintf(path, sizeof(path), "%s/%s.crt", pki, cert);
        snprintf(kpath, sizeof(kpath), "%s/%s.key", pki, cert);
        if (SSL_CTX_use_certificate_file(cx, path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(cx, kpath, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "%s: can't load\n", path);
            return 2;
        }
    }
    if (strcmp(alpn, "none") != 0) {
        unsigned char w[64];
        w[0] = (unsigned char)strlen(alpn);
        memcpy(w + 1, alpn, w[0]);
        SSL_CTX_set_alpn_protos(cx, w, 1u + w[0]);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[1])) };
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("no listener\n");
        return 1;
    }
    S = SSL_new(cx);
    SSL_set_fd(S, fd);
    SSL_set1_host(S, "localhost");
    if (SSL_connect(S) != 1) {
        printf("refused\n");
        return 0;
    }
    uint8_t f[OC_API_FRAME_MAX];
    size_t n = 3;
    uint8_t code = 0;
    if (strcmp(op, "hold") == 0) return wait_close(atoi(arg));
    if (strcmp(op, "pipe") == 0) return pipe_calls(atoi(arg));
    if (strcmp(op, "core.status") == 0) code = OC_API_CORE_STATUS;
    else if (strcmp(op, "num.check") == 0) code = OC_API_NUM_CHECK;
    else if (strcmp(op, "sub.create") == 0) code = OC_API_SUB_CREATE;
    else if (strcmp(op, "sub.status") == 0) code = OC_API_SUB_STATUS;
    else if (strcmp(op, "sub.release") == 0) code = OC_API_SUB_RELEASE;
    else if (strcmp(op, "drip") == 0) code = OC_API_CORE_STATUS;
    else return 2;
    f[2] = code;
    for (int k = 0; k < 4; k++) f[n++] = (uint8_t)(7u >> (8 * k)); /* req 7 */
    for (int k = 0; k < 4; k++) f[n++] = (uint8_t)(actor >> (8 * k));
    if (code != OC_API_CORE_STATUS) {
        if (oc_sig_number_to_bcd(arg, strlen(arg), f + n) != 0) return 2;
        n += OC_SIG_NUMBER_LEN;
    }
    f[0] = (uint8_t)((n - 2) >> 8);
    f[1] = (uint8_t)(n - 2);
    if (strcmp(op, "drip") == 0) {
        SSL_write(S, f, 1);
        return wait_close(atoi(arg));
    }
    if (SSL_write(S, f, (int)n) != (int)n || answer(f) < 0) {
        printf("refused\n");
        return 0;
    }
    uint8_t status = f[7];
    printf("%s", oc_api_status_name(status));
    if (status == OC_API_OK && code == OC_API_CORE_STATUS) {
        const uint8_t *b = f + 8 + 20;
        printf(" %.*s", b[0], (const char *)b + 1);
        b += 1 + b[0];
        printf(" %.*s", b[0], (const char *)b + 1);
    }
    if (status == OC_API_OK && code == OC_API_SUB_CREATE) printf("\n%.*s", f[8 + 12], (const char *)f + 8 + 13);
    printf("\n");
    SSL_shutdown(S);
    SSL_free(S);
    SSL_CTX_free(cx);
    close(fd);
    return 0;
}
