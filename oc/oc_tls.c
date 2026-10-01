#define _GNU_SOURCE
#include "oc_tls.h"

#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

struct oc_tls {
    SSL_CTX     *ctx;
    oc_tls_cfg_t cfg;
    uint8_t      alpn_wire[64]; /* the protocol as ALPN sends it: len | name */
    size_t       alpn_n;
};

static int conn_idx = -1; /* SSL ex_data: the oc_tls_conn_t, for the verify callback's reason */

static void ssl_err(char *out, size_t cap, const char *what)
{
    unsigned long e = ERR_get_error();
    char b[160] = "";
    if (e != 0) ERR_error_string_n(e, b, sizeof(b));
    snprintf(out, cap, "%s%s%s", what, b[0] != '\0' ? ": " : "", b);
    ERR_clear_error();
}

int oc_tls_fpr_parse(const char *hex, uint8_t out[32])
{
    if (hex == NULL || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            int ch = tolower((unsigned char)hex[2 * i + j]);
            if (!isxdigit(ch)) return -1;
            v = v * 16u + (unsigned)(isdigit(ch) ? ch - '0' : ch - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int has_policy(X509 *x, const char *oid)
{
    CERTIFICATEPOLICIES *cp = X509_get_ext_d2i(x, NID_certificate_policies, NULL, NULL);
    int found = 0;
    for (int i = 0; cp != NULL && i < sk_POLICYINFO_num(cp); i++) {
        char b[128];
        POLICYINFO *pi = sk_POLICYINFO_value(cp, i);
        if (OBJ_obj2txt(b, sizeof(b), pi->policyid, 1) > 0 && strcmp(b, oid) == 0) found = 1;
    }
    CERTIFICATEPOLICIES_free(cp);
    return found;
}

/* The chain was checked by OpenSSL (preverify_ok): at the peer's own
 * certificate (depth 0), its pin and its role too. */
static int verify_cb(int ok, X509_STORE_CTX *st)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(st, SSL_get_ex_data_X509_STORE_CTX_idx());
    oc_tls_conn_t *c = SSL_get_ex_data(ssl, conn_idx);
    oc_tls_t *t = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    const char *who = t->cfg.client ? "server" : "client";
    if (!ok) {
        int e = X509_STORE_CTX_get_error(st);
        snprintf(c->why, sizeof(c->why), "%s certificate refused: %s (depth %d)", who,
                 X509_verify_cert_error_string(e), X509_STORE_CTX_get_error_depth(st));
        return 0;
    }
    if (X509_STORE_CTX_get_error_depth(st) != 0) return 1;
    X509 *x = X509_STORE_CTX_get_current_cert(st);
    uint8_t md[32];
    unsigned mdn = 0;
    if (X509_digest(x, EVP_sha256(), md, &mdn) != 1 || mdn != 32) {
        snprintf(c->why, sizeof(c->why), "%s certificate refused: no fingerprint", who);
        return 0;
    }
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", md[i]);
    int pinned = 0;
    for (unsigned i = 0; i < t->cfg.npin; i++) pinned |= memcmp(md, t->cfg.pin[i], 32) == 0;
    if (!pinned) {
        snprintf(c->why, sizeof(c->why), "%s certificate %.16s... is not pinned", who, hex);
        return 0;
    }
    if (!has_policy(x, t->cfg.role)) {
        snprintf(c->why, sizeof(c->why), "%s certificate %.16s... lacks the role %s", who, hex, t->cfg.role);
        return 0;
    }
    memcpy(c->peer, hex, sizeof(hex));
    return 1;
}

static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                   unsigned int inlen, void *arg)
{
    oc_tls_t *t = arg;
    unsigned char *sel = NULL;
    oc_tls_conn_t *c = SSL_get_ex_data(ssl, conn_idx);
    if (SSL_select_next_proto(&sel, outlen, t->alpn_wire, (unsigned)t->alpn_n, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        snprintf(c->why, sizeof(c->why), "the client does not speak %s (ALPN)", t->cfg.alpn);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

oc_tls_t *oc_tls_new(const oc_tls_cfg_t *cfg, char *err, size_t cap)
{
    if (cfg->npin == 0 || cfg->npin > OC_TLS_PINS || cfg->alpn == NULL || strlen(cfg->alpn) == 0 ||
        strlen(cfg->alpn) > 60 || cfg->role == NULL) {
        snprintf(err, cap, "TLS: a pinned peer certificate, an ALPN protocol and a role are needed");
        return NULL;
    }
    if (conn_idx < 0) conn_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    oc_tls_t *t = calloc(1, sizeof(*t));
    if (t == NULL) {
        snprintf(err, cap, "out of memory");
        return NULL;
    }
    t->cfg = *cfg;
    t->alpn_wire[0] = (uint8_t)strlen(cfg->alpn);
    memcpy(t->alpn_wire + 1, cfg->alpn, t->alpn_wire[0]);
    t->alpn_n = 1u + t->alpn_wire[0];
    t->ctx = SSL_CTX_new(cfg->client ? TLS_client_method() : TLS_server_method());
    STACK_OF(X509_NAME) *names = NULL;
    if (t->ctx == NULL) {
        ssl_err(err, cap, "TLS: no context");
        goto fail;
    }
    SSL_CTX_set_app_data(t->ctx, t);
    if (SSL_CTX_set_min_proto_version(t->ctx, TLS1_3_VERSION) != 1) {
        ssl_err(err, cap, "TLS: no TLS 1.3");
        goto fail;
    }
    if (SSL_CTX_use_certificate_chain_file(t->ctx, cfg->cert) != 1) {
        ssl_err(err, cap, cfg->cert);
        goto fail;
    }
    if (SSL_CTX_use_PrivateKey_file(t->ctx, cfg->key, SSL_FILETYPE_PEM) != 1 || SSL_CTX_check_private_key(t->ctx) != 1) {
        char what[300];
        snprintf(what, sizeof(what), "%s: not the key of %s", cfg->key, cfg->cert);
        ssl_err(err, cap, what);
        goto fail;
    }
    if (SSL_CTX_load_verify_locations(t->ctx, cfg->ca, NULL) != 1) {
        ssl_err(err, cap, cfg->ca);
        goto fail;
    }
    if (cfg->client) { /* offer the one protocol; the server's certificate is for a server */
        X509_VERIFY_PARAM_set_purpose(SSL_CTX_get0_param(t->ctx), X509_PURPOSE_SSL_SERVER);
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, verify_cb);
        if (SSL_CTX_set_alpn_protos(t->ctx, t->alpn_wire, (unsigned)t->alpn_n) != 0) {
            ssl_err(err, cap, "TLS: ALPN");
            goto fail;
        }
    } else {
        if ((names = SSL_load_client_CA_file(cfg->ca)) == NULL) {
            ssl_err(err, cap, cfg->ca);
            goto fail;
        }
        SSL_CTX_set_client_CA_list(t->ctx, names);
        X509_VERIFY_PARAM_set_purpose(SSL_CTX_get0_param(t->ctx), X509_PURPOSE_SSL_CLIENT);
        SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
        SSL_CTX_set_alpn_select_cb(t->ctx, alpn_cb, t);
    }
    SSL_CTX_set_verify_depth(t->ctx, 2);
    SSL_CTX_set_session_cache_mode(t->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(t->ctx, 0);
    return t;
fail:
    oc_tls_free(t);
    return NULL;
}

void oc_tls_free(oc_tls_t *t)
{
    if (t == NULL) return;
    SSL_CTX_free(t->ctx);
    free(t);
}

int oc_tls_conn_start(oc_tls_t *t, oc_tls_conn_t *c, int fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    c->ssl = SSL_new(t->ctx);
    if (c->ssl == NULL || SSL_set_fd(c->ssl, fd) != 1 || SSL_set_ex_data(c->ssl, conn_idx, c) != 1) {
        oc_tls_conn_close(c);
        return -1;
    }
    if (t->cfg.client) {
        SSL_set_connect_state(c->ssl);
        c->want = POLLOUT; /* the ClientHello goes first */
    } else {
        SSL_set_accept_state(c->ssl);
        c->want = POLLIN;
    }
    return 0;
}

/* After an SSL call that returned r <= 0: 0 (want set) or -1. */
static int again(oc_tls_conn_t *c, int r)
{
    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ) {
        c->want = POLLIN;
        return 0;
    }
    if (e == SSL_ERROR_WANT_WRITE) {
        c->want = POLLOUT;
        return 0;
    }
    return -1;
}

int oc_tls_conn_handshake(oc_tls_conn_t *c)
{
    if (c->ssl == NULL) return -1;
    ERR_clear_error();
    int r = SSL_do_handshake(c->ssl);
    if (r == 1) {
        const unsigned char *p = NULL;
        unsigned n = 0;
        SSL_get0_alpn_selected(c->ssl, &p, &n);
        if (n == 0) { /* a client offering no ALPN at all never reaches alpn_cb; a server may choose none */
            snprintf(c->why, sizeof(c->why), SSL_is_server(c->ssl) ? "the client offered no ALPN protocol"
                                                                    : "the server chose no ALPN protocol");
            return -1;
        }
        if (c->peer[0] == '\0') { /* verify_cb always sets it: belt and braces */
            snprintf(c->why, sizeof(c->why), "no verified peer certificate");
            return -1;
        }
        c->want = POLLIN;
        return 1;
    }
    if (again(c, r) == 0) return 0;
    if (c->why[0] == '\0') ssl_err(c->why, sizeof(c->why), "handshake failed");
    ERR_clear_error();
    return -1;
}

long oc_tls_conn_read(oc_tls_conn_t *c, void *buf, size_t n)
{
    if (c->ssl == NULL) return -1;
    ERR_clear_error();
    int r = SSL_read(c->ssl, buf, n > 0x7fffffffu ? 0x7fffffff : (int)n);
    if (r > 0) return r;
    return again(c, r) == 0 ? 0 : -1;
}

long oc_tls_conn_write(oc_tls_conn_t *c, const void *buf, size_t n)
{
    if (c->ssl == NULL) return -1;
    ERR_clear_error();
    int r = SSL_write(c->ssl, buf, n > 0x7fffffffu ? 0x7fffffff : (int)n);
    if (r > 0) return r;
    return again(c, r) == 0 ? 0 : -1;
}

int oc_tls_conn_pending(const oc_tls_conn_t *c) { return c->ssl != NULL ? SSL_pending(c->ssl) : 0; }

void oc_tls_conn_close(oc_tls_conn_t *c)
{
    if (c->ssl != NULL) {
        if (SSL_is_init_finished(c->ssl)) SSL_shutdown(c->ssl); /* one try: the socket is non-blocking */
        SSL_free(c->ssl);
        c->ssl = NULL;
        ERR_clear_error();
    }
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
}
