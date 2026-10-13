#include "oc_conn.h"

#include <string.h>

#include "oc_sig_keys.h" /* oc_sig_wipe */

void oc_conn_init_io(oc_conn_t *c, int fd, const oc_conn_io_t *io)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->io = *io;
}

void oc_conn_close(oc_conn_t *c)
{
    if (c->fd >= 0) c->io.close(c->io.ctx);
    c->fd = -1;
    oc_sig_wipe(c->rx, sizeof(c->rx)); /* what was read or queued is gone with the link, key material too */
    oc_sig_wipe(c->tx, sizeof(c->tx));
    c->rn = c->tn = 0;
}

int oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx)
{
    if (c->fd < 0) return -1;
    for (;;) {
        long r = c->io.recv(c->io.ctx, c->rx + c->rn, sizeof(c->rx) - c->rn);
        if (r < 0) return -1;
        if (r == 0) return 0;
        c->rn += (size_t)r;
        size_t off = 0;
        while (c->rn - off >= 2) {
            size_t len = ((size_t)c->rx[off] << 8) | c->rx[off + 1];
            if (len == 0 || len + 2u > OC_CORE_FRAME_MAX) return -1; /* the stream is broken */
            if (c->rn - off < len + 2u) break;
            oc_core_msg_t m;
            int ok = oc_core_decode(c->rx + off, len + 2u, &m) == 0;
            if (ok) cb(ctx, &m);
            oc_sig_wipe(&m, sizeof(m)); /* an AV_RES's CK and IK (oc-cell's side) */
            if (!ok) c->bad++;
            else if (c->fd < 0) return -1; /* cb closed it */
            off += len + 2u;
        }
        memmove(c->rx, c->rx + off, c->rn - off);
        oc_sig_wipe(c->rx + c->rn - off, off); /* the frames handed on */
        c->rn -= off;
    }
}

int oc_conn_flush(oc_conn_t *c)
{
    if (c->fd < 0) return -1;
    while (c->tn > 0) {
        long w = c->io.send(c->io.ctx, c->tx, c->tn);
        if (w < 0) return -1;
        if (w == 0) return 0;
        memmove(c->tx, c->tx + w, c->tn - (size_t)w);
        oc_sig_wipe(c->tx + c->tn - (size_t)w, (size_t)w); /* the bytes sent (an AV_RES's CK and IK, say) */
        c->tn -= (size_t)w;
    }
    return 0;
}

int oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m)
{
    uint8_t f[OC_CORE_FRAME_MAX];
    if (c->fd < 0) return -1;
    size_t n = oc_core_encode(m, f, sizeof(f));
    if (n == 0 || c->tn + n > sizeof(c->tx)) {
        oc_sig_wipe(f, sizeof(f));
        return -1;
    }
    memcpy(c->tx + c->tn, f, n);
    oc_sig_wipe(f, sizeof(f));
    c->tn += n;
    return oc_conn_flush(c);
}
