// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include <bpf/xsk.h>
#include <linux/if_link.h>

static volatile int stop;
static void on_sigint(int sig) { (void)sig; stop = 1; }

/* ---------------- UMEM pool (LIFO stack) ---------------- */

struct umem_pool {
    uint64_t *stk;
    uint32_t cap;
    uint32_t top;
};

static int pool_init(struct umem_pool *p, uint32_t cap)
{
    p->stk = calloc(cap, sizeof(uint64_t));
    if (!p->stk) return -1;
    p->cap = cap;
    p->top = 0;
    return 0;
}

static inline void pool_push(struct umem_pool *p, uint64_t addr)
{
    /* best-effort: if overflow, drop */
    if (p->top < p->cap)
        p->stk[p->top++] = addr;
}

static inline int pool_pop(struct umem_pool *p, uint64_t *addr)
{
    if (!p->top) return 0;
    *addr = p->stk[--p->top];
    return 1;
}

/* ---------------- AF_XDP endpoint ---------------- */

struct xsk_ep {
    const char *ifname;
    int qid;

    void *umem_area;
    uint64_t umem_size;

    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    struct umem_pool pool; /* free frames for this UMEM */
};

static void complete_tx(struct xsk_ep *ep, int budget)
{
    uint32_t idx;
    int n = xsk_ring_cons__peek(&ep->cq, budget, &idx);
    if (n <= 0) return;

    for (int i = 0; i < n; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&ep->cq, idx + i);
        pool_push(&ep->pool, addr);
    }
    xsk_ring_cons__release(&ep->cq, n);
}

/* reserve small batches, submit only what we filled */
static void refill_fq(struct xsk_ep *ep, int want)
{
    if (ep->pool.top == 0) return;

    /* poolにある分だけ入れる（＝必ず全部埋められる数だけreserveする） */
    if ((uint32_t)want > ep->pool.top) want = ep->pool.top;
    if (want <= 0) return;

    uint32_t idx;
    int r = xsk_ring_prod__reserve(&ep->fq, want, &idx);
    if (r <= 0) return;

    /* reserveした数 r は必ず埋める */
    for (int i = 0; i < r; i++) {
        uint64_t addr;
        (void)pool_pop(&ep->pool, &addr); /* 必ず成功する前提 */
        *xsk_ring_prod__fill_addr(&ep->fq, idx + i) = addr;
    }
    xsk_ring_prod__submit(&ep->fq, r);
}

static int ep_init(struct xsk_ep *ep,
                   const char *ifname, int qid,
                   uint32_t num_frames,
                   uint32_t frame_size,
                   uint32_t rxsz, uint32_t txsz,
                   uint32_t xdp_flags, uint32_t bind_flags)
{
    memset(ep, 0, sizeof(*ep));
    ep->ifname = ifname;
    ep->qid = qid;

    ep->umem_size = (uint64_t)num_frames * frame_size;
    if (posix_memalign(&ep->umem_area, 4096, ep->umem_size)) {
        fprintf(stderr, "posix_memalign(%s) failed\n", ifname);
        return -1;
    }
    memset(ep->umem_area, 0, ep->umem_size);

    struct xsk_umem_config ucfg = {
        .fill_size = rxsz,     /* OK to reuse rxsz */
        .comp_size = txsz,
        .frame_size = frame_size,
        .frame_headroom = 0,
        .flags = 0,
    };

    int ret = xsk_umem__create(&ep->umem, ep->umem_area, ep->umem_size,
                              &ep->fq, &ep->cq, &ucfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create(%s): %s\n", ifname, strerror(-ret));
        return -1;
    }

    struct xsk_socket_config scfg = {
        .rx_size = rxsz,
        .tx_size = txsz,
        .xdp_flags = xdp_flags,
        .bind_flags = bind_flags,
        .libbpf_flags = 0,
    };

    ret = xsk_socket__create(&ep->xsk, ifname, qid, ep->umem,
                             &ep->rx, &ep->tx, &scfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create(%s): %s\n", ifname, strerror(-ret));
        return -1;
    }

    if (pool_init(&ep->pool, num_frames)) {
        fprintf(stderr, "pool_init(%s) failed\n", ifname);
        return -1;
    }
    for (uint32_t i = 0; i < num_frames; i++)
        pool_push(&ep->pool, (uint64_t)i * frame_size);

    /* prefill FQ */
    for (int i = 0; i < 64; i++)
        refill_fq(ep, 64);

    return 0;
}

static void ep_destroy(struct xsk_ep *ep)
{
    if (ep->xsk) xsk_socket__delete(ep->xsk);
    if (ep->umem) xsk_umem__delete(ep->umem);
    free(ep->pool.stk);
    free(ep->umem_area);
}

static inline void kick_tx_if_needed(struct xsk_ep *ep)
{
    /* need_wakeup を使ってるならkick */
    (void)sendto(xsk_socket__fd(ep->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static int forward_copy(struct xsk_ep *src, struct xsk_ep *dst, int budget,
                        uint64_t *rx_pkts, uint64_t *tx_pkts, uint64_t *copy_pkts, uint64_t *drop_pkts)
{
    /* 送信済み回収と受信用補充は、呼び出し側でまとめてやってもOK */
    uint32_t rx_idx;
    int rcvd = xsk_ring_cons__peek(&src->rx, budget, &rx_idx);
    if (rcvd <= 0) return 0;

    *rx_pkts += (uint64_t)rcvd;

    uint32_t tx_idx;
    int can_tx = xsk_ring_prod__reserve(&dst->tx, rcvd, &tx_idx);
    if (can_tx < 0) can_tx = 0;

    int sent = 0;
    for (; sent < rcvd && sent < can_tx; sent++) {
        const struct xdp_desc *rd = xsk_ring_cons__rx_desc(&src->rx, rx_idx + sent);
        uint64_t src_addr = rd->addr;
        uint32_t len      = rd->len;

        uint64_t dst_addr;
        if (!pool_pop(&dst->pool, &dst_addr)) {
            break; /* dst側TXバッファ枯渇 */
        }

        void *s = xsk_umem__get_data(src->umem_area, src_addr);
        void *d = xsk_umem__get_data(dst->umem_area, dst_addr);
        memcpy(d, s, len);

        struct xdp_desc *td = xsk_ring_prod__tx_desc(&dst->tx, tx_idx + sent);
        td->addr = dst_addr;
        td->len  = len;

        pool_push(&src->pool, src_addr); /* srcフレーム返却 */
        (*copy_pkts)++;
    }

    /* 送れなかった分は src に返して drop カウント */
    for (int i = sent; i < rcvd; i++) {
        uint64_t src_addr = xsk_ring_cons__rx_desc(&src->rx, rx_idx + i)->addr;
        pool_push(&src->pool, src_addr);
        (*drop_pkts)++;
    }

    xsk_ring_cons__release(&src->rx, rcvd);

    if (sent > 0) {
        xsk_ring_prod__submit(&dst->tx, sent);
        *tx_pkts += (uint64_t)sent;
        kick_tx_if_needed(dst);
    }

    return sent;
}

/* ---------------- Main forwarding loop ---------------- */

int main(int argc, char **argv)
{
    const char *in_if  = "enp4s0f1";
    int in_qid         = 0;
    const char *out_if = "veth-gate";
    int out_qid        = 0;

    if (argc >= 2) in_if = argv[1];
    if (argc >= 3) in_qid = atoi(argv[2]);
    if (argc >= 4) out_if = argv[3];
    if (argc >= 5) out_qid = atoi(argv[4]);

    signal(SIGINT, on_sigint);

    const uint32_t NUM_FRAMES = 4096;
    const uint32_t FRAME_SIZE = XSK_UMEM__DEFAULT_FRAME_SIZE;

    /* in: driver/native (enp4s0f1) */
    struct xsk_ep in = {0};
    /* out: veth is generic/SKB XDP */
    struct xsk_ep out = {0};

    /* in side: don't clobber existing; driver/native auto */
    if (ep_init(&in, in_if, in_qid, NUM_FRAMES, FRAME_SIZE,
                2048, 2048,
                XDP_FLAGS_UPDATE_IF_NOEXIST,
                XDP_USE_NEED_WAKEUP) != 0) {
        fprintf(stderr, "init in failed\n");
        return 1;
    }

    /* out side: veth => SKB mode */
    if (ep_init(&out, out_if, out_qid, NUM_FRAMES, FRAME_SIZE,
                2048, 2048,
                XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
                XDP_USE_NEED_WAKEUP) != 0) {
        fprintf(stderr, "init out failed\n");
        ep_destroy(&in);
        return 1;
    }

    int in_fd  = xsk_socket__fd(in.xsk);
    int out_fd = xsk_socket__fd(out.xsk);

    printf("OK: IN  if=%s qid=%d fd=%d\n", in_if, in_qid, in_fd);
    printf("OK: OUT if=%s qid=%d fd=%d (SKB)\n", out_if, out_qid, out_fd);
    printf("Forward: IN(RX) -> memcpy -> OUT(TX) -> OVS -> VM\n");

    uint64_t rx_pkts = 0, tx_pkts = 0, drop_pkts = 0, copy_pkts = 0;
    uint64_t last_rx = 0, last_tx = 0, last_drop = 0, last_copy = 0;
    time_t last_ts = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    last_ts = ts.tv_sec;

    while (!stop) {

        /* TX completion 回収 */
        complete_tx(&in,  256);
        complete_tx(&out, 256);

        /* RX用FQ補充 */
        refill_fq(&in,  256);
        refill_fq(&out, 256);

        /* 双方向コピー */
        int a = forward_copy(&in,  &out, 64,
                            &rx_pkts, &tx_pkts, &copy_pkts, &drop_pkts);
        int b = forward_copy(&out, &in,  64,
                            &rx_pkts, &tx_pkts, &copy_pkts, &drop_pkts);

        if (a == 0 && b == 0)
            usleep(50);

        /* statsだけ残す */
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if (ts.tv_sec != last_ts) {
            printf("RX=%lu TX=%lu COPY=%lu DROP=%lu in_pool=%u out_pool=%u\n",
                rx_pkts, tx_pkts, copy_pkts, drop_pkts,
                in.pool.top, out.pool.top);
            fflush(stdout);
            last_ts = ts.tv_sec;
        }
    }

    ep_destroy(&out);
    ep_destroy(&in);
    return 0;
}
