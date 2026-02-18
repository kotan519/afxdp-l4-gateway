#include "xsk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *xmalloc_aligned(size_t alignment, size_t size)
{
    void *p = NULL;
    if (posix_memalign(&p, alignment, size) != 0)
        return NULL;
    memset(p, 0, size);
    return p;
}

int xsk_port_init(struct xsk_port *p, const char *ifname, uint32_t qid,
                  uint32_t num_frames, uint32_t frame_size)
{
    memset(p, 0, sizeof(*p));
    p->ifname = ifname;
    p->queue_id = qid;
    p->num_frames = num_frames;
    p->frame_size = frame_size;

    p->umem_size = (uint64_t)num_frames * frame_size;
    p->umem_area = xmalloc_aligned(4096, (size_t)p->umem_size);
    if (!p->umem_area) {
        perror("posix_memalign");
        return -1;
    }

    struct xsk_umem_config ucfg = {
        .fill_size = 4096,
        .comp_size = 4096,
        .frame_size = frame_size,
        .frame_headroom = 0,
        .flags = 0,
    };

    int ret = xsk_umem__create(&p->umem, p->umem_area, p->umem_size,
                              &p->fill, &p->comp, &ucfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret));
        return -1;
    }

    struct xsk_socket_config scfg = {
        .rx_size = 2048,
        .tx_size = 2048,
        .libbpf_flags = 0,
        .xdp_flags = 0,                 /* driver/generic is chosen by attach side */
        .bind_flags = 0,
    };

    ret = xsk_socket__create(&p->xsk, ifname, qid, p->umem,
                             &p->rx, &p->tx, &scfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create: %s\n", strerror(-ret));
        return -1;
    }

    p->xsk_fd = xsk_socket__fd(p->xsk);
    return 0;
}

int xsk_port_fill_all(struct xsk_port *p)
{
    uint32_t idx;
    int want = (int)p->num_frames;

    int got = xsk_ring_prod__reserve(&p->fill, want, &idx);
    if (got <= 0)
        return got;

    for (int i = 0; i < got; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        *xsk_ring_prod__fill_addr(&p->fill, idx + i) = addr;
    }
    xsk_ring_prod__submit(&p->fill, got);
    return got;
}

int xsk_port_rx_burst(struct xsk_port *p, struct xdp_desc *descs, int max)
{
    uint32_t idx;
    int n = xsk_ring_cons__peek(&p->rx, max, &idx);
    if (n <= 0)
        return n;

    for (int i = 0; i < n; i++)
        descs[i] = *xsk_ring_cons__rx_desc(&p->rx, idx + i);

    xsk_ring_cons__release(&p->rx, n);
    return n;
}

int xsk_port_recycle(struct xsk_port *p, uint64_t addr)
{
    uint32_t idx;
    int ret = xsk_ring_prod__reserve(&p->fill, 1, &idx);
    if (ret != 1)
        return -ENOSPC;

    *xsk_ring_prod__fill_addr(&p->fill, idx) = addr;
    xsk_ring_prod__submit(&p->fill, 1);
    return 0;
}

void xsk_port_destroy(struct xsk_port *p)
{
    if (p->xsk)  xsk_socket__delete(p->xsk);
    if (p->umem) xsk_umem__delete(p->umem);
    free(p->umem_area);
    memset(p, 0, sizeof(*p));
}
