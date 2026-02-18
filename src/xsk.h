#pragma once
#include <stdint.h>
#include <bpf/xsk.h>

struct xsk_port {
    const char *ifname;
    uint32_t queue_id;

    struct xsk_umem *umem;
    void *umem_area;
    uint64_t umem_size;

    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    struct xsk_socket *xsk;
    int xsk_fd;

    uint32_t frame_size;
    uint32_t num_frames;
};

int  xsk_port_init(struct xsk_port *p, const char *ifname, uint32_t qid,
                   uint32_t num_frames, uint32_t frame_size);
int  xsk_port_fill_all(struct xsk_port *p);
int  xsk_port_rx_burst(struct xsk_port *p, struct xdp_desc *descs, int max);
int  xsk_port_recycle(struct xsk_port *p, uint64_t addr);
void xsk_port_destroy(struct xsk_port *p);
