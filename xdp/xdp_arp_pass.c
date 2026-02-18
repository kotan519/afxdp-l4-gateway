// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);          // キュー数に合わせて増やす（今は1でもOK）
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* VLANなし最小（まず動かす用） */
SEC("xdp")
int xdp_arp_pass_xsk(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    __u16 h_proto = eth->h_proto;

    /* ARPはカーネルへ */
    if (h_proto == __constant_htons(ETH_P_ARP))
        return XDP_PASS;

    /* それ以外はAF_XDPへ */
    __u32 qid = ctx->rx_queue_index;

    /* エントリが無い/ソケット未登録ならPASS（とりあえず安全側） */
    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
