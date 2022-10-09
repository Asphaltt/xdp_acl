
#include "bpf_endian.h"

#include "libxdp_acl.h"

SEC("xdp_acl")
int xdp_acl_func_imm(struct xdp_md *ctx) {
    return xdp_acl_ipv4(ctx);
}

SEC("xdp_acl")
int xdp_acl_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    eth = (typeof(eth))data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 l3_proto = eth->h_proto;

    if (bpf_htons(ETH_P_IP) == l3_proto) {
        bpf_tail_call_static(ctx, &progs, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
