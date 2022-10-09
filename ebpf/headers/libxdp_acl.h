#ifndef __LIBXDP_ACL_H_
#define __LIBXDP_ACL_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "libxdp_map.h"

static volatile const __u32 XDPACL_BITMAP_ARRAY_SIZE_LIMIT = BITMAP_ARRAY_SIZE;

static volatile const __u32 XDPACL_DEBUG = 0;

#define bpf_debug_printk(fmt, ...)          \
    do {                                    \
        if (XDPACL_DEBUG)                   \
            bpf_printk(fmt, ##__VA_ARGS__); \
    } while (0)

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

// cacheline alignment
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

// likely optimization
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static __always_inline void get_hit_rules_optimize(__u64 *rule_array[], __u32 rules_num, __u64 *arr_index, __u64 *hit_rules) {
#define index_rule(idx) (rule_array[idx][(*arr_index)])
#define bit_and_5() (index_rule(0) & index_rule(1) & index_rule(2) & index_rule(3) & index_rule(4))
#define bit_and_3() (index_rule(0) & index_rule(1) & index_rule(2))
#define hit_rule_5()              \
    do {                          \
        *hit_rules = bit_and_5(); \
        if (*hit_rules > 0)       \
            return;               \
    } while (0)
#define hit_rule_3()              \
    do {                          \
        *hit_rules = bit_and_3(); \
        if (*hit_rules > 0)       \
            return;               \
    } while (0)
#define inc_then_hit_rule_5() \
    (*arr_index)++;           \
    hit_rule_5()
#define inc_then_hit_rule_3() \
    (*arr_index)++;           \
    hit_rule_3()

    if (5 == rules_num) {
        // 5

        hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();
        inc_then_hit_rule_5();

    } else {
        // 3

        hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
        inc_then_hit_rule_3();
    }

#undef inc_then_hit_rule
#undef hit_rule
#undef bit_and_5
#undef bit_and_3
#undef index_rule

    return;
}

static __always_inline __u32
get_priority(__u64 bit, __u64 index) {
    __u64 shift = 0;
    if (bit >= ((__u64)1 << 32)) {
        bit >>= 32;
        shift += 32;
    }
    if (bit >= (1 << 16)) {
        bit >>= 16;
        shift += 16;
    }
    if (bit >= (1 << 8)) {
        bit >>= 8;
        shift += 8;
    }
    if (bit >= (1 << 4)) {
        bit >>= 4;
        shift += 4;
    }
    if (bit >= (1 << 2)) {
        bit >>= 2;
        shift += 2;
    }
    if (bit == 1) {
        shift++;
    } else if (bit == 2) {
        shift += 2;
    }

    return (__u32)((index << 6) + shift) - 1; // get the index of the '1' bit in bitmap
}

static __always_inline int get_rule_action_v4(__u64 *rule_array[], __u32 rules_num) {
    /*
    三种特殊情况:
      未匹配到规则:
        1 *rule_array_len == 0 => (bitmap[0] == 0); 或者 *rule_array_len == 1 2 4 返回 XDP_PASS;
        2 *rule_array_len != 0; 但 bitmap 按位与时，都为 0 => (bitmap[BITMAP_ARRAY_SIZE - 1] == 0); 返回 XDP_PASS

      匹配到规则:
        3 未找到 action
    */

    if (unlikely(3 != rules_num && 5 != rules_num)) {
        // 特殊情况 1
        return XDP_PASS;
    }

    __u64 rule_array_index ____cacheline_aligned = 0;
    __u64 hit_rules ____cacheline_aligned = 0;

    __u64 rule_array_outer_index ____cacheline_aligned = 0;
#pragma unroll
    for (; rule_array_outer_index < BITMAP_ARRAY_SIZE; rule_array_outer_index += 8) {
        get_hit_rules_optimize(rule_array, rules_num, &rule_array_index, &hit_rules);
        if (hit_rules > 0) {
            break;
        }
        rule_array_index++;
    }

    if (rule_array_index >= XDPACL_BITMAP_ARRAY_SIZE_LIMIT) {
        // 特殊情况 2
        return XDP_PASS;
    }

    hit_rules = hit_rules & (-hit_rules); // get the very first '1' bit
    __u32 key = get_priority(hit_rules, rule_array_index);

    bpf_debug_printk("xdpacl, get rule, hit_rules: 0x%x, array index: %d, key: %d\n", hit_rules, rule_array_index, key);

    struct rule_action *value;
    value = (typeof(value))bpf_map_lookup_elem(&rule_action_v4, &key);
    if (NULL != value) {
        __sync_fetch_and_add(&value->count, 1);
        return value->action;
    }

    // 特殊情况 3，现在默认为 XDP_PASS

    return XDP_PASS;
}

static __always_inline int
xdp_acl_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 *rule_arr[5];
    __u32 rules_num = 0;

    struct lpm_key_ipv4 key = {};
    key.prefixlen = LPM_PREFIXLEN_IPv4;

    __u64 *bitmap;

#define lookup_map(map, key)                                      \
    do {                                                          \
        bitmap = (typeof(bitmap))bpf_map_lookup_elem(&map, &key); \
        if (NULL != bitmap)                                       \
            rule_arr[rules_num++] = bitmap;                       \
    } while (0)

    struct iphdr *iph;
    iph = (typeof(iph))(data + sizeof(struct ethhdr));

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 l4_proto = iph->protocol;
    bool is_tcp_udp = (IPPROTO_TCP == l4_proto || IPPROTO_UDP == l4_proto);
    bool is_icmp = (IPPROTO_ICMP == l4_proto);

    if (is_tcp_udp) {
        struct udphdr *udph;
        udph = (typeof(udph))((void *)iph + iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        bpf_debug_printk("TCP or UDP packet, dport: %d\n", bpf_ntohs(udph->dest));

        key.data = iph->saddr;
        lookup_map(src_v4, key);

        key.data = iph->daddr;
        lookup_map(dst_v4, key);

        __u16 port = udph->source;
        lookup_map(sport_v4, port);

        port = udph->dest;
        lookup_map(dport_v4, port);

    } else if (is_icmp) {
        bpf_debug_printk("ICMP packet\n");

        key.data = iph->saddr;
        lookup_map(src_v4, key);

        key.data = iph->daddr;
        lookup_map(dst_v4, key);

    } else {
        return XDP_PASS;
    }

    lookup_map(proto_v4, l4_proto);

#undef lookup_map

    return get_rule_action_v4(rule_arr, rules_num);
}

#endif // __LIBXDP_ACL_H_