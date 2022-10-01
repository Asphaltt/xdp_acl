#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define BITMAP_ARRAY_SIZE 160
/*
about BITMAP_ARRAY_SIZE
240 (15360) also ok; 288(18432; unroll 最大 36) is ok;
320 (20480) ok (需要全部展开)
必须是 8 的整数倍
*/

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

static volatile const __u32 XDPACL_DEBUG = 0;

#define bpf_debug_printk(fmt, ...)          \
    do {                                    \
        if (XDPACL_DEBUG)                   \
            bpf_printk(fmt, ##__VA_ARGS__); \
    } while (0)

// FIXED value
// #define ETH_HDR_SIZE 14
// #define IP_HDR_SIZE 20
// #define TCP_HDR_SIZE 20
// #define UDP_HDR_SIZE 8

// 支持的最多规则条数, 必须是 64 的整数倍; 比如: 64 * 16 == 1024
#define RULE_NUM_MAX_ENTRIES_V4 64 * BITMAP_ARRAY_SIZE

#define IP_MAX_ENTRIES_V4 RULE_NUM_MAX_ENTRIES_V4

// 支持的最多端口个数 1~65535; 65536 == 2^16
#define PORT_MAX_ENTRIES_V4 65536

// 支持的最多协议类型数 tcp udp icmp
#define PROTO_MAX_ENTRIES_V4 4

// 支持的规则数 编号
#define RULE_ACTION_MAX_ENTRIES_V4 RULE_NUM_MAX_ENTRIES_V4

#define LPM_PREFIXLEN_IPv4 32

struct lpm_key_ipv4 {
    __u32 prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
    __u8 data[4];    /* Arbitrary size */
} __attribute__((aligned(4)));

// v4 v6 可共用
__u64 bitmap[BITMAP_ARRAY_SIZE];

// v4 v6 可共用此结构体
struct rule_action {
    __u64 action;
    __u64 count;
};

// v4 v6 可共用此结构体
struct rule_action_key {
    __u64 bitmap_ffs;
    __u64 bitmap_array_index;
};

struct bpf_map_def SEC("maps") src_v4 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_key_ipv4), // 8 byte: mask len; 8 byte: host byte oreder
    .value_size = sizeof(bitmap),
    .max_entries = IP_MAX_ENTRIES_V4,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") sport_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16), // 2 byte; net byte oreder
    .value_size = sizeof(bitmap),
    .max_entries = PORT_MAX_ENTRIES_V4,
};

struct bpf_map_def SEC("maps") dst_v4 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_key_ipv4), // 8 byte: mask len; 8 byte; host byte oreder
    .value_size = sizeof(bitmap),
    .max_entries = IP_MAX_ENTRIES_V4,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dport_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16), // 2 byte; net byte oreder
    .value_size = sizeof(bitmap),
    .max_entries = PORT_MAX_ENTRIES_V4,
};

struct bpf_map_def SEC("maps") proto_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32), // 4 byte; host byte oreder
    .value_size = sizeof(bitmap),
    .max_entries = PROTO_MAX_ENTRIES_V4,
};

struct bpf_map_def SEC("maps") rule_action_v4 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct rule_action_key),
    .value_size = sizeof(struct rule_action),
    .max_entries = RULE_ACTION_MAX_ENTRIES_V4,
};

struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr_l2) {
    *ethhdr_l2 = nh->pos;

    //  Byte-count bounds check; check if current pointer + size of header is after data_end.
    if ((void *)((*ethhdr_l2) + 1) > data_end) {
        return -1;
    }

    nh->pos += sizeof(struct ethhdr);
    return (*ethhdr_l2)->h_proto; // network-byte-order
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr_l3) {
    *iphdr_l3 = nh->pos;

    if ((void *)((*iphdr_l3) + 1) > data_end) {
        return -1;
    }

    int hdrsize = ((*iphdr_l3)->ihl) << 2; // * 4

    // Sanity check packet field is valid
    if (hdrsize < sizeof(struct iphdr)) {
        return -1;
    }

    // Variable-length IPv4 header, need to use byte-based arithmetic
    nh->pos += hdrsize;
    if (nh->pos > data_end) {
        return -1;
    }

    return (*iphdr_l3)->protocol;
}

// parse and return the length of the tcp header
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct tcphdr **tcphdr_l4) {
    *tcphdr_l4 = nh->pos;

    if ((void *)((*tcphdr_l4) + 1) > data_end) {
        return -1;
    }

    int len = ((*tcphdr_l4)->doff) << 2; // * 4
    // Sanity check packet field is valid
    if (len < sizeof(struct tcphdr)) {
        return -1;
    }

    // Variable-length TCP header, need to use byte-based arithmetic
    nh->pos += len;
    if (nh->pos > data_end) {
        return -1;
    }

    return len;
}

// parse the udp header and return the length of the udp payload
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr_l4) {
    *udphdr_l4 = nh->pos;

    if ((void *)((*udphdr_l4) + 1) > data_end) {
        return -1;
    }

    nh->pos += sizeof(struct udphdr);

    int len = bpf_ntohs((*udphdr_l4)->len) - sizeof(struct udphdr);
    if (len < 0) {
        return -1;
    }

    return len;
}

static __always_inline void get_lpm_prefix_data_v4(__u32 addr, struct lpm_key_ipv4 *lpm_key_v4) {
    lpm_key_v4->data[0] = addr & 0xff; // bpf_ntohl(iphdr_l3->saddr);
    lpm_key_v4->data[1] = (addr >> 8) & 0xff;
    lpm_key_v4->data[2] = (addr >> 16) & 0xff;
    lpm_key_v4->data[3] = (addr >> 24) & 0xff;
}

static __always_inline void get_bitmap_array_for_tcp_v4(__u64 *rule_array[], __u32 *rule_array_len, int *proto_type, struct iphdr *iphdr_l3, struct tcphdr *tcphdr_l4) {
    struct lpm_key_ipv4 lpm_key_v4;
    __u64 *bitmap = NULL;

    // addr src
    lpm_key_v4.prefixlen = LPM_PREFIXLEN_IPv4;

    get_lpm_prefix_data_v4(iphdr_l3->saddr, &lpm_key_v4);

    bitmap = bpf_map_lookup_elem(&src_v4, &lpm_key_v4);

    if (NULL != bitmap) {
        bpf_debug_printk("hit addr src: %u\n", bpf_ntohl(iphdr_l3->saddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // addr dst
    get_lpm_prefix_data_v4(iphdr_l3->daddr, &lpm_key_v4);
    bitmap = bpf_map_lookup_elem(&dst_v4, &lpm_key_v4);
    if (NULL != bitmap) {
        bpf_debug_printk("hit addr dst: %u\n", bpf_ntohl(iphdr_l3->daddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // port src
    __u16 port = tcphdr_l4->source; // bpf_ntohs(tcphdr_l4->source);
    bitmap = bpf_map_lookup_elem(&sport_v4, &port);
    if (NULL != bitmap) {
        bpf_debug_printk("hit port srd: %u; bitmap[0]: %llu\n", bpf_ntohs(tcphdr_l4->source), bitmap[0]);
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // port dst bpf_ntohs(tcphdr_l4->dest);
    port = tcphdr_l4->dest;

    bpf_debug_printk("port dst h-order: %u; n-order: %u\n", bpf_ntohs(tcphdr_l4->dest), tcphdr_l4->dest);

    bitmap = bpf_map_lookup_elem(&dport_v4, &port);
    if (NULL != bitmap) {
        bpf_debug_printk("hit port dst: %u; bitmap[7]: %llu\n", bpf_ntohs(tcphdr_l4->dest), bitmap[7]);
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // proto
    bitmap = bpf_map_lookup_elem(&proto_v4, proto_type);
    if (NULL != bitmap) {
        bpf_debug_printk("hit tcp\n");
        rule_array[(*rule_array_len)++] = bitmap;
    }
}

static __always_inline void get_bitmap_array_for_udp_v4(__u64 *rule_array[], __u32 *rule_array_len, int *proto_type, struct iphdr *iphdr_l3, struct udphdr *udphdr_l4) {
    struct lpm_key_ipv4 lpm_key_v4;
    __u64 *bitmap;

    // addr src
    lpm_key_v4.prefixlen = LPM_PREFIXLEN_IPv4;

    get_lpm_prefix_data_v4(iphdr_l3->saddr, &lpm_key_v4);
    bitmap = bpf_map_lookup_elem(&src_v4, &lpm_key_v4);
    if (NULL != bitmap) {
        bpf_debug_printk("hit addr src: %u\n", bpf_ntohl(iphdr_l3->saddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // addr dst
    get_lpm_prefix_data_v4(iphdr_l3->daddr, &lpm_key_v4);
    bitmap = bpf_map_lookup_elem(&dst_v4, &lpm_key_v4);
    if (NULL != bitmap) {
        bpf_debug_printk("hit addr dst: %u\n", bpf_ntohl(iphdr_l3->daddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // port src
    __u16 port = udphdr_l4->source; // bpf_ntohs(udphdr_l4->source);
    bitmap = bpf_map_lookup_elem(&sport_v4, &port);
    if (NULL != bitmap) {
        bpf_debug_printk("hit port src: %u\n", bpf_ntohl(udphdr_l4->source));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // port dst
    port = udphdr_l4->dest; // bpf_ntohs(udphdr_l4->dest);
    bitmap = bpf_map_lookup_elem(&dport_v4, &port);
    if (NULL != bitmap) {
        bpf_debug_printk("hit port dst: %u\n", bpf_ntohs(udphdr_l4->dest));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // proto
    bitmap = bpf_map_lookup_elem(&proto_v4, proto_type);
    if (NULL != bitmap) {
        bpf_debug_printk("hit udp\n");
        rule_array[(*rule_array_len)++] = bitmap;
    }
}

static __always_inline void get_bitmap_array_for_icmp_v4(__u64 *rule_array[], __u32 *rule_array_len, int *proto_type, struct iphdr *iphdr_l3) {
    struct lpm_key_ipv4 lpm_key_v4;
    __u64 *bitmap;

    // addr src
    lpm_key_v4.prefixlen = LPM_PREFIXLEN_IPv4;

    get_lpm_prefix_data_v4(iphdr_l3->saddr, &lpm_key_v4);
    bitmap = bpf_map_lookup_elem(&src_v4, &lpm_key_v4);
    if (NULL != bitmap) {
        bpf_debug_printk("hit addr src: %u\n", bpf_ntohl(iphdr_l3->saddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // addr dst
    get_lpm_prefix_data_v4(iphdr_l3->daddr, &lpm_key_v4);
    bitmap = bpf_map_lookup_elem(&dst_v4, &lpm_key_v4);
    if (NULL != bitmap) {
        bpf_debug_printk("hit addr dst: %u\n", bpf_ntohl(iphdr_l3->daddr));
        rule_array[(*rule_array_len)++] = bitmap;
    }

    // proto
    bitmap = bpf_map_lookup_elem(&proto_v4, proto_type);
    if (NULL != bitmap) {
        bpf_debug_printk("hit icmp\n");
        rule_array[(*rule_array_len)++] = bitmap;
    }
}

static __always_inline void get_hit_rules_optimize(__u64 *rule_array[], __u32 *rule_array_len_ptr, __u64 *rule_array_index_ptr, __u64 *hit_rules_ptr) {
#define index_rule(idx) (rule_array[idx][*rule_array_index_ptr])
#define bit_and_5() (index_rule(0) & index_rule(1) & index_rule(2) & index_rule(3) & index_rule(4))
#define bit_and_3() (index_rule(0) & index_rule(1) & index_rule(2))
#define hit_rule(fn)            \
    do {                        \
        *hit_rules_ptr = fn();  \
        if (*hit_rules_ptr > 0) \
            return;             \
    } while (0)
#define inc_then_hit_rule(fn)  \
    (*rule_array_index_ptr)++; \
    hit_rule(fn)

    if (5 == *rule_array_len_ptr) {
        // 5

        hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);
        inc_then_hit_rule(bit_and_5);

    } else {
        // 3

        hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
        inc_then_hit_rule(bit_and_3);
    }

#undef inc_then_hit_rule
#undef hit_rule
#undef bit_and_5
#undef bit_and_3
#undef index_rule

    return;
}

static __always_inline int get_rule_action_v4(__u64 *rule_array[], __u32 *rule_array_len_ptr) {
    /*
    三种特殊情况:
      未匹配到规则:
        1 *rule_array_len == 0 => (bitmap[0] == 0); 或者 *rule_array_len == 1 2 4 返回 XDP_PASS;
        2 *rule_array_len != 0; 但 bitmap 按位与时，都为 0 => (bitmap[BITMAP_ARRAY_SIZE - 1] == 0); 返回 XDP_PASS

      匹配到规则:
        3 未找到 action
    */

    struct rule_action_key key;
    struct rule_action *value;

    if (unlikely(3 != *rule_array_len_ptr && 5 != *rule_array_len_ptr)) {
        // 特殊情况 1

        bpf_debug_printk("result => rule action: specified 1\n");

        return XDP_PASS;
    }

    __u64 rule_array_index ____cacheline_aligned = 0;
    __u64 hit_rules ____cacheline_aligned = 0;

    __u64 rule_array_outer_index ____cacheline_aligned = 0;
#pragma unroll
    for (; rule_array_outer_index < BITMAP_ARRAY_SIZE; rule_array_outer_index += 8) {
        get_hit_rules_optimize(rule_array, rule_array_len_ptr, &rule_array_index, &hit_rules);
        if (hit_rules > 0) {
            break;
        }
        rule_array_index++;
    }

    bpf_debug_printk("result => rule_array.size = %lu; rule_array_index: %llu; hit_rules: %llu;\n",
                     *rule_array_len_ptr, rule_array_index, hit_rules);

    if (rule_array_index >= BITMAP_ARRAY_SIZE) {
        // 特殊情况 2
        bpf_debug_printk("result => hit bitmap[%d]: %llu; specified 2;\n", rule_array_index, hit_rules);
        return XDP_PASS;
    }

    key.bitmap_ffs = hit_rules & (-hit_rules);
    key.bitmap_array_index = rule_array_index;

    value = bpf_map_lookup_elem(&rule_action_v4, &key);
    if (NULL != value) {
        bpf_debug_printk("result => hit bitmap[%d]: %llu; ffs: %llu; normal\n",
                         rule_array_index, hit_rules, key.bitmap_ffs);
        bpf_debug_printk("hit bitmap[%d]: ffs: %llu; action: %d\n", key.bitmap_ffs, value->action);
        (value->count)++;
        return value->action;
    }

    // 特殊情况 3，现在默认为 XDP_PASS
    bpf_debug_printk("result => hit bitmap[%d]: %llu; ffs: %llu; rule action: specified 3;\n", rule_array_index, hit_rules, key.bitmap_ffs);

    return XDP_PASS;
}

SEC("xdp_acl")
int xdp_acl_func(struct xdp_md *ctx) {
    bpf_debug_printk("\n\nreceive new frame, ingress_ifindex: %u; rx_queue_index: %u\n",
                     ctx->ingress_ifindex, ctx->rx_queue_index);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor nh = {.pos = data};
    int proto_type;
    struct ethhdr *ethhdr_l2;

    proto_type = parse_ethhdr(&nh, data_end, &ethhdr_l2);

    if (bpf_htons(ETH_P_IP) == proto_type) {
        // IPv4
        __u64 *rule_array[5];
        __u32 rule_array_len = 0;

        struct iphdr *iphdr_l3;
        proto_type = parse_iphdr(&nh, data_end, &iphdr_l3);
        if (likely(IPPROTO_TCP == proto_type)) {
            bpf_debug_printk("receive TCP pkt\n");
            struct tcphdr *tcphdr_l4;
            if (parse_tcphdr(&nh, data_end, &tcphdr_l4) < 0) {
                bpf_debug_printk("\ndrop TCP pkt\n");
                return XDP_DROP;
            }

            get_bitmap_array_for_tcp_v4(rule_array, &rule_array_len, &proto_type, iphdr_l3, tcphdr_l4);
        } else if (IPPROTO_UDP == proto_type) {
            bpf_debug_printk("receive UDP pkt\n");

            struct udphdr *udphdr_l4;
            if (parse_udphdr(&nh, data_end, &udphdr_l4) < 0) {
                return XDP_DROP;
            }

            get_bitmap_array_for_udp_v4(rule_array, &rule_array_len, &proto_type, iphdr_l3, udphdr_l4);
        } else if (IPPROTO_ICMP == proto_type) {
            bpf_debug_printk("receive ICMP pkt\n");
            get_bitmap_array_for_icmp_v4(rule_array, &rule_array_len, &proto_type, iphdr_l3);
        } else {
            // IPPROTO_GRE IPPROTO_OSPF...
            bpf_debug_printk("\n\nreceive Unknown IP pkt\n");
            return XDP_PASS;
        }

        return get_rule_action_v4(rule_array, &rule_array_len);
    } else if (proto_type > 0) {
        bpf_debug_printk("\nreceive Not IP frame\n");
        // contain ETH_P_IPV6 ETH_P_ARP
        return XDP_PASS;
    } else {
        bpf_debug_printk("\ndrop eth frame\n");
        return XDP_DROP;
    }
}

char _license[] SEC("license") = "GPL";
