#ifndef __LIBXDP_MAP_H_
#define __LIBXDP_MAP_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#define BITMAP_ARRAY_SIZE 160

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
    __u32 data;      /* network order */
} __attribute__((aligned(4)));

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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_ipv4);
    __type(value, bitmap);
    __uint(max_entries, IP_MAX_ENTRIES_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, bitmap);
    __uint(max_entries, PORT_MAX_ENTRIES_V4);
} sport_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_ipv4);
    __type(value, bitmap);
    __uint(max_entries, IP_MAX_ENTRIES_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, bitmap);
    __uint(max_entries, PORT_MAX_ENTRIES_V4);
} dport_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, bitmap);
    __uint(max_entries, PROTO_MAX_ENTRIES_V4);
} proto_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_action);
    __uint(max_entries, RULE_ACTION_MAX_ENTRIES_V4);
} rule_action_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} progs SEC(".maps");

#endif // __LIBXDP_MAP_H_