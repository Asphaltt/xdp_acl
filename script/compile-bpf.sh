#!/bin/bash

set -e

CUR_DIR=$(cd $(dirname $0) || exit 1; pwd -P)
BPFFILE="${CUR_DIR}/../ebpf/headers/libxdp_generated.h"

build_bpf() {
    num="$1"
    cat >${BPFFILE} <<EOF
#ifndef __LIBXDP_GENERATED_H_
#define __LIBXDP_GENERATED_H_

#define BITMAP_ARRAY_SIZE ${num}

#endif // __LIBXDP_GENERATED_H_
EOF

    go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang "XDPACL${num}" ./ebpf/xdp_acl.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -nostdinc  -Wall -o3
}

main() {
    for x in {8,16,32,64,128,160,256}; do
        build_bpf $x
    done
}

main
