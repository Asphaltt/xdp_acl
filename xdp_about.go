package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/vishvananda/netlink"
)

const (
	XDP_DROP = 1
	XDP_PASS = 2

	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0

	// XDP_FLAGS_AUTO_MODE int = 0 // custom
	XDP_FLAGS_SKB_MODE int = 1 << 1
	XDP_FLAGS_DRV_MODE int = 1 << 2
	XDP_FLAGS_HW_MODE  int = 1 << 3
	XDP_FLAGS_REPLACE  int = 1 << 4

	XDP_FLAGS_MODES = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE
	XDP_FLAGS_MASK  = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE
)

var (
	NumCPU            int  = 0
	XDP_FLAGS         int  = 0
	LOAD_XDP_WITH_ELF bool = false
	objs              XDPACLObjects
	linkArr           []netlink.Link
)

type LpmKeyV4 struct {
	mask uint32   /* up to 32 for AF_INET, 128 for AF_INET6 */
	data [4]uint8 /* Arbitrary size */
}

type PortMapKey uint16

type ProtoMapKey uint32

type RuleActionKey struct {
	BitmapFFS      uint64
	BitmapArrayInx uint64
}

type RuleAction struct {
	Action uint64
	Count  uint64
}

func checkNetDevAndGenLink() {
	linkArr = make([]netlink.Link, 0)
	for i := 0; i < len(opt.dev); i++ {
		link, err := netlink.LinkByName(opt.dev[i])
		if err != nil {
			zlog.Error(err.Error(), "; Please check your input device name: 「", opt.dev[i], "」 is right.")
			panic(err)
		}
		linkArr = append(linkArr, link)
	}
}

func unloadXDP(link netlink.Link) {
	netlink.LinkSetXdpFdWithFlags(link, -1, XDP_FLAGS)
}

func unLoadAllXdpFromLink() {
	for i := 0; i < len(linkArr); i++ {
		unloadXDP(linkArr[i])
	}
}

func fillXdpObjs() {
	var spec *ebpf.CollectionSpec
	var err error
	if !LOAD_XDP_WITH_ELF {
		// bpf2go
		spec, err = LoadXDPACL()
	} else {
		// load elf file
		spec, err = ebpf.LoadCollectionSpec("./xdpacl_bpfel.o")
	}

	if err != nil {
		zlog.Fatalf("Failed to load spec: %v", err)
	}

	b2u32 := func(b bool) uint32 {
		if b {
			return 1
		}
		return 0
	}

	rw := map[string]interface{}{
		"XDPACL_DEBUG": b2u32(opt.debug),
	}
	if err := spec.RewriteConstants(rw); err != nil {
		zlog.Fatalf("Failed to rewrite constants: %v: %v", rw, err)
	}

	var btfSpec *btf.Spec
	if opt.kernelBTF != "" {
		btfSpec, err = btf.LoadSpec(opt.kernelBTF)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		zlog.Fatalf("Failed to load BTF spec: %v", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		zlog.Fatalf("Failed to load and assign objs: %v", err)
	}
}

func loadXdpOnLink() {
	for i := 0; i < len(linkArr); i++ {
		err := netlink.LinkSetXdpFdWithFlags(linkArr[i], objs.XdpAclFunc.FD(), XDP_FLAGS)
		if err != nil {
			zlog.Errorf("%s; Failed to load xdp on %d mode", err.Error(), XDP_FLAGS)
			panic(err)
		}
	}
}
