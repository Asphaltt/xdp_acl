package main

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type xdp struct {
	devices []netlink.Link
	xdps    []link.Link

	bpfSpec *ebpf.CollectionSpec
	btfSpec *btf.Spec

	updatableObjs  *XDPACLObjects
	persistentObjs *XDPACLObjects

	attachFlags link.XDPAttachFlags

	debugMode       uint32
	bitmapArraySize uint32
}

func newXdp(flags *Flags, r *Rules) (*xdp, error) {
	var x xdp

	x.devices = make([]netlink.Link, 0, len(flags.Dev))
	for _, dev := range flags.Dev {
		l, err := netlink.LinkByName(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to get device from %s: %w", dev, err)
		}

		x.devices = append(x.devices, l)
	}

	b2u32 := func(b bool) uint32 {
		if b {
			return 1
		}
		return 0
	}

	x.debugMode = b2u32(flags.Debug)
	x.fixBitmapArraySize(len(r.rules))

	err := x.loadSpec()
	if err != nil {
		return nil, err
	}

	if flags.KernelBTF != "" {
		x.btfSpec, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		x.btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load BTF spec: %w", err)
	}

	x.attachFlags = getXDPAttachFlags(flags.Skb, flags.Native)

	x.updatableObjs = new(XDPACLObjects)
	x.persistentObjs = new(XDPACLObjects)

	if err := x.loadObj(x.persistentObjs, len(r.rules)); err != nil {
		return nil, fmt.Errorf("failed to load and assign objs: %w", err)
	}

	if err := x.persistentObjs.Progs.Put(uint32(0), x.persistentObjs.XdpAclFuncImm); err != nil {
		return nil, fmt.Errorf("failed to update progs bpf map: %w", err)
	}

	x.updatableObjs.SrcV4 = x.persistentObjs.SrcV4
	x.updatableObjs.DstV4 = x.persistentObjs.DstV4
	x.updatableObjs.SportV4 = x.persistentObjs.SportV4
	x.updatableObjs.DportV4 = x.persistentObjs.DportV4
	x.updatableObjs.ProtoV4 = x.persistentObjs.ProtoV4
	x.updatableObjs.RuleActionV4 = x.persistentObjs.RuleActionV4
	x.updatableObjs.XdpAclFuncImm = x.persistentObjs.XdpAclFuncImm
	x.persistentObjs.SrcV4 = nil
	x.persistentObjs.DstV4 = nil
	x.persistentObjs.SportV4 = nil
	x.persistentObjs.DportV4 = nil
	x.persistentObjs.ProtoV4 = nil
	x.persistentObjs.RuleActionV4 = nil
	x.persistentObjs.XdpAclFuncImm = nil

	if err := x.storeRules(r, map[uint32]uint64{}); err != nil {
		_ = x.Close()
		return nil, err
	}

	if err := x.attach(); err != nil {
		_ = x.Close()
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
	}

	return &x, nil
}

func (x *xdp) loadSpec() error {
	var err error
	x.bpfSpec, err = LoadXDPACL()
	if err != nil {
		return fmt.Errorf("failed to load bpf spec: %w", err)
	}

	// const bpfFlagValueSize = 1 << 13

	valueSize := x.bitmapArraySize << 3
	fixMaps := func(names ...string) {
		for _, name := range names {
			mapSpec := x.bpfSpec.Maps[name]
			// zlog.Debugf("old bpf spec of %s: %v, key btf: %v, value btf: %v", name, mapSpec, mapSpec.Key, mapSpec.Value)
			mapSpec.ValueSize = valueSize
			mapSpec.Value.(*btf.Array).Nelems = x.bitmapArraySize

			// zlog.Debugf("new bpf spec of %s: %v, key btf: %v, value btf: %v", name, mapSpec, mapSpec.Key, mapSpec.Value)

			mapSpec.BTF = nil // disable BTF for bpf map because of fault to change the valueSize

			// mapSpec.Flags |= bpfFlagValueSize
		}
	}
	fixMaps("src_v4", "dst_v4", "sport_v4", "dport_v4", "proto_v4")

	// mSpec := x.bpfSpec.Maps["src_v4"]
	// spew.Dump(mSpec.BTF)
	// spew.Dump(mSpec.Value)

	return nil
}

func (x *xdp) fixBitmapArraySize(ruleNum int) {
	x.bitmapArraySize = (uint32(ruleNum)>>6 + 1) << 3
}

func (x *xdp) loadObj(objs interface{}, ruleNum int) error {
	rc := map[string]interface{}{
		"XDPACL_DEBUG":                   x.debugMode,
		"XDPACL_BITMAP_ARRAY_SIZE_LIMIT": uint32(x.bitmapArraySize),
	}
	if err := x.bpfSpec.RewriteConstants(rc); err != nil {
		return fmt.Errorf("failed to rewrite constants: %v: %w", rc, err)
	}
	zlog.Infof("XDP rewrites constants: %v", rc)

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = x.btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 16

	if err := x.bpfSpec.LoadAndAssign(objs, &opts); err != nil {
		zlog.Warn("Failed to load bpf obj:")
		printVerifierError(err)
		return fmt.Errorf("failed to load bpf obj: %w", err)
	}

	return nil
}

func printVerifierError(err error) {
	zlog.Warnf("%T: %+v", err, err)

	u, ok := err.(interface {
		Unwrap() error
	})
	if ok {
		printVerifierError(u.Unwrap())
	}
}

func (x *xdp) storeRules(r *Rules, prevHitcount map[uint32]uint64) error {
	ts := time.Now()

	err := x.doStoreRules(r, prevHitcount)
	if err != nil {
		return err
	}

	// the rules' cache is useless
	r.ClearCache()

	zlog.Infof("🍉 name: storing %d rules. Cost: %s.", len(r.rules), time.Since(ts))

	return nil
}

func (x *xdp) attach() error {
	x.xdps = make([]link.Link, 0, len(x.devices))

	for _, l := range x.devices {
		xdp, err := link.AttachXDP(link.XDPOptions{
			Program:   x.persistentObjs.XdpAclFunc,
			Interface: l.Attrs().Index,
			Flags:     x.attachFlags,
		})
		if err != nil {
			return fmt.Errorf("failed to attach XDP to %s: %w", l.Attrs().Name, err)
		}

		x.xdps = append(x.xdps, xdp)
	}

	return nil
}

func (x *xdp) detach() {
	for _, l := range x.xdps {
		_ = l.Close()
	}
	x.xdps = nil
}

func (x *xdp) closeUpdatableObjs() {
	_ = x.updatableObjs.SrcV4.Close()
	_ = x.updatableObjs.DstV4.Close()
	_ = x.updatableObjs.SportV4.Close()
	_ = x.updatableObjs.DportV4.Close()
	_ = x.updatableObjs.ProtoV4.Close()
	_ = x.updatableObjs.RuleActionV4.Close()
	_ = x.updatableObjs.XdpAclFuncImm.Close()
	x.updatableObjs = nil
}

func (x *xdp) Close() error {
	x.detach()

	x.closeUpdatableObjs()

	_ = x.persistentObjs.Progs.Close()
	_ = x.persistentObjs.XdpAclFunc.Close()

	return nil
}

func (x *xdp) reload(r *Rules, prevHitcount map[uint32]uint64) error {
	ts := time.Now()

	if err := r.FixRules(); err != nil {
		return fmt.Errorf("failed to pre-handle rules: %w", err)
	}

	x.fixBitmapArraySize(len(r.rules))

	if err := x.loadSpec(); err != nil {
		return fmt.Errorf("failed to load bpf spec while reloading: %w", err)
	}

	o := x.updatableObjs
	x.updatableObjs = new(XDPACLObjects)

	if err := x.loadObj(x.updatableObjs, len(r.rules)); err != nil {
		return fmt.Errorf("failed to load xdp obj while reloading: %w", err)
	}

	_ = x.updatableObjs.Progs.Close()
	_ = x.updatableObjs.XdpAclFunc.Close()
	x.updatableObjs.Progs = nil
	x.updatableObjs.XdpAclFunc = nil

	if err := x.storeRules(r, prevHitcount); err != nil {
		x.closeUpdatableObjs()
		x.updatableObjs = o
		return fmt.Errorf("failed to store rules while reloading: %w", err)
	}

	if err := x.persistentObjs.Progs.Put(uint32(0), x.updatableObjs.XdpAclFuncImm); err != nil {
		x.closeUpdatableObjs()
		x.updatableObjs = o
		return fmt.Errorf("failed to update progs bpf map while reloading: %w", err)
	}

	_ = o.SrcV4.Close()
	_ = o.DstV4.Close()
	_ = o.SportV4.Close()
	_ = o.DportV4.Close()
	_ = o.ProtoV4.Close()
	_ = o.RuleActionV4.Close()
	_ = o.XdpAclFuncImm.Close()

	zlog.Infof("🍉 name: %s. Cost: %s.", "reloading rules", time.Since(ts))
	return nil
}

func getXDPAttachFlags(skbMode, nativeMode bool) link.XDPAttachFlags {
	var flag link.XDPAttachFlags
	if skbMode {
		flag = link.XDPGenericMode
	} else if nativeMode {
		flag = link.XDPDriverMode
	}
	return flag
}
