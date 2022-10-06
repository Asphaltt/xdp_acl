package main

import (
	"fmt"
	"sync"
	"time"

	"xdp_acl/internal/flag"
	"xdp_acl/internal/rule"

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

	objsMu sync.Mutex
	objs   *XDPACLObjects

	attachFlags link.XDPAttachFlags
}

func newXdp(flags *flag.Flags, r *rule.Rules) (*xdp, error) {
	var x xdp

	x.devices = make([]netlink.Link, 0, len(flags.Dev))
	for _, dev := range flags.Dev {
		l, err := netlink.LinkByName(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to get device from %s: %w", dev, err)
		}

		x.devices = append(x.devices, l)
	}

	var err error
	x.bpfSpec, err = LoadXDPACL()
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf spec: %w", err)
	}

	rc := map[string]interface{}{
		"XDPACL_DEBUG": b2u32(flags.Debug),
	}
	if err := x.bpfSpec.RewriteConstants(rc); err != nil {
		return nil, fmt.Errorf("failed to rewrite constants: %v: %w", rc, err)
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

	if err := x.loadObj(); err != nil {
		return nil, fmt.Errorf("failed to load xdp obj: %w", err)
	}

	if err := x.storeRules(r, nil); err != nil {
		_ = x.Close()
		return nil, fmt.Errorf("failed to store rules: %w", err)
	}

	if err := x.attach(); err != nil {
		_ = x.Close()
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
	}

	return &x, nil
}

func b2u32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func (x *xdp) loadObj() error {
	x.objs = new(XDPACLObjects)

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = x.btfSpec

	if err := x.bpfSpec.LoadAndAssign(x.objs, &opts); err != nil {
		return fmt.Errorf("failed to load and assign objs: %w", err)
	}

	return nil
}

func (x *xdp) storeRules(r *rule.Rules, oldAction *ebpf.Map) error {
	ts := time.Now()

	err := x.doStoreRules(r, oldAction)
	if err != nil {
		return fmt.Errorf("failed to store rules: %w", err)
	}

	// the rules' cache is useless
	r.ClearCache()

	zlog.Infof("🍉 name: %s. Cost: %s.", "storing rules", time.Since(ts))

	return nil
}

func (x *xdp) attach() error {
	x.xdps = make([]link.Link, 0, len(x.devices))

	for _, l := range x.devices {
		xdp, err := link.AttachXDP(link.XDPOptions{
			Program:   x.objs.XdpAclFunc,
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

func (x *xdp) Close() error {
	for _, l := range x.xdps {
		_ = l.Close()
	}
	x.xdps = nil

	_ = x.objs.Close()
	x.objs = nil

	return nil
}

func (x *xdp) reload(r *rule.Rules) error {
	ts := time.Now()

	x.objsMu.Lock()
	defer x.objsMu.Unlock()

	x.detach()
	o := x.objs

	r.FixRules()

	if err := x.loadObj(); err != nil {
		return fmt.Errorf("failed to load xdp obj while reloading: %w", err)
	}

	if err := x.storeRules(r, o.RuleActionV4); err != nil {
		return fmt.Errorf("failed to store rules while reloading: %w", err)
	}

	if err := x.attach(); err != nil {
		return fmt.Errorf("failed to attach XDP while reloading: %w", err)
	}

	_ = o.SrcV4.Close()
	_ = o.DstV4.Close()
	_ = o.SportV4.Close()
	_ = o.DportV4.Close()
	_ = o.ProtoV4.Close()
	_ = o.RuleActionV4.Close()
	_ = o.XdpAclFunc.Close()

	zlog.Infof("🍉 name: %s. Cost: %s.", "reloading rules", time.Since(ts))
	return nil
}

// getObjs protects objs while reloading rules
func (x *xdp) getObjs() *XDPACLObjects {
	x.objsMu.Lock()
	defer x.objsMu.Unlock()
	return x.objs
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
