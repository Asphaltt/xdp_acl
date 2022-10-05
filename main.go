package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"xdp_acl/internal/flag"
	"xdp_acl/internal/rule"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang XDPACL ./ebpf/xdp_acl.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -nostdinc  -Wall -o3

var wgGlobal sync.WaitGroup

func holdApp() {
	quitSignalChan := make(chan os.Signal, 1)
	signal.Notify(quitSignalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	zlog.Info("XDP program successfully loaded and attached.")
	zlog.Info("Press CTRL+C to stop.")

	for range quitSignalChan {
		// close quitSignalChan
		close(quitSignalChan)

		webSignal <- 1

		// close newOpsBuffer
		close(newOpsBuffer)

		wgGlobal.Wait()

		zlog.Info("stop acl app")
	}
}

func main() {
	b := time.Now()

	flags := flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		zlog.Fatalf("Failed to remove memory lock: %v", err)
	}

	zlog.Info("dev: ", flags.Dev)
	if len(flags.Dev) == 0 {
		return
	}

	links := make([]netlink.Link, 0, len(flags.Dev))
	for _, dev := range flags.Dev {
		l, err := netlink.LinkByName(dev)
		if err != nil {
			zlog.Fatalf("Failed to get device from %s: %v", dev, err)
		}

		links = append(links, l)
	}

	spec, err := LoadXDPACL()
	if err != nil {
		zlog.Fatalf("Failed to load spec: %v", err)
	}

	rc := map[string]interface{}{
		"XDPACL_DEBUG": b2u32(flags.Debug),
	}
	if err := spec.RewriteConstants(rc); err != nil {
		zlog.Fatalf("Failed to rewrite constants: %v: %v", rc, err)
	}

	var btfSpec *btf.Spec
	if flags.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		zlog.Fatalf("Failed to load BTF spec: %v", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec

	var objs XDPACLObjects
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		zlog.Fatalf("Failed to load and assign objs: %v", err)
	}
	defer objs.Close()

	ts := time.Now()
	rules, err := rule.LoadRules(flags)
	if err != nil {
		zlog.Errorf("Failed to load rules: %v", err)
		return
	}
	zlog.Infof("🍉 name: %s. Cost: %s.", "loading rules", time.Since(ts))

	ts = time.Now()
	err = storeRules(rules, &objs)
	if err != nil {
		zlog.Errorf("Failed to store rules: %v", err)
		return
	}
	zlog.Infof("🍉 name: %s. Cost: %s.", "storing rules", time.Since(ts))

	xdpAttachFlags := getXDPAttachFlags(flags)
	for _, l := range links {
		xdp, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpAclFunc,
			Interface: l.Attrs().Index,
			Flags:     xdpAttachFlags,
		})
		if err != nil {
			zlog.Errorf("Failed to attach XDP to %s: %v", l.Attrs().Name, err)
			return
		}

		defer xdp.Close()
	}

	go loadImmediateRules("loadImmediateRules")

	go webInit(&opt)

	zlog.Infof("🍉🍉 name: %s. Cost: %s.", "app", time.Since(b))

	holdApp()
}

func b2u32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func getXDPAttachFlags(flags *flag.Flags) link.XDPAttachFlags {
	var flag link.XDPAttachFlags
	if flags.Skb {
		flag = link.XDPGenericMode
	} else if flags.Native {
		flag = link.XDPDriverMode
	}
	return flag
}
