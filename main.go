package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang XDPACL ./ebpf/xdp_acl.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -nostdinc  -Wall -o3

func main() {
	b := time.Now()

	flags := parseFlags()

	if err := rlimit.RemoveMemlock(); err != nil {
		zlog.Fatalf("Failed to remove memory lock: %v", err)
	}

	zlog.Info("dev: ", flags.Dev)
	if len(flags.Dev) == 0 {
		return
	}

	ts := time.Now()
	rules, err := LoadRules(flags.Conf, flags.LastRuleAccept, flags.LastRuleFixed)
	if err != nil {
		zlog.Errorf("Failed to load rules: %v", err)
		return
	}
	zlog.Infof("🍉 name: %s. Cost: %s.", "loading rules", time.Since(ts))

	xdp, err := newXdp(flags, rules)
	if err != nil {
		zlog.Fatalf("Failed to new xdp: %v", err)
	}

	defer xdp.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return runWebApp(ctx, flags, rules, xdp)
	})

	zlog.Infof("🍉🍉 name: %s. Cost: %s.", "app", time.Since(b))

	if err := errg.Wait(); err != nil {
		zlog.Errorf("Failed to run web server: %v", err)
	}
}
