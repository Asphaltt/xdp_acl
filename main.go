package main

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang XDPACL ./ebpf/xdp_acl.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -nostdinc  -Wall -o3

var wgGlobal sync.WaitGroup

func xdpACLIinit() {
	// 日志初始化
	InitLogger()

	NumCPU = runtime.NumCPU()

	zlog.Info("cpu core nums: ", NumCPU)

	// 加载本地规则文件
	preOriginalRules()

	zlog.Info("ruleBuffer len: ", len(newOpsBuffer))

	// 初始化 webSignal
	webSignal = make(chan int)
}

func setResourceLimit() {
	if err := rlimit.RemoveMemlock(); err != nil {
		zlog.Error(err.Error() + "; Failed to adjust rlimit")
		panic(err)
	}
}

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
	// 解析命令行参数
	cmdLineInputParamsInit()

	xdpACLIinit()
	defer zlog.Sync()

	zlog.Info("dev: ", opt.dev)

	checkNetDevAndGenLink()

	setResourceLimit()

	fillXdpObjs()
	defer objs.Close()

	loadOriginalRules()

	loadXdpOnLink()
	defer unLoadAllXdpFromLink()

	go loadImmediateRules("loadImmediateRules")

	go webInit(&opt)

	zlog.Infof("🍉🍉 name: %s. Cost=%+v.", "app", time.Since(b))

	holdApp()
}
