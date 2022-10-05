package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"xdp_acl/internal/rule"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

func storeRules(rules *rule.Rules, objs *XDPACLObjects) error {
	var errg errgroup.Group

	errg.Go(func() error { return storePortRules(rules.SrcPortPriorities(), objs.SportV4) })
	errg.Go(func() error { return storePortRules(rules.DstPortPriorities(), objs.DportV4) })
	errg.Go(func() error { return storeAddrRules(rules.SrcCIDRPriorities(), objs.SrcV4) })
	errg.Go(func() error { return storeAddrRules(rules.DstCIDRPriorities(), objs.DstV4) })
	errg.Go(func() error { return storeProtocolRules(rules.ProtocolPriorities(), objs.ProtoV4) })
	errg.Go(func() error { return storeActions(rules.PriorityActions(), objs.RuleActionV4) })

	err := errg.Wait()
	if err != nil {
		return fmt.Errorf("failed to store rules: %w", err)
	}

	return nil
}

func storePortRules(ports map[uint16][]uint32, m *ebpf.Map) error {
	for port, priorities := range ports {
		var b bitmap
		for _, prio := range priorities {
			b.Set(prio)
		}

		k := htons(port)
		if err := m.Put(k, b); err != nil {
			return fmt.Errorf("failed to update rules of port(%d) to bpf map: %w", port, err)
		}
	}

	return nil
}

func htons(n uint16) uint16 {
	b := *(*[2]uint8)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func storeAddrRules(addrs map[netip.Prefix][]uint32, m *ebpf.Map) error {
	type lpmKey struct {
		Prefix uint32
		Addr   [4]uint8
	}

	for cidr, priorities := range addrs {
		var b bitmap
		for _, prio := range priorities {
			b.Set(prio)
		}

		var k lpmKey
		k.Prefix = uint32(cidr.Bits())
		k.Addr = cidr.Addr().As4() // network order

		if err := m.Put(k, b); err != nil {
			return fmt.Errorf("failed to update rules of CIDR(%s) to bpf map: %w", cidr, err)
		}
	}

	return nil
}

func storeProtocolRules(protos map[uint32][]uint32, m *ebpf.Map) error {
	for proto, priorities := range protos {
		var b bitmap
		for _, prio := range priorities {
			b.Set(prio)
		}

		if err := m.Put(proto, b); err != nil {
			return fmt.Errorf("failed to update rules of protocol(%d) to bpf map: %w", proto, err)
		}
	}

	return nil
}

func storeActions(actions map[uint32]uint8, m *ebpf.Map) error {
	type actionKey struct {
		BitmapFFS    uint64 // the value of bit on uint64
		BitmapArrIdx uint64 // index of array
	}
	getActionKey := func(priority uint32) actionKey {
		var key actionKey
		key.BitmapFFS = 1 << (priority & bitmapMask)
		key.BitmapArrIdx = uint64(priority) / bitmapSize
		return key
	}

	type actionValue struct {
		Action uint64
		Count  uint64
	}
	numCPU := runtime.NumCPU()
	getActionValue := func(strategy uint8) []actionValue {
		val := make([]actionValue, numCPU)
		for i := range val {
			val[i].Action = uint64(strategy)
		}
		return val
	}

	for priority, action := range actions {
		key, val := getActionKey(priority), getActionValue(action)
		if err := m.Put(key, val); err != nil {
			return fmt.Errorf("failed to update action of priority(%d) to bpf map: %w", priority, err)
		}
	}

	return nil
}
