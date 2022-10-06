package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"runtime"
	"unsafe"

	"xdp_acl/internal/rule"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

func (x *xdp) doStoreRules(rules *rule.Rules, oldAction *ebpf.Map) error {
	var errg errgroup.Group

	errg.Go(func() error { return storePortRules(rules.SrcPortPriorities(), x.objs.SportV4) })
	errg.Go(func() error { return storePortRules(rules.DstPortPriorities(), x.objs.DportV4) })
	errg.Go(func() error { return storeAddrRules(rules.SrcCIDRPriorities(), x.objs.SrcV4) })
	errg.Go(func() error { return storeAddrRules(rules.DstCIDRPriorities(), x.objs.DstV4) })
	errg.Go(func() error { return storeProtocolRules(rules.ProtocolPriorities(), x.objs.ProtoV4) })
	errg.Go(func() error { return storeActions(rules.PriorityActions(), x.objs.RuleActionV4, oldAction) })

	err := errg.Wait()
	if err != nil {
		return fmt.Errorf("failed to store rules: %w", err)
	}

	return nil
}

func storePortRules(ports [][]uint32, m *ebpf.Map) error {
	for port, priorities := range ports {
		// ignore the missing-priorities ports
		if len(priorities) == 0 {
			continue
		}

		var b bitmap
		for _, prio := range priorities {
			b.Set(prio)
		}

		k := htons(uint16(port))
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

type actionKey struct {
	BitmapFFS    uint64 // the value of bit on uint64
	BitmapArrIdx uint64 // index of array
}

func getActionKey(priority uint32) actionKey {
	var key actionKey
	key.BitmapFFS = 1 << (priority & bitmapMask)
	key.BitmapArrIdx = uint64(priority) / bitmapSize
	return key
}

func (k actionKey) getPriority() uint64 {
	l := bits.LeadingZeros64(k.BitmapFFS)
	shift := bitmapMask - l
	return k.BitmapArrIdx*bitmapSize + uint64(shift)
}

type actionValue struct {
	Action uint64
	Count  uint64
}

var numCPU = runtime.NumCPU()

func getActionValue(strategy uint8, count uint64) []actionValue {
	val := make([]actionValue, numCPU)
	for i := range val {
		val[i].Action = uint64(strategy)
		val[i].Count = count
	}
	return val
}

// storeActions retrieves the old-hit-count-data from oldMap, and updates it to m.
func storeActions(actions map[uint32]uint8, m, oldMap *ebpf.Map) error {
	var counts map[uint32]uint64
	if oldMap != nil {
		var err error
		counts, err = retrieveHitCount(oldMap)
		if err != nil {
			zlog.Warnf("Failed to retrieve hit count while storing actions: %v", err)
		}
	} else {
		counts = make(map[uint32]uint64)
	}

	for priority, action := range actions {
		key, val := getActionKey(priority), getActionValue(action, counts[priority])
		if err := m.Put(key, val); err != nil {
			return fmt.Errorf("failed to update action of priority(%d) to bpf map: %w", priority, err)
		}
	}

	return nil
}

func retrieveHitCount(m *ebpf.Map) (map[uint32]uint64, error) {
	counts := make(map[uint32]uint64, 1024)

	sumOfVal := func(val []actionValue) uint64 {
		var sum uint64
		for _, val := range val {
			sum += val.Count
		}
		return sum
	}

	key, val := actionKey{}, make([]actionValue, numCPU)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		counts[uint32(key.getPriority())] = sumOfVal(val)
	}

	if err := iter.Err(); err != nil {
		return counts, fmt.Errorf("failed to retrieve hit count: %w", err)
	}

	return counts, nil
}
