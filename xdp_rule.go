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

func (x *xdp) doStoreRules(rules *rule.Rules, prevHitcount map[uint32]uint64) error {
	var errg errgroup.Group

	errg.Go(func() error {
		return storePortRules(rules.SrcPortPriorities(), x.updatableObjs.SportV4, rules.BitmapArraySize)
	})
	errg.Go(func() error {
		return storePortRules(rules.DstPortPriorities(), x.updatableObjs.DportV4, rules.BitmapArraySize)
	})
	errg.Go(func() error {
		return storeAddrRules(rules.SrcCIDRPriorities(), x.updatableObjs.SrcV4, rules.BitmapArraySize)
	})
	errg.Go(func() error {
		return storeAddrRules(rules.DstCIDRPriorities(), x.updatableObjs.DstV4, rules.BitmapArraySize)
	})
	errg.Go(func() error {
		return storeProtocolRules(rules.ProtocolPriorities(), x.updatableObjs.ProtoV4, rules.BitmapArraySize)
	})
	errg.Go(func() error {
		return storeActions(rules.PriorityActions(), rules, x.updatableObjs.RuleActionV4, prevHitcount)
	})

	err := errg.Wait()
	if err != nil {
		return fmt.Errorf("failed to store rules: %w", err)
	}

	return nil
}

func storePortRules(ports [][]uint32, m *ebpf.Map, bitmapArraySize int) error {
	for port, priorities := range ports {
		// ignore the missing-priorities ports
		if len(priorities) == 0 {
			continue
		}

		b := newBitmap(bitmapArraySize)
		for _, prio := range priorities {
			b.Set(prio)
		}

		k := htons(uint16(port))
		v, _ := b.MarshalBinary()
		if err := m.Put(k, v); err != nil {
			return fmt.Errorf("failed to update rules of port(%d) to bpf map: %w", port, err)
		}
	}

	return nil
}

func htons(n uint16) uint16 {
	b := *(*[2]uint8)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func storeAddrRules(addrs map[netip.Prefix][]uint32, m *ebpf.Map, bitmapArraySize int) error {
	type lpmKey struct {
		Prefix uint32
		Addr   [4]uint8
	}

	for cidr, priorities := range addrs {
		b := newBitmap(bitmapArraySize)
		for _, prio := range priorities {
			b.Set(prio)
		}

		var k lpmKey
		k.Prefix = uint32(cidr.Bits())
		k.Addr = cidr.Addr().As4() // network order

		v, _ := b.MarshalBinary()
		if err := m.Put(k, v); err != nil {
			return fmt.Errorf("failed to update rules of CIDR(%s) to bpf map: %w", cidr, err)
		}
	}

	return nil
}

func storeProtocolRules(protos map[uint32][]uint32, m *ebpf.Map, bitmapArraySize int) error {
	for proto, priorities := range protos {
		b := newBitmap(bitmapArraySize)
		for _, prio := range priorities {
			b.Set(prio)
		}

		v, _ := b.MarshalBinary()
		if err := m.Put(proto, v); err != nil {
			return fmt.Errorf("failed to update rules of protocol(%d) to bpf map: %w", proto, err)
		}
	}

	return nil
}

type actionValue struct {
	Action uint64
	Count  uint64
}

var numCPU = runtime.NumCPU()

func getActionValue(action uint8, count uint64) []actionValue {
	val := make([]actionValue, numCPU)
	for i := range val {
		val[i].Action = uint64(action)
		val[i].Count = count
	}
	return val
}

// storeActions retrieves the old-hit-count-data from oldMap, and updates it to m.
func storeActions(actions []uint8, r *rule.Rules, m *ebpf.Map, prevHitCount map[uint32]uint64) error {
	for priority, action := range actions {
		key, val := uint32(priority), getActionValue(action, prevHitCount[r.GetRealPriority(uint32(priority))])
		if err := m.Put(key, val); err != nil {
			return fmt.Errorf("failed to update action of priority(%d) to bpf map: %w", priority, err)
		}
	}

	return nil
}

func getHitCount(m *ebpf.Map, r *rule.Rules) (map[uint32]uint64, error) {
	counts, err := retrieveHitCount(m, len(r.Rules()))
	if err != nil {
		return nil, err
	}

	hits := make(map[uint32]uint64, len(counts))
	for i, c := range counts {
		hits[r.GetRealPriority(uint32(i))] = c
	}
	return hits, nil
}

func retrieveHitCount(m *ebpf.Map, ruleNum int) ([]uint64, error) {
	counts := make([]uint64, ruleNum)

	sumOfVal := func(val []actionValue) uint64 {
		var sum uint64
		for _, val := range val {
			sum += val.Count
		}
		return sum
	}

	var err error
	value := make([]actionValue, numCPU)
	for key := uint32(0); key < uint32(ruleNum); key++ {
		err = m.Lookup(key, &value)
		if err != nil {
			return counts, fmt.Errorf("failed to retrieve hit count: %w", err)
		}

		counts[key] = sumOfVal(value)
	}

	return counts, nil
}
