package rule

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/samber/lo"
)

func (r *Rule) checkCIDR(addrs []Addr) (map[netip.Prefix]struct{}, error) {
	m := make(map[netip.Prefix]struct{}, len(addrs))

	for i := range addrs {
		addr := addrs[i]
		cidr, err := netip.ParsePrefix(addr.CidrUser)
		if err != nil {
			return nil, fmt.Errorf("%s is an invalid CIDR", addr.CidrUser)
		}

		cidr = cidr.Masked()
		addrs[i].CidrStandard = cidr.String()

		for k := range m {
			if cidr.Overlaps(k) {
				return nil, fmt.Errorf("%s overlaps with %s", cidr, k)
			}
		}

		m[cidr] = struct{}{}
	}

	return m, nil
}

func (r *Rule) checkSrcCIDR() (map[netip.Prefix]struct{}, error) {
	m, err := r.checkCIDR(r.AddrSrcArr)
	if err != nil {
		return nil, fmt.Errorf("failed to check src addrs: %w", err)
	}

	return m, nil
}

func (r *Rules) addSrcCIDRPriority(rule *Rule) error {
	m, err := rule.checkSrcCIDR()
	if err != nil {
		return err
	}

	err = r.checkCIDRLimit(r.srcCIDRPriorities, m)
	if err != nil {
		return fmt.Errorf("source CIDR limit: %w", err)
	}

	for k := range m {
		r.srcCIDRPriorities[k] = append(r.srcCIDRPriorities[k], rule.Priority)
	}

	return nil
}

func (r *Rule) checkDstCIDR() (map[netip.Prefix]struct{}, error) {
	m, err := r.checkCIDR(r.AddrDstArr)
	if err != nil {
		return nil, fmt.Errorf("failed to check dst addrs: %w", err)
	}

	return m, nil
}

func (r *Rules) addDstCIDRPriority(rule *Rule) error {
	m, err := rule.checkDstCIDR()
	if err != nil {
		return err
	}

	err = r.checkCIDRLimit(r.dstCIDRPriorities, m)
	if err != nil {
		return fmt.Errorf("destination CIDR limit: %w", err)
	}

	for k := range m {
		r.dstCIDRPriorities[k] = append(r.dstCIDRPriorities[k], rule.Priority)
	}

	return nil
}

func (r *Rules) checkCIDRLimit(mExist map[netip.Prefix][]uint32, mAdding map[netip.Prefix]struct{}) error {
	nAdding := 0
	for k := range mAdding {
		if _, ok := mExist[k]; !ok {
			nAdding++
		}
	}

	if total := len(mExist) + nAdding; total > ipMaxEntries {
		return fmt.Errorf("the number of entry %d exceeds the limit %d", total, ipMaxEntries)
	}

	return nil
}

func (r *Rules) fixCIDRPriority(m map[netip.Prefix][]uint32) {
	prefixes := lo.Keys(m)
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Bits() < b.Bits() {
			return true
		}
		if a.Bits() > b.Bits() {
			return false
		}

		ipA, ipB := a.Addr(), b.Addr()
		return ipA.Less(ipB)
	})

	length := len(prefixes)
	for i := range prefixes {
		prev := prefixes[i]
		for j := i + 1; j < length; j++ {
			curr := prefixes[j]

			if prev.Overlaps(curr) {
				// prev CIDR contains curr CIDR
				// then append all priority of prev to curr
				// because curr is part of prev
				m[curr] = append(m[curr], m[prev]...)

				// remove duplicated priority
				// not required, but for performance
				m[curr] = lo.Uniq(m[curr])
			}
		}
	}
}

func (r *Rules) fixSrcCIDRPriority() {
	r.fixCIDRPriority(r.srcCIDRPriorities)
}

func (r *Rules) fixDstCIDRPriority() {
	r.fixCIDRPriority(r.dstCIDRPriorities)
}
