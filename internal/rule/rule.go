package rule

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"xdp_acl/internal/flag"
)

const (
	bitmapArraySize = 160
	bitmapSize      = 64

	maxPriority = bitmapArraySize*bitmapSize - 1
	minPriority = 1

	// 必须与 XDP 程序中 IP_MAX_ENTRIES_V4 保持一致
	ipMaxEntries = bitmapArraySize * bitmapSize

	xdpDrop = 1
	xdpPass = 2

	tcpBit  uint8 = 0b0001
	udpBit  uint8 = 0b0010
	icmpBit uint8 = 0b0100

	protoICMP uint32 = 1
	protoTCP  uint32 = 6
	protoUDP  uint32 = 17

	portBegin uint16 = 0
	portEnd   uint16 = 65535
)

type Addr struct {
	CidrUser     string       `json:"cidr_user"`
	CidrStandard string       `json:"cidr_standard"`
	CidrSpecial  netip.Prefix `json:"-"`
}

type Rule struct {
	Priority   uint32   `json:"priority"`
	Strategy   uint8    `json:"strategy"`
	Protos     uint8    `json:"protos"`
	CreateTime int64    `json:"create_time"`
	AddrSrcArr []Addr   `json:"addr_src_arr"`
	PortSrcArr []uint16 `json:"port_src_arr"`
	AddrDstArr []Addr   `json:"addr_dst_arr"`
	PortDstArr []uint16 `json:"port_dst_arr"`
	HitCounts  string   `json:"-"`
	CanNotDel  uint8    `json:"can_not_del,omitempty"`
}

func (r *Rule) onlyICMP() bool {
	return (r.Protos&icmpBit != 0) && (r.Protos&(tcpBit|udpBit) == 0)
}

type Rules struct {
	rules []*Rule

	priorityMu sync.Mutex
	priorities map[uint32]struct{}

	allSrcPortPriorities []uint32
	allDstPortPriorities []uint32

	srcCIDRPriorities  map[netip.Prefix][]uint32
	dstCIDRPriorities  map[netip.Prefix][]uint32
	srcPortPriorities  map[uint16][]uint32
	dstPortPriorities  map[uint16][]uint32
	protocolPriorities map[uint32][]uint32
	priorityActions    map[uint32]uint8
}

func (r *Rules) SrcCIDRPriorities() map[netip.Prefix][]uint32 { return r.srcCIDRPriorities }
func (r *Rules) DstCIDRPriorities() map[netip.Prefix][]uint32 { return r.dstCIDRPriorities }
func (r *Rules) SrcPortPriorities() map[uint16][]uint32       { return r.srcPortPriorities }
func (r *Rules) DstPortPriorities() map[uint16][]uint32       { return r.dstPortPriorities }
func (r *Rules) ProtocolPriorities() map[uint32][]uint32      { return r.protocolPriorities }
func (r *Rules) PriorityActions() map[uint32]uint8            { return r.priorityActions }

func newRules() *Rules {
	var r Rules
	r.priorities = make(map[uint32]struct{})
	r.srcCIDRPriorities = make(map[netip.Prefix][]uint32)
	r.dstCIDRPriorities = make(map[netip.Prefix][]uint32)
	r.srcPortPriorities = make(map[uint16][]uint32)
	r.dstPortPriorities = make(map[uint16][]uint32)
	r.protocolPriorities = make(map[uint32][]uint32, 3) // ICMP, TCP, UDP
	r.priorityActions = make(map[uint32]uint8)
	return &r
}

func loadRules(fpath string) (*Rules, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fpath, err)
	}
	defer fd.Close()

	r := newRules()
	err = json.NewDecoder(fd).Decode(&r.rules)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rules from %s: %w", fpath, err)
	}

	return r, nil
}

func LoadRules(flags *flag.Flags) (*Rules, error) {
	r, err := loadRules(flags.Conf)
	if err != nil {
		return nil, err
	}

	r.sort()

	if flags.LastRuleFixed {
		r.fixLastRule(flags.LastRuleAccept)
	}

	r.fixDeletion(flags.LastRuleFixed)

	if err := r.check(); err != nil {
		return nil, err
	}

	if err := r.addPriorities(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Rules) sort() {
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].CreateTime > r.rules[j].CreateTime
	})
}

func (r *Rules) fixLastRule(lastRuleAccept bool) {
	for i := range r.rules {
		if r.rules[i].Priority == maxPriority {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
			break
		}
	}

	zeroCidr := "0.0.0.0/0"

	lastRule := Rule{
		Priority:   maxPriority,
		Protos:     0b0111,
		CreateTime: time.Now().UnixNano() / int64(time.Millisecond),
		AddrSrcArr: []Addr{{CidrUser: zeroCidr, CidrStandard: zeroCidr}},
		PortSrcArr: []uint16{},
		AddrDstArr: []Addr{{CidrUser: zeroCidr, CidrStandard: zeroCidr}},
		PortDstArr: []uint16{},
		CanNotDel:  1,
	}

	if lastRuleAccept {
		lastRule.Strategy = xdpPass
	} else {
		lastRule.Strategy = xdpDrop
	}

	r.rules = append(r.rules, &lastRule)
}

func (r *Rules) fixDeletion(lastRuleFixed bool) {
	for i := range r.rules {
		if r.rules[i].Priority == maxPriority {
			if lastRuleFixed {
				r.rules[i].CanNotDel = 1
			} else {
				r.rules[i].CanNotDel = 0
			}
		}
	}
}

func (r *Rules) check() error {
	for i := range r.rules {
		rule := r.rules[i]
		if err := r.checkRule(rule); err != nil {
			return err
		}
	}

	return nil
}

func (r *Rules) checkRule(rule *Rule) error {
	return rule.check()
}

func (r *Rules) addPriorities() error {
	for _, rule := range r.rules {
		if err := r.addPriority(rule); err != nil {
			return err
		}
	}

	r.fixSrcCIDRPriority()
	r.fixDstCIDRPriority()

	r.fixSrcPortPriority()
	r.fixDstPortPriority()

	return nil
}

func (r *Rules) addPriority(rule *Rule) error {
	r.priorityMu.Lock()
	defer r.priorityMu.Unlock()

	if _, ok := r.priorities[rule.Priority]; ok {
		return fmt.Errorf("priority(%d) is duplicated", rule.Priority)
	}

	if err := r.addSrcCIDRPriority(rule); err != nil {
		return err
	}

	if err := r.addDstCIDRPriority(rule); err != nil {
		return err
	}

	r.addSrcPortPriority(rule)
	r.addDstPortPriority(rule)
	r.addProtocolPriority(rule)
	r.addPriorityAction(rule)

	return nil
}

func (r *Rules) addProtocolPriority(rule *Rule) {
	proto := rule.Protos
	if proto&tcpBit != 0 {
		r.protocolPriorities[protoTCP] = append(r.protocolPriorities[protoTCP], rule.Priority)
	}

	if proto&udpBit != 0 {
		r.protocolPriorities[protoUDP] = append(r.protocolPriorities[protoUDP], rule.Priority)
	}

	if proto&icmpBit != 0 {
		r.protocolPriorities[protoICMP] = append(r.protocolPriorities[protoICMP], rule.Priority)
	}
}

func (r *Rules) addPriorityAction(rule *Rule) {
	r.priorityActions[rule.Priority] = rule.Strategy
}
