package rule

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"
)

const (
	bitmapSize = 64
	bitmapMask = bitmapSize - 1

	xdpDrop = 1
	xdpPass = 2

	tcpBit  uint8 = 0b0001
	udpBit  uint8 = 0b0010
	icmpBit uint8 = 0b0100

	protoICMP uint32 = 1
	protoTCP  uint32 = 6
	protoUDP  uint32 = 17

	portBegin = 0
	portEnd   = 65535
)

var (
	ipMaxEntries uint32
	maxPriority  uint32
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

func (r *Rule) IsFixed(lastRuleFixed bool) bool {
	return lastRuleFixed && r.Priority == maxPriority
}

func (r *Rule) isLastRule() bool {
	zeroCidr := "0.0.0.0/0"
	return len(r.AddrSrcArr) == 1 && r.AddrSrcArr[0].CidrUser == zeroCidr &&
		len(r.AddrDstArr) == 1 && r.AddrDstArr[0].CidrUser == zeroCidr &&
		len(r.PortSrcArr) == 0 && len(r.PortDstArr) == 0 &&
		r.Protos&0b111 == 0b111
}

type Rules struct {
	file string

	BitmapArraySize int

	lastRuleAccept bool
	lastRuleFixed  bool

	rules []*Rule

	realPriorities []uint32

	allSrcPortPriorities []uint32
	allDstPortPriorities []uint32

	srcCIDRPriorities  map[netip.Prefix][]uint32
	dstCIDRPriorities  map[netip.Prefix][]uint32
	srcPortPriorities  [][]uint32
	dstPortPriorities  [][]uint32
	protocolPriorities map[uint32][]uint32
	priorityActions    []uint8
}

func (r *Rules) Rules() []*Rule                               { return r.rules }
func (r *Rules) SrcCIDRPriorities() map[netip.Prefix][]uint32 { return r.srcCIDRPriorities }
func (r *Rules) DstCIDRPriorities() map[netip.Prefix][]uint32 { return r.dstCIDRPriorities }
func (r *Rules) SrcPortPriorities() [][]uint32                { return r.srcPortPriorities }
func (r *Rules) DstPortPriorities() [][]uint32                { return r.dstPortPriorities }
func (r *Rules) ProtocolPriorities() map[uint32][]uint32      { return r.protocolPriorities }
func (r *Rules) PriorityActions() []uint8                     { return r.priorityActions }

func (r *Rules) init() {
	r.allSrcPortPriorities = nil
	r.allDstPortPriorities = nil
	r.srcCIDRPriorities = make(map[netip.Prefix][]uint32)
	r.dstCIDRPriorities = make(map[netip.Prefix][]uint32)
	r.srcPortPriorities = make([][]uint32, portEnd+1)
	r.dstPortPriorities = make([][]uint32, portEnd+1)
	r.protocolPriorities = make(map[uint32][]uint32, 3) // ICMP, TCP, UDP
	r.priorityActions = make([]uint8, len(r.rules))
}

func (r *Rules) ClearCache() {
	r.allSrcPortPriorities = nil
	r.allDstPortPriorities = nil
	r.srcCIDRPriorities = nil
	r.dstCIDRPriorities = nil
	r.srcPortPriorities = nil
	r.dstPortPriorities = nil
	r.protocolPriorities = nil
	r.priorityActions = nil
}

func loadRules(fpath string) ([]*Rule, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fpath, err)
	}
	defer fd.Close()

	var rules []*Rule
	err = json.NewDecoder(fd).Decode(&rules)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rules from %s: %w", fpath, err)
	}

	return rules, nil
}

func LoadRules(conf string, lastRuleAccept, lastRuleFixed bool) (*Rules, error) {
	rules, err := loadRules(conf)
	if err != nil {
		return nil, err
	}

	var r Rules
	r.file = conf
	r.rules = rules
	r.lastRuleAccept = lastRuleAccept
	r.lastRuleFixed = lastRuleFixed

	return &r, r.FixRules()
}

func (r *Rules) fixBitmap() {
	r.BitmapArraySize = roundUp(len(r.rules))
	ipMaxEntries = uint32(r.BitmapArraySize * bitmapSize)
	maxPriority = ipMaxEntries - 1
}

func roundUp(n int) int {
	n >>= 6        // n /= 64
	if n&63 != 0 { // n%64 != 0
		n++
	}

	rounds := []int{8, 16, 32, 64, 128, 160, 256}
	for _, r := range rounds {
		if n < r {
			return r
		}
	}

	panic("bitmap array size cannot be larger than 256")
}

func (r *Rules) FixRules() error {
	r.init()

	r.fixBitmap()

	if err := r.sortRules(); err != nil {
		return err
	}

	if r.lastRuleFixed {
		r.fixLastRule(r.lastRuleAccept)
	}

	r.fixDeletion(r.lastRuleFixed)

	if err := r.check(); err != nil {
		return err
	}

	if err := r.addPriorities(); err != nil {
		return err
	}

	return nil
}

func (r *Rules) GetRealPriority(p uint32) uint32 {
	if int(p) < len(r.realPriorities) {
		return r.realPriorities[p]
	}
	return p
}

func (r *Rules) sortRules() error {
	sort.Slice(r.rules, func(i, j int) bool {
		return r.rules[i].Priority < r.rules[j].Priority
	})

	length := len(r.rules)
	for i := 1; i < length; i++ {
		if r.rules[i].Priority == r.rules[i-1].Priority {
			return fmt.Errorf("duplicated rule's priority %d", r.rules[i].Priority)
		}
	}

	r.realPriorities = make([]uint32, length)
	for i := range r.rules {
		priority := uint32(i)
		r.realPriorities[priority] = r.rules[i].Priority
		r.rules[i].Priority = priority
	}

	return nil
}

func (r *Rules) fixLastRule(lastRuleAccept bool) {
	if len(r.rules) != 0 {
		if rule := r.rules[len(r.rules)-1]; rule.isLastRule() {
			if lastRuleAccept {
				rule.Strategy = xdpPass
			} else {
				rule.Strategy = xdpDrop
			}
			return
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

func (r *Rules) AddRule(rule *Rule) {
	rules := r.GetRulesWithRealPriority()
	rules = append(rules, rule)
	r.rules = rules
}

func (r *Rules) DeleteRule(rule *Rule) {
	rules := r.GetRulesWithRealPriority()
	r.rules = r.rules[:0]
	for i := range rules {
		if rules[i].Priority != rule.Priority {
			r.rules = append(r.rules, rules[i])
		}
	}
}

func (r *Rules) GetRulesWithRealPriority() []*Rule {
	copied := make([]*Rule, 0, len(r.rules))
	// Note: do deep copy instead of copying pointers
	for i := range r.rules {
		rule := *r.rules[i]
		rule.Priority = r.GetRealPriority(r.rules[i].Priority)
		copied = append(copied, &rule)
	}
	return copied
}

func (r *Rules) Save() error {
	data, err := json.MarshalIndent(r.GetRulesWithRealPriority(), "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	fd, err := os.OpenFile(r.file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open file %s to write rules: %w", r.file, err)
	}
	defer fd.Close()

	_, err = fd.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write rules to %s: %w", r.file, err)
	}

	return nil
}
