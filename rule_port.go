package main

func (r *Rules) addSrcPortPriority(rule *Rule) {
	if rule.onlyICMP() {
		return
	}

	if len(rule.PortSrcArr) == 0 { // including all ports
		r.allSrcPortPriorities = append(r.allSrcPortPriorities, rule.Priority)
		return
	}

	for _, port := range rule.PortSrcArr {
		r.srcPortPriorities[port] = append(r.srcPortPriorities[port], rule.Priority)
	}
}

func (r *Rules) addDstPortPriority(rule *Rule) {
	if rule.onlyICMP() {
		return
	}

	if len(rule.PortDstArr) == 0 { // including all ports
		r.allDstPortPriorities = append(r.allDstPortPriorities, rule.Priority)
		return
	}

	for _, port := range rule.PortDstArr {
		r.dstPortPriorities[port] = append(r.dstPortPriorities[port], rule.Priority)
	}
}

func (r *Rules) fixPortPriority(all []uint32, arr [][]uint32) {
	if len(all) == 0 {
		return
	}

	for port := portBegin; port <= portEnd; port++ {
		arr[port] = append(arr[port], all...)
	}
}

func (r *Rules) fixSrcPortPriority() {
	r.fixPortPriority(r.allSrcPortPriorities, r.srcPortPriorities)
}

func (r *Rules) fixDstPortPriority() {
	r.fixPortPriority(r.allDstPortPriorities, r.dstPortPriorities)
}
