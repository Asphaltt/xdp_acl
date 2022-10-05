package rule

import "fmt"

func (r *Rule) checkPriority() error {
	if minPriority <= r.Priority && r.Priority <= maxPriority {
		return nil
	}

	return fmt.Errorf("rule priority(%d) is invalid, should be %d <= PRIORITY <= %d",
		r.Priority, minPriority, maxPriority)
}

func (r *Rule) checkProtos() error {
	if r.Protos>>3 > 0 || r.Protos&0b0111 == 0 {
		return fmt.Errorf("rule protos(%04b) is invalid", r.Protos)
	}

	return nil
}

func (r *Rule) checkStrategy() error {
	if strategy := r.Strategy; strategy != xdpDrop && strategy != xdpPass {
		return fmt.Errorf("rule strategy(%d) is invalid", strategy)
	}

	return nil
}

func (r *Rule) check() error {
	type checker func() error
	checkers := []checker{
		r.checkPriority,
		r.checkProtos,
		r.checkStrategy,
	}

	for _, c := range checkers {
		if err := c(); err != nil {
			return err
		}
	}

	return nil
}
