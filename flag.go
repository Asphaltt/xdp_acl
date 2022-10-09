package main

import "github.com/spf13/pflag"

type Flags struct {
	Dev    []string
	Server string
	Port   uint16

	Auto   bool
	Skb    bool
	Native bool

	// 对存量，新增，删除，查看规则有影响
	LastRuleFixed   bool
	LastRuleAccept  bool
	LastRuleDisplay bool

	Debug     bool
	KernelBTF string

	Conf string
}

func parseFlags() *Flags {
	var flags Flags

	pflag.StringSliceVarP(&flags.Dev, "dev", "D", nil, "Input your net device name (multi devs have to be separated by ','")

	pflag.BoolVar(&flags.Debug, "debug", false, "Print XDP log")
	pflag.StringVar(&flags.KernelBTF, "kernel-btf", "", "Specify kernel BTF file")

	pflag.BoolVarP(&flags.Auto, "auto-mode", "A", true, "Auto-detect SKB or Native mode")
	pflag.BoolVarP(&flags.Skb, "skb-mode", "S", false, "Load XDP program in SKB mode")
	pflag.BoolVarP(&flags.Native, "native-mode", "N", false, "Load XDP program in native mode")

	pflag.BoolVar(&flags.LastRuleFixed, "last-rule-fixed", true, "Last rule is fixed or can be set")
	pflag.BoolVar(&flags.LastRuleAccept, "last-rule-accept", true, "Set the last rule strategy to accept or drop")
	pflag.BoolVar(&flags.LastRuleDisplay, "last-rule-display", false, "Display or hide the last rule")

	pflag.StringVarP(&flags.Conf, "conf", "c", "acl.json", "config file")
	pflag.StringVarP(&flags.Server, "server", "s", "0.0.0.0", "Input your server host")
	pflag.Uint16VarP(&flags.Port, "port", "p", 9090, "Input your server port")

	pflag.Parse()

	return &flags
}
