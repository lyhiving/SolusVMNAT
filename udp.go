package main

import (
	"SolusVMNAT/zlog"
)

func LoadUDPRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()
	zlog.Info("Loaded [", i, "] (UDP)", r.Listen, " => ", r.Forward)
	shell_exec("iptables -t nat -A PREROUTING -i " + Setting.Config.Eth + " -p udp -m udp --dport " + r.Listen + " -j FULLCONENAT --to-destination " + r.Forward)
}

func DeleteUDPRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	zlog.Info("Deleted [", i, "] (UDP)", r.Listen, " => ", r.Forward)
	shell_exec("iptables -t nat -D PREROUTING -i " + Setting.Config.Eth + " -p udp -m udp --dport " + r.Listen + " -j FULLCONENAT --to-destination " + r.Forward)

	Setting.Rules.Lock()
	delete(Setting.Config.Rules, i)
	Setting.Rules.Unlock()
}
