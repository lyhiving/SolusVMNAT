package main

import (
	"SolusVMNAT/zlog"
)

func LoadTCPRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()
	zlog.Info("Loaded [", i, "] (TCP)", r.Listen, " => ", r.Forward)
	shell_exec("iptables -t nat -A PREROUTING -i " + Setting.Config.Eth + " -p tcp -m tcp --dport " + r.Listen + " -j DNAT --to-destination " + r.Forward)
}

func DeleteTCPRules(i string) {
	Setting.Rules.RLock()
	r := Setting.Config.Rules[i]
	Setting.Rules.RUnlock()

	zlog.Info("Deleted [", i, "] (TCP)", r.Listen, " => ", r.Forward)
	shell_exec("iptables -t nat -D PREROUTING -i " + Setting.Config.Eth + " -p tcp -m tcp --dport " + r.Listen + " -j DNAT --to-destination " + r.Forward)

	Setting.Rules.Lock()
	delete(Setting.Config.Rules, i)
	Setting.Rules.Unlock()
}
