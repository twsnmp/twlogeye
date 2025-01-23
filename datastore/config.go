package datastore

type ConfigEnt struct {
	LogPath                  string `yaml:"logPath"`
	SyslogUDPPort            int    `yaml:"syslogUDPPort"`
	SyslogTCPPort            int    `yaml:"syslogTCPPort"`
	NetFlowPort              int    `yaml:"netflowPort"`
	SFlowPort                int    `yaml:"sflowPort"`
	SNMPTrapPort             int    `yaml:"snmpTrapPort"`
	WinEventLogType          string `yaml:"winEventLogType"`
	WinEventLogCheckInterval int    `yaml:"winEventLogCheckInterval"`
	// Dst
	SyslogDst     []string `yaml:"syslogDst"`
	TrapDst       []string `yaml:"trapDst"`
	TrapCommunity string   `yaml:"trapCommunity"`
	// gRPC Setting
	// Log retention period (hours)
	LogRetention int `yaml:"logRetention"`
	// Notify retention period (days)
	NotifyRetention int `yaml:"notifyRetention"`
	// GROK
	GrokPat string `yaml:"grockPat"`
	GrokDef string `yaml:"grokDef"`
	// Sigma
	SigmaConfig string `yaml:"sigmaConfig"`
	SigmaRules  string `yaml:"sigmaRules"`
	// SNMP MIB
	MIBPath string `yaml:"mibPath"`
}

var Config ConfigEnt
