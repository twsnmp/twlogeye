package datastore

type ConfigEnt struct {
	LogPath                  string `yaml:"logPath"`
	SyslogUDPPort            int    `yaml:"syslogUDPPort"`
	SyslogTCPPort            int    `yaml:"syslogTCPPort"`
	NetFlowPort              int    `yaml:"netflowPort"`
	SFlowPort                int    `yaml:"sflowPort"`
	SNMPTrapPort             int    `yaml:"snmpTrapPort"`
	WinEventLogChannel       string `yaml:"winEventLogChannel"`
	WinEventLogCheckInterval int    `yaml:"winEventLogCheckInterval"`
	WinEventLogCheckStart    int    `yaml:"winEventLogCheckStart"`
	WinRemote                string `yaml:"winRemote"`
	WinUser                  string `yaml:"winUser"`
	WinPassword              string `yaml:"winPassword"`
	WinAuth                  string `yaml:"winAuth"`
	// Dst
	SyslogDst     []string `yaml:"syslogDst"`
	TrapDst       []string `yaml:"trapDst"`
	TrapCommunity string   `yaml:"trapCommunity"`
	// Log retention period (hours)
	LogRetention int `yaml:"logRetention"`
	// Notify retention period (days)
	NotifyRetention int `yaml:"notifyRetention"`
	// GROK
	GrokPat []string `yaml:"grockPat"`
	GrokDef string   `yaml:"grokDef"`
	// Named capture
	NamedCaptures string `yaml:"nameCaps"`
	// Key/Vaue parse
	KeyValParse bool `yaml:"keyValParse"`
	// Sigma
	SigmaRules     string `yaml:"sigmaRules"`
	SigmaConfigs   string `yaml:"sigmaConfigs"`
	SigmaSkipError bool   `yaml:"sigmaSkipError"`
	// SNMP MIB
	MIBPath string `yaml:"mibPath"`
}

var Config ConfigEnt
