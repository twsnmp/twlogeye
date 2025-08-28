package datastore

type ConfigEnt struct {
	DBPath        string `yaml:"dbPath"`
	LogPath       string `yaml:"logPath"`
	SyslogUDPPort int    `yaml:"syslogUDPPort"`
	SyslogTCPPort int    `yaml:"syslogTCPPort"`
	NetFlowPort   int    `yaml:"netflowPort"`
	SNMPTrapPort  int    `yaml:"snmpTrapPort"`
	// Windows log
	WinEventLogChannel       string `yaml:"winEventLogChannel"`
	WinEventLogCheckInterval int    `yaml:"winEventLogCheckInterval"`
	WinEventLogCheckStart    int    `yaml:"winEventLogCheckStart"`
	WinRemote                string `yaml:"winRemote"`
	WinUser                  string `yaml:"winUser"`
	WinPassword              string `yaml:"winPassword"`
	WinAuth                  string `yaml:"winAuth"`
	WinLogSJIS               bool   `yaml:"winSJIS"`
	// Dst
	SyslogDst     []string `yaml:"syslogDst"`
	TrapDst       []string `yaml:"trapDst"`
	TrapCommunity string   `yaml:"trapCommunity"`
	// Log retention period (hours)
	LogRetention int `yaml:"logRetention"`
	// Notify retention period (days)
	NotifyRetention int `yaml:"notifyRetention"`
	// Report retention period (days)
	ReportRetention int `yaml:"reportRetention"`
	// Report interval day,hour,minut
	ReportInterval string `yaml:"reportInterval"`
	// Report Top N
	ReportTopN int `yaml:"reportTopN"`
	// GROK
	GrokPat []string `yaml:"grockPat"`
	GrokDef string   `yaml:"grokDef"`
	// Named capture
	NamedCaptures string `yaml:"namedCaptures"`
	// Key/Vaue parse
	KeyValParse bool `yaml:"keyValParse"`
	// Sigma
	SigmaRules     string `yaml:"sigmaRules"`
	SigmaConfigs   string `yaml:"sigmaConfigs"`
	SigmaSkipError bool   `yaml:"sigmaSkipError"`
	// SNMP MIB
	MIBPath string `yaml:"mibPath"`
	// Debug
	Debug bool `yaml:"debug"`
}

var Config ConfigEnt
