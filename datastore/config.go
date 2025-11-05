package datastore

type ConfigEnt struct {
	DBPath        string `yaml:"dbPath"`
	LogPath       string `yaml:"logPath"`
	SyslogUDPPort int    `yaml:"syslogUDPPort"`
	SyslogTCPPort int    `yaml:"syslogTCPPort"`
	NetFlowPort   int    `yaml:"netflowPort"`
	SNMPTrapPort  int    `yaml:"snmpTrapPort"`
	OTelHTTPPort  int    `yaml:"otelHTTPPort"`
	OTelgRPCPort  int    `yaml:"otelgRPCPort"`
	OTelRetention int    `yaml:"otelRetention"`
	OTelFrom      string `yaml:"otelFrom"`
	OTelCert      string `yaml:"otelCert"`
	OTelKey       string `yaml:"otelgKey"`
	OTelCA        string `yaml:"otelCA"`

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
	WebhookDst    []string `yaml:"webhookDst"`
	TrapCommunity string   `yaml:"trapCommunity"`
	// Log retention period (hours)
	LogRetention int `yaml:"logRetention"`
	// Notify retention period (days)
	NotifyRetention int `yaml:"notifyRetention"`
	// Report retention period (days)
	ReportRetention int `yaml:"reportRetention"`
	// Report interval (minute)
	ReportInterval int `yaml:"reportInterval"`
	// Report Top N
	ReportTopN int `yaml:"reportTopN"`
	// Threshold for Anomaly Detection Report
	AnomalyReportThreshold float64 `yaml:"anomalyReportThreshold"`
	// Use hour and weekend data for anomaly detection
	AnomalyUseTimeData bool `yaml:"anomalyUseTimeData"`
	// Grace period for sending notifications when detecting anomalies
	AnomalyNotifyDelay int `yaml:"anomalyNotifyDelay"`
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
	// MCP
	MCPEndpoint string `yaml:"mcpEndpoint"`
	MCPFrom     string `yaml:"mcpFrom"`
	MCPToken    string `yaml:"mcpToken"`
	// Debug
	Debug bool `yaml:"debug"`
}

var Config ConfigEnt
