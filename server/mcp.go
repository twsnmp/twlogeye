package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/araddon/dateparse"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

var mcpAllow sync.Map

func StartMCPServer(ctx context.Context, wg *sync.WaitGroup, cert, key, version string) {
	defer wg.Done()
	if datastore.Config.MCPEndpoint == "" {
		return
	}
	log.Printf("start mcp server")
	setMCPAllow()
	e := makeMCPServer(cert, key, version)
	<-ctx.Done()
	log.Println("stop mcp server")
	if e != nil {
		e.Shutdown(ctx)
	}
}

func makeMCPServer(cert, key, version string) *echo.Echo {
	// Create MCP Server
	s := mcp.NewServer(
		&mcp.Implementation{
			Name:    "TwLogEye MCP Server",
			Version: version,
		}, nil)
	// Add tools to MCP server
	addTools(s)
	// Add prompts to MCP server
	addPrompts(s)

	sv := &http.Server{}
	sv.Addr = datastore.Config.MCPEndpoint
	if c, err := getMCPServerCert(cert, key); err == nil {
		if c != nil {
			sv.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*c},
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				MinVersion: tls.VersionTLS13,
			}
		}
	} else {
		log.Printf("getMCPServerCert err=%v", err)
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s
	}, nil)

	e.Any("/mcp", func(c echo.Context) error {
		if !checkMCPACL(c) {
			return echo.ErrUnauthorized
		}
		handler.ServeHTTP(c.Response().Writer, c.Request())
		return nil
	})
	log.Printf("start mcp server listening on %s", datastore.Config.MCPEndpoint)
	go func() {
		if err := e.StartServer(sv); err != nil {
			log.Printf("start mcp server err=%v", err)
		}
	}()
	return e
}

func addTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_log",
		Description: "Search log from TwLogEye database.",
	}, searchLog)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_notify",
		Description: "Search notify from TwLogEye database.",
	}, searchNotify)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_report",
		Description: "Get report from TwLogEye database.",
	}, getReport)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_last_report",
		Description: "Get last report from TwLogEye database.",
	}, getLastReport)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_anomaly_report",
		Description: "Get anomaly report from TwLogEye database.",
	}, getAnomalyReport)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sigma_evaluator_list",
		Description: "Get sigma rule evaluator list from TwLogEye.",
	}, getSigmaRuleEvaluatorList)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sigma_rule_id_list",
		Description: "Get sigma rule id list from TwLogEye.",
	}, getSigmaRuleIDList)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sigma_rule",
		Description: "Get sigma rule from TwLogEye.",
	}, getSigmaRule)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "add_sigma_rule",
		Description: "Add sigma rule to TwLogEye.",
	}, addSigmaRule)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_sigma_rule",
		Description: "Delete sigma rule from TwLogEye",
	}, deleteSigmaRule)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "reload_sigma_rule",
		Description: "reload sigma rule",
	}, ReloadSigmaRule)
}

// Add prompts
func addPrompts(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{
		Name:        "search_log",
		Title:       "Search log",
		Description: "Search log with filters.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "filter",
				Title:       "Filter logs by regular expression. Empty is no filter.",
				Description: "Filter logs by regular expression. Empty is no filter.",
				Required:    false,
			},
			{
				Name:        "type",
				Title:       "Type of log to search.",
				Description: "Type of log to search. type can be syslog,trap,netflow,winevent,otel,mqtt.",
				Required:    false,
			},
			{
				Name:        "start",
				Title:       "Start date and time for log search.",
				Description: "Start date and time for log search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
			{
				Name:        "end",
				Title:       "End date and time for log search.",
				Description: "End date and time for log search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
		},
	}, searchLogPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "search_notify",
		Title:       "Search notify",
		Description: "Search notify with filters.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "level",
				Title:       "Regular expression-based notify level filter.",
				Description: "Regular expression-based notify level filter. level name is info,low,high,medium,critical empty is no filter.",
				Required:    false,
			},
			{
				Name:        "start",
				Title:       "Start date and time for notify search.",
				Description: "Start date and time for notify search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
			{
				Name:        "end",
				Title:       "End date and time for notify search.",
				Description: "End date and time for notify search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
		},
	}, searchNotifyPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "get_report",
		Title:       "Get report from TwLogEye.",
		Description: "Get report from TwLogEye database.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "type",
				Title:       "Type of report.",
				Description: "Type of report. type can be syslog,trap,netflow,winevent,otel,mqtt,anomaly,monitor.",
				Required:    false,
			},
			{
				Name:        "start",
				Title:       "Start date and time to get report.",
				Description: "Start date and time for report search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
			{
				Name:        "end",
				Title:       "End date and time to get report.",
				Description: "End date and time to get report. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
		},
	}, getReportPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "get_last_report",
		Title:       "Get last report from TwLogEye.",
		Description: "Get last report from TwLogEye database.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "type",
				Title:       "Type of report.",
				Description: "Type of report. type can be syslog,trap,netflow,winevent,otel,mqtt,anomaly,monitor.",
				Required:    false,
			},
		},
	}, getLastReportPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "get_anomaly_report",
		Title:       "Get anomaly report from TwLogEye.",
		Description: "Get anomaly report from TwLogEye database.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "type",
				Title:       "Type of anomaly report.",
				Description: "Type of anomaly report. type can be syslog,trap,netflow,winevent,anomaly,otel,mqtt,monitor.",
				Required:    false,
			},
			{
				Name:        "start",
				Title:       "Start date and time to get anomaly report.",
				Description: "Start date and time for anomaly report search. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
			{
				Name:        "end",
				Title:       "End date and time to get anomaly report.",
				Description: "End date and time to get anomaly report. Example: 2025/10/26 11:00:00",
				Required:    false,
			},
		},
	}, getAnomalyReportPrompt)

}

func getMCPServerCert(cert, key string) (*tls.Certificate, error) {
	if key == "" || cert == "" {
		return nil, nil
	}
	keyPem, err := os.ReadFile(key)
	if err == nil {
		certPem, err := os.ReadFile(cert)
		if err == nil {
			cert, err := tls.X509KeyPair(certPem, keyPem)
			if err == nil {
				return &cert, nil
			}
		}
	}
	return nil, err
}

func setMCPAllow() {
	for _, ip := range strings.Split(datastore.Config.MCPFrom, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			mcpAllow.Store(ip, true)
		}
	}
}

func checkMCPACL(c echo.Context) bool {
	if datastore.Config.MCPToken != "" {
		t := c.Request().Header.Get("Authorization")
		if !strings.Contains(t, datastore.Config.MCPToken) {
			return false
		}
	}
	if datastore.Config.MCPFrom == "" {
		return true
	}
	if ip, _, err := net.SplitHostPort(c.Request().RemoteAddr); err == nil {
		if _, ok := mcpAllow.Load(ip); ok {
			return true
		}
	}
	if _, ok := mcpAllow.Load(c.RealIP()); ok {
		return true
	}
	return false
}

type mcpLogEnt struct {
	Time string
	Type string
	Src  string
	Log  string
}

type searchLogParams struct {
	Filter string `json:"filter" jsonschema:"Filter logs by regular expression. Empty is no filter"`
	Type   string `json:"type" jsonschema:"Type of log to search. type can be syslog,trap,netflow,winevent,otel,mqtt"`
	Start  string `json:"start" jsonschema:"Start date and time for log search. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End    string `json:"end" jsonschema:"End date and time for log search. Empty is now. Example: 2025/10/26 11:00:00"`
}

func searchLog(ctx context.Context, req *mcp.CallToolRequest, args searchLogParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	logType := args.Type
	if logType == "" {
		logType = "syslog"
	}
	filter := makeRegexFilter(args.Filter)
	list := []mcpLogEnt{}
	datastore.ForEachLog(logType, st, et, func(l *datastore.LogEnt) bool {
		if filter != nil && !filter.MatchString(l.Log) {
			return true
		}
		list = append(list, mcpLogEnt{
			Time: time.Unix(0, l.Time).Format(time.RFC3339Nano),
			Type: l.Type.String(),
			Src:  l.Src,
			Log:  l.Log,
		})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		j = []byte(err.Error())
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(j)},
		},
	}, nil, nil
}

func searchLogPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	c := []string{}
	if filter, ok := req.Params.Arguments["filter"]; ok {
		c = append(c, fmt.Sprintf("- Filter: %s", filter))
	}
	if limit, ok := req.Params.Arguments["limit"]; ok {
		c = append(c, fmt.Sprintf("- Limit: %s", limit))
	}
	if start, ok := req.Params.Arguments["start"]; ok {
		c = append(c, fmt.Sprintf("- Start: %s", start))
	}
	if end, ok := req.Params.Arguments["end"]; ok {
		c = append(c, fmt.Sprintf("- End: %s", end))
	}
	p := "Search log in TWLogEye database by using search_log tool"
	if len(c) > 0 {
		p += " with following conditions.\n" + strings.Join(c, "\n")
	} else {
		p += "."
	}
	return &mcp.GetPromptResult{
		Description: "search log prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

type mcpNotifyEnt struct {
	Time  string
	Type  string
	Log   string
	Src   string
	ID    string
	Title string
	Tags  string
	Level string
}
type searchNotifyParams struct {
	Level string `json:"level" jsonschema:"Regular expression-based notify level filter. level name is info,low,high,medium,critical empty is no filter."`
	Start string `json:"start" jsonschema:"Start date and time for notify search. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end" jsonschema:"End date and time for notify search. Empty is now. Example: 2025/10/26 11:00:00"`
}

func searchNotify(ctx context.Context, req *mcp.CallToolRequest, args searchNotifyParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	level := makeRegexFilter(args.Level)
	list := []mcpNotifyEnt{}
	datastore.ForEachNotify(st, et, func(n *datastore.NotifyEnt) bool {
		if level != nil && !level.MatchString(n.Level) {
			return true
		}
		list = append(list, mcpNotifyEnt{
			Time:  time.Unix(0, n.Time).Format(time.RFC3339Nano),
			Type:  n.Type.String(),
			Src:   n.Src,
			Log:   n.Log,
			ID:    n.ID,
			Title: n.Title,
			Tags:  n.Tags,
			Level: n.Level,
		})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		j = []byte(err.Error())
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(j)},
		},
	}, nil, nil
}

func searchNotifyPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	c := []string{}
	if level, ok := req.Params.Arguments["level"]; ok {
		c = append(c, fmt.Sprintf("- Level filter: %s", level))
	}
	if start, ok := req.Params.Arguments["start"]; ok {
		c = append(c, fmt.Sprintf("- Start: %s", start))
	}
	if end, ok := req.Params.Arguments["end"]; ok {
		c = append(c, fmt.Sprintf("- End: %s", end))
	}
	p := "Search notify in TWLogEye database by using search_notify tool"
	if len(c) > 0 {
		p += " with following conditions.\n" + strings.Join(c, "\n")
	} else {
		p += "."
	}
	return &mcp.GetPromptResult{
		Description: "search notify prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

func getTime(s string, dt int64) int64 {
	if t, err := dateparse.ParseLocal(s); err == nil {
		return t.UnixNano()
	}
	return dt
}

func makeRegexFilter(s string) *regexp.Regexp {
	if s != "" {
		if f, err := regexp.Compile(s); err == nil && f != nil {
			return f
		}
	}
	return nil
}

type getReportParams struct {
	Type  string `json:"type" jsonschema:"type of report. type can be syslog,trap,netflow,winevent,otel,monitor.winevent is windows event log"`
	Start string `json:"start" jsonschema:"Start date and time to get report. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end" jsonschema:"End date and time to get report. Empty is now. Example: 2025/10/26 11:00:00"`
}

func getReport(ctx context.Context, req *mcp.CallToolRequest, args getReportParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	r := ""
	switch args.Type {
	case "trap":
		r = getTrapReport(st, et)
	case "netflow":
		r = getNetflowReport(st, et)
	case "winevent":
		r = getWindowsEventReport(st, et)
	case "otel":
		r = getOTelReport(st, et)
	case "mqtt":
		r = getMqttReport(st, et)
	case "monitor":
		r = getMonitorReport(st, et)
	default:
		r = getSyslogReport(st, et)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: r},
		},
	}, nil, nil
}

func getReportPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	c := []string{}
	if reportType, ok := req.Params.Arguments["type"]; ok {
		c = append(c, fmt.Sprintf("- Report type: %s", reportType))
	}
	if start, ok := req.Params.Arguments["start"]; ok {
		c = append(c, fmt.Sprintf("- Start: %s", start))
	}
	if end, ok := req.Params.Arguments["end"]; ok {
		c = append(c, fmt.Sprintf("- End: %s", end))
	}
	p := "Get report from TWLogEye database by using get_report tool"
	if len(c) > 0 {
		p += " with following conditions.\n" + strings.Join(c, "\n")
	} else {
		p += "."
	}
	return &mcp.GetPromptResult{
		Description: "get report prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

type getLastReportParams struct {
	Type string `json:"type" jsonschema:"type of report. type can be syslog,trap,netflow,winevent,otel,anomaly,monitor.winevent is windows event log"`
}

func getLastReport(ctx context.Context, req *mcp.CallToolRequest, args getLastReportParams) (*mcp.CallToolResult, any, error) {
	r := ""
	switch args.Type {
	case "trap":
		r = getLastTrapReport()
	case "netflow":
		r = getLastNetflowReport()
	case "winevent":
		r = getLastWindowsEventReport()
	case "otel":
		r = getLastOTelReport()
	case "mqtt":
		r = getLastMqttReport()
	case "monitor":
		r = getLastMonitorReport()
	case "anomaly":
		r = getLastAnomalyReport()
	default:
		r = getLastSyslogReport()
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: r},
		},
	}, nil, nil
}

type mcpSyslogReportEnt struct {
	Time         string
	Normal       int
	Warn         int
	Error        int
	Patterns     int
	ErrPatterns  int
	TopList      []datastore.LogSummaryEnt
	TopErrorList []datastore.LogSummaryEnt
}

func getSyslogReport(st, et int64) string {
	list := []mcpSyslogReportEnt{}
	datastore.ForEachSyslogReport(st, et, func(r *datastore.SyslogReportEnt) bool {
		list = append(list,
			mcpSyslogReportEnt{
				Time:         time.Unix(0, r.Time).Format(time.RFC3339),
				Normal:       r.Normal,
				Warn:         r.Warn,
				Error:        r.Error,
				Patterns:     r.Patterns,
				ErrPatterns:  r.ErrPatterns,
				TopList:      r.TopList,
				TopErrorList: r.TopErrorList,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastSyslogReport() string {
	l := datastore.GetLastSyslogReport()
	if l == nil {
		return "syslog report not found"
	}
	r := &mcpSyslogReportEnt{
		Time:         time.Unix(0, l.Time).Format(time.RFC3339),
		Normal:       l.Normal,
		Warn:         l.Warn,
		Error:        l.Error,
		Patterns:     l.Patterns,
		ErrPatterns:  l.ErrPatterns,
		TopList:      l.TopList,
		TopErrorList: l.TopErrorList,
	}
	j, err := json.Marshal(r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpTrapReportEnt struct {
	Time    string
	Count   int
	Types   int
	TopList []datastore.TrapSummaryEnt
}

func getTrapReport(st, et int64) string {
	list := []mcpTrapReportEnt{}
	datastore.ForEachTrapReport(st, et, func(r *datastore.TrapReportEnt) bool {
		list = append(list,
			mcpTrapReportEnt{
				Time:    time.Unix(0, r.Time).Format(time.RFC3339),
				Count:   r.Count,
				Types:   r.Types,
				TopList: r.TopList,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastTrapReport() string {
	l := datastore.GetLastTrapReport()
	if l == nil {
		return "trap report not found"
	}
	r := &mcpTrapReportEnt{
		Time:    time.Unix(0, l.Time).Format(time.RFC3339),
		Count:   l.Count,
		Types:   l.Types,
		TopList: l.TopList,
	}
	j, err := json.Marshal(r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpNetflowReportEnt struct {
	Time               string
	Packets            int64
	Bytes              int64
	MACs               int
	IPs                int
	Flows              int
	Protocols          int
	Fumbles            int
	TopMACPacketsList  []datastore.NetflowPacketsSummaryEnt
	TopMACBytesList    []datastore.NetflowBytesSummaryEnt
	TopIPPacketsList   []datastore.NetflowPacketsSummaryEnt
	TopIPBytesList     []datastore.NetflowBytesSummaryEnt
	TopFlowPacketsList []datastore.NetflowPacketsSummaryEnt
	TopFlowBytesList   []datastore.NetflowBytesSummaryEnt
	TopProtocolList    []datastore.NetflowKeyCountEnt
	TopFumbleSrcList   []datastore.NetflowKeyCountEnt
}

func getNetflowReport(st, et int64) string {
	list := []mcpNetflowReportEnt{}
	datastore.ForEachNetflowReport(st, et, func(r *datastore.NetflowReportEnt) bool {
		list = append(list,
			mcpNetflowReportEnt{
				Time:               time.Unix(0, r.Time).Format(time.RFC3339),
				Packets:            r.Packets,
				Bytes:              r.Bytes,
				MACs:               r.MACs,
				IPs:                r.IPs,
				Flows:              r.Flows,
				Protocols:          r.Protocols,
				Fumbles:            r.Fumbles,
				TopMACPacketsList:  r.TopMACPacketsList,
				TopMACBytesList:    r.TopMACBytesList,
				TopIPPacketsList:   r.TopIPPacketsList,
				TopIPBytesList:     r.TopIPBytesList,
				TopFlowPacketsList: r.TopFlowPacketsList,
				TopFlowBytesList:   r.TopFlowBytesList,
				TopProtocolList:    r.TopProtocolList,
				TopFumbleSrcList:   r.TopFumbleSrcList,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastNetflowReport() string {
	l := datastore.GetLastNetflowReport()
	if l == nil {
		return "netflow report not found"
	}
	r := &mcpNetflowReportEnt{
		Time:               time.Unix(0, l.Time).Format(time.RFC3339),
		Packets:            l.Packets,
		Bytes:              l.Bytes,
		MACs:               l.MACs,
		IPs:                l.IPs,
		Flows:              l.Flows,
		Protocols:          l.Protocols,
		Fumbles:            l.Fumbles,
		TopMACPacketsList:  l.TopMACPacketsList,
		TopMACBytesList:    l.TopMACBytesList,
		TopIPPacketsList:   l.TopIPPacketsList,
		TopIPBytesList:     l.TopIPBytesList,
		TopFlowPacketsList: l.TopFlowPacketsList,
		TopFlowBytesList:   l.TopFlowBytesList,
		TopProtocolList:    l.TopProtocolList,
		TopFumbleSrcList:   l.TopFumbleSrcList,
	}
	j, err := json.Marshal(r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpWindowsEventReportEnt struct {
	Time         string
	Normal       int
	Warn         int
	Error        int
	Patterns     int
	ErrPatterns  int
	TopList      []datastore.WindowsEventSummary
	TopErrorList []datastore.WindowsEventSummary
}

func getWindowsEventReport(st, et int64) string {
	list := []mcpWindowsEventReportEnt{}
	datastore.ForEachWindowsEventReport(st, et, func(r *datastore.WindowsEventReportEnt) bool {
		list = append(list,
			mcpWindowsEventReportEnt{
				Time:         time.Unix(0, r.Time).Format(time.RFC3339),
				Normal:       r.Normal,
				Warn:         r.Warn,
				Error:        r.Error,
				TopList:      r.TopList,
				TopErrorList: r.TopErrorList,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastWindowsEventReport() string {
	l := datastore.GetLastWindowsEventReport()
	if l == nil {
		return "windows event report not found"
	}
	r := &mcpWindowsEventReportEnt{
		Time:         time.Unix(0, l.Time).Format(time.RFC3339),
		Normal:       l.Normal,
		Warn:         l.Warn,
		Error:        l.Error,
		TopList:      l.TopList,
		TopErrorList: l.TopErrorList,
	}
	j, err := json.Marshal(&r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpOTelReportEnt struct {
	Time         string
	Normal       int
	Warn         int
	Error        int
	Types        int
	ErrorTypes   int
	TopList      []datastore.OTelSummaryEnt
	TopErrorList []datastore.OTelSummaryEnt
	Hosts        int
	TraceIDs     int
	TraceCount   int
	MericsCount  int
}

func getOTelReport(st, et int64) string {
	list := []mcpOTelReportEnt{}
	datastore.ForEachOTelReport(st, et, func(r *datastore.OTelReportEnt) bool {
		list = append(list,
			mcpOTelReportEnt{
				Time:         time.Unix(0, r.Time).Format(time.RFC3339),
				Normal:       r.Normal,
				Warn:         r.Warn,
				Error:        r.Error,
				ErrorTypes:   r.ErrorTypes,
				TopList:      r.TopList,
				TopErrorList: r.TopErrorList,
				Hosts:        r.Hosts,
				TraceIDs:     r.TraceIDs,
				TraceCount:   r.TraceCount,
				MericsCount:  r.MericsCount,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastOTelReport() string {
	l := datastore.GetLastOTelReport()
	if l == nil {
		return "windows event report not found"
	}
	r := &mcpOTelReportEnt{
		Time:         time.Unix(0, l.Time).Format(time.RFC3339),
		Normal:       l.Normal,
		Warn:         l.Warn,
		Error:        l.Error,
		ErrorTypes:   l.ErrorTypes,
		TopList:      l.TopList,
		TopErrorList: l.TopErrorList,
		Hosts:        l.Hosts,
		TraceIDs:     l.TraceIDs,
		TraceCount:   l.TraceCount,
		MericsCount:  l.MericsCount,
	}
	j, err := json.Marshal(&r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpMqttReportEnt struct {
	Time    string
	Count   int
	Types   int
	TopList []datastore.MqttSummaryEnt
}

func getMqttReport(st, et int64) string {
	list := []mcpMqttReportEnt{}
	datastore.ForEachMqttReport(st, et, func(r *datastore.MqttReportEnt) bool {
		list = append(list,
			mcpMqttReportEnt{
				Time:    time.Unix(0, r.Time).Format(time.RFC3339),
				Count:   r.Count,
				Types:   r.Types,
				TopList: r.TopList,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastMqttReport() string {
	l := datastore.GetLastMqttReport()
	if l == nil {
		return "mqtt report not found"
	}
	r := &mcpMqttReportEnt{
		Time:    time.Unix(0, l.Time).Format(time.RFC3339),
		Count:   l.Count,
		Types:   l.Types,
		TopList: l.TopList,
	}
	j, err := json.Marshal(r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastReportPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	c := []string{}
	if reportType, ok := req.Params.Arguments["type"]; ok {
		c = append(c, fmt.Sprintf("- Report type: %s", reportType))
	}
	p := "Get last report from TWLogEye database by using get_last_report tool"
	if len(c) > 0 {
		p += " with following conditions.\n" + strings.Join(c, "\n")
	} else {
		p += "."
	}
	return &mcp.GetPromptResult{
		Description: "get last report prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

type mcpAnomalyReportEnt struct {
	Time  string
	Score float64
}

type getAnomalyReportParams struct {
	Type  string `json:"type" jsonschema:"type of anomaly report. type can be syslog,trap,netflow,winevent,otel,monitor.winevent is windows event log"`
	Start string `json:"start" jsonschema:"Start date and time to get report. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end" jsonschema:"End date and time to get report. Empty is now. Example: 2025/10/26 11:00:00"`
}

func getAnomalyReport(ctx context.Context, req *mcp.CallToolRequest, args getAnomalyReportParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	r := getAnomalyReportSub(args.Type, st, et)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: r},
		},
	}, nil, nil
}

func getAnomalyReportSub(t string, st, et int64) string {
	list := []mcpAnomalyReportEnt{}
	datastore.ForEachAnomalyReport(t, st, et, func(r *datastore.AnomalyReportEnt) bool {
		list = append(list,
			mcpAnomalyReportEnt{
				Time:  time.Unix(0, r.Time).Format(time.RFC3339),
				Score: r.Score,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getAnomalyReportPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	c := []string{}
	if reportType, ok := req.Params.Arguments["type"]; ok {
		c = append(c, fmt.Sprintf("- Report type: %s", reportType))
	}
	if start, ok := req.Params.Arguments["start"]; ok {
		c = append(c, fmt.Sprintf("- Start: %s", start))
	}
	if end, ok := req.Params.Arguments["end"]; ok {
		c = append(c, fmt.Sprintf("- End: %s", end))
	}
	p := "Get anomaly report from TWLogEye database by using get_anomaly_report tool"
	if len(c) > 0 {
		p += " with following conditions.\n" + strings.Join(c, "\n")
	} else {
		p += "."
	}
	return &mcp.GetPromptResult{
		Description: "get anomaly report prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

type mcpLastAnomalyReportScore struct {
	Time  string
	Type  string
	Score float64
}
type mcpLastAnomalyReportEnt struct {
	Time      string
	ScoreList []*mcpLastAnomalyReportScore
}

func getLastAnomalyReport() string {
	r := &mcpLastAnomalyReportEnt{
		Time:      time.Now().Format(time.RFC3339),
		ScoreList: []*mcpLastAnomalyReportScore{},
	}
	for _, t := range []string{"syslog", "trap", "netflow", "winevent", "otel", "monitor"} {
		l := datastore.GetLastAnomalyReport(t)
		if l != nil {
			r.ScoreList = append(r.ScoreList, &mcpLastAnomalyReportScore{
				Type:  t,
				Time:  time.Unix(0, l.Time).Format(time.RFC3339),
				Score: l.Score,
			})
		}
	}
	j, err := json.Marshal(&r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

type mcpMonitorReportEnt struct {
	Time    string
	CPU     float64
	Memory  float64
	Load    float64
	Disk    float64
	Net     float64
	Bytes   int64
	DBSpeed float64
	DBSize  int64
}

func getMonitorReport(st, et int64) string {
	list := []mcpMonitorReportEnt{}
	datastore.ForEachMonitorReport(st, et, func(r *datastore.MonitorReportEnt) bool {
		list = append(list,
			mcpMonitorReportEnt{
				Time:    time.Unix(0, r.Time).Format(time.RFC3339),
				CPU:     r.CPU,
				Memory:  r.Memory,
				Load:    r.Load,
				Disk:    r.Disk,
				Net:     r.Net,
				Bytes:   r.Bytes,
				DBSpeed: r.DBSpeed,
				DBSize:  r.DBSize,
			})
		return true
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getLastMonitorReport() string {
	l := datastore.GetLastMonitorReport()
	if l == nil {
		return "monitor report not found"
	}
	r := &mcpMonitorReportEnt{
		Time:    time.Unix(0, l.Time).Format(time.RFC3339),
		CPU:     l.CPU,
		Memory:  l.Memory,
		Load:    l.Load,
		Disk:    l.Disk,
		Net:     l.Net,
		Bytes:   l.Bytes,
		DBSpeed: l.DBSpeed,
		DBSize:  l.DBSize,
	}
	j, err := json.Marshal(r)
	if err != nil {
		return (err.Error())
	}
	return string(j)
}

func getSigmaRuleEvaluatorList(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {

	list := auditor.GetEvaluators()
	j, err := json.Marshal(&list)
	if err != nil {
		j = []byte(err.Error())
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(j)},
		},
	}, nil, nil
}

func getSigmaRuleIDList(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
	list := []string{}
	datastore.ForEachSigmaRuleOnDB(func(c []byte, k string) {
		a := strings.SplitN(k, ":", 3)
		if len(a) == 3 {
			list = append(list, a[2])
		}
	})
	j, err := json.Marshal(&list)
	if err != nil {
		j = []byte(err.Error())
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(j)},
		},
	}, nil, nil
}

type getSigmaRuleParams struct {
	ID string `json:"id" jsonschema:"id of sigma rule to get."`
}

func getSigmaRule(ctx context.Context, req *mcp.CallToolRequest, args getSigmaRuleParams) (*mcp.CallToolResult, any, error) {

	id := args.ID
	r, err := datastore.GetSigmaRuleFromDB(id)
	if err != nil {
		log.Printf("get sigma rule id=%s err=%v", id, err)
		r = err.Error()
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: r},
		},
	}, nil, nil
}

type addSigmaRuleParams struct {
	Rule string `json:"rule" jsonschema:"YAML-formatted Sigma rule string."`
}

func addSigmaRule(ctx context.Context, req *mcp.CallToolRequest, args addSigmaRuleParams) (*mcp.CallToolResult, any, error) {
	rule := args.Rule
	if rule == "" {
		return nil, nil, fmt.Errorf("rule is required")
	}
	if !strings.Contains(rule, "id: ") {
		// Auto generate ID
		i := uuid.New()
		rule = "id: " + i.String() + "\n" + rule
	}
	id, err := auditor.ParseSigmaRule(rule)
	if id == "" {
		return nil, nil, fmt.Errorf("invalid rule format")
	}
	if err != nil {
		log.Printf("parse sigma rule err=%v", err)
		log.Printf("rule=%s", rule)
		return nil, nil, err
	}
	err = datastore.AddSigmaRuleToDB(id, rule)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "add sigma rule id=" + id},
		},
	}, nil, nil
}

type deleteSigmaRuleParams struct {
	ID string `json:"id" jsonschema:"ID of sigma rule to delete"`
}

func deleteSigmaRule(ctx context.Context, req *mcp.CallToolRequest, args deleteSigmaRuleParams) (*mcp.CallToolResult, any, error) {
	id := args.ID
	err := datastore.DeleteSigmaRuleFromDB(id)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "delete sigma rule id=" + id},
		},
	}, nil, nil
}

func ReloadSigmaRule(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {

	go func() {
		time.Sleep(time.Second)
		auditor.Reload()
	}()
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "start reload"},
		},
	}, nil, nil
}
