package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

var mcpAllow sync.Map

func StartMCPServer(ctx context.Context, wg *sync.WaitGroup, cert, key string) {
	defer wg.Done()
	if datastore.Config.MCPEndpoint == "" {
		return
	}
	log.Printf("start mcp server")
	setMCPAllow()
	mcpsv, e := makeMCPServer(cert, key)
	<-ctx.Done()
	log.Println("stop mcp server")
	if mcpsv != nil {
		mcpsv.Shutdown(ctx)
	}
	if e != nil {
		e.Shutdown(ctx)
	}

}

func makeMCPServer(cert, key string) (*server.StreamableHTTPServer, *echo.Echo) {
	// Create MCP Server
	s := server.NewMCPServer(
		"TwLogEye MCP Server",
		"0.2.0",
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)
	// Add tools to MCP server
	addSearchLogTool(s)
	addSearchNotifyTool(s)
	addGetReportTool(s)
	addGetSigmaRuleEvaluatorListTool(s)
	addReloadSigmaRuleTool(s)
	addGetSigmaRuleIDListTool(s)
	addGetSigmaRuleTool(s)
	addAddSigmaRuleTool(s)
	addDeleteSigmaRuleTool(s)
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
	mcpsv := server.NewStreamableHTTPServer(s)
	e.Any("/mcp", func(c echo.Context) error {
		if !checkMCPACL(c) {
			return echo.ErrUnauthorized
		}
		mcpsv.ServeHTTP(c.Response().Writer, c.Request())
		return nil
	})
	log.Printf("start mcp server listening on %s", datastore.Config.MCPEndpoint)
	go func() {
		if err := e.StartServer(sv); err != nil {
			log.Printf("start mcp server err=%v", err)
		}
	}()
	return mcpsv, e
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

func addSearchLogTool(s *server.MCPServer) {
	tool := mcp.NewTool("search_log",
		mcp.WithDescription("search log from TwLogEye"),
		mcp.WithString("start",
			mcp.Description(`start date and time to search log. ex. 2025/08/30 11:00:00. empty is 1970/01/01 00:00:00`),
		),
		mcp.WithString("end",
			mcp.Description(`end date and time to search log. ex. 2025/08/30 11:00:00 empty is now.`),
		),
		mcp.WithString("type",
			mcp.Description(`type is type of log. type can be "syslog","trap","netflow","winevent"`),
		),
		mcp.WithString("filter",
			mcp.Description(`Log Filtering Using Regular Expressions`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		st := getTime(request.GetString("start", ""), 0)
		et := getTime(request.GetString("end", ""), time.Now().UnixNano())
		logType := request.GetString("type", "syslog")
		filter := makeRegexFilter(request.GetString("filter", ""))
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
		return mcp.NewToolResultText(string(j)), nil
	})
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

func addSearchNotifyTool(s *server.MCPServer) {
	tool := mcp.NewTool("search_notify",
		mcp.WithDescription("search notify from TwLogEye"),
		mcp.WithString("start",
			mcp.Description(`start date and time to search notify. ex. 2025/08/30 11:00:00. empty is 1970/01/01 00:00:00`),
		),
		mcp.WithString("end",
			mcp.Description(`end date and time to search notify. ex. 2025/08/30 11:00:00 empty is now.`),
		),
		mcp.WithString("level",
			mcp.Description(`Regular expression-based notify level filter. level name is "info","low","high","medium","critical" empty is no filter.`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		st := getTime(request.GetString("start", ""), 0)
		et := getTime(request.GetString("end", ""), time.Now().UnixNano())
		level := makeRegexFilter(request.GetString("level", ""))
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
		return mcp.NewToolResultText(string(j)), nil
	})
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

func addGetReportTool(s *server.MCPServer) {
	tool := mcp.NewTool("get_report",
		mcp.WithDescription("get report from TwLogEye"),
		mcp.WithString("start",
			mcp.Description(`start date and time to get report. ex. 2025/08/30 11:00:00. empty is 1970/01/01 00:00:00`),
		),
		mcp.WithString("end",
			mcp.Description(`end date and time to get report. ex. 2025/08/30 11:00:00 empty is now.`),
		),
		mcp.WithString("type",
			mcp.Description(`type of report. type can be "syslog","trap","netflow","winevent","anomaly","monitor"
"winevent" is windows event log`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		st := getTime(request.GetString("start", ""), 0)
		et := getTime(request.GetString("end", ""), time.Now().UnixNano())
		reportType := request.GetString("type", "syslog")
		r := ""
		switch reportType {
		case "trap":
			r = getTrapReport(st, et)
		case "netflow":
			r = getNetflowReport(st, et)
		case "winevent":
			r = getWindowsEventReport(st, et)
		case "anomaly":
			r = getAnomalyReport(st, et)
		case "monitor":
			r = getMonitorReport(st, et)
		default:
			r = getSyslogReport(st, et)
		}
		return mcp.NewToolResultText(r), nil
	})
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
	TopProtocolList    []datastore.NetflowProtocolCountEnt
	TopFumbleSrcList   []datastore.NetflowIPCountEnt
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

type mcpAnomalyReportEnt struct {
	Time    string
	Type    string
	Score   float64
	Max     float64
	MaxTime string
}

func getAnomalyReport(st, et int64) string {
	list := []mcpAnomalyReportEnt{}
	datastore.ForEachAnomalyReport(st, et, func(r *datastore.AnomalyReportEnt) bool {
		list = append(list,
			mcpAnomalyReportEnt{
				Time:    time.Unix(0, r.Time).Format(time.RFC3339),
				Type:    r.Type,
				Score:   r.Score,
				Max:     r.Max,
				MaxTime: time.Unix(0, r.MaxTime).Format(time.RFC3339),
			})
		return true
	})
	j, err := json.Marshal(&list)
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

func addGetSigmaRuleEvaluatorListTool(s *server.MCPServer) {
	tool := mcp.NewTool("get_sigma_evaluator_list",
		mcp.WithDescription("get sigma rule evaluator list from TwLogEye"),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		list := auditor.GetEvaluators()
		j, err := json.Marshal(&list)
		if err != nil {
			j = []byte(err.Error())
		}
		return mcp.NewToolResultText(string(j)), nil
	})
}

func addGetSigmaRuleIDListTool(s *server.MCPServer) {
	tool := mcp.NewTool("get_sigma_rule_id_list",
		mcp.WithDescription("get sigma rule id list from TwLogEye"),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		return mcp.NewToolResultText(string(j)), nil
	})
}

func addGetSigmaRuleTool(s *server.MCPServer) {
	tool := mcp.NewTool("get_sigma_rule",
		mcp.WithDescription("get sigma rule from TwLogEye"),
		mcp.WithString("id",
			mcp.Description(`id of sigma rule`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := request.GetString("id", "")
		r, err := datastore.GetSigmaRuleFromDB(id)
		if err != nil {
			log.Printf("get sigma rule id=%s err=%v", id, err)
			r = err.Error()
		}
		return mcp.NewToolResultText(r), nil
	})
}

func addAddSigmaRuleTool(s *server.MCPServer) {
	tool := mcp.NewTool("add_sigma_rule",
		mcp.WithDescription("add sigma rule to TwLogEye"),
		mcp.WithString("rule",
			mcp.Description(`YAML-formatted Sigma rule string.`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rule := request.GetString("rule", "")
		if rule == "" {
			return mcp.NewToolResultText("rule is empty"), nil
		}
		if !strings.Contains(rule, "id: ") {
			// Auto generate ID
			i := uuid.New()
			rule = "id: " + i.String() + "\n" + rule
		}
		id, err := auditor.ParseSigmaRule(rule)
		if id == "" {
			log.Printf("id not found rule=%s", rule)
			return mcp.NewToolResultText("id not found"), nil
		}
		if err != nil {
			log.Printf("parse sigma rule err=%v", err)
			log.Printf("rule=%s", rule)
			return mcp.NewToolResultText(err.Error()), nil
		}
		err = datastore.AddSigmaRuleToDB(id, rule)
		if err != nil {
			return mcp.NewToolResultText(err.Error()), nil
		}
		return mcp.NewToolResultText("add sigma rule id=" + id), nil
	})
}

func addDeleteSigmaRuleTool(s *server.MCPServer) {
	tool := mcp.NewTool("delete_sigma_rule",
		mcp.WithDescription("delete sigma rule from TwLogEye"),
		mcp.WithString("id",
			mcp.Description(`id of sigma rule`),
		),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := request.GetString("id", "")
		err := datastore.DeleteSigmaRuleFromDB(id)
		if err != nil {
			return mcp.NewToolResultText(err.Error()), nil
		}
		return mcp.NewToolResultText("delete sigma rule id=" + id), nil
	})
}

func addReloadSigmaRuleTool(s *server.MCPServer) {
	tool := mcp.NewTool("reload_sigma_rule",
		mcp.WithDescription("reload sigma rule"),
	)
	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		go func() {
			time.Sleep(time.Second)
			auditor.Reload()
		}()
		return mcp.NewToolResultText("start reload"), nil
	})
}
