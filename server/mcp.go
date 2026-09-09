package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/araddon/dateparse"
	"github.com/bradleyjkemp/sigma-go"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/twsnmp/twlogeye/api"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

var (
	mcpAllow   sync.Map
	grpcClient api.TWLogEyeServiceClient
)

func SetGRPCClient(c api.TWLogEyeServiceClient) {
	grpcClient = c
}

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

func NewMCPServer(version string) *mcp.Server {
	s := mcp.NewServer(
		&mcp.Implementation{
			Name:    "TwLogEye MCP Server",
			Version: version,
		}, nil)
	addTools(s)
	addPrompts(s)
	addResources(s)
	return s
}

func makeMCPServer(cert, key, version string) *echo.Echo {
	s := NewMCPServer(version)

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
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sigma_packs",
		Description: "Get list of available built-in Sigma rule packs or details of a specific pack.",
	}, getSigmaPacks)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "convert_wazuh_rules",
		Description: "Convert Wazuh XML rules to Sigma YAML rules with hierarchy resolution and correlation.",
	}, convertWazuhRules)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "convert_and_add_wazuh_rule",
		Description: "Convert Wazuh XML rules and add them directly to TwLogEye Sigma rule database.",
	}, convertAndAddWazuhRule)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "convert_wazuh_decoder",
		Description: "Convert Wazuh XML decoders to Go named-capture regex patterns for TwLogEye log extraction.",
	}, convertWazuhDecoder)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "investigate_ip",
		Description: "Investigate IP address including GeoIP, DNS PTR, and related logs (Netflow, Syslog, WinEvent, Trap).",
	}, investigateIP)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "test_sigma_rule",
		Description: "Backtest a YAML Sigma rule against historical logs to check matches and false positives.",
	}, testSigmaRule)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_otel_trace",
		Description: "Get OpenTelemetry trace details by trace ID.",
	}, getOTelTrace)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_otel_metric",
		Description: "Get OpenTelemetry metric details by metric key/ID.",
	}, getOTelMetric)
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
	s.AddPrompt(&mcp.Prompt{
		Name:        "investigate_incident",
		Title:       "Investigate security incident",
		Description: "Investigate a suspicious event or notification by checking logs, IP details, and threat indicators.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "target",
				Title:       "Target IP, hostname, or notification ID to investigate.",
				Description: "Target IP, hostname, or notification ID to investigate.",
				Required:    true,
			},
			{
				Name:        "time_range",
				Title:       "Time range (e.g. last 1 hour, last 24 hours).",
				Description: "Time range (e.g. last 1 hour, last 24 hours).",
				Required:    false,
			},
		},
	}, investigateIncidentPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "daily_security_briefing",
		Title:       "Daily Security Briefing",
		Description: "Generate a daily summary report of security notifications, anomaly scores, and error patterns.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "date",
				Title:       "Target date (e.g. today, yesterday, 2025/10/26).",
				Description: "Target date (e.g. today, yesterday, 2025/10/26).",
				Required:    false,
			},
		},
	}, dailySecurityBriefingPrompt)
	s.AddPrompt(&mcp.Prompt{
		Name:        "test_and_add_sigma_rule",
		Title:       "Test and Add Sigma Rule",
		Description: "Backtest a proposed Sigma rule against historical logs before adding it to TwLogEye.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "rule",
				Title:       "YAML-formatted Sigma rule.",
				Description: "YAML-formatted Sigma rule.",
				Required:    true,
			},
			{
				Name:        "log_type",
				Title:       "Log type to test (syslog, winevent, netflow, trap, otel, mqtt).",
				Description: "Log type to test (syslog, winevent, netflow, trap, otel, mqtt).",
				Required:    false,
			},
		},
	}, testAndAddSigmaRulePrompt)
}

func addResources(s *mcp.Server) {
	s.AddResource(&mcp.Resource{
		URI:         "twlogeye://status",
		Name:        "System Status",
		Description: "Current system status and resource metrics of TwLogEye.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      "twlogeye://status",
					MIMEType: "application/json",
					Text:     getLastMonitorReport(),
				},
			},
		}, nil
	})
	s.AddResource(&mcp.Resource{
		URI:         "twlogeye://sigma/rules",
		Name:        "Sigma Rule IDs",
		Description: "List of currently active Sigma Rule IDs.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		var ids []string
		if grpcClient != nil {
			resp, err := grpcClient.GetSigmaRuleList(ctx, &api.Empty{})
			if err == nil && resp != nil {
				ids = resp.GetRuleIds()
			}
		}
		if len(ids) == 0 {
			ids = auditor.GetRuleIDs()
		}
		if len(ids) == 0 {
			idMap := make(map[string]bool)
			datastore.ForEachSigmaRules(func(c []byte, p string) {
				rule, err := sigma.ParseRule(c)
				if err == nil {
					id := rule.ID
					if id == "" {
						id = p
					}
					if !idMap[id] {
						idMap[id] = true
						ids = append(ids, id)
					}
				}
			})
		}
		if ids == nil {
			ids = []string{}
		}
		j, _ := json.Marshal(ids)
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      "twlogeye://sigma/rules",
					MIMEType: "application/json",
					Text:     string(j),
				},
			},
		}, nil
	})
	s.AddResource(&mcp.Resource{
		URI:         "twlogeye://sigma/packs",
		Name:        "Sigma Rule Packs",
		Description: "List of available built-in Sigma rule packs with descriptions and rule counts.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		packs := datastore.GetAllSigmaPacksInfo()
		j, _ := json.Marshal(packs)
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      "twlogeye://sigma/packs",
					MIMEType: "application/json",
					Text:     string(j),
				},
			},
		}, nil
	})
	for _, rType := range []string{"syslog", "trap", "netflow", "winevent", "otel", "mqtt", "monitor", "anomaly"} {
		t := rType
		s.AddResource(&mcp.Resource{
			URI:         fmt.Sprintf("twlogeye://reports/%s/latest", t),
			Name:        fmt.Sprintf("Latest %s Report", t),
			Description: fmt.Sprintf("Latest generated report for %s.", t),
			MIMEType:    "application/json",
		}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			var text string
			switch t {
			case "trap":
				text = getLastTrapReport()
			case "netflow":
				text = getLastNetflowReport()
			case "winevent":
				text = getLastWindowsEventReport()
			case "otel":
				text = getLastOTelReport()
			case "mqtt":
				text = getLastMqttReport()
			case "monitor":
				text = getLastMonitorReport()
			case "anomaly":
				text = getLastAnomalyReport()
			default:
				text = getLastSyslogReport()
			}
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{
						URI:      fmt.Sprintf("twlogeye://reports/%s/latest", t),
						MIMEType: "application/json",
						Text:     text,
					},
				},
			}, nil
		})
	}
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
		if !strings.HasPrefix(t, "Bearer ") || strings.TrimPrefix(t, "Bearer ") != datastore.Config.MCPToken {
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

func toolError(msg string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
	}, nil, nil
}

func toolSuccess(msg string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
	}, nil, nil
}

type mcpLogEnt struct {
	Time string `json:"time"`
	Type string `json:"type"`
	Src  string `json:"src"`
	Log  string `json:"log"`
}

type searchLogParams struct {
	Filter string `json:"filter,omitempty" jsonschema:"Filter logs by regular expression. Empty is no filter"`
	Type   string `json:"type,omitempty" jsonschema:"Type of log to search. type can be syslog,trap,netflow,winevent,otel,mqtt. Default is syslog"`
	Start  string `json:"start,omitempty" jsonschema:"Start date and time for log search. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End    string `json:"end,omitempty" jsonschema:"End date and time for log search. Empty is now. Example: 2025/10/26 11:00:00"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of logs to return. Default 100, max 1000"`
}

func searchLog(ctx context.Context, req *mcp.CallToolRequest, args searchLogParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	logType := args.Type
	if logType == "" {
		logType = "syslog"
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	filter := makeRegexFilter(args.Filter)
	list := []mcpLogEnt{}

	if grpcClient != nil {
		stream, err := grpcClient.SearchLog(ctx, &api.LogRequest{
			Logtype: logType,
			Start:   st,
			End:     et,
			Search:  args.Filter,
		})
		if err == nil {
			for {
				l, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				if filter != nil && !filter.MatchString(l.GetLog()) {
					continue
				}
				list = append(list, mcpLogEnt{
					Time: time.Unix(0, l.GetTime()).Format(time.RFC3339Nano),
					Type: logType,
					Src:  l.GetSrc(),
					Log:  l.GetLog(),
				})
				if len(list) >= limit {
					break
				}
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return toolError(err.Error())
			}
			return toolSuccess(string(j))
		}
	}

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
		return len(list) < limit
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
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
	Time  string `json:"time"`
	Type  string `json:"type"`
	Log   string `json:"log"`
	Src   string `json:"src"`
	ID    string `json:"id"`
	Title string `json:"title"`
	Tags  string `json:"tags"`
	Level string `json:"level"`
}
type searchNotifyParams struct {
	Level string `json:"level,omitempty" jsonschema:"Regular expression-based notify level filter. level name is info,low,high,medium,critical empty is no filter."`
	Start string `json:"start,omitempty" jsonschema:"Start date and time for notify search. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end,omitempty" jsonschema:"End date and time for notify search. Empty is now. Example: 2025/10/26 11:00:00"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum number of notifications to return. Default 100, max 1000"`
}

func searchNotify(ctx context.Context, req *mcp.CallToolRequest, args searchNotifyParams) (*mcp.CallToolResult, any, error) {
	st := getTime(args.Start, 0)
	et := getTime(args.End, time.Now().UnixNano())
	limit := args.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	level := makeRegexFilter(args.Level)
	list := []mcpNotifyEnt{}

	if grpcClient != nil {
		stream, err := grpcClient.SearchNotify(ctx, &api.NofifyRequest{
			Start: st,
			End:   et,
			Level: args.Level,
		})
		if err == nil {
			for {
				n, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				if level != nil && !level.MatchString(n.GetLevel()) {
					continue
				}
				list = append(list, mcpNotifyEnt{
					Time:  time.Unix(0, n.GetTime()).Format(time.RFC3339Nano),
					Type:  "",
					Src:   n.GetSrc(),
					Log:   n.GetLog(),
					ID:    n.GetId(),
					Title: n.GetTitle(),
					Tags:  n.GetTags(),
					Level: n.GetLevel(),
				})
				if len(list) >= limit {
					break
				}
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return toolError(err.Error())
			}
			return toolSuccess(string(j))
		}
	}

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
		return len(list) < limit
	})
	j, err := json.Marshal(&list)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
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
	Type  string `json:"type,omitempty" jsonschema:"type of report. type can be syslog,trap,netflow,winevent,otel,mqtt,monitor. Default is syslog"`
	Start string `json:"start,omitempty" jsonschema:"Start date and time to get report. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end,omitempty" jsonschema:"End date and time to get report. Empty is now. Example: 2025/10/26 11:00:00"`
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
	Type string `json:"type,omitempty" jsonschema:"type of report. type can be syslog,trap,netflow,winevent,otel,anomaly,monitor. Default is syslog"`
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
	if grpcClient != nil {
		stream, err := grpcClient.GetSyslogReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topList := []datastore.LogSummaryEnt{}
				for _, t := range r.GetTopList() {
					topList = append(topList, datastore.LogSummaryEnt{
						LogPattern: t.GetLogPattern(),
						Count:      int(t.GetCount()),
					})
				}
				topErrorList := []datastore.LogSummaryEnt{}
				for _, t := range r.GetTopErrorList() {
					topErrorList = append(topErrorList, datastore.LogSummaryEnt{
						LogPattern: t.GetLogPattern(),
						Count:      int(t.GetCount()),
					})
				}
				list = append(list, mcpSyslogReportEnt{
					Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Normal:       int(r.GetNormal()),
					Warn:         int(r.GetWarn()),
					Error:        int(r.GetError()),
					Patterns:     int(r.GetPatterns()),
					ErrPatterns:  int(r.GetErrPatterns()),
					TopList:      topList,
					TopErrorList: topErrorList,
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastSyslogReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topList := []datastore.LogSummaryEnt{}
			for _, t := range r.GetTopList() {
				topList = append(topList, datastore.LogSummaryEnt{
					LogPattern: t.GetLogPattern(),
					Count:      int(t.GetCount()),
				})
			}
			topErrorList := []datastore.LogSummaryEnt{}
			for _, t := range r.GetTopErrorList() {
				topErrorList = append(topErrorList, datastore.LogSummaryEnt{
					LogPattern: t.GetLogPattern(),
					Count:      int(t.GetCount()),
				})
			}
			ent := &mcpSyslogReportEnt{
				Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Normal:       int(r.GetNormal()),
				Warn:         int(r.GetWarn()),
				Error:        int(r.GetError()),
				Patterns:     int(r.GetPatterns()),
				ErrPatterns:  int(r.GetErrPatterns()),
				TopList:      topList,
				TopErrorList: topErrorList,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		stream, err := grpcClient.GetTrapReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topList := []datastore.TrapSummaryEnt{}
				for _, t := range r.GetTopList() {
					topList = append(topList, datastore.TrapSummaryEnt{
						Sender:   t.GetSender(),
						TrapType: t.GetTrapType(),
						Count:    int(t.GetCount()),
					})
				}
				list = append(list, mcpTrapReportEnt{
					Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Count:   int(r.GetCount()),
					Types:   int(r.GetTypes()),
					TopList: topList,
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastTrapReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topList := []datastore.TrapSummaryEnt{}
			for _, t := range r.GetTopList() {
				topList = append(topList, datastore.TrapSummaryEnt{
					Sender:   t.GetSender(),
					TrapType: t.GetTrapType(),
					Count:    int(t.GetCount()),
				})
			}
			ent := &mcpTrapReportEnt{
				Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Count:   int(r.GetCount()),
				Types:   int(r.GetTypes()),
				TopList: topList,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		stream, err := grpcClient.GetNetflowReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topMACPackets := []datastore.NetflowPacketsSummaryEnt{}
				for _, t := range r.GetTopMacPacketsList() {
					topMACPackets = append(topMACPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
				}
				topMACBytes := []datastore.NetflowBytesSummaryEnt{}
				for _, t := range r.GetTopMacBytesList() {
					topMACBytes = append(topMACBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
				}
				topIPPackets := []datastore.NetflowPacketsSummaryEnt{}
				for _, t := range r.GetTopIpPacketsList() {
					topIPPackets = append(topIPPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
				}
				topIPBytes := []datastore.NetflowBytesSummaryEnt{}
				for _, t := range r.GetTopIpBytesList() {
					topIPBytes = append(topIPBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
				}
				topFlowPackets := []datastore.NetflowPacketsSummaryEnt{}
				for _, t := range r.GetTopFlowPacketsList() {
					topFlowPackets = append(topFlowPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
				}
				topFlowBytes := []datastore.NetflowBytesSummaryEnt{}
				for _, t := range r.GetTopFlowBytesList() {
					topFlowBytes = append(topFlowBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
				}
				topProtocol := []datastore.NetflowKeyCountEnt{}
				for _, t := range r.GetTopProtocolList() {
					topProtocol = append(topProtocol, datastore.NetflowKeyCountEnt{Key: t.GetKey(), Count: int(t.GetCount())})
				}
				topFumble := []datastore.NetflowKeyCountEnt{}
				for _, t := range r.GetTopFumbleSrcList() {
					topFumble = append(topFumble, datastore.NetflowKeyCountEnt{Key: t.GetKey(), Count: int(t.GetCount())})
				}
				list = append(list, mcpNetflowReportEnt{
					Time:               time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Packets:            r.GetPackets(),
					Bytes:              r.GetBytes(),
					MACs:               int(r.GetMacs()),
					IPs:                int(r.GetIps()),
					Flows:              int(r.GetFlows()),
					Protocols:          int(r.GetProtocols()),
					Fumbles:            int(r.GetFumbles()),
					TopMACPacketsList:  topMACPackets,
					TopMACBytesList:    topMACBytes,
					TopIPPacketsList:   topIPPackets,
					TopIPBytesList:     topIPBytes,
					TopFlowPacketsList: topFlowPackets,
					TopFlowBytesList:   topFlowBytes,
					TopProtocolList:    topProtocol,
					TopFumbleSrcList:   topFumble,
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastNetflowReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topMACPackets := []datastore.NetflowPacketsSummaryEnt{}
			for _, t := range r.GetTopMacPacketsList() {
				topMACPackets = append(topMACPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
			}
			topMACBytes := []datastore.NetflowBytesSummaryEnt{}
			for _, t := range r.GetTopMacBytesList() {
				topMACBytes = append(topMACBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
			}
			topIPPackets := []datastore.NetflowPacketsSummaryEnt{}
			for _, t := range r.GetTopIpPacketsList() {
				topIPPackets = append(topIPPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
			}
			topIPBytes := []datastore.NetflowBytesSummaryEnt{}
			for _, t := range r.GetTopIpBytesList() {
				topIPBytes = append(topIPBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
			}
			topFlowPackets := []datastore.NetflowPacketsSummaryEnt{}
			for _, t := range r.GetTopFlowPacketsList() {
				topFlowPackets = append(topFlowPackets, datastore.NetflowPacketsSummaryEnt{Key: t.GetKey(), Packets: int(t.GetPackets())})
			}
			topFlowBytes := []datastore.NetflowBytesSummaryEnt{}
			for _, t := range r.GetTopFlowBytesList() {
				topFlowBytes = append(topFlowBytes, datastore.NetflowBytesSummaryEnt{Key: t.GetKey(), Bytes: t.GetBytes()})
			}
			topProtocol := []datastore.NetflowKeyCountEnt{}
			for _, t := range r.GetTopProtocolList() {
				topProtocol = append(topProtocol, datastore.NetflowKeyCountEnt{Key: t.GetKey(), Count: int(t.GetCount())})
			}
			topFumble := []datastore.NetflowKeyCountEnt{}
			for _, t := range r.GetTopFumbleSrcList() {
				topFumble = append(topFumble, datastore.NetflowKeyCountEnt{Key: t.GetKey(), Count: int(t.GetCount())})
			}
			ent := &mcpNetflowReportEnt{
				Time:               time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Packets:            r.GetPackets(),
				Bytes:              r.GetBytes(),
				MACs:               int(r.GetMacs()),
				IPs:                int(r.GetIps()),
				Flows:              int(r.GetFlows()),
				Protocols:          int(r.GetProtocols()),
				Fumbles:            int(r.GetFumbles()),
				TopMACPacketsList:  topMACPackets,
				TopMACBytesList:    topMACBytes,
				TopIPPacketsList:   topIPPackets,
				TopIPBytesList:     topIPBytes,
				TopFlowPacketsList: topFlowPackets,
				TopFlowBytesList:   topFlowBytes,
				TopProtocolList:    topProtocol,
				TopFumbleSrcList:   topFumble,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		stream, err := grpcClient.GetWindowsEventReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topList := []datastore.WindowsEventSummary{}
				for _, t := range r.GetTopList() {
					topList = append(topList, datastore.WindowsEventSummary{
						Computer: t.GetComputer(),
						Provider: t.GetProvider(),
						EventID:  t.GetEventId(),
						Count:    int(t.GetCount()),
					})
				}
				topErrorList := []datastore.WindowsEventSummary{}
				for _, t := range r.GetTopErrorList() {
					topErrorList = append(topErrorList, datastore.WindowsEventSummary{
						Computer: t.GetComputer(),
						Provider: t.GetProvider(),
						EventID:  t.GetEventId(),
						Count:    int(t.GetCount()),
					})
				}
				list = append(list, mcpWindowsEventReportEnt{
					Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Normal:       int(r.GetNormal()),
					Warn:         int(r.GetWarn()),
					Error:        int(r.GetError()),
					TopList:      topList,
					TopErrorList: topErrorList,
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastWindowsEventReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topList := []datastore.WindowsEventSummary{}
			for _, t := range r.GetTopList() {
				topList = append(topList, datastore.WindowsEventSummary{
					Computer: t.GetComputer(),
					Provider: t.GetProvider(),
					EventID:  t.GetEventId(),
					Count:    int(t.GetCount()),
				})
			}
			topErrorList := []datastore.WindowsEventSummary{}
			for _, t := range r.GetTopErrorList() {
				topErrorList = append(topErrorList, datastore.WindowsEventSummary{
					Computer: t.GetComputer(),
					Provider: t.GetProvider(),
					EventID:  t.GetEventId(),
					Count:    int(t.GetCount()),
				})
			}
			ent := &mcpWindowsEventReportEnt{
				Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Normal:       int(r.GetNormal()),
				Warn:         int(r.GetWarn()),
				Error:        int(r.GetError()),
				TopList:      topList,
				TopErrorList: topErrorList,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		stream, err := grpcClient.GetOTelReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topList := []datastore.OTelSummaryEnt{}
				for _, t := range r.GetTopList() {
					topList = append(topList, datastore.OTelSummaryEnt{
						Host:     t.GetHost(),
						Service:  t.GetService(),
						Scope:    t.GetScope(),
						Severity: t.GetSeverity(),
						Count:    int(t.GetCount()),
					})
				}
				topErrorList := []datastore.OTelSummaryEnt{}
				for _, t := range r.GetTopErrorList() {
					topErrorList = append(topErrorList, datastore.OTelSummaryEnt{
						Host:     t.GetHost(),
						Service:  t.GetService(),
						Scope:    t.GetScope(),
						Severity: t.GetSeverity(),
						Count:    int(t.GetCount()),
					})
				}
				list = append(list, mcpOTelReportEnt{
					Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Normal:       int(r.GetNormal()),
					Warn:         int(r.GetWarn()),
					Error:        int(r.GetError()),
					ErrorTypes:   int(r.GetErrorTypes()),
					TopList:      topList,
					TopErrorList: topErrorList,
					Hosts:        int(r.GetHosts()),
					TraceIDs:     int(r.GetTraceIds()),
					TraceCount:   int(r.GetTraceCount()),
					MericsCount:  int(r.GetMericsCount()),
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastOTelReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topList := []datastore.OTelSummaryEnt{}
			for _, t := range r.GetTopList() {
				topList = append(topList, datastore.OTelSummaryEnt{
					Host:     t.GetHost(),
					Service:  t.GetService(),
					Scope:    t.GetScope(),
					Severity: t.GetSeverity(),
					Count:    int(t.GetCount()),
				})
			}
			topErrorList := []datastore.OTelSummaryEnt{}
			for _, t := range r.GetTopErrorList() {
				topErrorList = append(topErrorList, datastore.OTelSummaryEnt{
					Host:     t.GetHost(),
					Service:  t.GetService(),
					Scope:    t.GetScope(),
					Severity: t.GetSeverity(),
					Count:    int(t.GetCount()),
				})
			}
			ent := &mcpOTelReportEnt{
				Time:         time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Normal:       int(r.GetNormal()),
				Warn:         int(r.GetWarn()),
				Error:        int(r.GetError()),
				ErrorTypes:   int(r.GetErrorTypes()),
				TopList:      topList,
				TopErrorList: topErrorList,
				Hosts:        int(r.GetHosts()),
				TraceIDs:     int(r.GetTraceIds()),
				TraceCount:   int(r.GetTraceCount()),
				MericsCount:  int(r.GetMericsCount()),
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
	l := datastore.GetLastOTelReport()
	if l == nil {
		return "otel report not found"
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
	if grpcClient != nil {
		stream, err := grpcClient.GetMqttReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				topList := []datastore.MqttSummaryEnt{}
				for _, t := range r.GetTopList() {
					topList = append(topList, datastore.MqttSummaryEnt{
						ClientID: t.GetClientId(),
						Topic:    t.GetTopic(),
						Count:    int(t.GetCount()),
					})
				}
				list = append(list, mcpMqttReportEnt{
					Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Count:   int(r.GetCount()),
					Types:   int(r.GetTypes()),
					TopList: topList,
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastMqttReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			topList := []datastore.MqttSummaryEnt{}
			for _, t := range r.GetTopList() {
				topList = append(topList, datastore.MqttSummaryEnt{
					ClientID: t.GetClientId(),
					Topic:    t.GetTopic(),
					Count:    int(t.GetCount()),
				})
			}
			ent := &mcpMqttReportEnt{
				Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
				Count:   int(r.GetCount()),
				Types:   int(r.GetTypes()),
				TopList: topList,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	Type  string `json:"type,omitempty" jsonschema:"type of anomaly report. type can be syslog,trap,netflow,winevent,otel,monitor. Default is syslog"`
	Start string `json:"start,omitempty" jsonschema:"Start date and time to get report. Empty is 1970/1/1. Example: 2025/10/26 11:00:00"`
	End   string `json:"end,omitempty" jsonschema:"End date and time to get report. Empty is now. Example: 2025/10/26 11:00:00"`
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
	if t == "" {
		t = "syslog"
	}
	list := []mcpAnomalyReportEnt{}
	if grpcClient != nil {
		stream, err := grpcClient.GetAnomalyReport(context.Background(), &api.AnomalyReportRequest{Type: t, Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				list = append(list, mcpAnomalyReportEnt{
					Time:  time.Unix(0, r.GetTime()).Format(time.RFC3339),
					Score: r.GetScore(),
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastAnomalyReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			scores := []*mcpLastAnomalyReportScore{}
			for _, s := range r.GetScoreList() {
				scores = append(scores, &mcpLastAnomalyReportScore{
					Time:  time.Unix(0, s.GetTime()).Format(time.RFC3339),
					Type:  s.GetType(),
					Score: s.GetScore(),
				})
			}
			ent := &mcpLastAnomalyReportEnt{
				Time:      time.Unix(0, r.GetTime()).Format(time.RFC3339),
				ScoreList: scores,
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		stream, err := grpcClient.GetMonitorReport(context.Background(), &api.ReportRequest{Start: st, End: et})
		if err == nil {
			for {
				r, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				list = append(list, mcpMonitorReportEnt{
					Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
					CPU:     r.GetCpu(),
					Memory:  r.GetMemory(),
					Load:    r.GetLoad(),
					Disk:    r.GetDisk(),
					Net:     r.GetNet(),
					Bytes:   r.GetBytes(),
					DBSpeed: r.GetDbSpeed(),
					DBSize:  r.GetDbSize(),
				})
			}
			j, err := json.Marshal(&list)
			if err != nil {
				return err.Error()
			}
			return string(j)
		}
	}
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
	if grpcClient != nil {
		r, err := grpcClient.GetLastMonitorReport(context.Background(), &api.Empty{})
		if err == nil && r != nil {
			ent := &mcpMonitorReportEnt{
				Time:    time.Unix(0, r.GetTime()).Format(time.RFC3339),
				CPU:     r.GetCpu(),
				Memory:  r.GetMemory(),
				Load:    r.GetLoad(),
				Disk:    r.GetDisk(),
				Net:     r.GetNet(),
				Bytes:   r.GetBytes(),
				DBSpeed: r.GetDbSpeed(),
				DBSize:  r.GetDbSize(),
			}
			if j, err := json.Marshal(ent); err == nil {
				return string(j)
			}
		}
	}
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
	if grpcClient != nil {
		resp, err := grpcClient.GetSigmaRuleList(ctx, &api.Empty{})
		if err == nil && resp != nil {
			j, _ := json.Marshal(resp.GetRuleIds())
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(j)},
				},
			}, nil, nil
		}
	}
	entries := auditor.GetRuleEntries()
	if len(entries) > 0 {
		type ruleInfo struct {
			ID          string                     `json:"id"`
			Title       string                     `json:"title"`
			Level       string                     `json:"level"`
			Logsource   map[string]string          `json:"logsource,omitempty"`
			Source      string                     `json:"source,omitempty"`
			Path        string                     `json:"path,omitempty"`
			Correlation *auditor.CorrelationConfig `json:"correlation,omitempty"`
		}
		var list []ruleInfo
		for _, e := range entries {
			if e != nil && e.Evaluator != nil {
				ls := make(map[string]string)
				if e.Evaluator.Rule.Logsource.Product != "" {
					ls["product"] = e.Evaluator.Rule.Logsource.Product
				}
				if e.Evaluator.Rule.Logsource.Category != "" {
					ls["category"] = e.Evaluator.Rule.Logsource.Category
				}
				if e.Evaluator.Rule.Logsource.Service != "" {
					ls["service"] = e.Evaluator.Rule.Logsource.Service
				}
				list = append(list, ruleInfo{
					ID:          e.Evaluator.Rule.ID,
					Title:       e.Evaluator.Rule.Title,
					Level:       e.Evaluator.Rule.Level,
					Logsource:   ls,
					Source:      e.Source,
					Path:        e.Path,
					Correlation: e.Correlation,
				})
			}
		}
		j, err := json.Marshal(&list)
		if err == nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(j)},
				},
			}, nil, nil
		}
	}
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
	if grpcClient != nil {
		resp, err := grpcClient.GetSigmaRuleList(ctx, &api.Empty{})
		if err == nil && resp != nil {
			j, _ := json.Marshal(resp.GetRuleIds())
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(j)},
				},
			}, nil, nil
		}
	}
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
	if grpcClient != nil {
		resp, err := grpcClient.GetSigmaRule(ctx, &api.IDRequest{Id: id})
		if err == nil && resp != nil && resp.GetRule() != "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: resp.GetRule()},
				},
			}, nil, nil
		}
	}
	r := auditor.GetRule(id)
	if r == "" {
		return toolError(fmt.Sprintf("sigma rule %s not found", id))
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
	if grpcClient != nil {
		resp, err := grpcClient.AddSigmaRule(ctx, &api.SigmaRuleRequest{Id: id, Rule: rule})
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: resp.GetMessage()},
			},
		}, nil, nil
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
	if grpcClient != nil {
		resp, err := grpcClient.DeleteSigmaRule(ctx, &api.IDRequest{Id: id})
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: resp.GetMessage()},
			},
		}, nil, nil
	}
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
	if grpcClient != nil {
		resp, err := grpcClient.Reload(ctx, &api.Empty{})
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: resp.GetMessage()},
			},
		}, nil, nil
	}
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

type getSigmaPacksParams struct {
	Pack string `json:"pack,omitempty" jsonschema:"Optional pack name to get detailed rule list for a specific pack"`
}

func getSigmaPacks(ctx context.Context, req *mcp.CallToolRequest, args getSigmaPacksParams) (*mcp.CallToolResult, any, error) {
	if args.Pack != "" {
		info, err := datastore.GetSigmaPackInfo(args.Pack, true)
		if err != nil {
			return toolError(err.Error())
		}
		j, err := json.Marshal(info)
		if err != nil {
			return toolError(err.Error())
		}
		return toolSuccess(string(j))
	}
	packs := datastore.GetAllSigmaPacksInfo()
	j, err := json.Marshal(packs)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type convertWazuhRulesParams struct {
	XML            string `json:"xml" jsonschema:"Wazuh rules XML content to convert"`
	MinLevel       int    `json:"min_level,omitempty" jsonschema:"Minimum Wazuh rule level to convert (default 0)"`
	SkipFrequency  bool   `json:"skip_frequency,omitempty" jsonschema:"Skip frequency/timeframe correlation attributes"`
	DefaultProduct string `json:"default_product,omitempty" jsonschema:"Default Sigma logsource product (e.g. linux, windows)"`
	DefaultService string `json:"default_service,omitempty" jsonschema:"Default Sigma logsource service (e.g. sshd, sudo)"`
}

type mcpConvertedRule struct {
	ID             string                    `json:"id"`
	Title          string                    `json:"title"`
	Level          string                    `json:"level"`
	YAML           string                    `json:"yaml"`
	HasCorrelation bool                      `json:"has_correlation"`
	Correlation    *auditor.SigmaCorrelation `json:"correlation,omitempty"`
}

type mcpConvertWazuhResult struct {
	TotalRules     int                `json:"total_rules"`
	ConvertedCount int                `json:"converted_count"`
	Rules          []mcpConvertedRule `json:"rules"`
}

func convertWazuhRules(ctx context.Context, req *mcp.CallToolRequest, args convertWazuhRulesParams) (*mcp.CallToolResult, any, error) {
	xmlStr := strings.TrimSpace(args.XML)
	if xmlStr == "" {
		return toolError("xml is required")
	}
	rawRules, err := auditor.ParseWazuhRulesXML([]byte(xmlStr))
	if err != nil {
		return toolError(fmt.Sprintf("failed to parse Wazuh rules XML: %v", err))
	}
	resolved := auditor.ResolveRuleHierarchy(rawRules, args.DefaultService)
	opts := auditor.WazuhConvertOptions{
		MinLevel:       args.MinLevel,
		SkipFrequency:  args.SkipFrequency,
		DefaultProduct: args.DefaultProduct,
		DefaultService: args.DefaultService,
	}
	result := mcpConvertWazuhResult{
		TotalRules: len(rawRules),
		Rules:      []mcpConvertedRule{},
	}
	for _, r := range resolved {
		sigmaRule, err := auditor.ConvertWazuhRuleToSigma(r, opts)
		if err != nil || sigmaRule == nil {
			continue
		}
		yamlBytes, err := auditor.FormatSigmaYAML(sigmaRule)
		if err != nil {
			continue
		}
		converted := mcpConvertedRule{
			ID:             sigmaRule.ID,
			Title:          sigmaRule.Title,
			Level:          sigmaRule.Level,
			YAML:           string(yamlBytes),
			HasCorrelation: sigmaRule.Correlation != nil,
			Correlation:    sigmaRule.Correlation,
		}
		result.Rules = append(result.Rules, converted)
	}
	result.ConvertedCount = len(result.Rules)
	j, err := json.Marshal(result)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type mcpConvertAndAddResult struct {
	TotalRules int      `json:"total_rules"`
	AddedCount int      `json:"added_count"`
	AddedIDs   []string `json:"added_ids"`
	Errors     []string `json:"errors,omitempty"`
}

func convertAndAddWazuhRule(ctx context.Context, req *mcp.CallToolRequest, args convertWazuhRulesParams) (*mcp.CallToolResult, any, error) {
	xmlStr := strings.TrimSpace(args.XML)
	if xmlStr == "" {
		return toolError("xml is required")
	}
	rawRules, err := auditor.ParseWazuhRulesXML([]byte(xmlStr))
	if err != nil {
		return toolError(fmt.Sprintf("failed to parse Wazuh rules XML: %v", err))
	}
	resolved := auditor.ResolveRuleHierarchy(rawRules, args.DefaultService)
	opts := auditor.WazuhConvertOptions{
		MinLevel:       args.MinLevel,
		SkipFrequency:  args.SkipFrequency,
		DefaultProduct: args.DefaultProduct,
		DefaultService: args.DefaultService,
	}
	res := mcpConvertAndAddResult{
		TotalRules: len(rawRules),
		AddedIDs:   []string{},
	}
	for _, r := range resolved {
		sigmaRule, err := auditor.ConvertWazuhRuleToSigma(r, opts)
		if err != nil || sigmaRule == nil {
			continue
		}
		yamlBytes, err := auditor.FormatSigmaYAML(sigmaRule)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("rule %s format yaml error: %v", sigmaRule.ID, err))
			continue
		}
		id := sigmaRule.ID
		ruleContent := string(yamlBytes)
		if grpcClient != nil {
			resp, err := grpcClient.AddSigmaRule(ctx, &api.SigmaRuleRequest{Id: id, Rule: ruleContent})
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("rule %s grpc error: %v", id, err))
				continue
			}
			_ = resp
			res.AddedIDs = append(res.AddedIDs, id)
			res.AddedCount++
		} else {
			if err := datastore.AddSigmaRuleToDB(id, ruleContent); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("rule %s db error: %v", id, err))
				continue
			}
			res.AddedIDs = append(res.AddedIDs, id)
			res.AddedCount++
		}
	}
	if res.AddedCount > 0 {
		if grpcClient != nil {
			_, _ = grpcClient.Reload(ctx, &api.Empty{})
		} else {
			go func() {
				time.Sleep(time.Second)
				auditor.Reload()
			}()
		}
	}
	j, err := json.Marshal(res)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type convertWazuhDecoderParams struct {
	XML string `json:"xml" jsonschema:"Wazuh decoders XML content to convert"`
}

type mcpConvertedDecoder struct {
	Name   string `json:"name"`
	Parent string `json:"parent,omitempty"`
	Order  string `json:"order"`
	Regex  string `json:"regex"`
}

type mcpConvertDecoderResult struct {
	TotalDecoders  int                   `json:"total_decoders"`
	ConvertedCount int                   `json:"converted_count"`
	Decoders       []mcpConvertedDecoder `json:"decoders"`
}

func convertWazuhDecoder(ctx context.Context, req *mcp.CallToolRequest, args convertWazuhDecoderParams) (*mcp.CallToolResult, any, error) {
	xmlStr := strings.TrimSpace(args.XML)
	if xmlStr == "" {
		return toolError("xml is required")
	}
	decs, err := auditor.ParseWazuhDecodersXML([]byte(xmlStr))
	if err != nil {
		return toolError(fmt.Sprintf("failed to parse Wazuh decoders XML: %v", err))
	}
	res := mcpConvertDecoderResult{
		TotalDecoders: len(decs),
		Decoders:      []mcpConvertedDecoder{},
	}
	for _, d := range decs {
		if d.Regex == "" || d.Order == "" {
			continue
		}
		re, err := auditor.ConvertDecoderToNamedRegex(d)
		if err != nil {
			continue
		}
		res.Decoders = append(res.Decoders, mcpConvertedDecoder{
			Name:   d.Name,
			Parent: d.Parent,
			Order:  d.Order,
			Regex:  re,
		})
	}
	res.ConvertedCount = len(res.Decoders)
	j, err := json.Marshal(res)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type investigateIPParams struct {
	IP    string `json:"ip" jsonschema:"IP address to investigate"`
	Start string `json:"start,omitempty" jsonschema:"Start date and time. Empty is 24 hours ago. Example: 2025/10/26 11:00:00"`
	End   string `json:"end,omitempty" jsonschema:"End date and time. Empty is now. Example: 2025/10/26 11:00:00"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum number of related logs to return. Default 20, max 100"`
}

type mcpInvestigateIPResult struct {
	IP          string         `json:"ip"`
	GeoLocation string         `json:"geo_location"`
	HostName    string         `json:"host_name"`
	Logs        []mcpLogEnt    `json:"logs"`
	Notifies    []mcpNotifyEnt `json:"notifies"`
}

func investigateIP(ctx context.Context, req *mcp.CallToolRequest, args investigateIPParams) (*mcp.CallToolResult, any, error) {
	ip := strings.TrimSpace(args.IP)
	if ip == "" {
		return toolError("ip is required")
	}
	st := getTime(args.Start, time.Now().Add(-24*time.Hour).UnixNano())
	et := getTime(args.End, time.Now().UnixNano())
	limit := args.Limit
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	res := mcpInvestigateIPResult{
		IP:          ip,
		GeoLocation: datastore.GetLocByIP(ip),
		HostName:    datastore.GetHostByIP(ip),
		Logs:        []mcpLogEnt{},
		Notifies:    []mcpNotifyEnt{},
	}

	for _, logType := range []string{"syslog", "netflow", "winevent", "trap"} {
		if grpcClient != nil {
			stream, err := grpcClient.SearchLog(ctx, &api.LogRequest{
				Logtype: logType,
				Start:   st,
				End:     et,
				Search:  ip,
			})
			if err == nil {
				for {
					l, err := stream.Recv()
					if errors.Is(err, io.EOF) || err != nil {
						break
					}
					if l.GetSrc() == ip || strings.Contains(l.GetLog(), ip) {
						res.Logs = append(res.Logs, mcpLogEnt{
							Time: time.Unix(0, l.GetTime()).Format(time.RFC3339Nano),
							Type: logType,
							Src:  l.GetSrc(),
							Log:  l.GetLog(),
						})
					}
					if len(res.Logs) >= limit {
						break
					}
				}
			}
		} else {
			datastore.ForEachLog(logType, st, et, func(l *datastore.LogEnt) bool {
				if l.Src == ip || strings.Contains(l.Log, ip) {
					res.Logs = append(res.Logs, mcpLogEnt{
						Time: time.Unix(0, l.Time).Format(time.RFC3339Nano),
						Type: l.Type.String(),
						Src:  l.Src,
						Log:  l.Log,
					})
				}
				return len(res.Logs) < limit
			})
		}
		if len(res.Logs) >= limit {
			break
		}
	}

	if grpcClient != nil {
		stream, err := grpcClient.SearchNotify(ctx, &api.NofifyRequest{
			Start: st,
			End:   et,
		})
		if err == nil {
			for {
				n, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				if n.GetSrc() == ip || strings.Contains(n.GetLog(), ip) || strings.Contains(n.GetTitle(), ip) {
					res.Notifies = append(res.Notifies, mcpNotifyEnt{
						Time:  time.Unix(0, n.GetTime()).Format(time.RFC3339Nano),
						Type:  "",
						Src:   n.GetSrc(),
						Log:   n.GetLog(),
						ID:    n.GetId(),
						Title: n.GetTitle(),
						Tags:  n.GetTags(),
						Level: n.GetLevel(),
					})
				}
				if len(res.Notifies) >= limit {
					break
				}
			}
		}
	} else {
		datastore.ForEachNotify(st, et, func(n *datastore.NotifyEnt) bool {
			if n.Src == ip || strings.Contains(n.Log, ip) || strings.Contains(n.Title, ip) {
				res.Notifies = append(res.Notifies, mcpNotifyEnt{
					Time:  time.Unix(0, n.Time).Format(time.RFC3339Nano),
					Type:  n.Type.String(),
					Src:   n.Src,
					Log:   n.Log,
					ID:    n.ID,
					Title: n.Title,
					Tags:  n.Tags,
					Level: n.Level,
				})
			}
			return len(res.Notifies) < limit
		})
	}

	j, err := json.Marshal(&res)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type testSigmaRuleParams struct {
	Rule  string `json:"rule" jsonschema:"YAML-formatted Sigma rule string to backtest"`
	Type  string `json:"type,omitempty" jsonschema:"Type of log to test against. Default syslog (can be syslog,trap,netflow,winevent,otel,mqtt)"`
	Start string `json:"start,omitempty" jsonschema:"Start date and time. Empty is 24 hours ago. Example: 2025/10/26 11:00:00"`
	End   string `json:"end,omitempty" jsonschema:"End date and time. Empty is now. Example: 2025/10/26 11:00:00"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum number of sample matched logs to return. Default 5, max 50"`
}

type mcpTestSigmaRuleResult struct {
	RuleID       string      `json:"rule_id"`
	TotalScanned int         `json:"total_scanned"`
	TotalMatches int         `json:"total_matches"`
	Samples      []mcpLogEnt `json:"samples"`
}

func testSigmaRule(ctx context.Context, req *mcp.CallToolRequest, args testSigmaRuleParams) (*mcp.CallToolResult, any, error) {
	if args.Rule == "" {
		return toolError("rule is required")
	}
	ev, err := auditor.CreateRuleEvaluator(args.Rule)
	if err != nil {
		return toolError(fmt.Sprintf("failed to parse sigma rule: %v", err))
	}
	st := getTime(args.Start, time.Now().Add(-24*time.Hour).UnixNano())
	et := getTime(args.End, time.Now().UnixNano())
	logType := args.Type
	if logType == "" {
		logType = "syslog"
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 5
	} else if limit > 50 {
		limit = 50
	}

	res := mcpTestSigmaRuleResult{
		RuleID:  ev.Rule.ID,
		Samples: []mcpLogEnt{},
	}

	if grpcClient != nil {
		stream, err := grpcClient.SearchLog(ctx, &api.LogRequest{
			Logtype: logType,
			Start:   st,
			End:     et,
		})
		if err == nil {
			for {
				l, err := stream.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					break
				}
				res.TotalScanned++
				logEnt := &datastore.LogEnt{
					Time: l.GetTime(),
					Src:  l.GetSrc(),
					Log:  l.GetLog(),
				}
				if auditor.MatchSigmaRuleWithEvaluator(ev, logEnt) {
					res.TotalMatches++
					if len(res.Samples) < limit {
						res.Samples = append(res.Samples, mcpLogEnt{
							Time: time.Unix(0, l.GetTime()).Format(time.RFC3339Nano),
							Type: logType,
							Src:  l.GetSrc(),
							Log:  l.GetLog(),
						})
					}
				}
			}
			j, err := json.Marshal(&res)
			if err != nil {
				return toolError(err.Error())
			}
			return toolSuccess(string(j))
		}
	}

	datastore.ForEachLog(logType, st, et, func(l *datastore.LogEnt) bool {
		res.TotalScanned++
		if auditor.MatchSigmaRuleWithEvaluator(ev, l) {
			res.TotalMatches++
			if len(res.Samples) < limit {
				res.Samples = append(res.Samples, mcpLogEnt{
					Time: time.Unix(0, l.Time).Format(time.RFC3339Nano),
					Type: l.Type.String(),
					Src:  l.Src,
					Log:  l.Log,
				})
			}
		}
		return true
	})

	j, err := json.Marshal(&res)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type getOTelTraceParams struct {
	ID string `json:"id" jsonschema:"Trace ID of OpenTelemetry trace"`
}

func getOTelTrace(ctx context.Context, req *mcp.CallToolRequest, args getOTelTraceParams) (*mcp.CallToolResult, any, error) {
	if args.ID == "" {
		return toolError("id is required")
	}
	if grpcClient != nil {
		t, err := grpcClient.GetOTelTrace(ctx, &api.IDRequest{Id: args.ID})
		if err == nil && t != nil {
			j, err := json.Marshal(t)
			if err != nil {
				return toolError(err.Error())
			}
			return toolSuccess(string(j))
		}
	}
	t := datastore.GetOTelTrace(args.ID)
	if t == nil {
		return toolError("trace not found")
	}
	j, err := json.Marshal(t)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

type getOTelMetricParams struct {
	ID string `json:"id" jsonschema:"Metric ID/key of OpenTelemetry metric"`
}

func getOTelMetric(ctx context.Context, req *mcp.CallToolRequest, args getOTelMetricParams) (*mcp.CallToolResult, any, error) {
	if args.ID == "" {
		return toolError("id is required")
	}
	if grpcClient != nil {
		m, err := grpcClient.GetOTelMetric(ctx, &api.IDRequest{Id: args.ID})
		if err == nil && m != nil {
			j, err := json.Marshal(m)
			if err != nil {
				return toolError(err.Error())
			}
			return toolSuccess(string(j))
		}
	}
	m := datastore.GetOTelMetric(args.ID)
	if m == nil {
		return toolError("metric not found")
	}
	j, err := json.Marshal(m)
	if err != nil {
		return toolError(err.Error())
	}
	return toolSuccess(string(j))
}

func investigateIncidentPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	target := req.Params.Arguments["target"]
	timeRange := req.Params.Arguments["time_range"]
	p := fmt.Sprintf(`Please investigate the security incident related to target: '%s'.
1. If '%s' is an IP address, use investigate_ip to retrieve GeoIP, DNS host, and correlated logs/alerts.
2. If it is a notification or rule, search notifications with search_notify and search associated logs with search_log.
3. Check the anomaly score reports using get_last_report or get_anomaly_report.
4. Summarize the timeline, severity, affected systems, root cause hypothesis, and recommended mitigation actions.`, target, target)
	if timeRange != "" {
		p += fmt.Sprintf("\nTime range: %s", timeRange)
	}
	return &mcp.GetPromptResult{
		Description: "incident investigation prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

func dailySecurityBriefingPrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	date := req.Params.Arguments["date"]
	p := `Please generate a comprehensive daily security briefing for TwLogEye:
1. Retrieve latest anomaly scores using get_last_report(type="anomaly").
2. Check for critical or high-level alerts using search_notify(level="critical|high").
3. Inspect log volume and error patterns across syslog, windows event, and netflow using get_report or get_last_report.
4. Summarize key findings, suspicious activities, top offending IPs/hosts, and actionable security recommendations.`
	if date != "" {
		p += fmt.Sprintf("\nTarget date: %s", date)
	}
	return &mcp.GetPromptResult{
		Description: "daily security briefing prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}

func testAndAddSigmaRulePrompt(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	rule := req.Params.Arguments["rule"]
	logType := req.Params.Arguments["log_type"]
	if logType == "" {
		logType = "syslog"
	}
	p := fmt.Sprintf(`Please review, backtest, and validate the following Sigma rule for log type '%s':
1. Use test_sigma_rule to evaluate the rule against historical logs.
2. Analyze the match count and sample logs to check for potential false positives.
3. If adjustments are needed, refine the rule condition/detection and re-test.
4. Once verified, use add_sigma_rule to register the rule and reload_sigma_rule to apply it.

Rule:
%s`, logType, rule)
	return &mcp.GetPromptResult{
		Description: "test and add sigma rule prompt",
		Messages: []*mcp.PromptMessage{
			{
				Role:    "user",
				Content: &mcp.TextContent{Text: p},
			},
		},
	}, nil
}
