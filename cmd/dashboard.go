/*
Copyright © 2025 Masayuki Yamai <twsnmp@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

var dashboardHistory int
var topNLines int
var dashboardMap = make(map[string]bool)
var dashboardPanel = []string{}
var dashboardOTelMetrics = []string{}

// dashboardCmd represents the dashboard command
var dashboardCmd = &cobra.Command{
	Use:   "dashboard <panel type>...",
	Short: "Display twlogeye dashboard",
	Long: `Display twlogeye dashboard.
<panel type> is
  monitor | anomaly
  syslog.count | syslog.pattern | syslog.error
  trap.count | trap.type 
  netflow.count | netflow.ip.packtet | netflow.ip.byte | netflow.mac.packet | netflow.mac.byte 
  netflow.flow.packet | netflow.flow.byte | netflow.fumble | netflow.prot
  winevent.count | winevent.pattern | winevent.error
  otel.count | otel.pattern | otel.error | otel.metric.<id>
`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, p := range args {
			if p == "monitor" || p == "anomaly" {
				dashboardMap[p] = true
				dashboardPanel = append(dashboardPanel, p)
				continue
			}
			a := strings.SplitN(p, ".", 3)
			if len(a) < 2 {
				continue
			}
			switch a[0] {
			case "syslog", "winevent":
				switch a[1] {
				case "count", "pattern", "error":
					dashboardMap[a[0]] = true
					dashboardPanel = append(dashboardPanel, p)
				}
			case "otel":
				switch a[1] {
				case "count", "pattern", "error":
					dashboardMap[a[0]] = true
					dashboardPanel = append(dashboardPanel, p)
				case "metric":
					dashboardOTelMetrics = append(dashboardOTelMetrics, p)
				}
			case "trap":
				switch a[1] {
				case "count", "types":
					dashboardMap[a[0]] = true
					dashboardPanel = append(dashboardPanel, p)
				}
			case "netflow":
				switch a[1] {
				case "count", "ip.packet", "ip.byte", "mac.packet", "mac.byte", "flow.packet", "flow.byte", "fumble", "prot":
					dashboardMap[a[0]] = true
					dashboardPanel = append(dashboardPanel, p)
				}
			}
		}
		if len(dashboardPanel) < 1 && len(dashboardOTelMetrics) < 1 {
			log.Fatalln("no panel")
		}
		if topNLines < 1 {
			topNLines = 1
		} else if topNLines > 10 {
			topNLines = 10
		}
		dashboard()
	},
}

var teaProg *tea.Program

func init() {
	rootCmd.AddCommand(dashboardCmd)
	dashboardCmd.Flags().IntVar(&dashboardHistory, "history", 100, "Keep report history")
	dashboardCmd.Flags().IntVar(&topNLines, "topn", 5, "Number of top n lines.")
}

func dashboard() {
	teaProg = tea.NewProgram(initDashboardModel())
	var wg sync.WaitGroup
	wg.Add(1)
	stopCh := make(chan bool)
	go dashboardBackend(&wg, stopCh)
	if _, err := teaProg.Run(); err != nil {
		log.Fatalf("dashboard err=%v", err)
	}
	close(stopCh)
	wg.Wait()
}

func dashboardBackend(wg *sync.WaitGroup, stopCh chan bool) {
	defer wg.Done()
	timer := time.NewTicker(time.Second)
	loadOldReport()
	checkDashboardReport()
	for {
		select {
		case <-stopCh:
			return
		case <-timer.C:
			if time.Now().Unix()%60 == 2 {
				checkDashboardReport()
			}
		}
	}
}

func loadOldReport() {
	client := getClient()
	if _, ok := dashboardMap["syslog"]; ok {
		s, err := client.GetSyslogReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
		if err == nil {
			for {
				r, err := s.Recv()
				if err != nil {
					break
				}
				teaProg.Send(UpdateSyslogReportMsg{
					err:    err,
					report: r,
				})
			}
		}
	}
	if _, ok := dashboardMap["trap"]; ok {
		s, err := client.GetTrapReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
		if err == nil {
			for {
				r, err := s.Recv()
				if err != nil {
					break
				}
				teaProg.Send(UpdateTrapReportMsg{
					err:    err,
					report: r,
				})
			}
		}
	}
	if _, ok := dashboardMap["netflow"]; ok {
		s, err := client.GetNetflowReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
		if err == nil {
			for {
				r, err := s.Recv()
				if err != nil {
					break
				}
				teaProg.Send(UpdateNetflowReportMsg{
					err:    err,
					report: r,
				})
			}
		}
	}
	if _, ok := dashboardMap["winevent"]; ok {
		s, err := client.GetWindowsEventReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
		if err == nil {
			for {
				r, err := s.Recv()
				if err != nil {
					break
				}
				teaProg.Send(UpdateWindowsEventReportMsg{
					err:    err,
					report: r,
				})
			}
		}
	}
	if _, ok := dashboardMap["otel"]; ok {
		s, err := client.GetOTelReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
		if err == nil {
			for {
				r, err := s.Recv()
				if err != nil {
					break
				}
				teaProg.Send(UpdateOTelReportMsg{
					err:    err,
					report: r,
				})
			}
		}
	}
	s, err := client.GetMonitorReport(context.Background(), &api.ReportRequest{Start: 0, End: time.Now().UnixNano()})
	if err == nil {
		for {
			r, err := s.Recv()
			if err != nil {
				break
			}
			teaProg.Send(UpdateMonitorReportMsg{
				err:    err,
				report: r,
			})
		}
	}
}

func checkDashboardReport() {
	conn, err := getClientConn()
	if err != nil {
		log.Fatalf("getClinetConn err=%v", err)
	}
	defer conn.Close()
	client := api.NewTWLogEyeServiceClient(conn)
	if _, ok := dashboardMap["syslog"]; ok {
		sr, err := client.GetLastSyslogReport(context.Background(), &api.Empty{})
		teaProg.Send(UpdateSyslogReportMsg{
			err:    err,
			report: sr,
		})
	}
	if _, ok := dashboardMap["trap"]; ok {
		tr, err := client.GetLastTrapReport(context.Background(), &api.Empty{})
		teaProg.Send(UpdateTrapReportMsg{
			err:    err,
			report: tr,
		})
	}
	if _, ok := dashboardMap["netflow"]; ok {
		nr, err := client.GetLastNetflowReport(context.Background(), &api.Empty{})
		teaProg.Send(UpdateNetflowReportMsg{
			err:    err,
			report: nr,
		})
	}
	if _, ok := dashboardMap["winevent"]; ok {
		wr, err := client.GetLastWindowsEventReport(context.Background(), &api.Empty{})
		teaProg.Send(UpdateWindowsEventReportMsg{
			err:    err,
			report: wr,
		})
	}
	if _, ok := dashboardMap["otel"]; ok {
		or, err := client.GetLastOTelReport(context.Background(), &api.Empty{})
		teaProg.Send(UpdateOTelReportMsg{
			err:    err,
			report: or,
		})
	}
	for _, om := range dashboardOTelMetrics {
		a := strings.SplitAfterN(om, ".", 3)
		if len(a) == 3 {
			m, err := client.GetOTelMetric(context.Background(), &api.IDRequest{Id: a[2]})
			teaProg.Send(UpdateOTelMetricMsg{
				err:    err,
				id:     a[2],
				metric: m,
			})
		}
	}
	mr, err := client.GetLastMonitorReport(context.Background(), &api.Empty{})
	teaProg.Send(UpdateMonitorReportMsg{
		err:    err,
		report: mr,
	})
	lar, err := client.GetLastAnomalyReport(context.Background(), &api.Empty{})
	armsg := UpdateAnomalyReportMsg{
		err:             err,
		report:          lar,
		AnomalyScoreMap: make(map[string]*AnomalyScoreEnt),
	}
	if err == nil && lar != nil {
		for _, a := range lar.ScoreList {
			as := &AnomalyScoreEnt{}
			if s, err := client.GetAnomalyReport(context.Background(), &api.AnomalyReportRequest{Start: 0, End: time.Now().UnixNano(), Type: a.Type}); err == nil {
				for {
					r, err := s.Recv()
					if err != nil {
						break
					}
					as.Scores = append(as.Scores, r.Score)
					as.Times = append(as.Times, r.Time)
				}
			}
			armsg.AnomalyScoreMap[a.Type] = as
		}
	}
	teaProg.Send(armsg)
}

type dashboardModel struct {
	// State
	width    int
	height   int
	quitting bool
	errMsg   string
	// Data
	syslogReport       []*api.SyslogReportEnt
	trapReport         []*api.TrapReportEnt
	netflowReport      []*api.NetflowReportEnt
	windowsEventReport []*api.WindowsEventReportEnt
	otelReport         []*api.OTelReportEnt
	otelMetricMap      map[string]*api.OTelMetricEnt
	monitorReport      []*api.MonitorReportEnt
	anomalyReport      *api.LastAnomalyReportEnt
	anomalyScoreMap    map[string]*AnomalyScoreEnt
}

type UpdateSyslogReportMsg struct {
	err    error
	report *api.SyslogReportEnt
}

type UpdateTrapReportMsg struct {
	err    error
	report *api.TrapReportEnt
}

type UpdateNetflowReportMsg struct {
	err    error
	report *api.NetflowReportEnt
}
type UpdateWindowsEventReportMsg struct {
	err    error
	report *api.WindowsEventReportEnt
}
type UpdateOTelReportMsg struct {
	err    error
	report *api.OTelReportEnt
}

type UpdateMonitorReportMsg struct {
	err    error
	report *api.MonitorReportEnt
}
type UpdateOTelMetricMsg struct {
	err    error
	id     string
	metric *api.OTelMetricEnt
}

type UpdateAnomalyReportMsg struct {
	err             error
	AnomalyScoreMap map[string]*AnomalyScoreEnt
	report          *api.LastAnomalyReportEnt
}

type AnomalyScoreEnt struct {
	Times  []int64
	Scores []float64
}

func initDashboardModel() dashboardModel {
	return dashboardModel{
		otelMetricMap: make(map[string]*api.OTelMetricEnt),
	}
}

func (m dashboardModel) Init() tea.Cmd {
	return nil
}

func (m dashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "c":
			m.errMsg = ""
		case "e":
			m.errMsg = "test Error"
		default:
			return m, nil
		}
	case UpdateSyslogReportMsg:
		if msg.report != nil {
			if len(m.syslogReport) < 1 || m.syslogReport[len(m.syslogReport)-1].Time < msg.report.Time {
				m.syslogReport = append(m.syslogReport, msg.report)
				if len(m.syslogReport) > dashboardHistory {
					m.syslogReport = m.syslogReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateTrapReportMsg:
		if msg.report != nil {
			if len(m.trapReport) < 1 || m.trapReport[len(m.trapReport)-1].Time < msg.report.Time {
				m.trapReport = append(m.trapReport, msg.report)
				if len(m.trapReport) > dashboardHistory {
					m.trapReport = m.trapReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateNetflowReportMsg:
		if msg.report != nil {
			if len(m.netflowReport) < 1 || m.netflowReport[len(m.netflowReport)-1].Time < msg.report.Time {
				m.netflowReport = append(m.netflowReport, msg.report)
				if len(m.netflowReport) > dashboardHistory {
					m.netflowReport = m.netflowReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateWindowsEventReportMsg:
		if msg.report != nil {
			if len(m.windowsEventReport) < 1 || m.windowsEventReport[len(m.windowsEventReport)-1].Time < msg.report.Time {
				m.windowsEventReport = append(m.windowsEventReport, msg.report)
				if len(m.windowsEventReport) > dashboardHistory {
					m.windowsEventReport = m.windowsEventReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateOTelReportMsg:
		if msg.report != nil {
			if len(m.otelReport) < 1 || m.otelReport[len(m.otelReport)-1].Time < msg.report.Time {
				m.otelReport = append(m.otelReport, msg.report)
				if len(m.otelReport) > dashboardHistory {
					m.otelReport = m.otelReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateOTelMetricMsg:
		if msg.metric != nil && msg.id != "" {
			m.otelMetricMap[msg.id] = msg.metric
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateMonitorReportMsg:
		if msg.report != nil {
			if len(m.monitorReport) < 1 || m.monitorReport[len(m.monitorReport)-1].Time < msg.report.Time {
				m.monitorReport = append(m.monitorReport, msg.report)
				if len(m.monitorReport) > dashboardHistory {
					m.monitorReport = m.monitorReport[1:]
				}
			}
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	case UpdateAnomalyReportMsg:
		if msg.report != nil {
			m.anomalyReport = msg.report
			m.anomalyScoreMap = msg.AnomalyScoreMap
		} else if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		return m, nil
	default:
		return m, nil
	}
	return m, nil
}

// Color palette
var (
	ColorBlue     = lipgloss.Color("#0f93fc")
	ColorGreen    = lipgloss.Color("#49E209")
	ColorNavy     = lipgloss.Color("#081C39")
	ColorGray     = lipgloss.Color("#BCBEC0")
	ColorDarkGray = lipgloss.Color("#2D2D2D") // Dark gray for modal backgrounds
	ColorBlack    = lipgloss.Color("#000000")
	ColorWhite    = lipgloss.Color("#FFFFFF")
	ColorRed      = lipgloss.Color("#FF6B6B")
	ColorYellow   = lipgloss.Color("#FFD93D")
	ColorOrange   = lipgloss.Color("#FF8C42")
	ColorPink     = lipgloss.Color("#FF69B4")
)

// Shared styles used across multiple view components
var (
	sectionStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorGray).
			Padding(0, 1).
			Margin(0)

	helpStyle = lipgloss.NewStyle().
			Foreground(ColorGray).
			Italic(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(ColorRed).
			Italic(true)

	titleStyle = lipgloss.NewStyle().
			Foreground(ColorBlue).
			Bold(true).
			Align(lipgloss.Center)
)

func (m dashboardModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return "Initializing dashboard..."
	}
	if m.quitting {
		return "Quitting...."
	}
	row := []string{}
	if m.errMsg != "" {
		row = append(row, errorStyle.Render(m.errMsg))
		row = append(row, helpStyle.Render("Press q to quit. Press c to clear error."))
		return lipgloss.JoinVertical(lipgloss.Left, row...)
	}
	if m.width < 80 {
		if m.height < 10*len(dashboardPanel) {
			return fmt.Sprintf("Terminal too small. Resize to at least %d lines. height=%d", 10*len(dashboardPanel), m.height)
		}
		for _, p := range dashboardPanel {
			row = append(row, m.renderPanel(p))
		}
	} else {
		if m.height < 5*len(dashboardPanel) {
			return fmt.Sprintf("Terminal too small. Resize to at least %d lines. height=%d", 5*len(dashboardPanel), m.height)
		}
		col := []string{}
		for _, p := range dashboardPanel {
			col = append(col, m.renderPanel(p))
			if len(col) == 2 {
				row = append(row, lipgloss.JoinHorizontal(lipgloss.Top, col...))
				col = []string{}
			}
		}
		for id := range m.otelMetricMap {
			col = append(col, m.renderOTelMetric(id))
			if len(col) == 2 {
				row = append(row, lipgloss.JoinHorizontal(lipgloss.Top, col...))
				col = []string{}
			}
		}
		if len(col) > 0 {
			row = append(row, col[0])
		}
	}
	row = append(row, helpStyle.Render("Press q to quit."))
	finalStyle := lipgloss.NewStyle().
		Height(m.height).
		MaxWidth(m.width)

	return finalStyle.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderPanel(p string) string {
	switch p {
	case "monitor":
		return m.renderMonitor()
	case "anomaly":
		return m.renderAnomaly()
	case "syslog.count":
		return m.renderSyslogCount()
	case "syslog.pattern":
		return m.renderSyslogPattern()
	case "syslog.error":
		return m.renderSyslogErrorPattern()
	case "trap.count":
		return m.renderTrapCount()
	case "trap.type":
		return m.renderTrapTypes()
	case "netflow.count":
		return m.renderNetflowCount()
	case "netflow.ip.packet":
		return m.renderNetflowIP(false)
	case "netflow.ip.byte":
		return m.renderNetflowIP(true)
	case "netflow.mac.packet":
		return m.renderNetflowMAC(false)
	case "netflow.mac.byte":
		return m.renderNetflowMAC(true)
	case "netflow.flow.packet":
		return m.renderNetflowFlow(false)
	case "netflow.flow.byte":
		return m.renderNetflowFlow(true)
	case "netflow.prot":
		return m.renderNetflowProt()
	case "netflow.fumble":
		return m.renderNetflowFumble()
	case "winevent.count":
		return m.renderWindowsEventCount()
	case "winevent.pattern":
		return m.renderWindowsEventPattern()
	case "winevent.error":
		return m.renderWindowsEventErrorPattern()
	case "otel.count":
		return m.renderOTelCount()
	case "otel.pattern":
		return m.renderOTelPattern()
	case "otel.error":
		return m.renderOTelErrorPattern()
	}
	return "not implement"
}
