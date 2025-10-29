package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/lipgloss"
	"github.com/dustin/go-humanize"
	"github.com/montanaflynn/stats"
)

func (m dashboardModel) renderNetflowCount() string {
	height := 8
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		packets := []float64{}
		bytes := []float64{}
		ips := []float64{}
		macs := []float64{}
		fumbles := []float64{}
		prots := []float64{}
		flows := []float64{}
		for _, e := range m.netflowReport {
			fumbles = append(fumbles, float64(e.Fumbles))
			packets = append(packets, float64(e.Packets))
			bytes = append(bytes, float64(e.Bytes))
			prots = append(prots, float64(e.Protocols))
			flows = append(flows, float64(e.Flows))
			ips = append(ips, float64(e.Ips))
			macs = append(macs, float64(e.Macs))
		}
		leftTitle := "Netflow Count " + time.Unix(0, m.netflowReport[len(m.netflowReport)-1].Time).Format("2006-01-02 15:04")
		rightTitle := "Cur/Avg/Max"
		spacerWidth := width - 4 - len(leftTitle) - len(rightTitle)
		headerText := titleStyle.Render(leftTitle)
		if spacerWidth > 0 {
			headerText = titleStyle.Render(leftTitle) + strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(ColorGray).Render(rightTitle)
		}
		row = append(row, headerText)
		row = append(row, formatNetflowCountLine("Fumble", fumbles, width, lipgloss.NewStyle().Foreground(ColorRed)))
		row = append(row, formatNetflowPacketsLine("Packet", packets, width, lipgloss.NewStyle().Foreground(ColorBlue)))
		row = append(row, formatNetflowBytesLine("Bytes(MB)", bytes, width, lipgloss.NewStyle().Foreground(ColorBlue)))
		row = append(row, formatNetflowCountLine("IP", ips, width, lipgloss.NewStyle().Foreground(ColorGray)))
		row = append(row, formatNetflowCountLine("MAC", macs, width, lipgloss.NewStyle().Foreground(ColorGray)))
		row = append(row, formatNetflowCountLine("Flow", flows, width, lipgloss.NewStyle().Foreground(ColorWhite)))
		row = append(row, formatNetflowCountLine("Prot", prots, width, lipgloss.NewStyle().Foreground(ColorWhite)))
	} else {
		row = append(row, titleStyle.Render("Netflow Count"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func formatNetflowCountLine(l string, values []float64, width int, style lipgloss.Style) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%7d/%7.1f/%7d", int64(c), avg, int64(max))
	label := fmt.Sprintf(" %-10s", l)
	text := style.Render(label + value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func formatNetflowPacketsLine(l string, values []float64, width int, style lipgloss.Style) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%7s/%7s/%7s", humanize.SIWithDigits(c, 1, ""), humanize.SIWithDigits(avg, 1, ""), humanize.SIWithDigits(max, 1, ""))
	label := fmt.Sprintf(" %-10s", l)
	text := style.Render(label + value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func formatNetflowBytesLine(l string, values []float64, width int, style lipgloss.Style) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%7.1f/%7.1f/%7.1f", c/(1024*1024), avg/(1024*1024), max/(1024*1024))
	label := fmt.Sprintf(" %-10s", l)
	text := style.Render(label + value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func (m dashboardModel) renderNetflowIP(bytes bool) string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		last := m.netflowReport[len(m.netflowReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Netflow %d IP from %d packets",
			last.Ips, last.Packets)))
		patterns := []*netflowTopListEnt{}
		if bytes {
			for _, e := range last.TopIpBytesList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: e.Bytes,
					Key:   e.Key,
				})
			}
		} else {
			for _, e := range last.TopIpPacketsList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: int64(e.Packets),
					Key:   e.Key,
				})
			}
		}
		row = append(row, m.renderNetflowTopListContent(width, patterns, bytes))
	} else {
		row = append(row, titleStyle.Render("Netflow IP"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderNetflowMAC(bytes bool) string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		last := m.netflowReport[len(m.netflowReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Netflow %d MAC from %d packets",
			last.Macs, last.Packets)))
		patterns := []*netflowTopListEnt{}
		if bytes {
			for _, e := range last.TopMacBytesList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: e.Bytes,
					Key:   e.Key,
				})
			}
		} else {
			for _, e := range last.TopMacPacketsList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: int64(e.Packets),
					Key:   e.Key,
				})
			}
		}
		row = append(row, m.renderNetflowTopListContent(width, patterns, bytes))
	} else {
		row = append(row, titleStyle.Render("Netflow MAC"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderNetflowFlow(bytes bool) string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		last := m.netflowReport[len(m.netflowReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Netflow %d flows from %d packets",
			last.Flows, last.Packets)))
		patterns := []*netflowTopListEnt{}
		if bytes {
			for _, e := range last.TopFlowBytesList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: e.Bytes,
					Key:   e.Key,
				})
			}
		} else {
			for _, e := range last.TopFlowPacketsList {
				patterns = append(patterns, &netflowTopListEnt{
					Count: int64(e.Packets),
					Key:   e.Key,
				})
			}
		}
		row = append(row, m.renderNetflowTopListContent(width, patterns, bytes))
	} else {
		row = append(row, titleStyle.Render("Netflow Flow"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderNetflowFumble() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		last := m.netflowReport[len(m.netflowReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Netflow %d fumble src from %d packets",
			last.Fumbles, last.Packets)))
		patterns := []*netflowTopListEnt{}
		for _, e := range last.TopFumbleSrcList {
			patterns = append(patterns, &netflowTopListEnt{
				Count: int64(e.Count),
				Key:   e.Ip,
			})
		}
		row = append(row, m.renderNetflowTopListContent(width, patterns, false))
	} else {
		row = append(row, titleStyle.Render("Netflow fumbles"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderNetflowProt() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.netflowReport) > 0 {
		last := m.netflowReport[len(m.netflowReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Netflow %d protocols from %d packets",
			last.Protocols, last.Packets)))
		patterns := []*netflowTopListEnt{}
		for _, e := range last.TopProtocolList {
			patterns = append(patterns, &netflowTopListEnt{
				Count: int64(e.Count),
				Key:   e.Protocol,
			})
		}
		row = append(row, m.renderNetflowTopListContent(width, patterns, false))
	} else {
		row = append(row, titleStyle.Render("Netflow protocols"))
		row = append(row, "No netflow report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

type netflowTopListEnt struct {
	Key   string
	Count int64
}

func (m dashboardModel) renderNetflowTopListContent(chartWidth int, patterns []*netflowTopListEnt, bytes bool) string {
	maxCount := int64(0)
	for _, p := range patterns {
		if p.Count > maxCount {
			maxCount = p.Count
		}
	}
	var lines []string
	keyWidth := chartWidth - 27
	if keyWidth < 20 {
		keyWidth = 20
	}
	for i := 0; i < topNLines; i++ {
		if i < len(patterns) {
			pattern := patterns[i]
			barWidth := 10
			fillWidth := int(float64(pattern.Count) * float64(barWidth) / float64(maxCount))
			if fillWidth == 0 && pattern.Count > 0 {
				fillWidth = 1
			}
			bar := strings.Repeat("█", fillWidth) + strings.Repeat("░", barWidth-fillWidth)
			key := pattern.Key
			if len(key) > keyWidth {
				key = key[:keyWidth-3] + "..."
			}
			count := fmt.Sprintf("%7d", pattern.Count)
			if bytes {
				count = fmt.Sprintf("%7s", humanize.Bytes(uint64(pattern.Count)))
			}
			var barColor lipgloss.Style
			if i < 1 {
				barColor = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
			} else if i < 3 {
				barColor = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
			} else {
				barColor = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
			}
			line := fmt.Sprintf("%s %s │ %s",
				barColor.Render(bar),
				lipgloss.NewStyle().Foreground(ColorGray).Render(count),
				lipgloss.NewStyle().Foreground(ColorWhite).Render(key),
			)
			lines = append(lines, line)
		} else {
			emptyBar := strings.Repeat("░", 10)
			grayStyle := lipgloss.NewStyle().Foreground(ColorGray)
			line := fmt.Sprintf("%s %s │ %s",
				grayStyle.Render(emptyBar),
				grayStyle.Render("       "),
				grayStyle.Render("(empty)"),
			)
			lines = append(lines, line)
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}
