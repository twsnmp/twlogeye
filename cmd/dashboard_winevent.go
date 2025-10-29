package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/lipgloss"
	"github.com/montanaflynn/stats"
	"github.com/twsnmp/twlogeye/api"
)

func (m dashboardModel) renderWindowsEventCount() string {
	height := 8
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.windowsEventReport) > 0 {
		errors := []float64{}
		warns := []float64{}
		normals := []float64{}
		pats := []float64{}
		epats := []float64{}
		for _, e := range m.windowsEventReport {
			errors = append(errors, float64(e.Error))
			warns = append(warns, float64(e.Warn))
			normals = append(normals, float64(e.Normal))
			pats = append(pats, float64(e.Types))
			epats = append(epats, float64(e.ErrorTypes))
		}
		leftTitle := "Windows Event Count " + time.Unix(0, m.windowsEventReport[len(m.windowsEventReport)-1].Time).Format("2006-01-02 15:04")
		rightTitle := "Cur/Avg/Max"
		spacerWidth := width - 4 - len(leftTitle) - len(rightTitle)
		headerText := titleStyle.Render(leftTitle)
		if spacerWidth > 0 {
			headerText = titleStyle.Render(leftTitle) + strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(ColorGray).Render(rightTitle)
		}
		row = append(row, headerText)
		row = append(row, formatWindowsEventCountLine("Error", errors, width, lipgloss.NewStyle().Foreground(ColorRed)))
		row = append(row, formatWindowsEventCountLine("Warn", warns, width, lipgloss.NewStyle().Foreground(ColorYellow)))
		row = append(row, formatWindowsEventCountLine("Normal", normals, width, lipgloss.NewStyle().Foreground(ColorBlue)))
		row = append(row, formatWindowsEventCountLine("Pat", pats, width, lipgloss.NewStyle().Foreground(ColorGray)))
		row = append(row, formatWindowsEventCountLine("E.Pat", epats, width, lipgloss.NewStyle().Foreground(ColorGray)))
	} else {
		row = append(row, titleStyle.Render("Windows Event Count"))
		row = append(row, "No Windows Event report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func formatWindowsEventCountLine(l string, values []float64, width int, style lipgloss.Style) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%6d/%7.1f/%6d", int64(c), avg, int64(max))
	label := fmt.Sprintf(" %-10s", l)
	text := style.Render(label + value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func (m dashboardModel) renderWindowsEventPattern() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.windowsEventReport) > 0 {
		last := m.windowsEventReport[len(m.windowsEventReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Windows Event Patterns %d patterns from %d logs",
			last.Types, last.Normal+last.Warn+last.Error)))
		row = append(row, m.renderWindowsEventPatternContent(width, last.TopList))
	} else {
		row = append(row, titleStyle.Render("Windows Event Patterns"))
		row = append(row, "No Windows Event report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderWindowsEventErrorPattern() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.windowsEventReport) > 0 {
		last := m.windowsEventReport[len(m.windowsEventReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Windows Event Errors %d patterns from %d logs",
			last.Types, last.Normal+last.Warn+last.Error)))
		row = append(row, m.renderWindowsEventPatternContent(width, last.TopErrorList))
	} else {
		row = append(row, titleStyle.Render("Windows Event Errors"))
		row = append(row, "No Windows Event report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderWindowsEventPatternContent(chartWidth int, patterns []*api.WindowsEventSummary) string {
	maxCount := 0
	for _, p := range patterns {
		if int(p.Count) > maxCount {
			maxCount = int(p.Count)
		}
	}
	var lines []string

	logPatternWidth := chartWidth - 25
	if logPatternWidth < 20 {
		logPatternWidth = 20
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
			logPattern := fmt.Sprintf("%s %s %s", pattern.Computer, pattern.Provider, pattern.EventId)
			if len(logPattern) > logPatternWidth {
				logPattern = logPattern[:logPatternWidth-3] + "..."
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
				lipgloss.NewStyle().Foreground(ColorGray).Render(fmt.Sprintf("%5d", pattern.Count)),
				lipgloss.NewStyle().Foreground(ColorWhite).Render(logPattern),
			)
			lines = append(lines, line)
		} else {
			emptyBar := strings.Repeat("░", 10)
			grayStyle := lipgloss.NewStyle().Foreground(ColorGray)
			line := fmt.Sprintf("%s %s │ %s",
				grayStyle.Render(emptyBar),
				grayStyle.Render("     "),
				grayStyle.Render("(no pattern)"),
			)
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
