package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/lipgloss"
	"github.com/montanaflynn/stats"
)

func (m dashboardModel) renderTrapCount() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.trapReport) > 0 {
		counts := []float64{}
		types := []float64{}
		for _, e := range m.trapReport {
			counts = append(counts, float64(e.Count))
			types = append(types, float64(e.Types))
		}
		leftTitle := "Trap Count " + time.Unix(0, m.trapReport[len(m.trapReport)-1].Time).Format("2006-01-02 15:04")
		rightTitle := "Cur/Avg/Max"
		spacerWidth := width - 4 - len(leftTitle) - len(rightTitle)
		headerText := titleStyle.Render(leftTitle)
		if spacerWidth > 0 {
			headerText = titleStyle.Render(leftTitle) + strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(ColorGray).Render(rightTitle)
		}
		row = append(row, titleStyle.Render(headerText))
		row = append(row, formatTrapCountLine("Count", counts, width, lipgloss.NewStyle().Foreground(ColorBlue)))
		row = append(row, formatTrapCountLine("Types", types, width, lipgloss.NewStyle().Foreground(ColorGray)))
	} else {
		row = append(row, titleStyle.Render("Trap Count"))
		row = append(row, "No trap report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func formatTrapCountLine(l string, values []float64, width int, style lipgloss.Style) string {
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

func (m dashboardModel) renderTrapTypes() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.trapReport) > 0 {
		last := m.trapReport[len(m.trapReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("Trap Patterns %d patterns from %d logs",
			last.Types, last.Count)))
		row = append(row, m.renderTrapTypesContent(width))
	} else {
		row = append(row, titleStyle.Render("Trap Patterns"))
		row = append(row, "No trap report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderTrapTypesContent(chartWidth int) string {
	types := m.trapReport[len(m.trapReport)-1].TopList
	maxCount := 0
	for _, t := range types {
		if int(t.Count) > maxCount {
			maxCount = int(t.Count)
		}
	}
	var lines []string
	trapTypeWidth := chartWidth - 25
	if trapTypeWidth < 20 {
		trapTypeWidth = 20
	}
	for i := 0; i < topNLines; i++ {
		if i < len(types) {
			t := types[i]
			barWidth := 10
			fillWidth := int(float64(t.Count) * float64(barWidth) / float64(maxCount))
			if fillWidth == 0 && t.Count > 0 {
				fillWidth = 1
			}
			bar := strings.Repeat("█", fillWidth) + strings.Repeat("░", barWidth-fillWidth)
			trapType := fmt.Sprintf("%s %s", t.Sender, t.TrapType)
			if len(trapType) > trapTypeWidth {
				trapType = trapType[:trapTypeWidth-3] + "..."
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
				lipgloss.NewStyle().Foreground(ColorGray).Render(fmt.Sprintf("%5d", t.Count)),
				lipgloss.NewStyle().Foreground(ColorWhite).Render(trapType),
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
