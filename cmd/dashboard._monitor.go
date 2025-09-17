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

func (m dashboardModel) renderMonitor() string {
	height := 7
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.monitorReport) > 0 {
		r := m.monitorReport[len(m.monitorReport)-1]
		leftTitle := "TwLogEye Monitor " + time.Unix(0, r.Time).Format("2006-01-02 15:04")
		rightTitle := "Cur/Avg/Max"
		spacerWidth := width - 4 - len(leftTitle) - len(rightTitle)
		headerText := titleStyle.Render(leftTitle)
		if spacerWidth > 0 {
			headerText = titleStyle.Render(leftTitle) + strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(ColorGray).Render(rightTitle)
		}
		row = append(row, headerText)
		cpus := []float64{}
		mems := []float64{}
		disks := []float64{}
		loads := []float64{}
		nets := []float64{}
		dbSpeeds := []float64{}
		for _, r2 := range m.monitorReport {
			cpus = append(cpus, r2.Cpu)
			mems = append(mems, r2.Memory)
			disks = append(disks, r2.Disk)
			nets = append(nets, r2.Net)
			loads = append(loads, r2.Load)
			dbSpeeds = append(dbSpeeds, r2.DbSpeed)
		}
		row = append(row, formatUsageLine("CPU", cpus, width))
		row = append(row, formatUsageLine("Memory", mems, width))
		row = append(row, formatUsageLine("Disk", disks, width))
		row = append(row, formatLoadLine(loads, width))
		row = append(row, formatNetLine(nets, width))
		row = append(row, formatDBSizeLine(r.DbSize, dbSpeeds, width))
	} else {
		row = append(row, titleStyle.Render("TwLogEye Monitor"))
		row = append(row, "No monitor report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func formatUsageLine(l string, values []float64, width int) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%5.1f/%5.1f/%5.1f", c, avg, max)
	label := fmt.Sprintf(" %-10s", l)
	style := getUsageStyle(c)
	text := lipgloss.NewStyle().Foreground(ColorWhite).Render(label) + style.Render(value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style), sparkline.WithMaxValue(100))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func getUsageStyle(u float64) lipgloss.Style {
	if u > 90.0 {
		return lipgloss.NewStyle().Foreground(ColorRed)
	} else if u > 60.0 {
		return lipgloss.NewStyle().Foreground(ColorYellow)
	}
	return lipgloss.NewStyle().Foreground(ColorGray)
}

func formatNetLine(values []float64, width int) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%5.1f/%5.1f/%5.1f", c/(1000*1000), avg/(1000*1000), max/(1000*1000))
	label := fmt.Sprintf(" %-10s", "Net(Mbps)")
	style := getUsageStyle((c * 100) / (1000 * 1000 * 1000))
	text := lipgloss.NewStyle().Foreground(ColorWhite).Render(label) + style.Render(value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func formatDBSizeLine(d int64, values []float64, width int) string {
	value := fmt.Sprintf("%17s", humanize.Bytes(uint64(d)))
	label := fmt.Sprintf(" %-10s", "DB Size")
	text := lipgloss.NewStyle().Foreground(ColorWhite).Render(label) + lipgloss.NewStyle().Foreground(ColorGray).Render(value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(lipgloss.NewStyle().Foreground(ColorBlue)))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}

func formatLoadLine(values []float64, width int) string {
	c := values[len(values)-1]
	max, _ := stats.Max(values)
	avg, _ := stats.Mean(values)
	value := fmt.Sprintf("%5.1f/%5.1f/%5.1f", c, avg, max)
	label := fmt.Sprintf(" %-10s", "Load")
	style := getUsageStyle((100 * c / 8))
	text := lipgloss.NewStyle().Foreground(ColorWhite).Render(label) + style.Render(value)
	sparklineWidth := width - lipgloss.Width(text) - 2
	sl := sparkline.New(sparklineWidth, 1, sparkline.WithStyle(style))
	sl.PushAll(values)
	sl.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, sl.View(), text)
}
