package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/barchart"

	"github.com/charmbracelet/lipgloss"
	"github.com/twsnmp/twlogeye/api"
)

func (m dashboardModel) renderOTelCount() string {
	height := 8
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.otelReport) > 0 {
		errors := []float64{}
		warns := []float64{}
		normals := []float64{}
		pats := []float64{}
		epats := []float64{}
		for _, e := range m.otelReport {
			errors = append(errors, float64(e.Error))
			warns = append(warns, float64(e.Warn))
			normals = append(normals, float64(e.Normal))
			pats = append(pats, float64(e.Types))
			epats = append(epats, float64(e.ErrorTypes))
		}
		leftTitle := "OpenTelemetry log Count " + time.Unix(0, m.otelReport[len(m.otelReport)-1].Time).Format("2006-01-02 15:04")
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
		row = append(row, titleStyle.Render("OpenTelemetry log Count"))
		row = append(row, "No OpenTelemetry log report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderOTelPattern() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.otelReport) > 0 {
		last := m.otelReport[len(m.otelReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("OpenTelemetry log Patterns %d patterns from %d logs",
			last.Types, last.Normal+last.Warn+last.Error)))
		row = append(row, m.renderOTelPatternContent(width, last.TopList))
	} else {
		row = append(row, titleStyle.Render("OpenTelemetry log Patterns"))
		row = append(row, "No OpenTelemetry report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderOTelErrorPattern() string {
	height := 6
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if len(m.otelReport) > 0 {
		last := m.otelReport[len(m.otelReport)-1]
		row = append(row, titleStyle.Render(fmt.Sprintf("OpenTelemetry log Errors %d patterns from %d logs",
			last.Types, last.Normal+last.Warn+last.Error)))
		row = append(row, m.renderOTelPatternContent(width, last.TopErrorList))
	} else {
		row = append(row, titleStyle.Render("OpenTelemetry log Errors"))
		row = append(row, "No OpenTelemetry log report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func (m dashboardModel) renderOTelPatternContent(chartWidth int, patterns []*api.OTelSummaryEnt) string {
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
			logPattern := fmt.Sprintf("%s %s %s %s", pattern.Host, pattern.Service, pattern.Scope, pattern.Severity)
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

func (m dashboardModel) renderOTelMetric(id string) string {
	metric, ok := m.otelMetricMap[id]
	row := []string{}
	height := 8
	width := m.width - 2
	if m.width < 80 {
		width = m.width - 2
	}
	if !ok || len(metric.DataPoints) < 1 {
		style := sectionStyle.Width(width).Height(height)
		row = append(row, titleStyle.Render("OpenTelemetry metric"))
		row = append(row, "No metric data")
		return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
	}
	chartView := ""
	switch metric.Type {
	case "Sum":
		height = 2 + len(metric.DataPoints)*2
		chartView = renderOTelMetricSum(width-2, height-3, metric)
	case "Gauge":
		height = 2 + len(metric.DataPoints)*2
		chartView = renderOTelMetricGauge(width-2, height-3, metric)
	case "Histogram":
		height = 2 + len(metric.DataPoints)*8
		if height > m.height {
			height = m.height - 1
		}
		chartView = renderOTelMetricHistogram(width-2, (height-3)/len(metric.DataPoints), metric)
	}
	style := sectionStyle.Width(width).Height(height)
	leftTitle := fmt.Sprintf("%s %s %s(%s)", metric.Host, metric.Service, metric.Name, metric.Unit)
	rightTitle := time.Unix(0, metric.DataPoints[0].Time).Format("2006-01-02 15:04")
	spacerWidth := width - 4 - len(leftTitle) - len(rightTitle)
	headerText := titleStyle.Render(leftTitle)
	if spacerWidth > 0 {
		headerText = titleStyle.Render(leftTitle) + strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(ColorGray).Render(rightTitle)
	}
	row = append(row, headerText)
	row = append(row, metric.Description)
	row = append(row, chartView)
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))
}

func renderOTelMetricSum(width, height int, metric *api.OTelMetricEnt) string {
	values := []barchart.BarData{}
	for _, d := range metric.DataPoints {
		values = append(values,
			barchart.BarData{
				Label: strings.Join(d.Attributes, "/"),
				Values: []barchart.BarValue{
					{
						Name:  "Sum",
						Value: d.Sum,
						Style: lipgloss.NewStyle().Background(ColorBlue).Foreground(ColorBlue),
					},
				},
			},
		)
	}
	bc := barchart.New(width, height,
		barchart.WithDataSet(values),
		barchart.WithBarGap(0),
		barchart.WithHorizontalBars())
	bc.Draw()
	return bc.View()
}

func renderOTelMetricGauge(width, height int, metric *api.OTelMetricEnt) string {
	values := []barchart.BarData{}
	for _, d := range metric.DataPoints {
		values = append(values,
			barchart.BarData{
				Label: strings.Join(d.Attributes, "/"),
				Values: []barchart.BarValue{
					{
						Name:  "Gauge",
						Value: d.Gauge,
						Style: lipgloss.NewStyle().Background(ColorBlue).Foreground(ColorBlue),
					},
				},
			},
		)
	}
	bc := barchart.New(width, height,
		barchart.WithDataSet(values),
		barchart.WithBarGap(1),
		barchart.WithHorizontalBars())
	bc.Draw()
	return bc.View()
}

func renderOTelMetricHistogram(width, height int, metric *api.OTelMetricEnt) string {
	row := []string{}
	for _, d := range metric.DataPoints {
		row = append(row, strings.Join(d.Attributes, "/"))
		values := []barchart.BarData{}
		for i, b := range d.BucketCounts {
			l := "0.00"
			if i > 0 {
				l = fmt.Sprintf("%.2f", d.ExplicitBounds[i-1])
			}
			values = append(values,
				barchart.BarData{
					Label: l,
					Values: []barchart.BarValue{
						{
							Name:  "Value",
							Value: float64(b),
							Style: lipgloss.NewStyle().Background(ColorBlue).Foreground(ColorBlue),
						},
					},
				},
			)
		}
		bc := barchart.New(width, height,
			barchart.WithDataSet(values),
			barchart.WithBarGap(0))
		bc.Draw()
		row = append(row, bc.View())
	}
	return lipgloss.JoinVertical(lipgloss.Left, row...)
}
