package cmd

import (
	"fmt"
	"math"
	"time"

	"github.com/NimbleMarkets/ntcharts/heatmap"
	"github.com/charmbracelet/lipgloss"
	"github.com/montanaflynn/stats"
)

func (m dashboardModel) renderAnomaly() string {
	height := 7
	width := (m.width / 2) - 2
	if m.width < 80 {
		width = m.width - 2
	}
	style := sectionStyle.Width(width).Height(height)
	row := []string{}
	if m.anomalyReport != nil {
		r := m.anomalyReport
		row = append(row, titleStyle.Render("Anomaly Score "+time.Unix(0, r.Time).Format("2006-01-02 15:04")))
		for _, s := range r.ScoreList {
			row = append(row, m.formatAnomalyScoreLine(s.Type, s.Score, width))
		}
	} else {
		row = append(row, titleStyle.Render("Anomaly Score"))
		row = append(row, "No anomaly report")
	}
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, row...))

}

func (m dashboardModel) formatAnomalyScoreLine(l string, s float64, width int) string {
	e, ok := m.anomalyScoreMap[l]
	if !ok {
		return "no anomaly data"
	}
	max, _ := stats.Max(e.Scores)
	min, _ := stats.Min(e.Scores)
	scoreStyle := getScoreStyle(s, min, max)
	scoreValue := fmt.Sprintf("%5.1f", s)
	scoreLabel := fmt.Sprintf(" %-10s", l)
	scoreText := lipgloss.NewStyle().Foreground(ColorWhite).Render(scoreLabel) + scoreStyle.Render(scoreValue)
	hmWidth := width - lipgloss.Width(scoreText) - 2
	if hmWidth > len(e.Scores) {
		hmWidth = len(e.Scores)
	}
	hm := heatmap.New(hmWidth, 1, heatmap.WithValueRange(min, max), heatmap.WithColorScale(anomalyColorScale))
	for x, v := range e.Scores {
		hm.Push(heatmap.NewHeatPoint(float64(x), 1, v))
	}
	hm.Draw()
	return lipgloss.JoinHorizontal(lipgloss.Top, hm.View(), scoreText)
}

func getScoreStyle(s, min, max float64) lipgloss.Style {
	if max-min == 0 {
		return lipgloss.NewStyle().Foreground(ColorGray)
	}
	i := math.Min(float64(len(anomalyColorScale)-1), float64(len(anomalyColorScale))*((s-min)/(max-min)))
	i = math.Max(0, i)
	return lipgloss.NewStyle().Foreground(anomalyColorScale[int(i)])
}

var anomalyColorScale = []lipgloss.Color{
	lipgloss.Color("#0000FF"),
	lipgloss.Color("#0033FF"),
	lipgloss.Color("#6699FF"),
	lipgloss.Color("#CCE5FF"),
	lipgloss.Color("#E6F0FF"),
	lipgloss.Color("#FFF0C1"),
	lipgloss.Color("#FFE5A0"),
	lipgloss.Color("#FFD573"),
	lipgloss.Color("#FFC247"),
	lipgloss.Color("#FFAA33"),
	lipgloss.Color("#FF9124"),
	lipgloss.Color("#FF7216"),
	lipgloss.Color("#FF5500"),
	lipgloss.Color("#FF3300"),
	lipgloss.Color("#FF1100"),
}
