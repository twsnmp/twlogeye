package reporter

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/montanaflynn/stats"

	iforest "github.com/codegaudi/go-iforest"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

type anomalyChannelData struct {
	Time   int64
	Type   string
	Vector []float64
}

type anomalyCheckDataEnt struct {
	Times   []int64
	Vectors [][]float64
	Scores  []float64
}

var anomalyCh chan *anomalyChannelData
var syslogAnomaly anomalyCheckDataEnt
var trapAnomaly anomalyCheckDataEnt
var netflowAnomaly anomalyCheckDataEnt
var wineventAnomaly anomalyCheckDataEnt

func startAnomaly(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start anomaly reporter")
	defer wg.Done()
	loadReportData()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop anomaly reporter")
			return
		case a := <-anomalyCh:
			switch a.Type {
			case "syslog":
				syslogAnomaly.Times = append(syslogAnomaly.Times, a.Time)
				syslogAnomaly.Vectors = append(syslogAnomaly.Vectors, a.Vector)
				calcAnomalyScore("syslog", &syslogAnomaly)
			case "trap":
				trapAnomaly.Times = append(trapAnomaly.Times, a.Time)
				trapAnomaly.Vectors = append(trapAnomaly.Vectors, a.Vector)
				calcAnomalyScore("trap", &trapAnomaly)
			case "netflow":
				netflowAnomaly.Times = append(netflowAnomaly.Times, a.Time)
				netflowAnomaly.Vectors = append(netflowAnomaly.Vectors, a.Vector)
				calcAnomalyScore("netflow", &netflowAnomaly)
			case "winevent":
				wineventAnomaly.Times = append(wineventAnomaly.Times, a.Time)
				wineventAnomaly.Vectors = append(wineventAnomaly.Vectors, a.Vector)
				calcAnomalyScore("winevent", &wineventAnomaly)
			}
		}
	}
}

func loadReportData() {
	datastore.ForEachSyslogReport(0, time.Now().UnixNano(), func(r *datastore.SyslogReportEnt) bool {
		syslogAnomaly.Times = append(syslogAnomaly.Times, r.Time)
		syslogAnomaly.Vectors = append(syslogAnomaly.Vectors, syslogReportToVector(r))
		return true
	})
	datastore.ForEachTrapReport(0, time.Now().UnixNano(), func(r *datastore.TrapReportEnt) bool {
		trapAnomaly.Times = append(trapAnomaly.Times, r.Time)
		trapAnomaly.Vectors = append(trapAnomaly.Vectors, trapReportToVector(r))
		return true
	})
	datastore.ForEachNetflowReport(0, time.Now().UnixNano(), func(r *datastore.NetflowReportEnt) bool {
		netflowAnomaly.Times = append(netflowAnomaly.Times, r.Time)
		netflowAnomaly.Vectors = append(netflowAnomaly.Vectors, netflowReportToVector(r))
		return true
	})
	datastore.ForEachWindowsEventReport(0, time.Now().UnixNano(), func(r *datastore.WindowsEventReportEnt) bool {
		wineventAnomaly.Times = append(wineventAnomaly.Times, r.Time)
		wineventAnomaly.Vectors = append(wineventAnomaly.Vectors, wineventReportToVector(r))
		return true
	})
}

func syslogReportToVector(r *datastore.SyslogReportEnt) []float64 {
	t := time.Unix(0, r.Time)
	return []float64{
		float64(t.Hour()),
		float64(t.Weekday()),
		float64(r.Normal),
		float64(r.Warn),
		float64(r.Error),
		float64(r.Patterns),
		float64(r.ErrPatterns),
	}
}
func trapReportToVector(r *datastore.TrapReportEnt) []float64 {
	t := time.Unix(0, r.Time)
	return []float64{
		float64(t.Hour()),
		float64(t.Weekday()),
		float64(r.Count),
		float64(r.Types),
	}
}

func netflowReportToVector(r *datastore.NetflowReportEnt) []float64 {
	t := time.Unix(0, r.Time)
	return []float64{
		float64(t.Hour()),
		float64(t.Weekday()),
		float64(r.Packets),
		float64(r.Bytes),
		float64(r.MACs),
		float64(r.IPs),
		float64(r.Flows),
		float64(r.Protocols),
		float64(r.Fumbles),
	}
}

func wineventReportToVector(r *datastore.WindowsEventReportEnt) []float64 {
	t := time.Unix(0, r.Time)
	return []float64{
		float64(t.Hour()),
		float64(t.Weekday()),
		float64(r.Normal),
		float64(r.Warn),
		float64(r.Error),
		float64(r.Types),
		float64(r.ErrorTypes),
	}
}

func calcAnomalyScore(t string, a *anomalyCheckDataEnt) {
	a.Scores = []float64{}
	if len(a.Times) < 10 {
		return
	}
	subSamplingSize := 256
	if len(a.Vectors) < subSamplingSize {
		subSamplingSize = len(a.Vectors)
	}
	i, err := iforest.NewIForest(a.Vectors, 1000, subSamplingSize)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	r := make([]float64, len(a.Vectors))
	for j, v := range a.Vectors {
		r[j] = i.CalculateAnomalyScore(v)
	}
	max, err := stats.Max(r)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	min, err := stats.Min(r)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	diff := max - min
	if diff == 0 {
		log.Println("calcAnomalyScore diff=0")
		// All data is  same not anomaly
		datastore.SaveAnomalyReport(&datastore.AnomalyReportEnt{
			Time:    time.Now().UnixNano(),
			Type:    t,
			Score:   50.0,
			Max:     50.0,
			MaxTime: time.Now().UnixNano(),
		})
		return
	}
	for i := range r {
		r[i] /= diff
		r[i] *= 100.0
	}
	mean, err := stats.Mean(r)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	sd, err := stats.StandardDeviation(r)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	maxScore := 0.0
	maxTime := int64(0)
	lastScore := 0.0
	lastTime := int64(0)
	for j, v := range r {
		score := ((10 * (float64(v) - mean) / sd) + 50)
		a.Scores = append(a.Scores, score)
		if score > maxScore {
			maxScore = score
			maxTime = a.Times[j]
		}
		lastScore = score
		lastTime = a.Times[j]
	}
	datastore.SaveAnomalyReport(&datastore.AnomalyReportEnt{
		Time:    lastTime,
		Type:    t,
		Score:   lastScore,
		Max:     maxScore,
		MaxTime: maxTime,
	})
	if datastore.Config.AnomalyReportThreshold > 0 && datastore.Config.AnomalyReportThreshold < lastScore {
		auditor.Audit(&datastore.LogEnt{
			Time: lastTime,
			Type: datastore.AnomalyReport,
			Src:  "anomaly:" + t,
			Log:  fmt.Sprintf("%s reporter detect anomaly score=%.2f", t, lastScore),
		})
	}
}
