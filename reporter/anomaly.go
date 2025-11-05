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
var otelAnomaly anomalyCheckDataEnt
var monitorAnomaly anomalyCheckDataEnt
var clearAnomalyDataCh = make(chan bool)

func startAnomaly(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start anomaly reporter")
	defer wg.Done()
	loadReportData()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop anomaly reporter")
			return
		case <-clearAnomalyDataCh:
			loadReportData()
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
			case "otel":
				otelAnomaly.Times = append(otelAnomaly.Times, a.Time)
				otelAnomaly.Vectors = append(otelAnomaly.Vectors, a.Vector)
				calcAnomalyScore("otel", &otelAnomaly)
			case "monitor":
				monitorAnomaly.Times = append(monitorAnomaly.Times, a.Time)
				monitorAnomaly.Vectors = append(monitorAnomaly.Vectors, a.Vector)
				calcAnomalyScore("monitor", &monitorAnomaly)
			}
		}
	}
}

func ClearAnomalyData() {
	clearAnomalyDataCh <- true
}

func loadReportData() {
	syslogAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachSyslogReport(0, time.Now().UnixNano(), func(r *datastore.SyslogReportEnt) bool {
		syslogAnomaly.Times = append(syslogAnomaly.Times, r.Time)
		syslogAnomaly.Vectors = append(syslogAnomaly.Vectors, syslogReportToVector(r))
		return true
	})
	trapAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachTrapReport(0, time.Now().UnixNano(), func(r *datastore.TrapReportEnt) bool {
		trapAnomaly.Times = append(trapAnomaly.Times, r.Time)
		trapAnomaly.Vectors = append(trapAnomaly.Vectors, trapReportToVector(r))
		return true
	})
	netflowAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachNetflowReport(0, time.Now().UnixNano(), func(r *datastore.NetflowReportEnt) bool {
		netflowAnomaly.Times = append(netflowAnomaly.Times, r.Time)
		netflowAnomaly.Vectors = append(netflowAnomaly.Vectors, netflowReportToVector(r))
		return true
	})
	wineventAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachWindowsEventReport(0, time.Now().UnixNano(), func(r *datastore.WindowsEventReportEnt) bool {
		wineventAnomaly.Times = append(wineventAnomaly.Times, r.Time)
		wineventAnomaly.Vectors = append(wineventAnomaly.Vectors, wineventReportToVector(r))
		return true
	})
	otelAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachOTelReport(0, time.Now().UnixNano(), func(r *datastore.OTelReportEnt) bool {
		otelAnomaly.Times = append(otelAnomaly.Times, r.Time)
		otelAnomaly.Vectors = append(otelAnomaly.Vectors, otelReportToVector(r))
		return true
	})
	monitorAnomaly = anomalyCheckDataEnt{}
	datastore.ForEachMonitorReport(0, time.Now().UnixNano(), func(r *datastore.MonitorReportEnt) bool {
		monitorAnomaly.Times = append(monitorAnomaly.Times, r.Time)
		monitorAnomaly.Vectors = append(monitorAnomaly.Vectors, monitorReportToVector(r))
		return true
	})
}

func syslogReportToVector(r *datastore.SyslogReportEnt) []float64 {
	return []float64{
		float64(r.Normal),
		float64(r.Warn),
		float64(r.Error),
		float64(r.Patterns),
		float64(r.ErrPatterns),
	}
}

func trapReportToVector(r *datastore.TrapReportEnt) []float64 {
	return []float64{
		float64(r.Count),
		float64(r.Types),
	}
}

func netflowReportToVector(r *datastore.NetflowReportEnt) []float64 {
	return []float64{
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
	return []float64{
		float64(r.Normal),
		float64(r.Warn),
		float64(r.Error),
		float64(r.Types),
		float64(r.ErrorTypes),
	}
}

func monitorReportToVector(r *datastore.MonitorReportEnt) []float64 {
	return []float64{
		float64(r.CPU),
		float64(r.Memory),
		float64(r.Load),
		float64(r.Net),
		float64(r.Disk),
		float64(r.DBSpeed),
	}
}

func otelReportToVector(r *datastore.OTelReportEnt) []float64 {
	return []float64{
		float64(r.Normal),
		float64(r.Warn),
		float64(r.Error),
		float64(r.Types),
		float64(r.ErrorTypes),
		float64(r.Hosts),
		float64(r.MericsCount),
		float64(r.TraceCount),
		float64(r.TraceIDs),
	}
}

func calcAnomalyScore(t string, a *anomalyCheckDataEnt) {
	a.Scores = []float64{}
	if len(a.Times) < 10 {
		return
	}
	vectors := getVectors(a)
	subSamplingSize := 256
	if len(vectors) < subSamplingSize {
		subSamplingSize = len(vectors)
	}
	i, err := iforest.NewIForest(vectors, 1000, subSamplingSize)
	if err != nil {
		log.Printf("calcAnomalyScore err=%v", err)
		return
	}
	r := make([]float64, len(vectors))
	for j, v := range vectors {
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
		// All data is  same not anomaly
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
	list := []*datastore.AnomalyReportEnt{}
	var e *datastore.AnomalyReportEnt
	for j, v := range r {
		e = &datastore.AnomalyReportEnt{
			Time:  a.Times[j],
			Score: ((10 * (float64(v) - mean) / sd) + 50),
		}
		list = append(list, e)
	}
	datastore.SaveAnomalyReport(t, list)
	if e == nil || len(list) < 24 {
		return
	}
	if (e.Time - list[0].Time) < (int64(datastore.Config.AnomalyNotifyDelay) * 3600 * 1000 * 1000 * 1000) {
		return
	}
	if datastore.Config.AnomalyReportThreshold > 0 && datastore.Config.AnomalyReportThreshold < e.Score {
		auditor.Audit(&datastore.LogEnt{
			Time: e.Time,
			Type: datastore.AnomalyReport,
			Src:  "anomaly:" + t,
			Log:  fmt.Sprintf("%s reporter detect anomaly score=%.2f", t, e.Score),
		})
	}
}

func getVectors(a *anomalyCheckDataEnt) [][]float64 {
	if !datastore.Config.AnomalyUseTimeData ||
		a.Times[len(a.Times)-1]-a.Times[0] < 7*24*60*60*1000*1000*1000 ||
		len(a.Times) != len(a.Vectors) {
		return a.Vectors
	}
	r := [][]float64{}
	for i, v := range a.Vectors {
		t := time.Unix(0, a.Times[i])
		if t.Weekday() == time.Sunday || t.Weekday() == time.Saturday {
			v = append(v, float64(1))
		} else {
			v = append(v, float64(0))
		}
		v = append(v, float64(t.Hour()))
		r = append(r, v)
	}
	return r
}
