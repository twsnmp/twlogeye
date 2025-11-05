package reporter

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

var otelReporterCh chan *datastore.OTelLogEnt
var otelCountCh chan string
var otelReport *datastore.OTelReportEnt
var otelHostMap map[string]int
var otelTypeMap map[string]int
var otelErrorTypeMap map[string]int
var otelTraceIDMap map[string]int

func startOTel(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.OTelHTTPPort == 0 && datastore.Config.OTelgRPCPort == 0 {
		return
	}
	log.Printf("start otel reporter")
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	otelReport = &datastore.OTelReportEnt{}
	otelHostMap = make(map[string]int)
	otelTypeMap = make(map[string]int)
	otelErrorTypeMap = make(map[string]int)
	otelTraceIDMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop otel reporter")
			return
		case l := <-otelReporterCh:
			processOTelReport(l)
		case t := <-otelCountCh:
			switch t {
			case "metrics":
				otelReport.MericsCount++
			case "trace":
				otelReport.TraceCount++
			}
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveOTelReport()
				log.Printf("save otel report dur=%v", time.Since(st))
			}
		}
	}
}

func SendOTel(l *datastore.OTelLogEnt) {
	otelReporterCh <- l
}

func CountOTel(t string) {
	otelCountCh <- t
}

func processOTelReport(l *datastore.OTelLogEnt) {
	otelHostMap[l.Host]++
	k := fmt.Sprintf("%s\t%s\t%s\t%s", l.Host, l.Service, l.Scope, l.SeverityText)
	otelTypeMap[k]++
	switch {
	case l.SeverityNumber <= 16 && l.SeverityNumber > 12:
		otelReport.Warn++
	case l.SeverityNumber > 16:
		otelReport.Error++
		otelErrorTypeMap[k]++
	default:
		otelReport.Normal++
	}
}

func saveOTelReport() {
	otelReport.Time = time.Now().UnixNano()
	// make topList
	topList := []datastore.OTelSummaryEnt{}
	for k, v := range otelTypeMap {
		a := strings.SplitN(k, "\t", 4)
		if len(a) == 4 {
			topList = append(topList, datastore.OTelSummaryEnt{Host: a[0], Service: a[1], Scope: a[2], Severity: a[3], Count: v})
		}
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	// make topErrorList
	topErrorList := []datastore.OTelSummaryEnt{}
	for k, v := range otelErrorTypeMap {
		a := strings.SplitN(k, "\t", 4)
		if len(a) == 4 {
			topErrorList = append(topErrorList, datastore.OTelSummaryEnt{Host: a[0], Service: a[1], Scope: a[2], Severity: a[3], Count: v})
		}
	}
	sort.Slice(topErrorList, func(i, j int) bool {
		return topErrorList[i].Count > topErrorList[j].Count
	})
	if len(topErrorList) > datastore.Config.ReportTopN {
		topErrorList = topList[:datastore.Config.ReportTopN]
	}
	otelReport.TopList = topList
	otelReport.TopErrorList = topErrorList
	otelReport.Types = len(otelTypeMap)
	otelReport.Hosts = len(otelHostMap)
	otelReport.TraceIDs = len(otelTraceIDMap)
	otelReport.ErrorTypes = len(trapTypeMap)

	// Save trap Report
	datastore.SaveOTelReport(otelReport)
	anomalyCh <- &anomalyChannelData{
		Time:   otelReport.Time,
		Type:   "otel",
		Vector: otelReportToVector(otelReport),
	}
	// Clear report
	otelHostMap = make(map[string]int)
	otelTypeMap = make(map[string]int)
	otelErrorTypeMap = make(map[string]int)
	otelTraceIDMap = make(map[string]int)
	otelReport = &datastore.OTelReportEnt{}
}
