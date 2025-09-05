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

var wineventReporterCh chan *datastore.WindowsEventEnt
var wineventReport *datastore.WindowsEventReportEnt
var wineventTypeMap map[string]int
var wineventTypeErrorMap map[string]int

func startWindowsEvent(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.WinEventLogCheckInterval == 0 || datastore.Config.WinEventLogChannel == "" {
		return
	}
	log.Printf("start winevent reporter")
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	wineventReport = &datastore.WindowsEventReportEnt{}
	wineventTypeMap = make(map[string]int)
	wineventTypeErrorMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop winevent reporter")
			return
		case l := <-wineventReporterCh:
			processWindowsEventReport(l)
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveWindowsEventReport()
				log.Printf("save windows event report dur=%v", time.Since(st))
			}
		}
	}
}

func SendWindowsEvent(l *datastore.WindowsEventEnt) {
	wineventReporterCh <- l
}

func processWindowsEventReport(l *datastore.WindowsEventEnt) {
	key := fmt.Sprintf("%s\t%s\t%d", l.Log.System.Computer, l.Log.System.Provider.Name, l.Log.System.EventID)
	switch l.Log.System.Level {
	case 1, 2:
		wineventReport.Error++
		wineventTypeErrorMap[key]++
	case 3:
		wineventReport.Warn++
	default:
		wineventReport.Normal++
	}
	wineventTypeMap[key]++
}

func saveWindowsEventReport() {
	wineventReport.Time = time.Now().UnixNano()
	// make topList
	topList := []datastore.WindowsEventSummary{}
	for k, v := range wineventTypeMap {
		a := strings.SplitN(k, "\t", 3)
		if len(a) < 3 {
			topList = append(topList, datastore.WindowsEventSummary{Computer: a[0], Provider: a[1], EeventID: a[2], Count: v})
		}
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	wineventReport.TopList = topList
	wineventReport.Types = len(wineventTypeMap)

	topErrorList := []datastore.WindowsEventSummary{}
	for k, v := range wineventTypeErrorMap {
		a := strings.SplitN(k, "\t", 3)
		if len(a) < 3 {
			topErrorList = append(topErrorList, datastore.WindowsEventSummary{Computer: a[0], Provider: a[1], EeventID: a[2], Count: v})
		}
	}
	sort.Slice(topErrorList, func(i, j int) bool {
		return topErrorList[i].Count > topErrorList[j].Count
	})
	if len(topErrorList) > datastore.Config.ReportTopN {
		topErrorList = topErrorList[:datastore.Config.ReportTopN]
	}
	wineventReport.TopErrorList = topErrorList
	wineventReport.ErrorTypes = len(wineventTypeErrorMap)

	// Save trap Report
	datastore.SaveWindowsEventReport(wineventReport)
	anomalyCh <- &anomalyChannelData{
		Time:   wineventReport.Time,
		Type:   "winevent",
		Vector: wineventReportToVector(wineventReport),
	}
	// Clear report
	wineventTypeMap = make(map[string]int)
	wineventTypeErrorMap = make(map[string]int)
	wineventReport = &datastore.WindowsEventReportEnt{}
}
