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
	log.Printf("start winevent reporter")
	defer wg.Done()
	timer := time.NewTicker(time.Second * 1)
	lastH := time.Now().Hour()
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
			h := time.Now().Hour()
			if lastH != h {
				saveWindowsEventReport()
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
	// Save trap Report
	datastore.SaveWindowsEventReport(wineventReport)
	// Clear report
	wineventTypeMap = make(map[string]int)
	wineventTypeErrorMap = make(map[string]int)
	wineventReport = &datastore.WindowsEventReportEnt{}
}
