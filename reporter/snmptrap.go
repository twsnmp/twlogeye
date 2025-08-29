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

var trapReporterCh chan *datastore.TrapLogEnt
var trapReport *datastore.TrapReportEnt
var trapTypeMap map[string]int

func startTrap(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start trap reporter")
	defer wg.Done()
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	trapReport = &datastore.TrapReportEnt{}
	trapTypeMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop trap reporter")
			return
		case l := <-trapReporterCh:
			processTrapReport(l)
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveTrapReport()
				log.Printf("save trap report dur=%v", time.Since(st))
			}
		}
	}
}

func SendTrap(l *datastore.TrapLogEnt) {
	trapReporterCh <- l
}

func processTrapReport(l *datastore.TrapLogEnt) {
	var ok bool
	var fa string
	var trapType string
	if fa, ok = l.Log["FromAddress"].(string); !ok {
		return
	}
	var ent string
	if ent, ok = l.Log["Enterprise"].(string); !ok || ent == "" {
		if trapType, ok = l.Log["snmpTrapOID.0"].(string); !ok {
			return
		}
	} else {
		var gen int
		if gen, ok = l.Log["GenericTrap"].(int); !ok {
			return
		}
		var spe int
		if spe, ok = l.Log["SpecificTrap"].(int); !ok {
			return
		}
		trapType = fmt.Sprintf("%s:%d:%d", ent, int(gen), int(spe))
	}
	k := fmt.Sprintf("%s\t%s", fa, trapType)
	trapTypeMap[k]++
	trapReport.Count++
}

func saveTrapReport() {
	trapReport.Time = time.Now().UnixNano()
	// make topList
	topList := []datastore.TrapSummaryEnt{}
	for k, v := range trapTypeMap {
		a := strings.SplitN(k, "\t", 2)
		if len(a) == 2 {
			topList = append(topList, datastore.TrapSummaryEnt{Sender: a[0], TrapType: a[1], Count: v})
		}
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	trapReport.TopList = topList
	trapReport.Types = len(trapTypeMap)

	// Save trap Report
	datastore.SaveTrapReport(trapReport)
	anomalyCh <- &anomalyChannelData{
		Time:   trapReport.Time,
		Type:   "trap",
		Vector: trapReportToVector(trapReport),
	}
	// Clear report
	trapTypeMap = make(map[string]int)
	trapReport = &datastore.TrapReportEnt{}
}
