package reporter

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
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
	lastH := time.Now().Hour()
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
			h := time.Now().Hour()
			if lastH != h {
				saveTrapReport()
			}

		}
	}
}

func SendTrap(l *datastore.TrapLogEnt) {
	trapReporterCh <- l
}

var trapOidRegexp = regexp.MustCompile(`snmpTrapOID.0=(\S+)`)

func processTrapReport(l *datastore.TrapLogEnt) {
	var ok bool
	var fa string
	var trapType string
	if fa, ok = l.Log["FromAddress"].(string); !ok {
		return
	}
	var ent string
	if ent, ok = l.Log["Enterprise"].(string); !ok || ent == "" {
		var v string
		if v, ok = l.Log["Variables"].(string); !ok {
			return
		}
		a := trapOidRegexp.FindStringSubmatch(v)
		if len(a) > 1 {
			trapType = a[1]
		} else {
			trapType = ""
		}
	} else {
		var gen float64
		if gen, ok = l.Log["GenericTrap"].(float64); !ok {
			return
		}
		var spe float64
		if spe, ok = l.Log["SpecificTrap"].(float64); !ok {
			return
		}
		trapType = fmt.Sprintf("%s:%d:%d", ent, int(gen), int(spe))
	}
	k := fmt.Sprintf("%s\t%s", fa, trapType)
	trapTypeMap[k]++
	trapReport.Count++
}

func saveTrapReport() {
	// make topList
	topList := []datastore.TrapSummaryEnt{}
	for k, v := range trapTypeMap {
		topList = append(topList, datastore.TrapSummaryEnt{TrapType: k, Count: v})
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	trapReport.TopList = topList
	// Save trap Report
	datastore.SaveTrapReport(trapReport)
	// Clear report
	trapTypeMap = make(map[string]int)
	trapReport = &datastore.TrapReportEnt{}
}
