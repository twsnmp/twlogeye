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

var syslogReporterCh chan *datastore.SyslogEnt
var syslogReport *datastore.SyslogReportEnt
var syslogNormalizeMap map[string]int
var syslogNormalizeErrorMap map[string]int

func startSyslog(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start syslog reporter")
	defer wg.Done()
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	syslogReport = &datastore.SyslogReportEnt{}
	syslogNormalizeMap = make(map[string]int)
	syslogNormalizeErrorMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop syslog reporter")
			return
		case l := <-syslogReporterCh:
			processSyslogReport(l)
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveSyslogReport()
				log.Printf("save syslog report dur=%v", time.Since(st))
			}
		}
	}
}

func SendSyslog(l *datastore.SyslogEnt) {
	syslogReporterCh <- l
}

func processSyslogReport(l *datastore.SyslogEnt) {
	// Levelを取得する
	var sv int
	var ok bool
	if sv, ok = l.Log["severity"].(int); !ok {
		log.Printf("severity=%#v", l.Log["severity"])
		return
	}
	var host string
	if host, ok = l.Log["hostname"].(string); !ok {
		return
	}
	var tag string
	var message string
	if tag, ok = l.Log["tag"].(string); !ok {
		if tag, ok = l.Log["app_name"].(string); !ok {
			return
		}
		message = ""
		for i, k := range []string{"proc_id", "msg_id", "message", "structured_data"} {
			if m, ok := l.Log[k].(string); ok && m != "" {
				if i > 0 {
					message += " "
				}
				message += m
			}
		}
	} else {
		if message, ok = l.Log["content"].(string); !ok {
			return
		}
	}
	// 正規化する
	n := normalizeSyslog(fmt.Sprintf("%s %s %s", host, tag, message))
	syslogNormalizeMap[n]++
	switch {
	case sv < 4:
		syslogNormalizeErrorMap[n]++
		syslogReport.Error++
	case sv == 4:
		syslogReport.Warn++
	default:
		syslogReport.Normal++
	}
}

func saveSyslogReport() {
	// make topList
	syslogReport.Time = time.Now().UnixNano()

	topList := []datastore.LogSummaryEnt{}
	for k, v := range syslogNormalizeMap {
		topList = append(topList, datastore.LogSummaryEnt{LogPattern: k, Count: v})
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	syslogReport.TopList = topList
	syslogReport.Patterns = len(syslogNormalizeMap)

	topErrorList := []datastore.LogSummaryEnt{}
	for k, v := range syslogNormalizeErrorMap {
		topErrorList = append(topErrorList, datastore.LogSummaryEnt{LogPattern: k, Count: v})
	}
	sort.Slice(topErrorList, func(i, j int) bool {
		return topErrorList[i].Count > topErrorList[j].Count
	})
	if len(topErrorList) > datastore.Config.ReportTopN {
		topErrorList = topErrorList[:datastore.Config.ReportTopN]
	}
	syslogReport.TopErrorList = topErrorList
	syslogReport.ErrPatterns = len(syslogNormalizeErrorMap)

	// Save syslog Report
	datastore.SaveSyslogReport(syslogReport)
	// Clear report
	syslogNormalizeMap = make(map[string]int)
	syslogNormalizeErrorMap = make(map[string]int)
	syslogReport = &datastore.SyslogReportEnt{}
}

var regNum = regexp.MustCompile(`\b-?\d+(\.\d+)?\b`)
var regUUDI = regexp.MustCompile(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
var regEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
var regIP = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
var regMAC = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2})\b`)

func normalizeSyslog(msg string) string {
	normalized := msg
	normalized = regUUDI.ReplaceAllString(normalized, "#UUID#")
	normalized = regEmail.ReplaceAllString(normalized, "#EMAIL#")
	normalized = regIP.ReplaceAllString(normalized, "#IP#")
	normalized = regMAC.ReplaceAllString(normalized, "#MAC#")
	normalized = regNum.ReplaceAllString(normalized, "#NUM#")
	return normalized
}
