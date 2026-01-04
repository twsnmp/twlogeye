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

var mqttReporterCh chan *datastore.MqttLogEnt
var mqttReport *datastore.MqttReportEnt
var mqttTypeMap map[string]int

func startMqtt(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.MqttTCPPort == 0 && datastore.Config.MqttWSPort == 0 {
		return
	}
	log.Printf("start mqtt reporter")
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	mqttReport = &datastore.MqttReportEnt{}
	mqttTypeMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop mqtt reporter")
			return
		case l := <-mqttReporterCh:
			processMqttReport(l)
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveMqttReport()
				log.Printf("save mqtt report dur=%v", time.Since(st))
			}
		}
	}
}

func SendMqtt(l *datastore.MqttLogEnt) {
	mqttReporterCh <- l
}

func processMqttReport(l *datastore.MqttLogEnt) {
	k := fmt.Sprintf("%s\t%s", l.ClientID, l.Topic)
	mqttTypeMap[k]++
	mqttReport.Count++
}

func saveMqttReport() {
	mqttReport.Time = time.Now().UnixNano()
	// make topList
	topList := []datastore.MqttSummaryEnt{}
	for k, v := range mqttTypeMap {
		a := strings.SplitN(k, "\t", 2)
		if len(a) == 2 {
			topList = append(topList, datastore.MqttSummaryEnt{ClientID: a[0], Topic: a[1], Count: v})
		}
	}
	sort.Slice(topList, func(i, j int) bool {
		return topList[i].Count > topList[j].Count
	})
	if len(topList) > datastore.Config.ReportTopN {
		topList = topList[:datastore.Config.ReportTopN]
	}
	mqttReport.TopList = topList
	mqttReport.Types = len(mqttTypeMap)
	// Save mqtt Report
	datastore.SaveMqttReport(mqttReport)
	anomalyCh <- &anomalyChannelData{
		Time:   mqttReport.Time,
		Type:   "mqtt",
		Vector: mqttReportToVector(mqttReport),
	}
	// Clear report
	mqttTypeMap = make(map[string]int)
	mqttReport = &datastore.MqttReportEnt{}
}
