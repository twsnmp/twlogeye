package reporter

import (
	"context"
	"sync"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func Init() {
	datastore.LoadServiceMap()
	syslogReporterCh = make(chan *datastore.SyslogEnt, 20000)
	trapReporterCh = make(chan *datastore.TrapLogEnt, 20000)
	netflowReporterCh = make(chan *datastore.NetflowLogEnt, 20000)
	wineventReporterCh = make(chan *datastore.WindowsEventEnt, 20000)
	anomalyCh = make(chan *anomalyChannelData, 10)
	if datastore.Config.ReportInterval < 1 {
		datastore.Config.ReportInterval = 5
	}
}

func Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go startSyslog(ctx, wg)
	wg.Add(1)
	go startTrap(ctx, wg)
	wg.Add(1)
	go startNetflow(ctx, wg)
	wg.Add(1)
	go startWindowsEvent(ctx, wg)
	wg.Add(1)
	go startAnomaly(ctx, wg)
	wg.Add(1)
	go startMonitor(ctx, wg)
}

func getIntervalTime() int {
	return int(time.Now().Unix() / int64(datastore.Config.ReportInterval*60))
}
