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
	anomalyCh = make(chan *anomalyChannelData, 10)
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
	switch datastore.Config.ReportInterval {
	case "day":
		return time.Now().Local().Day()
	case "minute":
		return time.Now().Minute()
	default:
		return time.Now().Hour()
	}
}
