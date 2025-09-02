package reporter

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gopsnet "github.com/shirou/gopsutil/v3/net"

	"github.com/twsnmp/twlogeye/datastore"
)

var lastMonitorReport *datastore.MonitorReportEnt

func startMonitor(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start monitor reporter")
	defer wg.Done()
	timer := time.NewTicker(time.Second * 1)
	lastT := int64(0)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop monitor reporter")
			return
		case <-timer.C:
			t := time.Now().Unix() / 60
			if lastT != t {
				lastT = t
				saveMonitorReport()
			}
		}
	}
}

func saveMonitorReport() {
	m := &datastore.MonitorReportEnt{
		Time: time.Now().UnixNano(),
	}
	cpus, err := cpu.Percent(0, false)
	if err == nil {
		m.CPU = cpus[0]
	}
	l, err := load.Avg()
	if err == nil {
		m.Load = l.Load1
	}
	v, err := mem.VirtualMemory()
	if err == nil {
		m.Memory = v.UsedPercent
	}
	dbPath := datastore.Config.DBPath
	if dbPath == "" {
		dbPath = datastore.Config.LogPath
		if dbPath == "" {
			if wd, err := os.Getwd(); err == nil {
				dbPath = wd
			}
		}
	}
	d, err := disk.Usage(dbPath)
	if err == nil {
		m.Disk = d.UsedPercent
	}
	n, err := gopsnet.IOCounters(true)
	if err == nil {
		for _, nif := range n {
			m.Bytes += int64(nif.BytesRecv)
			m.Bytes += int64(nif.BytesSent)
		}
		if lastMonitorReport != nil {
			o := lastMonitorReport
			if m.Bytes >= o.Bytes && m.Time > o.Time {
				m.Net = float64(1000*1000*1000*8.0*(m.Bytes-o.Bytes)) / float64(m.Time-o.Time)
			} else {
				log.Println("skip net monior")
			}
		}
	}
	m.DBSize = datastore.GetDBSize()
	if lastMonitorReport != nil {
		if m.Time > lastMonitorReport.Time {
			m.DBSpeed = float64(1000*1000*1000*(m.DBSize-lastMonitorReport.DBSize)) / float64(m.Time-lastMonitorReport.Time)
		}
	}
	// Save monitor Report
	datastore.SaveMonitorReport(m)
	anomalyCh <- &anomalyChannelData{
		Time:   m.Time,
		Type:   "monitor",
		Vector: monitorReportToVector(m),
	}
	// Clear report
	lastMonitorReport = m
}
