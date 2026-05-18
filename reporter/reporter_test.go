package reporter

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestTrapReporter(t *testing.T) {
	datastore.Config.DBPath = ""
	datastore.Config.SNMPTrapPort = 162
	datastore.OpenDB()
	defer datastore.CloseDB()

	Init()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go startTrap(ctx, &wg)

	// Explicitly initialize
	trapReport = &datastore.TrapReportEnt{}
	trapTypeMap = make(map[string]int)

	time.Sleep(100 * time.Millisecond)

	now := time.Now().UnixNano()
	SendTrap(&datastore.TrapLogEnt{
		Time: now,
		Log: map[string]interface{}{
			"FromAddress":   "127.0.0.1",
			"snmpTrapOID.0": "1.3.6.1.4.1.8072.2.3.0.1",
		},
	})

	time.Sleep(100 * time.Millisecond)

	if trapReport.Count != 1 {
		t.Errorf("expected 1 trap, got %d", trapReport.Count)
	}

	cancel()
	wg.Wait()
}

func TestNetflowReporter(t *testing.T) {
	datastore.Config.DBPath = ""
	datastore.Config.NetFlowPort = 2055
	datastore.OpenDB()
	defer datastore.CloseDB()

	Init()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go startNetflow(ctx, &wg)

	// Explicitly initialize
	netflowReport = &datastore.NetflowReportEnt{}
	netflowMACMap = make(map[string]*netflowSummaryEnt)
	netflowIPMap = make(map[string]*netflowSummaryEnt)
	netflowFlowMap = make(map[string]*netflowSummaryEnt)
	netflowProtocolMap = make(map[string]int)
	netflowFumbleSrcMap = make(map[string]int)
	netflowHostMap = make(map[string]int)
	netflowCountryMap = make(map[string]int)
	netflowLocMap = make(map[string]int)

	time.Sleep(100 * time.Millisecond)

	now := time.Now().UnixNano()
	SendNetflow(&datastore.NetflowLogEnt{
		Time: now,
		Log: map[string]interface{}{
			"srcAddr": net.ParseIP("192.168.1.1"),
			"srcPort": 1234.0,
			"dstAddr": net.ParseIP("192.168.1.2"),
			"dstPort": 80.0,
			"bytes":   1000.0,
			"packets": 10.0,
		},
	})

	time.Sleep(100 * time.Millisecond)

	if netflowReport.Packets != 10 {
		t.Errorf("expected 10 packets, got %d", netflowReport.Packets)
	}
	if netflowReport.Bytes != 1000 {
		t.Errorf("expected 1000 bytes, got %d", netflowReport.Bytes)
	}

	cancel()
	wg.Wait()
}
