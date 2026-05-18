package logger

import (
	"context"
	"sync"
	"testing"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/reporter"
)

func TestSnmpTrapd(t *testing.T) {
	// Setup in-memory DB for datastore
	datastore.Config.DBPath = ""
	datastore.Config.LogRetention = 24
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Setup auditor and reporter
	auditor.Init()
	reporter.Init()

	// Get free UDP port
	trapPort, err := getFreeUDPPort()
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}

	datastore.Config.SNMPTrapPort = trapPort
	datastore.Config.TrapCommunity = "public"

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go StartSnmpTrapd(ctx, &wg)

	// Wait more for server to start and MIBDB to load
	time.Sleep(500 * time.Millisecond)

	// Send SNMP Trap (v2c)
	g := &gosnmp.GoSNMP{
		Target:    "127.0.0.1",
		Port:      uint16(trapPort),
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
	}
	err = g.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer g.Conn.Close()

	pdu := gosnmp.SnmpPDU{
		Name:  ".1.3.6.1.6.3.1.1.4.1.0", // snmpTrapOID.0
		Type:  gosnmp.ObjectIdentifier,
		Value: ".1.3.6.1.4.1.8072.2.3.0.1",
	}

	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{pdu},
	}

	_, err = g.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}
	t.Log("Trap sent")

	// Wait for processing and timer (1s)
	time.Sleep(2000 * time.Millisecond)

	cancel()
	wg.Wait()

	// Check if logs are saved
	count := 0
	datastore.ForEachLog("trap", 0, 0, func(l *datastore.LogEnt) bool {
		t.Logf("Found trap: %v", l)
		count++
		return true
	})
	if count < 1 {
		t.Errorf("expected at least 1 trap, got %d", count)
	}
}
