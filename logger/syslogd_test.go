package logger

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/reporter"
)

func TestSyslogd(t *testing.T) {
	// Setup in-memory DB for datastore
	datastore.Config.DBPath = ""
	datastore.Config.LogRetention = 24
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Setup auditor and reporter to avoid panics
	auditor.Init()
	reporter.Init()

	// Get free ports
	udpPort, err := getFreeUDPPort()
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}
	tcpPort, err := getFreeTCPPort()
	if err != nil {
		t.Fatalf("failed to get free TCP port: %v", err)
	}

	datastore.Config.SyslogUDPPort = udpPort
	datastore.Config.SyslogTCPPort = tcpPort
	datastore.Config.SigmaRules = "embed:test/syslog"

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go StartSyslogd(ctx, &wg)

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Send UDP syslog
	udpConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	fmt.Fprintf(udpConn, "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
	udpConn.Close()

	// Send TCP syslog
	tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to dial TCP: %v", err)
	}
	fmt.Fprintf(tcpConn, "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n")
	tcpConn.Close()

	// Wait for processing and timer (1s)
	time.Sleep(1500 * time.Millisecond)

	cancel()
	wg.Wait()

	// Check if logs are saved
	count := 0
	datastore.ForEachLog("syslog", 0, 0, func(l *datastore.LogEnt) bool {
		t.Logf("Found log: %v", l)
		count++
		return true
	})
	// We sent 2 messages
	if count < 1 {
		t.Errorf("expected at least 1 syslog, got %d", count)
	}
}
