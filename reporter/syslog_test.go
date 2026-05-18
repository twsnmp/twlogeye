package reporter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestSyslogReporter(t *testing.T) {
	// Setup in-memory DB
	datastore.Config.DBPath = ""
	datastore.Config.ReportInterval = 1
	datastore.Config.ReportTopN = 5
	datastore.Config.SyslogUDPPort = 514 // Non-zero to pass start check
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Initialize channels
	Init()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go startSyslog(ctx, &wg)

	// Wait for reporter to initialize syslogReport
	time.Sleep(100 * time.Millisecond)

	// Send some syslog entries
	now := time.Now().UnixNano()
	entries := []*datastore.SyslogEnt{
		{
			Time: now,
			Log: map[string]interface{}{
				"severity": 3, // Error
				"hostname": "host1",
				"tag":      "test",
				"content":  "error message 1",
			},
		},
		{
			Time: now + 1,
			Log: map[string]interface{}{
				"severity": 4, // Warning
				"hostname": "host1",
				"tag":      "test",
				"content":  "warning message 1",
			},
		},
		{
			Time: now + 2,
			Log: map[string]interface{}{
				"severity": 6, // Info
				"hostname": "host2",
				"tag":      "test",
				"content":  "info message 1",
			},
		},
	}

	for _, e := range entries {
		SendSyslog(e)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	if syslogReport == nil {
		t.Fatal("syslogReport is nil")
	}
	if syslogReport.Error != 1 {
		t.Errorf("expected 1 error, got %d", syslogReport.Error)
	}
	if syslogReport.Warn != 1 {
		t.Errorf("expected 1 warning, got %d", syslogReport.Warn)
	}
	if syslogReport.Normal != 1 {
		t.Errorf("expected 1 normal, got %d", syslogReport.Normal)
	}

	cancel()
	wg.Wait()
}

func TestNormalizeSyslog(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"host test 123", "host test #NUM#"},
		{"host test 192.168.1.1", "host test #IP#"},
		{"host test 00:11:22:33:44:55", "host test #MAC#"},
		{"host test user@example.com", "host test #EMAIL#"},
		{"host test 550e8400-e29b-41d4-a716-446655440000", "host test #UUID#"},
	}

	for _, tt := range tests {
		got := normalizeSyslog(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeSyslog(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}
