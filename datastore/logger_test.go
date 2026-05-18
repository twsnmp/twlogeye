package datastore

import (
	"testing"
	"time"
)

func TestSaveAndForEachLog(t *testing.T) {
	// Use in-memory DB
	Config.DBPath = ""
	Config.LogRetention = 24 // 24 hours
	OpenDB()
	defer CloseDB()

	now := time.Now().UnixNano()
	logs := []*LogEnt{
		{Time: now, Type: Syslog, Src: "host1", Log: "message 1"},
		{Time: now + 1, Type: Syslog, Src: "host2", Log: "message 2"},
	}

	err := SaveLogs("syslog", logs)
	if err != nil {
		t.Fatalf("SaveLogs failed: %v", err)
	}

	count := 0
	ForEachLog("syslog", now, now+1, func(l *LogEnt) bool {
		if l.Src != logs[count].Src {
			t.Errorf("expected Src %s, got %s", logs[count].Src, l.Src)
		}
		if l.Log != logs[count].Log {
			t.Errorf("expected Log %s, got %s", logs[count].Log, l.Log)
		}
		count++
		return true
	})

	if count != 2 {
		t.Errorf("expected 2 logs, got %d", count)
	}
}

func TestClearLog(t *testing.T) {
	Config.DBPath = ""
	Config.LogRetention = 24
	OpenDB()
	defer CloseDB()

	now := time.Now().UnixNano()
	SaveLogs("syslog", []*LogEnt{{Time: now, Type: Syslog, Src: "host1", Log: "msg"}})
	SaveLogs("netflow", []*LogEnt{{Time: now, Type: NetFlow, Src: "host1", Log: "msg"}})

	ClearLog("syslog")

	count := 0
	ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		count++
		return true
	})
	if count != 0 {
		t.Error("syslog should be cleared")
	}

	count = 0
	ForEachLog("netflow", 0, 0, func(l *LogEnt) bool {
		count++
		return true
	})
	if count == 0 {
		t.Error("netflow should NOT be cleared")
	}

	ClearLog("all")
	count = 0
	ForEachLog("netflow", 0, 0, func(l *LogEnt) bool {
		count++
		return true
	})
	if count != 0 {
		t.Error("netflow should be cleared by 'all'")
	}
}
