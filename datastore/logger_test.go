package datastore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndForEachLog_Badger(t *testing.T) {
	// Use in-memory DB
	Config.DBPath = ""
	Config.LogPath = ""
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

func TestClearLog_Badger(t *testing.T) {
	Config.DBPath = ""
	Config.LogPath = ""
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

func TestParquetLogDataStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_parquet_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	Config.DBPath = ""
	Config.LogPath = filepath.Join(tmpDir, "logs.parquet")
	Config.LogRetention = 24
	OpenDB()
	defer CloseDB()

	if logStore == nil || logStore.Type() != EngineParquet {
		t.Fatalf("expected logStore to be EngineParquet, got %v", logStore)
	}

	now := time.Now().UnixNano()
	logs := []*LogEnt{
		{Time: now - 2000, Type: Syslog, Src: "server1", Log: "syslog message 1"},
		{Time: now - 1000, Type: Syslog, Src: "server2", Log: "syslog message 2"},
		{Time: now, Type: Syslog, Src: "server1", Log: "syslog message 3"},
	}

	if err := SaveLogs("syslog", logs); err != nil {
		t.Fatalf("SaveLogs failed: %v", err)
	}
	_ = FlushLog()

	// Verify Hive directory structure: type=syslog/date=YYYY-MM-DD/part_*.parquet
	todayStr := time.Now().Format("2006-01-02")
	expectedPartDir := filepath.Join(Config.LogPath, "type=syslog", "date="+todayStr)
	files, err := filepath.Glob(filepath.Join(expectedPartDir, "*.parquet"))
	if err != nil || len(files) == 0 {
		t.Fatalf("expected parquet files in %s, got err=%v files=%v", expectedPartDir, err, files)
	}

	// ForEachLog query in range
	var scanned []*LogEnt
	ForEachLog("syslog", now-2500, now+500, func(l *LogEnt) bool {
		scanned = append(scanned, l)
		return true
	})

	if len(scanned) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(scanned))
	}
	if scanned[0].Src != "server1" || scanned[0].Log != "syslog message 1" {
		t.Errorf("unexpected scanned log 0: %+v", scanned[0])
	}

	// ForEachLog sub-range query
	var subScanned []*LogEnt
	ForEachLog("syslog", now-1500, now-500, func(l *LogEnt) bool {
		subScanned = append(subScanned, l)
		return true
	})
	if len(subScanned) != 1 || subScanned[0].Log != "syslog message 2" {
		t.Fatalf("expected 1 log in subrange, got %d", len(subScanned))
	}

	// Test NetFlow logs in same Parquet store
	netflowLogs := []*LogEnt{
		{Time: now, Type: NetFlow, Src: "router1", Log: "netflow data"},
	}
	if err := SaveLogs("netflow", netflowLogs); err != nil {
		t.Fatalf("SaveLogs netflow failed: %v", err)
	}

	var nfScanned []*LogEnt
	ForEachLog("netflow", 0, 0, func(l *LogEnt) bool {
		nfScanned = append(nfScanned, l)
		return true
	})
	if len(nfScanned) != 1 || nfScanned[0].Src != "router1" {
		t.Fatalf("expected 1 netflow log, got %d", len(nfScanned))
	}

	// Test ClearLog for specific type
	ClearLog("syslog")
	var afterClearSyslog []*LogEnt
	ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		afterClearSyslog = append(afterClearSyslog, l)
		return true
	})
	if len(afterClearSyslog) != 0 {
		t.Errorf("expected 0 syslog after clear, got %d", len(afterClearSyslog))
	}

	// Netflow should still exist
	var afterClearNF []*LogEnt
	ForEachLog("netflow", 0, 0, func(l *LogEnt) bool {
		afterClearNF = append(afterClearNF, l)
		return true
	})
	if len(afterClearNF) != 1 {
		t.Errorf("expected 1 netflow after syslog clear, got %d", len(afterClearNF))
	}

	// Test ClearLog all
	ClearLog("all")
	var afterClearAll []*LogEnt
	ForEachLog("netflow", 0, 0, func(l *LogEnt) bool {
		afterClearAll = append(afterClearAll, l)
		return true
	})
	if len(afterClearAll) != 0 {
		t.Errorf("expected 0 netflow after clear all, got %d", len(afterClearAll))
	}
}

func TestParquetCleanup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_cleanup_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pStore := NewParquetLogDataStore()
	if err := pStore.Open(tmpDir); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer pStore.Close()

	// Old date (3 days ago)
	oldTime := time.Now().Add(-72 * time.Hour).UnixNano()
	oldLogs := []*LogEnt{
		{Time: oldTime, Type: Syslog, Src: "oldHost", Log: "old log"},
	}
	if err := pStore.SaveLogs("syslog", oldLogs); err != nil {
		t.Fatalf("SaveLogs old failed: %v", err)
	}

	// Current date
	nowTime := time.Now().UnixNano()
	newLogs := []*LogEnt{
		{Time: nowTime, Type: Syslog, Src: "newHost", Log: "new log"},
	}
	if err := pStore.SaveLogs("syslog", newLogs); err != nil {
		t.Fatalf("SaveLogs new failed: %v", err)
	}

	// Run cleanup with retention of 48 hours
	if err := pStore.Cleanup(48); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Old logs should be gone, new logs should remain
	var remaining []*LogEnt
	pStore.ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		remaining = append(remaining, l)
		return true
	})

	if len(remaining) != 1 || remaining[0].Log != "new log" {
		t.Fatalf("expected 1 remaining log ('new log'), got %d (%v)", len(remaining), remaining)
	}
}

func TestDetectEngineType(t *testing.T) {
	tests := []struct {
		path     string
		expected EngineType
	}{
		{"", EngineBadger},
		{"./test.db", EngineBadger},
		{"./test.badger", EngineBadger},
		{"badger://./mybadger", EngineBadger},
		{"./test.parquet", EngineParquet},
		{"./test.pq", EngineParquet},
		{"parquet://./myparquet", EngineParquet},
	}

	for _, tt := range tests {
		got := DetectEngineType(tt.path)
		if got != tt.expected {
			t.Errorf("DetectEngineType(%q) = %v, expected %v", tt.path, got, tt.expected)
		}
	}
}

func TestParquetBufferAndFlush(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_buffer_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	Config.DBPath = ""
	Config.LogPath = filepath.Join(tmpDir, "logs.parquet")
	Config.ParquetBufferSize = 5 // Small buffer threshold
	Config.ParquetBufferTime = 60
	OpenDB()
	defer CloseDB()

	now := time.Now().UnixNano()

	// Save 3 logs (< buffer size of 5)
	logs := []*LogEnt{
		{Time: now - 3000, Type: Syslog, Src: "host1", Log: "buffered 1"},
		{Time: now - 2000, Type: Syslog, Src: "host1", Log: "buffered 2"},
		{Time: now - 1000, Type: Syslog, Src: "host1", Log: "buffered 3"},
	}
	if err := SaveLogs("syslog", logs); err != nil {
		t.Fatalf("SaveLogs failed: %v", err)
	}

	todayStr := time.Now().Format("2006-01-02")
	partDir := filepath.Join(Config.LogPath, "type=syslog", "date="+todayStr)

	// Since buffer is not yet full and no flush has occurred, files should not exist yet
	files, _ := filepath.Glob(filepath.Join(partDir, "*.parquet"))
	if len(files) != 0 {
		t.Errorf("expected 0 files before buffer full/flush, got %d", len(files))
	}

	// ForEachLog automatically flushes pending buffers
	var readLogs []*LogEnt
	ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		readLogs = append(readLogs, l)
		return true
	})

	if len(readLogs) != 3 {
		t.Fatalf("expected 3 logs after ForEachLog auto-flush, got %d", len(readLogs))
	}

	// Files should now exist
	files, _ = filepath.Glob(filepath.Join(partDir, "*.parquet"))
	if len(files) == 0 {
		t.Errorf("expected parquet file after auto-flush")
	}

	// Test threshold trigger: save 6 logs (> buffer size of 5)
	moreLogs := []*LogEnt{
		{Time: now + 1, Type: Syslog, Src: "host2", Log: "auto-flush 1"},
		{Time: now + 2, Type: Syslog, Src: "host2", Log: "auto-flush 2"},
		{Time: now + 3, Type: Syslog, Src: "host2", Log: "auto-flush 3"},
		{Time: now + 4, Type: Syslog, Src: "host2", Log: "auto-flush 4"},
		{Time: now + 5, Type: Syslog, Src: "host2", Log: "auto-flush 5"},
		{Time: now + 6, Type: Syslog, Src: "host2", Log: "auto-flush 6"},
	}
	if err := SaveLogs("syslog", moreLogs); err != nil {
		t.Fatalf("SaveLogs more failed: %v", err)
	}

	// Should have flushed automatically due to threshold
	filesAfter, _ := filepath.Glob(filepath.Join(partDir, "*.parquet"))
	if len(filesAfter) < 2 {
		t.Errorf("expected at least 2 files after threshold flush, got %d", len(filesAfter))
	}
}

func TestParquetCompaction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_compaction_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pStore := NewParquetLogDataStore()
	if err := pStore.Open(tmpDir); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer pStore.Close()

	// Create 3 separate batches on a past date (yesterday)
	yesterday := time.Now().Add(-24 * time.Hour)
	yesterdayStr := yesterday.Format("2006-01-02")
	baseTime := yesterday.UnixNano()

	b1 := []*LogEnt{{Time: baseTime + 100, Type: Syslog, Src: "h1", Log: "log 1"}}
	b2 := []*LogEnt{{Time: baseTime + 200, Type: Syslog, Src: "h2", Log: "log 2"}}
	b3 := []*LogEnt{{Time: baseTime + 300, Type: Syslog, Src: "h3", Log: "log 3"}}

	_ = pStore.SaveLogs("syslog", b1)
	_ = pStore.Flush()
	_ = pStore.SaveLogs("syslog", b2)
	_ = pStore.Flush()
	_ = pStore.SaveLogs("syslog", b3)
	_ = pStore.Flush()

	pastDateDir := filepath.Join(tmpDir, "type=syslog", "date="+yesterdayStr)
	filesBefore, _ := filepath.Glob(filepath.Join(pastDateDir, "*.parquet"))
	if len(filesBefore) != 3 {
		t.Fatalf("expected 3 parquet files before compaction, got %d", len(filesBefore))
	}

	// Today's log (should NOT be compacted)
	todayStr := time.Now().Format("2006-01-02")
	todayLogs1 := []*LogEnt{{Time: time.Now().UnixNano(), Type: Syslog, Src: "h4", Log: "today 1"}}
	todayLogs2 := []*LogEnt{{Time: time.Now().UnixNano() + 1, Type: Syslog, Src: "h4", Log: "today 2"}}
	_ = pStore.SaveLogs("syslog", todayLogs1)
	_ = pStore.Flush()
	_ = pStore.SaveLogs("syslog", todayLogs2)
	_ = pStore.Flush()

	todayDir := filepath.Join(tmpDir, "type=syslog", "date="+todayStr)
	todayFilesBefore, _ := filepath.Glob(filepath.Join(todayDir, "*.parquet"))
	if len(todayFilesBefore) != 2 {
		t.Fatalf("expected 2 files in today dir, got %d", len(todayFilesBefore))
	}

	// Run compaction for past dates
	if err := pStore.Compact(todayStr); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// Past date directory should now have exactly 1 compacted file
	filesAfter, _ := filepath.Glob(filepath.Join(pastDateDir, "*.parquet"))
	if len(filesAfter) != 1 {
		t.Fatalf("expected 1 compacted file in past date dir, got %d", len(filesAfter))
	}

	// Today's directory should still have 2 files (unmodified)
	todayFilesAfter, _ := filepath.Glob(filepath.Join(todayDir, "*.parquet"))
	if len(todayFilesAfter) != 2 {
		t.Fatalf("expected today dir to remain 2 files, got %d", len(todayFilesAfter))
	}

	// Verify all logs can still be scanned correctly and in order
	var allRead []*LogEnt
	pStore.ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		allRead = append(allRead, l)
		return true
	})

	if len(allRead) != 5 {
		t.Fatalf("expected 5 total logs, got %d", len(allRead))
	}
	if allRead[0].Log != "log 1" || allRead[1].Log != "log 2" || allRead[2].Log != "log 3" {
		t.Errorf("unexpected compacted log order: %+v", allRead)
	}
}

func TestParquetCompactionSplit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_compaction_split_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pStore := NewParquetLogDataStore()
	if err := pStore.Open(tmpDir); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer pStore.Close()

	// Create 5 separate entries on a past date
	yesterday := time.Now().Add(-24 * time.Hour)
	yesterdayStr := yesterday.Format("2006-01-02")
	baseTime := yesterday.UnixNano()

	for i := 1; i <= 5; i++ {
		entry := []*LogEnt{{Time: baseTime + int64(i*100), Type: Syslog, Src: "h", Log: "split log"}}
		_ = pStore.SaveLogs("syslog", entry)
		_ = pStore.Flush()
	}

	pastDateDir := filepath.Join(tmpDir, "type=syslog", "date="+yesterdayStr)
	filesBefore, _ := filepath.Glob(filepath.Join(pastDateDir, "*.parquet"))
	if len(filesBefore) != 5 {
		t.Fatalf("expected 5 files before compaction, got %d", len(filesBefore))
	}

	// Compact with maxRecords = 2 (should split 5 records into 3 files: 2 + 2 + 1)
	if err := pStore.compactDateDir(pastDateDir, 2); err != nil {
		t.Fatalf("compactDateDir failed: %v", err)
	}

	filesAfter, _ := filepath.Glob(filepath.Join(pastDateDir, "*.parquet"))
	if len(filesAfter) != 3 {
		t.Fatalf("expected 3 split compacted files, got %d", len(filesAfter))
	}

	// Verify all 5 records are scanned
	var allRead []*LogEnt
	pStore.ForEachLog("syslog", 0, 0, func(l *LogEnt) bool {
		allRead = append(allRead, l)
		return true
	})

	if len(allRead) != 5 {
		t.Fatalf("expected 5 total logs, got %d", len(allRead))
	}
}
