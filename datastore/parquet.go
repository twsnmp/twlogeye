package datastore

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

type ParquetLogRecord struct {
	Time      int64  `parquet:"time,snappy"`
	Timestamp int64  `parquet:"timestamp,timestamp(nanosecond),snappy"`
	Type      string `parquet:"type,dict,snappy"`
	Src       string `parquet:"src,dict,snappy"`
	Log       string `parquet:"log,zstd"`
}

type ParquetLogDataStore struct {
	dirPath        string
	bufferSize     int
	bufferInterval time.Duration

	mu          sync.Mutex
	typeBuffers map[string][]*LogEnt
	bufferCount int

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewParquetLogDataStore() *ParquetLogDataStore {
	return &ParquetLogDataStore{
		typeBuffers: make(map[string][]*LogEnt),
	}
}

func (s *ParquetLogDataStore) Type() EngineType {
	return EngineParquet
}

func (s *ParquetLogDataStore) Open(path string) error {
	cleanPath := path
	cleanPath = strings.TrimPrefix(cleanPath, "parquet://")
	if cleanPath == "" {
		cleanPath = "./twlogeye.parquet"
	}
	s.dirPath = cleanPath
	if err := os.MkdirAll(s.dirPath, 0755); err != nil {
		return fmt.Errorf("create parquet directory: %w", err)
	}

	s.bufferSize = Config.ParquetBufferSize
	if s.bufferSize <= 0 {
		s.bufferSize = 10000
	}

	bufTime := Config.ParquetBufferTime
	if bufTime <= 0 {
		bufTime = 60
	}
	s.bufferInterval = time.Duration(bufTime) * time.Second

	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	go s.flushLoop()

	return nil
}

func (s *ParquetLogDataStore) flushLoop() {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.bufferInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = s.Flush()
		case <-s.stopCh:
			return
		}
	}
}

func (s *ParquetLogDataStore) Close() error {
	if s.stopCh != nil {
		close(s.stopCh)
		<-s.doneCh
		s.stopCh = nil
	}
	return s.Flush()
}

func (s *ParquetLogDataStore) SaveLogs(t string, logs []*LogEnt) error {
	if len(logs) == 0 {
		return nil
	}
	s.mu.Lock()
	s.typeBuffers[t] = append(s.typeBuffers[t], logs...)
	s.bufferCount += len(logs)
	needFlush := s.bufferCount >= s.bufferSize
	s.mu.Unlock()

	if needFlush {
		return s.Flush()
	}
	return nil
}

func (s *ParquetLogDataStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bufferCount == 0 {
		return nil
	}

	for t, logs := range s.typeBuffers {
		if len(logs) == 0 {
			continue
		}

		// Group logs by date (YYYY-MM-DD)
		grouped := make(map[string][]*LogEnt)
		for _, l := range logs {
			d := time.Unix(0, l.Time).Format("2006-01-02")
			grouped[d] = append(grouped[d], l)
		}

		for dateStr, dateLogs := range grouped {
			partDir := filepath.Join(s.dirPath, "type="+t, "date="+dateStr)
			if err := os.MkdirAll(partDir, 0755); err != nil {
				return fmt.Errorf("create parquet partition directory: %w", err)
			}

			records := make([]ParquetLogRecord, len(dateLogs))
			for i, l := range dateLogs {
				records[i] = ParquetLogRecord{
					Time:      l.Time,
					Timestamp: l.Time,
					Type:      t,
					Src:       l.Src,
					Log:       l.Log,
				}
			}

			var randBytes [4]byte
			_, _ = rand.Read(randBytes[:])
			randVal := binary.BigEndian.Uint32(randBytes[:])

			fileName := fmt.Sprintf("part_%016x_%08x.parquet", time.Now().UnixNano(), randVal)
			filePath := filepath.Join(partDir, fileName)

			file, err := os.Create(filePath)
			if err != nil {
				return fmt.Errorf("create parquet file: %w", err)
			}

			writer := parquet.NewGenericWriter[ParquetLogRecord](file)
			if _, err := writer.Write(records); err != nil {
				_ = file.Close()
				return fmt.Errorf("write parquet records: %w", err)
			}
			if err := writer.Close(); err != nil {
				_ = file.Close()
				return fmt.Errorf("close parquet writer: %w", err)
			}
			_ = file.Close()
		}
	}

	s.typeBuffers = make(map[string][]*LogEnt)
	s.bufferCount = 0
	return nil
}

func (s *ParquetLogDataStore) ForEachLog(t string, st, et int64, callBack func(log *LogEnt) bool) {
	// Flush pending memory buffer to ensure search completeness
	_ = s.Flush()

	if et == 0 {
		et = time.Now().UnixNano()
	}

	var typeDirs []string
	if t == "all" || t == "" {
		pattern := filepath.Join(s.dirPath, "type=*")
		matches, _ := filepath.Glob(pattern)
		typeDirs = matches
		if len(typeDirs) == 0 {
			typeDirs = []string{s.dirPath}
		}
	} else {
		typeDirs = []string{filepath.Join(s.dirPath, "type="+t)}
	}

	for _, tDir := range typeDirs {
		dateDirs, _ := filepath.Glob(filepath.Join(tDir, "date=*"))
		if len(dateDirs) == 0 {
			s.scanParquetDir(tDir, st, et, callBack)
			continue
		}

		sort.Strings(dateDirs)
		startDateStr := time.Unix(0, st).Format("2006-01-02")
		endDateStr := time.Unix(0, et).Format("2006-01-02")

		for _, dDir := range dateDirs {
			base := filepath.Base(dDir)
			dStr := strings.TrimPrefix(base, "date=")
			if dStr < startDateStr || dStr > endDateStr {
				continue
			}
			if !s.scanParquetDir(dDir, st, et, callBack) {
				return
			}
		}
	}
}

func (s *ParquetLogDataStore) scanParquetDir(dir string, st, et int64, callBack func(log *LogEnt) bool) bool {
	files, err := filepath.Glob(filepath.Join(dir, "*.parquet"))
	if err != nil || len(files) == 0 {
		return true
	}
	sort.Strings(files)

	for _, filePath := range files {
		if strings.HasPrefix(filepath.Base(filePath), "compacting_") {
			continue
		}

		f, err := os.Open(filePath)
		if err != nil {
			continue
		}

		fi, err := f.Stat()
		if err != nil || fi.Size() == 0 {
			_ = f.Close()
			continue
		}

		pf, err := parquet.OpenFile(f, fi.Size())
		if err != nil {
			_ = f.Close()
			continue
		}

		reader := parquet.NewGenericReader[ParquetLogRecord](pf)
		buf := make([]ParquetLogRecord, 1024)
		stop := false

		for {
			n, err := reader.Read(buf)
			if n > 0 {
				for i := 0; i < n; i++ {
					rec := &buf[i]
					if rec.Time < st {
						continue
					}
					if rec.Time > et {
						continue
					}
					logType := Syslog
					switch rec.Type {
					case "syslog":
						logType = Syslog
					case "netflow":
						logType = NetFlow
					case "trap":
						logType = SnmpTrap
					case "windows":
						logType = WindowsEventLog
					case "otel":
						logType = OTel
					case "mqtt":
						logType = Mqtt
					case "anomalyReport":
						logType = AnomalyReport
					}
					entry := &LogEnt{
						Time: rec.Time,
						Type: logType,
						Src:  rec.Src,
						Log:  rec.Log,
					}
					if !callBack(entry) {
						stop = true
						break
					}
				}
			}
			if stop || err != nil {
				break
			}
		}
		_ = reader.Close()
		_ = f.Close()

		if stop {
			return false
		}
	}
	return true
}

func (s *ParquetLogDataStore) ClearLog(t string) {
	s.mu.Lock()
	if t == "all" {
		s.typeBuffers = make(map[string][]*LogEnt)
		s.bufferCount = 0
	} else {
		if len(s.typeBuffers[t]) > 0 {
			s.bufferCount -= len(s.typeBuffers[t])
			delete(s.typeBuffers, t)
		}
	}
	s.mu.Unlock()

	if t == "all" {
		typeDirs, _ := filepath.Glob(filepath.Join(s.dirPath, "type=*"))
		for _, d := range typeDirs {
			_ = os.RemoveAll(d)
		}
		files, _ := filepath.Glob(filepath.Join(s.dirPath, "*.parquet"))
		for _, f := range files {
			_ = os.Remove(f)
		}
		return
	}

	targetDir := filepath.Join(s.dirPath, "type="+t)
	_ = os.RemoveAll(targetDir)
}

func (s *ParquetLogDataStore) Cleanup(retentionHours int) error {
	if retentionHours <= 0 {
		return nil
	}
	_ = s.Flush()

	cutoffTime := time.Now().Add(-time.Hour * time.Duration(retentionHours))
	cutoffDateStr := cutoffTime.Format("2006-01-02")
	cutoffNano := cutoffTime.UnixNano()

	typeDirs, _ := filepath.Glob(filepath.Join(s.dirPath, "type=*"))
	for _, tDir := range typeDirs {
		dateDirs, _ := filepath.Glob(filepath.Join(tDir, "date=*"))
		for _, dDir := range dateDirs {
			base := filepath.Base(dDir)
			dStr := strings.TrimPrefix(base, "date=")
			if dStr < cutoffDateStr {
				_ = os.RemoveAll(dDir)
			} else if dStr == cutoffDateStr {
				files, _ := filepath.Glob(filepath.Join(dDir, "*.parquet"))
				for _, f := range files {
					if fi, err := os.Stat(f); err == nil {
						if fi.ModTime().UnixNano() < cutoffNano {
							_ = os.Remove(f)
						}
					}
				}
			}
		}
	}
	return nil
}

// Compact merges multiple parquet files in past date directories into a single compacted file.
func (s *ParquetLogDataStore) Compact(currentDate string) error {
	_ = s.Flush()

	if currentDate == "" {
		currentDate = time.Now().Format("2006-01-02")
	}

	typeDirs, _ := filepath.Glob(filepath.Join(s.dirPath, "type=*"))
	for _, tDir := range typeDirs {
		dateDirs, _ := filepath.Glob(filepath.Join(tDir, "date=*"))
		for _, dDir := range dateDirs {
			base := filepath.Base(dDir)
			dStr := strings.TrimPrefix(base, "date=")
			// Only compact past dates (date < currentDate)
			if dStr >= currentDate {
				continue
			}

			if err := s.compactDateDir(dDir); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ParquetLogDataStore) compactDateDir(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.parquet"))
	if err != nil || len(files) <= 1 {
		// Nothing to merge if 0 or 1 file
		return nil
	}

	// Read all records from existing files
	var allRecords []ParquetLogRecord
	validFiles := []string{}

	for _, filePath := range files {
		if strings.HasPrefix(filepath.Base(filePath), "compacting_") {
			_ = os.Remove(filePath)
			continue
		}

		f, err := os.Open(filePath)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil || fi.Size() == 0 {
			_ = f.Close()
			continue
		}

		pf, err := parquet.OpenFile(f, fi.Size())
		if err != nil {
			_ = f.Close()
			continue
		}

		reader := parquet.NewGenericReader[ParquetLogRecord](pf)
		buf := make([]ParquetLogRecord, 1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				allRecords = append(allRecords, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		_ = reader.Close()
		_ = f.Close()
		validFiles = append(validFiles, filePath)
	}

	if len(validFiles) <= 1 || len(allRecords) == 0 {
		return nil
	}

	// Sort records by Time
	sort.Slice(allRecords, func(i, j int) bool {
		return allRecords[i].Time < allRecords[j].Time
	})

	var randBytes [4]byte
	_, _ = rand.Read(randBytes[:])
	randVal := binary.BigEndian.Uint32(randBytes[:])

	tmpFileName := fmt.Sprintf("compacting_%016x_%08x.parquet", time.Now().UnixNano(), randVal)
	tmpFilePath := filepath.Join(dir, tmpFileName)

	outFile, err := os.Create(tmpFilePath)
	if err != nil {
		return fmt.Errorf("create compacted parquet file: %w", err)
	}

	writer := parquet.NewGenericWriter[ParquetLogRecord](outFile)
	if _, err := writer.Write(allRecords); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmpFilePath)
		return fmt.Errorf("write compacted parquet records: %w", err)
	}
	if err := writer.Close(); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmpFilePath)
		return fmt.Errorf("close compacted parquet writer: %w", err)
	}
	_ = outFile.Close()

	// Remove old files
	for _, oldFile := range validFiles {
		_ = os.Remove(oldFile)
	}

	// Rename temporary file to final compacted file
	finalFileName := fmt.Sprintf("compacted_%016x_%08x.parquet", time.Now().UnixNano(), randVal)
	finalFilePath := filepath.Join(dir, finalFileName)
	_ = os.Rename(tmpFilePath, finalFilePath)

	return nil
}
