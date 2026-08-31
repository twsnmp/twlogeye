package datastore

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger/v4"
)

type EngineType string

const (
	EngineBadger  EngineType = "badger"
	EngineParquet EngineType = "parquet"
)

type LogDataStore interface {
	Open(path string) error
	Close() error
	Type() EngineType
	SaveLogs(t string, logs []*LogEnt) error
	ForEachLog(t string, st, et int64, callBack func(log *LogEnt) bool)
	ClearLog(t string)
	Cleanup(retentionHours int) error
	Compact(currentDate string) error
	Flush() error
	Size() int64
}

var (
	db       *badger.DB
	logStore LogDataStore
)

// DetectEngineType determines the engine type based on path.
func DetectEngineType(path string) EngineType {
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, "parquet://") || strings.HasSuffix(lower, ".parquet") || strings.HasSuffix(lower, ".pq") {
		return EngineParquet
	}
	if strings.HasPrefix(lower, "badger://") || strings.HasSuffix(lower, ".badger") {
		return EngineBadger
	}

	// Check if path is an existing directory
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		// If it contains parquet files or type= partition directories
		matches, _ := filepath.Glob(filepath.Join(path, "*.parquet"))
		if len(matches) > 0 {
			return EngineParquet
		}
		typeMatches, _ := filepath.Glob(filepath.Join(path, "type=*"))
		if len(typeMatches) > 0 {
			return EngineParquet
		}
		// If it contains MANIFEST (Badger)
		if _, err := os.Stat(filepath.Join(path, "MANIFEST")); err == nil {
			return EngineBadger
		}
	}

	return EngineBadger
}

// OpenDB : open metadata and log database
func OpenDB() {
	logPath := Config.LogPath
	if logPath == "" {
		logPath = Config.DBPath
	}

	engine := DetectEngineType(logPath)

	// Open Badger for metadata (reports, notify, CA, etc.)
	badgerPath := Config.DBPath
	if DetectEngineType(Config.DBPath) == EngineParquet {
		// When DBPath itself is parquet, run metadata Badger in-memory
		badgerPath = ""
	}

	opt := badger.DefaultOptions(badgerPath)
	if !Config.Debug {
		opt = opt.WithLoggingLevel(badger.WARNING)
	}
	if badgerPath == "" {
		opt = opt.WithInMemory(true)
	}
	var err error
	db, err = badger.Open(opt)
	if err != nil {
		log.Fatalln(err)
	}

	// Initialize log datastore
	switch engine {
	case EngineParquet:
		pStore := NewParquetLogDataStore()
		if err := pStore.Open(logPath); err != nil {
			log.Fatalln(err)
		}
		logStore = pStore
	case EngineBadger:
		if Config.LogPath != "" && Config.LogPath != Config.DBPath {
			bStore := NewBadgerLogDataStore(nil)
			if err := bStore.Open(Config.LogPath); err != nil {
				log.Fatalln(err)
			}
			logStore = bStore
		} else {
			logStore = NewBadgerLogDataStore(db)
		}
	default:
		logStore = NewBadgerLogDataStore(db)
	}
}

// CloseDB : close log database
func CloseDB() {
	if logStore != nil {
		_ = logStore.Close()
		logStore = nil
	}
	if db != nil {
		_ = db.Close()
		db = nil
	}
}

func GetDBSize() int64 {
	metaSize := int64(0)
	if db != nil {
		lsm, dbs := db.Size()
		metaSize = lsm + dbs
	}
	if logStore != nil {
		if b, ok := logStore.(*BadgerLogDataStore); ok && !b.ownedDB {
			// Shared db, already counted in metaSize
			return metaSize
		}
		return metaSize + logStore.Size()
	}
	return metaSize
}

func GetLogStore() LogDataStore {
	return logStore
}

func SetLogStore(ds LogDataStore) {
	logStore = ds
}
