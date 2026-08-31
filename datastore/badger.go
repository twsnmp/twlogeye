package datastore

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type BadgerLogDataStore struct {
	db      *badger.DB
	ownedDB bool
}

func NewBadgerLogDataStore(db *badger.DB) *BadgerLogDataStore {
	return &BadgerLogDataStore{
		db:      db,
		ownedDB: false,
	}
}

func (s *BadgerLogDataStore) Type() EngineType {
	return EngineBadger
}

func (s *BadgerLogDataStore) Open(path string) error {
	if s.db != nil {
		return nil
	}
	opt := badger.DefaultOptions(path)
	if !Config.Debug {
		opt = opt.WithLoggingLevel(badger.WARNING)
	}
	if path == "" {
		opt = opt.WithInMemory(true)
	}
	var err error
	s.db, err = badger.Open(opt)
	if err != nil {
		return fmt.Errorf("open badger log datastore: %w", err)
	}
	s.ownedDB = true
	return nil
}

func (s *BadgerLogDataStore) Close() error {
	if s.ownedDB && s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

func (s *BadgerLogDataStore) SaveLogs(t string, logs []*LogEnt) error {
	if s.db == nil || len(logs) == 0 {
		return nil
	}
	txn := s.db.NewTransaction(true)
	defer txn.Discard()
	for i, l := range logs {
		k := fmt.Sprintf("%s:%016x:%04x", t, l.Time, i)
		e := badger.NewEntry([]byte(k), []byte(l.Src+"\t"+l.Log)).WithTTL(time.Hour * time.Duration(Config.LogRetention))
		if err := txn.SetEntry(e); err != nil {
			if err == badger.ErrTxnTooBig {
				if err := txn.Commit(); err != nil {
					return err
				}
				txn = s.db.NewTransaction(true)
				defer txn.Discard()
				if err := txn.SetEntry(e); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}
	return txn.Commit()
}

func (s *BadgerLogDataStore) ForEachLog(t string, st, et int64, callBack func(log *LogEnt) bool) {
	if s.db == nil {
		return
	}
	if et == 0 {
		et = time.Now().UnixNano()
	}
	_ = s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(t + ":")
		stPrefix := []byte(fmt.Sprintf("%s:%016x", t, st))
		for it.Seek(stPrefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if ts, err := strconv.ParseInt(a[1], 16, 64); err == nil {
					if ts > et {
						break
					}
					var str string
					_ = item.Value(func(v []byte) error {
						str = strings.Clone(string(v))
						return nil
					})
					a = strings.SplitN(str, "\t", 2)
					if len(a) == 2 {
						if !callBack(&LogEnt{
							Time: ts,
							Src:  a[0],
							Log:  a[1],
						}) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}

func (s *BadgerLogDataStore) ClearLog(t string) {
	if s.db == nil {
		return
	}
	switch t {
	case "syslog", "netflow", "trap", "windows", "otel", "mqtt":
		_ = s.db.DropPrefix([]byte(t + ":"))
	case "all":
		_ = s.db.DropPrefix([]byte("syslog:"))
		_ = s.db.DropPrefix([]byte("trap:"))
		_ = s.db.DropPrefix([]byte("netflow:"))
		_ = s.db.DropPrefix([]byte("windows:"))
		_ = s.db.DropPrefix([]byte("otel:"))
		_ = s.db.DropPrefix([]byte("mqtt:"))
	default:
		_ = s.db.DropPrefix([]byte(t + ":"))
	}
}

func (s *BadgerLogDataStore) Cleanup(retentionHours int) error {
	return nil
}

func (s *BadgerLogDataStore) Compact(currentDate string) error {
	return nil
}

func (s *BadgerLogDataStore) Flush() error {
	return nil
}

func (s *BadgerLogDataStore) Size() int64 {
	if s.db == nil {
		return 0
	}
	lsm, dbs := s.db.Size()
	return lsm + dbs
}
