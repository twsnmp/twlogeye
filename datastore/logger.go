package datastore

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var db *badger.DB

// OpenLogDB : open log database
func OpenLogDB() {
	opt := badger.DefaultOptions(Config.LogPath)
	if Config.LogPath == "" {
		opt = opt.WithInMemory(true)
	}
	var err error
	db, err = badger.Open(opt)
	if err != nil {
		log.Fatalln(err)
	}
}

// CloseLogDB : close log database
func CloseLogDB() {
	if db != nil {
		db.Close()
	}
}

type LogType int

const (
	Syslog LogType = iota
	NetFlow
	SnmpTrap
	WindowsEventLog
)

type LogEnt struct {
	Time int64
	Type LogType
	Src  string
	Log  string
}

// SaveLogs : save log to database
func SaveLogs(t string, logs []*LogEnt) {
	txn := db.NewTransaction(true)
	for i, l := range logs {
		k := fmt.Sprintf("%s:%016x:%04x", t, l.Time, i)
		e := badger.NewEntry([]byte(k), []byte(l.Src+"\t"+l.Log)).WithTTL(time.Hour * time.Duration(Config.LogRetention))
		if err := txn.SetEntry(e); err != nil {
			if err == badger.ErrTxnTooBig {
				txn.Commit()
				txn = db.NewTransaction(true)
				txn.SetEntry(e)
			}
		}
	}
	txn.Commit()
}

// ForEachLogs : for each logs
func ForEachLog(t string, st, et int64, callBack func(log *LogEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
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
					var s string
					item.Value(func(v []byte) error {
						s = strings.Clone(string(v))
						return nil
					})
					a = strings.SplitN(s, "\t", 2)
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

type NotifyEnt struct {
	// Log
	Time int64
	Type LogType
	Log  string
	Src  string
	// Sigma rule
	ID    string
	Title string
	Tags  string
	Level string
}

func SaveNotify(n *NotifyEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("notify:%016x:%s", n.Time, n.ID)
		if v, err := json.Marshal(n); err == nil {
			e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.NotifyRetention))
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		} else {
			return err
		}
		return nil
	})
}

func ForEachNotify(st, et int64, callBack func(n *NotifyEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("notify:%016x", st))); it.ValidForPrefix([]byte("notify:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[1], 16, 64); err == nil {
					if t > et {
						break
					}
					var n NotifyEnt
					if err := item.Value(func(v []byte) error {
						return json.Unmarshal(v, &n)
					}); err == nil {
						if !callBack(&n) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}
