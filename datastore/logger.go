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

type LogEnt struct {
	Time int64
	Src  string
	Log  string
}

// SaveLogs : save log to database
func SaveLogs(t string, logs []*LogEnt) {
	txn := db.NewTransaction(true)
	for i, l := range logs {
		k := fmt.Sprintf("%s:%016x:%04x", t, l.Time, i)
		e := badger.NewEntry([]byte(k), []byte(l.Log)).WithTTL(time.Hour * time.Duration(Config.LogRetention))
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
func ForEachLog(t string, callBack func(log *LogEnt) bool) {
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(t + ":")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				item.Value(func(v []byte) error {
					if t, err := strconv.ParseInt(a[1], 16, 64); err == nil {
						callBack(&LogEnt{
							Time: t,
							Log:  strings.Clone(string(v)),
						})
					}
					return nil
				})
			}
		}
		return nil
	})
}

type NotifyEnt struct {
	// Log
	Time int64
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
