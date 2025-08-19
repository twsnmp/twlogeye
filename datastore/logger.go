package datastore

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

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
