package datastore

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

func ClearNotify() {
	db.DropPrefix([]byte("notify:"))
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
