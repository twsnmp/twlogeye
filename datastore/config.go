package datastore

import (
	"encoding/json"
	"strings"

	"github.com/dgraph-io/badger/v4"
)

type ConfigEnt struct {
	SyslogPort               int
	NetFlowPort              int
	SFlowPort                int
	TCPPort                  int
	SNMPTrapPort             int
	WinEventLogType          []string
	WinEvenyLogCheckInterval int
	SyslogDst                []string
	TrapDst                  []string
	APIPort                  int
	APIMode                  string
	LogRetention             int // Log retention period　(hours)
}

var Config ConfigEnt

func LoadConfig() {
	db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("config"))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &Config)
		})
	})
	if Config.APIPort == 0 {
		setDefault()
	}
}

func SaveConfig() {
	db.Update(func(txn *badger.Txn) error {
		j, err := json.Marshal(&Config)
		if err != nil {
			return err
		}
		return txn.Set([]byte("conifg"), j)
	})
}

// GetAPIParam : get apikey,apicert
func GetAPIParam(key string) string {
	ret := ""
	db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			ret = strings.Clone(string(val))
			return nil
		})
	})
	return ret
}

func SetAPIParam(key, val string) {
	db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("conifg"), []byte(val))
	})
}

func GetSigmaRules() []string {
	ret := []string{}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("sigma:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				ret = append(ret, strings.Clone(string(v)))
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return ret
}

func AddSigmaRule(id, rule string) error {
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("sigma:"+id), []byte(rule))
	})
}

func DeleteSigmaRule(id string) error {
	return db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte("sigma:" + id))
	})
}

func setDefault() {
	Config.APIPort = 8086
	Config.LogRetention = 24
	SaveConfig()
}
