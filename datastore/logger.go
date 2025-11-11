package datastore

import (
	"encoding/xml"
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
	AnomalyReport
	OTel
	Mqtt
)

func (t LogType) String() string {
	switch t {
	case Syslog:
		return "syslog"
	case NetFlow:
		return "netflow"
	case SnmpTrap:
		return "trap"
	case WindowsEventLog:
		return "windowsEvent"
	case AnomalyReport:
		return "anomalyReport"
	case OTel:
		return "otel"
	case Mqtt:
		return "mqtt"
	}
	return "unknown"
}

func ClearLog(t string) {
	switch t {
	case "syslog":
	case "netflow":
	case "trap":
	case "windows":
	case "otel":
	case "mqtt":
	case "all":
		db.DropPrefix([]byte("syslog:"))
		db.DropPrefix([]byte("trap:"))
		db.DropPrefix([]byte("netflow:"))
		db.DropPrefix([]byte("windows:"))
		db.DropPrefix([]byte("otel:"))
		db.DropPrefix([]byte("mqtt:"))
	default:
		return
	}
	db.DropPrefix([]byte(t + ":"))
}

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

type WindowsEvent struct {
	XMLName xml.Name `xml:"Event"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
	System  struct {
		Text     string `xml:",chardata"`
		Provider struct {
			Text string `xml:",chardata"`
			Name string `xml:"Name,attr"`
			Guid string `xml:"Guid,attr"`
		} `xml:"Provider"`
		EventID     int64  `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       int64  `xml:"Level"`
		Task        string `xml:"Task"`
		Opcode      string `xml:"Opcode"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			Text       string `xml:",chardata"`
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID int64  `xml:"EventRecordID"`
		Correlation   string `xml:"Correlation"`
		Execution     struct {
			Text      string `xml:",chardata"`
			ProcessID int64  `xml:"ProcessID,attr"`
			ThreadID  int64  `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			Text   string `xml:",chardata"`
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Text string `xml:",chardata"`
		Data []struct {
			Text string `xml:",chardata"`
			Name string `xml:"Name,attr"`
		} `xml:"Data"`
	} `xml:"EventData"`
}
