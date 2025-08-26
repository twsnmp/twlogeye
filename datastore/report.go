package datastore

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

//go:embed etc/*
var etcfs embed.FS
var serviceMap = make(map[string]string)

func LoadServiceMap() {
	f, err := etcfs.Open("etc/services")
	if err != nil {
		log.Fatalf("LoadServiceMap err=%v", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if len(l) < 1 || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		sn := f[0]
		a := strings.Split(f[1], "/")
		if len(a) > 1 {
			sn += "/" + a[1]
		}
		serviceMap[f[1]] = sn
	}
}

func GetServiceName(prot string, port int) (string, bool) {
	k := fmt.Sprintf("%d/%s", port, prot)
	if s, ok := serviceMap[k]; ok {
		return s, true
	}
	return k, false
}

type SyslogEnt struct {
	Time int64
	Log  map[string]any
}

type LogSummaryEnt struct {
	LogPattern string
	Count      int
}

type SyslogReportEnt struct {
	Time         int64
	Normal       int
	Warn         int
	Error        int
	TopList      []LogSummaryEnt
	TopErrorList []LogSummaryEnt
}

func SaveSyslogReport(r *SyslogReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:syslog:%016x", r.Time)
		if v, err := json.Marshal(r); err == nil {
			e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.ReportRetention))
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		} else {
			return err
		}
		return nil
	})
}

func ForEachSyslogReport(st, et int64, callBack func(r *SyslogReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:syslog:%016x", st))); it.ValidForPrefix([]byte("report:syslog:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r SyslogReportEnt
					if err := item.Value(func(v []byte) error {
						return json.Unmarshal(v, &r)
					}); err == nil {
						if !callBack(&r) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}

type TrapLogEnt struct {
	Time int64
	Log  map[string]any
}

type TrapSummaryEnt struct {
	Sender   string
	TrapType string
	Count    int
}

type TrapReportEnt struct {
	Time    int64
	Count   int
	TopList []TrapSummaryEnt
}

func SaveTrapReport(r *TrapReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:trap:%016x", r.Time)
		if v, err := json.Marshal(r); err == nil {
			e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.ReportRetention))
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		} else {
			return err
		}
		return nil
	})
}

func ForEachTrapReport(st, et int64, callBack func(r *TrapReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:trap:%016x", st))); it.ValidForPrefix([]byte("report:trap:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r TrapReportEnt
					if err := item.Value(func(v []byte) error {
						return json.Unmarshal(v, &r)
					}); err == nil {
						if !callBack(&r) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}

type NetflowLogEnt struct {
	Time int64
	Log  map[string]any
}

type NetflowPacketsSummaryEnt struct {
	Key     string
	Packets int
}

type NetflowBytesSummaryEnt struct {
	Key   string
	Bytes int64
}

type NetflowProtocolCountEnt struct {
	Protocol string
	Count    int
}
type NetflowIPCountEnt struct {
	IP    string
	Count int
}

type NetFlowReportEnt struct {
	Time               int64
	Packets            int64
	Bytes              int64
	TopMACPacketsList  []NetflowPacketsSummaryEnt
	TopMACBytesList    []NetflowBytesSummaryEnt
	TopIPPacketsList   []NetflowPacketsSummaryEnt
	TopIPBytesList     []NetflowBytesSummaryEnt
	TopFlowPacketsList []NetflowPacketsSummaryEnt
	TopFlowBytesList   []NetflowBytesSummaryEnt
	TopProtocolList    []NetflowProtocolCountEnt
	TopFumbleSrcList   []NetflowIPCountEnt
}

func SaveNetflowReport(r *NetFlowReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:netflow:%016x", r.Time)
		if v, err := json.Marshal(r); err == nil {
			e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.ReportRetention))
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		} else {
			return err
		}
		return nil
	})
}

func ForEachNetflowReport(st, et int64, callBack func(r *NetFlowReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:netflow:%016x", st))); it.ValidForPrefix([]byte("report:netflow:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r NetFlowReportEnt
					if err := item.Value(func(v []byte) error {
						return json.Unmarshal(v, &r)
					}); err == nil {
						if !callBack(&r) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}

type WindowsEventEnt struct {
	Time int64
	Log  *WindowsEvent
}

type WindowsEventSummary struct {
	Computer string
	Provider string
	EeventID string
	Count    int
}

type WindowsEventReportEnt struct {
	Time         int64
	Normal       int
	Warn         int
	Error        int
	TopList      []WindowsEventSummary
	TopErrorList []WindowsEventSummary
}

func SaveWindowsEventReport(r *WindowsEventReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:winevent:%016x", r.Time)
		if v, err := json.Marshal(r); err == nil {
			e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.ReportRetention))
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		} else {
			return err
		}
		return nil
	})
}

func ForEachWindowsEventReport(st, et int64, callBack func(r *WindowsEventReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:winevent:%016x", st))); it.ValidForPrefix([]byte("report:winevent:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r WindowsEventReportEnt
					if err := item.Value(func(v []byte) error {
						return json.Unmarshal(v, &r)
					}); err == nil {
						if !callBack(&r) {
							break
						}
					}
				}
			}
		}
		return nil
	})
}
