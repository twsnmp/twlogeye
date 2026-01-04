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

func ClearReport(t string) {
	prefix := "report:"
	if t != "" && t != "all" {
		prefix += t
	}
	db.DropPrefix([]byte(prefix))
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
	Patterns     int
	ErrPatterns  int
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

func GetLastSyslogReport() *SyslogReportEnt {
	var r *SyslogReportEnt
	prefix := []byte("report:syslog:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:syslog:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var sr SyslogReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &sr)
			}); err == nil {
				r = &sr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
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
	Types   int
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

func GetLastTrapReport() *TrapReportEnt {
	var r *TrapReportEnt
	prefix := []byte("report:trap:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:trap:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var tr TrapReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &tr)
			}); err == nil {
				r = &tr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
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

type NetflowKeyCountEnt struct {
	Key   string
	Count int
}

type NetflowReportEnt struct {
	Time               int64
	Packets            int64
	Bytes              int64
	MACs               int
	IPs                int
	Flows              int
	Protocols          int
	Fumbles            int
	Hosts              int
	Locs               int
	Country            int
	TopMACPacketsList  []NetflowPacketsSummaryEnt
	TopMACBytesList    []NetflowBytesSummaryEnt
	TopIPPacketsList   []NetflowPacketsSummaryEnt
	TopIPBytesList     []NetflowBytesSummaryEnt
	TopFlowPacketsList []NetflowPacketsSummaryEnt
	TopFlowBytesList   []NetflowBytesSummaryEnt
	TopProtocolList    []NetflowKeyCountEnt
	TopFumbleSrcList   []NetflowKeyCountEnt
	TopHostList        []NetflowKeyCountEnt
	TopLocList         []NetflowKeyCountEnt
	TopCountryList     []NetflowKeyCountEnt
}

func SaveNetflowReport(r *NetflowReportEnt) {
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

func GetLastNetflowReport() *NetflowReportEnt {
	var r *NetflowReportEnt
	prefix := []byte("report:netflow:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:netflow:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var nr NetflowReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &nr)
			}); err == nil {
				r = &nr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
}

func ForEachNetflowReport(st, et int64, callBack func(r *NetflowReportEnt) bool) {
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
					var r NetflowReportEnt
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
	EventID  string
	Count    int
}

type WindowsEventReportEnt struct {
	Time         int64
	Normal       int
	Warn         int
	Error        int
	Types        int
	ErrorTypes   int
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

func GetLastWindowsEventReport() *WindowsEventReportEnt {
	var r *WindowsEventReportEnt
	prefix := []byte("report:winevent:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:winevent:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var wr WindowsEventReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &wr)
			}); err == nil {
				r = &wr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
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

type AnomalyReportEnt struct {
	Time  int64
	Score float64
}

func SaveAnomalyReport(t string, list []*AnomalyReportEnt) {
	db.DropPrefix([]byte("report:anomaly:" + t + ":"))
	db.Update(func(txn *badger.Txn) error {
		for _, r := range list {
			k := fmt.Sprintf("report:anomaly:%s:%016x", t, r.Time)
			if v, err := json.Marshal(r); err == nil {
				e := badger.NewEntry([]byte(k), []byte(v)).WithTTL(time.Hour * 24 * time.Duration(Config.ReportRetention))
				if err := txn.SetEntry(e); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		return nil
	})
}

func GetLastAnomalyReport(t string) *AnomalyReportEnt {
	var r *AnomalyReportEnt
	prefix := []byte("report:anomaly:" + t)
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:anomaly:" + t + ":z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var ar AnomalyReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &ar)
			}); err == nil {
				r = &ar
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
}

func ForEachAnomalyReport(t string, st, et int64, callBack func(r *AnomalyReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:anomaly:%s:%016x", t, st))); it.ValidForPrefix([]byte("report:anomaly:" + t + ":")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 4)
			if len(a) == 4 {
				if t, err := strconv.ParseInt(a[3], 16, 64); err == nil {
					if t > et {
						break
					}
					var r AnomalyReportEnt
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

type MonitorReportEnt struct {
	Time    int64
	CPU     float64
	Memory  float64
	Load    float64
	Disk    float64
	Net     float64
	Bytes   int64
	DBSpeed float64
	DBSize  int64
}

func SaveMonitorReport(r *MonitorReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:monitor:%016x", r.Time)
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

func GetLastMonitorReport() *MonitorReportEnt {
	var r *MonitorReportEnt
	prefix := []byte("report:monitor:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:monitor:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var mr MonitorReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &mr)
			}); err == nil {
				r = &mr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
}

func ForEachMonitorReport(st, et int64, callBack func(r *MonitorReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:monitor:%016x", st))); it.ValidForPrefix([]byte("report:monitor:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r MonitorReportEnt
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

type OTelSummaryEnt struct {
	Host     string
	Service  string
	Scope    string
	Severity string
	Count    int
}

type OTelReportEnt struct {
	Time         int64
	Normal       int
	Warn         int
	Error        int
	Types        int
	ErrorTypes   int
	TopList      []OTelSummaryEnt
	TopErrorList []OTelSummaryEnt
	Hosts        int
	TraceIDs     int
	TraceCount   int
	MericsCount  int
}

func SaveOTelReport(r *OTelReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:otel:%016x", r.Time)
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

func GetLastOTelReport() *OTelReportEnt {
	var r *OTelReportEnt
	prefix := []byte("report:otel:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:otel:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var or OTelReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &or)
			}); err == nil {
				r = &or
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
}

func ForEachOTelReport(st, et int64, callBack func(r *OTelReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:otel:%016x", st))); it.ValidForPrefix([]byte("report:otel:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r OTelReportEnt
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

type MqttLogEnt struct {
	Time     int64
	ClientID string
	Topic    string
}

type MqttSummaryEnt struct {
	ClientID string
	Topic    string
	Count    int
}

type MqttReportEnt struct {
	Time    int64
	Count   int
	Types   int
	TopList []MqttSummaryEnt
}

func SaveMqttReport(r *MqttReportEnt) {
	db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("report:mqtt:%016x", r.Time)
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

func GetLastMqttReport() *MqttReportEnt {
	var r *MqttReportEnt
	prefix := []byte("report:mqtt:")
	db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		it.Seek([]byte("report:mqtt:z"))
		if it.ValidForPrefix(prefix) {
			item := it.Item()
			var tr MqttReportEnt
			if err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &tr)
			}); err == nil {
				r = &tr
			} else {
				log.Printf("err=%v", err)
			}
		}
		return nil
	})
	return r
}

func ForEachMqttReport(st, et int64, callBack func(r *MqttReportEnt) bool) {
	if et == 0 {
		et = time.Now().UnixNano()
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(fmt.Sprintf("report:mqtt:%016x", st))); it.ValidForPrefix([]byte("report:mqtt:")); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 3)
			if len(a) == 3 {
				if t, err := strconv.ParseInt(a[2], 16, 64); err == nil {
					if t > et {
						break
					}
					var r MqttReportEnt
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
