package datastore

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type OTelMetricDataPointEnt struct {
	Start      int64    `json:"Start"`
	Time       int64    `json:"Time"`
	Attributes []string `json:"Attributes"`
	// Histogram
	Count          uint64    `json:"Count"`
	BucketCounts   []uint64  `json:"BucketCounts"`
	ExplicitBounds []float64 `json:"ExplicitBounds"`
	Sum            float64   `json:"Sum"`
	Min            float64   `json:"Min"`
	Max            float64   `json:"Max"`
	// Gauge
	Gauge float64 `json:"Gauge"`
	// ExponentialHistogram
	Positive      []uint64 `json:"Positive"`
	Negative      []uint64 `json:"Negative"`
	Scale         int64    `json:"Scale"`
	ZeroCount     int64    `json:"ZeroCount"`
	ZeroThreshold float64  `json:"ZeroThreshold"`
}

type OTelMetricEnt struct {
	Host        string                    `json:"Host"`
	Service     string                    `json:"Service"`
	Scope       string                    `json:"Scope"`
	Name        string                    `json:"Name"`
	Type        string                    `json:"Type"`
	Description string                    `json:"Description"`
	Unit        string                    `json:"Unit"`
	DataPoints  []*OTelMetricDataPointEnt `json:"DataPoints"`
	Count       int                       `json:"Count"`
	First       int64                     `json:"First"`
	Last        int64                     `json:"Last"`
}

type OTelMetricListEnt struct {
	ID          string `json:"ID"`
	Host        string `json:"Host"`
	Service     string `json:"Service"`
	Scope       string `json:"Scope"`
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Description string `json:"Description"`
	Unit        string `json:"Unit"`
	Count       int    `json:"Count"`
	First       int64  `json:"First"`
	Last        int64  `json:"Last"`
}

var metricMap sync.Map

type OTelTraceSpanEnt struct {
	SpanID       string   `json:"SpanID"`
	ParentSpanID string   `json:"ParentSpanID"`
	Host         string   `json:"Host"`
	Service      string   `json:"Service"`
	Scope        string   `json:"Scope"`
	Name         string   `json:"Name"`
	Start        int64    `json:"Start"`
	End          int64    `json:"End"`
	Dur          float64  `json:"Dur"`
	Attributes   []string `json:"Attributes"`
}

type OTelTraceEnt struct {
	TraceID string             `json:"TraceID"`
	Start   int64              `json:"Start"`
	End     int64              `json:"End"`
	Dur     float64            `json:"Dur"`
	Spans   []OTelTraceSpanEnt `json:"Spans"`
	Last    int64              `json:"Last"`
}

type OTelTraceListEnt struct {
	TraceID string  `json:"TraceID"`
	Start   int64   `json:"Start"`
	End     int64   `json:"End"`
	Dur     float64 `json:"Dur"`
	Last    int64   `json:"Last"`
}

type OTelLogEnt struct {
	Host           string `json:"Host"`
	Service        string `json:"Service"`
	Scope          string `json:"Scope"`
	TraceID        string `json:"TraceID"`
	SpanID         string `json:"SpanID"`
	SeverityText   string `json:"SeverityText"`
	SeverityNumber int    `json:"SeverityNumber"`
	Event          string `json:"Event"`
	Body           string `json:"Body"`
}

func AddOTelMetric(m *OTelMetricEnt) {
	k := getOTelMetricKey(m.Host, m.Service, m.Scope, m.Name)
	metricMap.Store(k, m)
}

func ForEachOTelMetric(f func(id string, m *OTelMetricEnt) bool) {
	metricMap.Range(func(key any, value any) bool {
		if m, ok := value.(*OTelMetricEnt); ok {
			return f(key.(string), m)
		}
		return true
	})
}

func FindOTelMetric(host, service, scope, name string) *OTelMetricEnt {
	k := getOTelMetricKey(host, service, scope, name)
	if v, ok := metricMap.Load(k); ok {
		if m, ok := v.(*OTelMetricEnt); ok {
			return m
		}
	}
	return nil
}

func GetOTelMetric(id string) *OTelMetricEnt {
	if v, ok := metricMap.Load(id); ok {
		if m, ok := v.(*OTelMetricEnt); ok {
			return m
		}
	}
	return nil
}

func DeleteOTelMetric(m *OTelMetricEnt) {
	k := getOTelMetricKey(m.Host, m.Service, m.Scope, m.Name)
	metricMap.Delete(k)
}

// LoadOTelMetric loads metrics from the DB.
func LoadOTelMetric() {
	if db == nil {
		return
	}
	st := time.Now()
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("otelMetric:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			a := strings.SplitN(string(k), ":", 2)
			if len(a) != 2 {
				continue
			}
			item.Value(func(v []byte) error {
				var m OTelMetricEnt
				if err := json.Unmarshal(v, &m); err == nil {
					metricMap.Store(string(k), &m)
				}

				return nil
			})
		}
		return nil
	})
	log.Printf("load otel metric dur=%v", time.Since(st))
}

// SaveOTelMetric saves metrics to the DB.
func SaveOTelMetric() {
	if db == nil {
		return
	}
	st := time.Now()
	txn := db.NewTransaction(true)
	metricMap.Range(func(key any, value any) bool {
		if k, ok := key.(string); ok {
			if m, ok := value.(*OTelMetricEnt); ok {
				if j, err := json.Marshal(m); err == nil {
					e := badger.NewEntry([]byte(k), j).WithTTL(time.Hour * time.Duration(Config.OTelRetention))
					if err := txn.SetEntry(e); err != nil {
						if err == badger.ErrTxnTooBig {
							txn.Commit()
							txn = db.NewTransaction(true)
							txn.SetEntry(e)
						}
					}
				}
			}
		}
		return true
	})
	txn.Commit()
	log.Printf("save otel metric dur=%v", time.Since(st))
}

func getOTelMetricKey(host, service, scope, name string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("%s\t%s\t%s\t%s", host, service, scope, name))))
}

func UpdateOTelTrace(list []*OTelTraceEnt) error {
	if db == nil {
		return fmt.Errorf("db not open")
	}
	st := time.Now()
	txn := db.NewTransaction(true)
	for _, t := range list {
		j, err := json.Marshal(t)
		if err != nil {
			continue
		}
		k := fmt.Sprintf("otelTrace:%s", t.TraceID)
		e := badger.NewEntry([]byte(k), j).WithTTL(time.Hour * time.Duration(Config.OTelRetention))
		if err := txn.SetEntry(e); err != nil {
			if err == badger.ErrTxnTooBig {
				txn.Commit()
				txn = db.NewTransaction(true)
				txn.SetEntry(e)
			}
		}
	}
	txn.Commit()
	log.Printf("update otel trace len=%d dur=%v", len(list), time.Since(st))
	return nil
}

func GetOTelTrace(tid string) *OTelTraceEnt {
	if db == nil {
		return nil
	}
	k := fmt.Sprintf("otelTrace:%s", tid)
	var ret *OTelTraceEnt
	db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(k))
		if err == nil {
			item.Value(func(v []byte) error {
				var t OTelTraceEnt
				if err := json.Unmarshal(v, &t); err == nil {
					ret = &t
				}
				return nil
			})
		}
		return nil
	})
	return ret
}

func ForEachOTelTrace(f func(t *OTelTraceEnt) bool) {
	if db == nil {
		return
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("otelTrace:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				log.Printf("trace=%s", string(v))
				var t OTelTraceEnt
				if err := json.Unmarshal(v, &t); err == nil {
					if !f(&t) {
						return fmt.Errorf("stop earch")
					}
				}
				return nil
			})
			if err != nil {
				break
			}
		}
		return nil
	})
}

func DeleteAllOTelData() {
	metricMap.Clear()
	if db == nil {
		return
	}
	db.DropPrefix([]byte("otelMetric:"))
	db.DropPrefix([]byte("otelTrace:"))
}
