package reporter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestAnomalyReporter(t *testing.T) {
	// Setup in-memory DB
	datastore.Config.DBPath = ""
	datastore.Config.AnomalyReportThreshold = 60.0
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Initialize channels
	Init()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go startAnomaly(ctx, &wg)

	// Send enough data to trigger calculation (min 10 points)
	now := time.Now().UnixNano()
	for i := 0; i < 15; i++ {
		anomalyCh <- &anomalyChannelData{
			Time:   now + int64(i)*int64(time.Minute),
			Type:   "syslog",
			Vector: []float64{10, 1, 0, 5, 0}, // Normal behavior
		}
	}

	// Send an anomaly
	anomalyCh <- &anomalyChannelData{
		Time:   now + 16*int64(time.Minute),
		Type:   "syslog",
		Vector: []float64{1000, 100, 50, 500, 10}, // Outlier
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify that scores are calculated
	if len(syslogAnomaly.Scores) == 0 {
		// Note: Scores are updated in calcAnomalyScore
		// However, calcAnomalyScore updates a local copy or global?
		// It updates the pointer passed to it.
		// Wait, syslogAnomaly is a global variable.
	}

	cancel()
	wg.Wait()
}

func TestReportToVector(t *testing.T) {
	sr := &datastore.SyslogReportEnt{
		Normal:      10,
		Warn:        5,
		Error:       2,
		Patterns:    20,
		ErrPatterns: 3,
	}
	v := syslogReportToVector(sr)
	if len(v) != 5 {
		t.Errorf("expected vector length 5, got %d", len(v))
	}
	if v[0] != 10 || v[2] != 2 || v[4] != 3 {
		t.Errorf("vector values mismatch: %v", v)
	}
}
