package auditor

import (
	"testing"
	"time"

	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/twsnmp/twlogeye/datastore"
)

func TestParseCorrelationConfig(t *testing.T) {
	raw := map[string]interface{}{
		"frequency": 5,
		"timeframe": "120s",
		"group_by":  []interface{}{"client", "user"},
	}

	conf := ParseCorrelationConfig(raw)
	if conf == nil {
		t.Fatalf("expected non-nil config")
	}
	if conf.Frequency != 5 {
		t.Errorf("expected frequency 5, got %d", conf.Frequency)
	}
	if conf.Timeframe != 120*time.Second {
		t.Errorf("expected timeframe 120s, got %v", conf.Timeframe)
	}
	if len(conf.GroupBy) != 2 || conf.GroupBy[0] != "client" || conf.GroupBy[1] != "user" {
		t.Errorf("unexpected GroupBy: %+v", conf.GroupBy)
	}
}

func TestCorrelationTracker_SlidingWindow(t *testing.T) {
	tracker := NewCorrelationTracker()
	conf := &CorrelationConfig{
		Frequency: 3,
		Timeframe: 10 * time.Second,
		GroupBy:   []string{"client"},
	}

	baseTime := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC).UnixNano()

	// 1st hit at T=0 -> false
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime, conf); hit {
		t.Errorf("expected false for 1st hit, got true")
	}

	// 2nd hit at T=3s -> false
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime+3*time.Second.Nanoseconds(), conf); hit {
		t.Errorf("expected false for 2nd hit, got true")
	}

	// 1st hit for different IP at T=4s -> false (isolated by groupKey)
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.2", baseTime+4*time.Second.Nanoseconds(), conf); hit {
		t.Errorf("expected false for different IP, got true")
	}

	// 3rd hit at T=6s -> true (frequency=3 reached!)
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime+6*time.Second.Nanoseconds(), conf); !hit {
		t.Errorf("expected true for 3rd hit, got false")
	}

	// 4th hit at T=7s -> false (window was reset after alert)
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime+7*time.Second.Nanoseconds(), conf); hit {
		t.Errorf("expected false right after trigger reset, got true")
	}

	// Now test window expiration
	// 5th hit at T=25s -> false
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime+25*time.Second.Nanoseconds(), conf); hit {
		t.Errorf("expected false, got true")
	}
	// 6th hit at T=40s (15s after 25s, so 25s expired since timeframe is 10s) -> false, should have count 1
	if hit := tracker.RecordAndCheck("rule-1", "192.168.1.1", baseTime+40*time.Second.Nanoseconds(), conf); hit {
		t.Errorf("expected false due to window expiration, got true")
	}
}

func TestMatchSigmaRule_WithCorrelation(t *testing.T) {
	evaluatorsBackup := evaluators
	ruleEntriesBackup := ruleEntries
	defer func() {
		evaluators = evaluatorsBackup
		ruleEntries = ruleEntriesBackup
	}()

	ev, err := CreateRuleEvaluator(`
title: SSH Brute Force Test
id: test-corr-ssh
level: high
logsource:
    product: linux
    service: sshd
detection:
    selection:
        content|contains: 'Failed password'
    condition: selection
`)
	if err != nil {
		t.Fatal(err)
	}

	conf := &CorrelationConfig{
		Frequency: 3,
		Timeframe: 5 * time.Second,
		GroupBy:   []string{"client"},
	}

	evaluators = []*evaluator.RuleEvaluator{ev}
	ruleEntries = []*SigmaRuleEntry{
		{
			Evaluator:   ev,
			Source:      "test",
			Path:        "test",
			Correlation: conf,
		},
	}
	globalCorrelationTracker.Reset()

	base := time.Now().UnixNano()
	logEnt1 := &datastore.LogEnt{
		Time: base,
		Type: datastore.Syslog,
		Src:  "192.168.1.50",
		Log:  `{"content":"Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"}`,
	}

	// 1st hit -> should not trigger match
	if m := matchSigmaRule(logEnt1); m != nil {
		t.Errorf("expected nil on 1st occurrence, got %v", m)
	}

	// 2nd hit -> should not trigger match
	logEnt2 := &datastore.LogEnt{
		Time: base + 1*time.Second.Nanoseconds(),
		Type: datastore.Syslog,
		Src:  "192.168.1.50",
		Log:  `{"content":"Failed password for invalid user root from 192.168.1.50 port 22 ssh2"}`,
	}
	if m := matchSigmaRule(logEnt2); m != nil {
		t.Errorf("expected nil on 2nd occurrence, got %v", m)
	}

	// 3rd hit -> should trigger match!
	logEnt3 := &datastore.LogEnt{
		Time: base + 2*time.Second.Nanoseconds(),
		Type: datastore.Syslog,
		Src:  "192.168.1.50",
		Log:  `{"content":"Failed password for invalid user test from 192.168.1.50 port 22 ssh2"}`,
	}
	m := matchSigmaRule(logEnt3)
	if m == nil || m.Rule.ID != "test-corr-ssh" {
		t.Errorf("expected match on 3rd occurrence, got %v", m)
	}
}
