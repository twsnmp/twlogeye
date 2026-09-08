package auditor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestAvailableSigmaPacks(t *testing.T) {
	packs := datastore.GetAvailableSigmaPacks()
	if len(packs) == 0 {
		t.Fatalf("expected available packs, got 0")
	}
	hasWindows := false
	hasLinux := false
	for _, p := range packs {
		if p == "windows-essential" {
			hasWindows = true
		}
		if p == "linux-auth" {
			hasLinux = true
		}
	}
	if !hasWindows || !hasLinux {
		t.Errorf("expected windows-essential and linux-auth in packs, got %v", packs)
	}
}

func TestSigmaPacksLoadingAndMatching(t *testing.T) {
	datastore.Config.SigmaPacks = []string{"windows-essential", "linux-auth"}
	datastore.Config.SigmaRules = "none" // do not load default embed

	entries := GetSigmaRuleEntries()
	if len(entries) < 10 {
		t.Fatalf("expected at least 10 rules loaded from packs, got %d", len(entries))
	}

	for _, e := range entries {
		if e.Source != "pack:windows-essential" && e.Source != "pack:linux-auth" {
			t.Errorf("unexpected source for pack rule: %s", e.Source)
		}
	}

	// Test Windows Event 4625 matching
	winLog := `{"Event":{"System":{"Channel":"Security","Computer":"WIN-DC","EventID":4625,"Level":0},"EventData":{"TargetUserName":"admin","WorkstationName":"DESKTOP-1" karma}}}`
	// Use well-formed JSON
	winLog = `{"Event":{"System":{"Channel":"Security","Computer":"WIN-DC","EventID":4625,"Level":0},"EventData":{"TargetUserName":"admin","WorkstationName":"DESKTOP-1"}}}`
	lWin := &datastore.LogEnt{
		Time: time.Now().UnixNano(),
		Type: datastore.WindowsEventLog,
		Src:  "Security",
		Log:  winLog,
	}

	matchedWin := matchSigmaRule(lWin)
	if matchedWin == nil {
		t.Errorf("expected Windows 4625 rule to match, got nil")
	} else if matchedWin.ID != "018d9f10-ff31-419b-a36c-941cbfa0451a" {
		t.Errorf("expected rule ID 018d9f10-ff31-419b-a36c-941cbfa0451a, got %s", matchedWin.ID)
	}

	// Test Linux SSH failed login matching
	linuxLog := `{"hostname":"server1","content":"Failed password for invalid user admin from 192.168.1.100 port 45678 ssh2"}`
	lLinux := &datastore.LogEnt{
		Time: time.Now().UnixNano(),
		Type: datastore.Syslog,
		Src:  "server1",
		Log:  linuxLog,
	}

	matchedLinux := matchSigmaRule(lLinux)
	if matchedLinux == nil {
		t.Errorf("expected Linux SSH failed login rule to match, got nil")
	}
}

func TestSigmaOverridePriority(t *testing.T) {
	// Create temporary custom rule with same ID as win_security_failed_logons but different level and title
	tmpDir, err := os.MkdirTemp("", "sigma_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	customRule := `title: Customized Failed Logon
id: 018d9f10-ff31-419b-a36c-941cbfa0451a
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: critical
`
	ruleFile := filepath.Join(tmpDir, "custom.yaml")
	if err := os.WriteFile(ruleFile, []byte(customRule), 0644); err != nil {
		t.Fatal(err)
	}

	datastore.Config.SigmaPacks = []string{"windows-essential"}
	datastore.Config.SigmaRules = tmpDir

	entries := GetSigmaRuleEntries()
	var overriddenEntry *SigmaRuleEntry
	for _, e := range entries {
		if e.Evaluator.ID == "018d9f10-ff31-419b-a36c-941cbfa0451a" {
			overriddenEntry = e
			break
		}
	}

	if overriddenEntry == nil {
		t.Fatalf("rule 018d9f10-ff31-419b-a36c-941cbfa0451a not found")
	}
	if overriddenEntry.Source != "file:"+ruleFile {
		t.Errorf("expected source file:%s, got %s", ruleFile, overriddenEntry.Source)
	}
	if overriddenEntry.Evaluator.Level != "critical" {
		t.Errorf("expected level critical, got %s", overriddenEntry.Evaluator.Level)
	}
	if overriddenEntry.Evaluator.Title != "Customized Failed Logon" {
		t.Errorf("expected title Customized Failed Logon, got %s", overriddenEntry.Evaluator.Title)
	}
}
