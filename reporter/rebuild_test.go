package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestRebuildReportsFromLogs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "twlogeye_rebuild_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	datastore.Config.DBPath = ""
	datastore.Config.LogPath = filepath.Join(tmpDir, "logs.parquet")
	datastore.Config.ReportInterval = 5
	datastore.Config.ReportRetention = 7
	datastore.Config.ReportTopN = 10
	datastore.OpenDB()
	defer datastore.CloseDB()

	Init()

	now := time.Now().UnixNano()
	intervalNano := int64(5 * 60 * 1000 * 1000 * 1000)
	pastSlot1 := now - 2*intervalNano
	pastSlot2 := now - intervalNano

	// 1. Syslog logs across 2 intervals
	syslogData1, _ := json.Marshal(map[string]any{"hostname": "server1", "severity": 3, "tag": "sshd", "content": "Failed password for root"})
	syslogData2, _ := json.Marshal(map[string]any{"hostname": "server2", "severity": 6, "tag": "nginx", "content": "GET /index.html 200"})
	syslogs := []*datastore.LogEnt{
		{Time: pastSlot1 + 100, Type: datastore.Syslog, Src: "server1", Log: string(syslogData1)},
		{Time: pastSlot2 + 100, Type: datastore.Syslog, Src: "server2", Log: string(syslogData2)},
	}
	if err := datastore.SaveLogs("syslog", syslogs); err != nil {
		t.Fatalf("SaveLogs syslog failed: %v", err)
	}

	// 2. Netflow logs
	nfData, _ := json.Marshal(map[string]any{
		"srcAddr": "192.168.1.10", "dstAddr": "8.8.8.8", "packets": 10, "bytes": 1500,
		"srcPort": 54321, "dstPort": 53, "protocol": 17, "protocolStr": "udp",
	})
	netflows := []*datastore.LogEnt{
		{Time: pastSlot1 + 200, Type: datastore.NetFlow, Src: "192.168.1.1", Log: string(nfData)},
	}
	if err := datastore.SaveLogs("netflow", netflows); err != nil {
		t.Fatalf("SaveLogs netflow failed: %v", err)
	}

	// 3. Trap logs
	trapData, _ := json.Marshal(map[string]any{
		"FromAddress": "192.168.1.254", "Enterprise": "1.3.6.1.4.1.9.9", "GenericTrap": 6, "SpecificTrap": 1,
	})
	traps := []*datastore.LogEnt{
		{Time: pastSlot1 + 300, Type: datastore.SnmpTrap, Src: "192.168.1.254", Log: string(trapData)},
	}
	if err := datastore.SaveLogs("trap", traps); err != nil {
		t.Fatalf("SaveLogs trap failed: %v", err)
	}

	// 4. Windows Event logs
	winData, _ := json.Marshal(map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Computer": "PC-01",
				"Provider": map[string]any{"Name": "Security"},
				"EventID":  4625,
				"Level":    2,
			},
		},
	})
	winevents := []*datastore.LogEnt{
		{Time: pastSlot1 + 400, Type: datastore.WindowsEventLog, Src: "PC-01", Log: string(winData)},
	}
	if err := datastore.SaveLogs("windows", winevents); err != nil {
		t.Fatalf("SaveLogs windows failed: %v", err)
	}

	// 5. OTel logs
	otelData, _ := json.Marshal(datastore.OTelLogEnt{
		Host:           "app-host",
		Service:        "auth-service",
		Scope:          "http",
		SeverityText:   "ERROR",
		SeverityNumber: 17,
	})
	otels := []*datastore.LogEnt{
		{Time: pastSlot1 + 500, Type: datastore.OTel, Src: "app-host", Log: string(otelData)},
	}
	if err := datastore.SaveLogs("otel", otels); err != nil {
		t.Fatalf("SaveLogs otel failed: %v", err)
	}

	// 6. Mqtt logs
	mqttData, _ := json.Marshal(datastore.MqttLogEnt{
		ClientID: "sensor-1",
		Topic:    "sensors/temp",
	})
	mqtts := []*datastore.LogEnt{
		{Time: pastSlot1 + 600, Type: datastore.Mqtt, Src: "sensor-1", Log: string(mqttData)},
	}
	if err := datastore.SaveLogs("mqtt", mqtts); err != nil {
		t.Fatalf("SaveLogs mqtt failed: %v", err)
	}

	_ = datastore.FlushLog()

	// Clear in-memory Badger reports to simulate a fresh restart
	datastore.ClearReport("all")

	// Run rebuild
	RebuildReportsFromLogs(7)

	// Verify Syslog reports
	var syslogReports []*datastore.SyslogReportEnt
	datastore.ForEachSyslogReport(0, now+intervalNano, func(r *datastore.SyslogReportEnt) bool {
		syslogReports = append(syslogReports, r)
		return true
	})
	if len(syslogReports) != 2 {
		t.Fatalf("expected 2 rebuilt syslog reports, got %d", len(syslogReports))
	}
	if syslogReports[0].Error != 1 {
		t.Errorf("expected 1 error in first syslog report, got %d", syslogReports[0].Error)
	}
	if syslogReports[1].Normal != 1 {
		t.Errorf("expected 1 normal in second syslog report, got %d", syslogReports[1].Normal)
	}

	// Verify Netflow reports
	var nfReports []*datastore.NetflowReportEnt
	datastore.ForEachNetflowReport(0, now+intervalNano, func(r *datastore.NetflowReportEnt) bool {
		nfReports = append(nfReports, r)
		return true
	})
	if len(nfReports) != 1 {
		t.Fatalf("expected 1 rebuilt netflow report, got %d", len(nfReports))
	}
	if nfReports[0].Packets != 10 || nfReports[0].Bytes != 1500 {
		t.Errorf("unexpected netflow report content: %+v", nfReports[0])
	}

	// Verify Trap reports
	var trapReports []*datastore.TrapReportEnt
	datastore.ForEachTrapReport(0, now+intervalNano, func(r *datastore.TrapReportEnt) bool {
		trapReports = append(trapReports, r)
		return true
	})
	if len(trapReports) != 1 {
		t.Fatalf("expected 1 rebuilt trap report, got %d", len(trapReports))
	}

	// Verify Windows Event reports
	var winReports []*datastore.WindowsEventReportEnt
	datastore.ForEachWindowsEventReport(0, now+intervalNano, func(r *datastore.WindowsEventReportEnt) bool {
		winReports = append(winReports, r)
		return true
	})
	if len(winReports) != 1 {
		t.Fatalf("expected 1 rebuilt winevent report, got %d", len(winReports))
	}
	if winReports[0].Error != 1 {
		t.Errorf("expected 1 error in winevent report, got %d", winReports[0].Error)
	}

	// Verify OTel reports
	var otelReports []*datastore.OTelReportEnt
	datastore.ForEachOTelReport(0, now+intervalNano, func(r *datastore.OTelReportEnt) bool {
		otelReports = append(otelReports, r)
		return true
	})
	if len(otelReports) != 1 {
		t.Fatalf("expected 1 rebuilt otel report, got %d", len(otelReports))
	}
	if otelReports[0].Error != 1 {
		t.Errorf("expected 1 error in otel report, got %d", otelReports[0].Error)
	}

	// Verify MQTT reports
	var mqttReports []*datastore.MqttReportEnt
	datastore.ForEachMqttReport(0, now+intervalNano, func(r *datastore.MqttReportEnt) bool {
		mqttReports = append(mqttReports, r)
		return true
	})
	if len(mqttReports) != 1 {
		t.Fatalf("expected 1 rebuilt mqtt report, got %d", len(mqttReports))
	}

	// Verify Anomaly loading from rebuilt reports
	loadReportData()
	if len(syslogAnomaly.Times) != 2 {
		t.Errorf("expected 2 syslog anomaly times after loadReportData, got %d", len(syslogAnomaly.Times))
	}
	if len(netflowAnomaly.Times) != 1 {
		t.Errorf("expected 1 netflow anomaly times after loadReportData, got %d", len(netflowAnomaly.Times))
	}
}
