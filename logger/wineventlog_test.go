package logger

import (
	"encoding/json"
	"encoding/xml"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

func TestEvtlogXML2JSON(t *testing.T) {
	xmlStr := `
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
		<EventID>4624</EventID>
		<Version>0</Version>
		<Level>0</Level>
		<Task>12544</Task>
		<Opcode>0</Opcode>
		<Keywords>0x8020000000000000</Keywords>
		<TimeCreated SystemTime="2026-05-18T08:00:00.000000000Z" />
		<EventRecordID>12345</EventRecordID>
		<Correlation />
		<Execution ProcessID="4" ThreadID="12" />
		<Channel>Security</Channel>
		<Computer>DESKTOP-TEST</Computer>
		<Security UserID="S-1-5-18" />
	</System>
	<EventData>
		<Data Name="TargetUserSid">S-1-5-18</Data>
		<Data Name="TargetUserName">SYSTEM</Data>
		<Data Name="TargetDomainName">NT AUTHORITY</Data>
		<Data Name="TargetLogonId">0x3e7</Data>
		<Data Name="LogonType">0</Data>
	</EventData>
</Event>`

	var e datastore.WindowsEvent
	err := xml.Unmarshal([]byte(xmlStr), &e)
	if err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	jsonStr, err := evtlogXML2JSON(&e)
	if err != nil {
		t.Fatalf("evtlogXML2JSON failed: %v", err)
	}

	var m map[string]interface{}
	err = json.Unmarshal([]byte(jsonStr), &m)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	event, ok := m["Event"].(map[string]interface{})
	if !ok {
		t.Fatal("Event key not found in JSON")
	}

	system, ok := event["System"].(map[string]interface{})
	if !ok {
		t.Fatal("System key not found in JSON")
	}

	if system["EventID"] != float64(4624) {
		t.Errorf("expected EventID 4624, got %v", system["EventID"])
	}

	eventData, ok := event["EventData"].(map[string]interface{})
	if !ok {
		t.Fatal("EventData key not found in JSON")
	}

	if eventData["TargetUserName"] != "SYSTEM" {
		t.Errorf("expected TargetUserName SYSTEM, got %v", eventData["TargetUserName"])
	}
}

func TestGetEventTime(t *testing.T) {
	s := "2026-05-18T08:00:00.000000000Z"
	tm := getEventTime(s)
	if tm.IsZero() {
		t.Error("getEventTime returned zero time")
	}
	if tm.UTC().Format(time.RFC3339) != "2026-05-18T08:00:00Z" {
		t.Errorf("expected 2026-05-18T08:00:00Z, got %v", tm.UTC().Format(time.RFC3339))
	}
}
