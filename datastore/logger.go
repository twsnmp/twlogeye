package datastore

import (
	"encoding/xml"
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

func getOrInitLogStore() LogDataStore {
	if logStore != nil {
		return logStore
	}
	if db != nil {
		logStore = NewBadgerLogDataStore(db)
		return logStore
	}
	return nil
}

func ClearLog(t string) {
	ls := getOrInitLogStore()
	if ls != nil {
		ls.ClearLog(t)
	}
}

type LogEnt struct {
	Time int64
	Type LogType
	Src  string
	Log  string
}

// SaveLogs : save log to database
func SaveLogs(t string, logs []*LogEnt) error {
	ls := getOrInitLogStore()
	if ls != nil {
		return ls.SaveLogs(t, logs)
	}
	return nil
}

// ForEachLogs : for each logs
func ForEachLog(t string, st, et int64, callBack func(log *LogEnt) bool) {
	ls := getOrInitLogStore()
	if ls != nil {
		ls.ForEachLog(t, st, et, callBack)
	}
}

// CleanupLog : clean up expired logs
func CleanupLog(retentionHours int) error {
	ls := getOrInitLogStore()
	if ls != nil {
		return ls.Cleanup(retentionHours)
	}
	return nil
}

// CompactLog : compact parquet files in past date directories
func CompactLog(currentDate string) error {
	ls := getOrInitLogStore()
	if ls != nil {
		return ls.Compact(currentDate)
	}
	return nil
}

// FlushLog : flush buffered logs to disk
func FlushLog() error {
	ls := getOrInitLogStore()
	if ls != nil {
		return ls.Flush()
	}
	return nil
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
