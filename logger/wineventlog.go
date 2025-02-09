package logger

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"log"
	"os/exec"
	"strings"
	"sync"

	"fmt"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

type Event struct {
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

var lastTime time.Time

func StartWinEventLogd(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.WinEventLogCheckInterval == 0 || datastore.Config.WinEventLogChannel == "" {
		return
	}
	log.Printf("start WinEventLogd")
	lastTime = time.Now().Add(time.Hour * time.Duration(-datastore.Config.WinEventLogCheckStart))
	timer := time.NewTicker(time.Second * time.Duration(datastore.Config.WinEventLogCheckInterval))
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop WinEventLogd")
			return
		case <-timer.C:
			st := time.Now()
			list := getWindowsEventLogs()
			if len(list) > 0 {
				datastore.SaveLogs("windows", list)
			}
			log.Printf("windows event log len=%d dur=%v", len(list), time.Since(st))
		}
	}
}

// getWindowsEventLogs:
func getWindowsEventLogs() []*datastore.LogEnt {
	ret := []*datastore.LogEnt{}
	filter := fmt.Sprintf(`/q:*[System[TimeCreated[@SystemTime>'%s']]]`, lastTime.UTC().Format("2006-01-02T15:04:05"))
	lastTime = time.Now()
	params := []string{"qe", datastore.Config.WinEventLogChannel, filter}
	src := datastore.Config.WinEventLogChannel
	if datastore.Config.WinRemote != "" {
		src += "@" + datastore.Config.WinRemote
		params = append(params, "/r:"+datastore.Config.WinRemote)
		params = append(params, "/u:"+datastore.Config.WinUser)
		params = append(params, "/p:"+datastore.Config.WinPassword)
		if datastore.Config.WinAuth != "" {
			params = append(params, "/a:"+datastore.Config.WinAuth)
		}
	}
	out, err := exec.Command("wevtutil.exe", params...).Output()
	if err != nil {
		log.Printf("getWindowsEventLogs params=%+v err=%v", params, err)
		return ret
	}
	if len(out) < 5 {
		return ret
	}
	e := new(Event)
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\n", ""), "</Event>") {
		l := strings.TrimSpace(l) + "</Event>"
		if len(l) < 10 {
			continue
		}
		if datastore.Config.WinLogSJIS {
			if str, _, err := transform.String(japanese.ShiftJIS.NewDecoder(), l); err == nil {
				l = str
			}
		}
		err := xml.Unmarshal([]byte(l), e)
		if err != nil {
			log.Printf("xml err=%v", err)
			if datastore.Config.Debug {
				log.Printf("log=%s", l)
			}
			continue
		}
		t := getEventTime(e.System.TimeCreated.SystemTime)
		j, err := evtlogXML2JSON(e)
		if err != nil {
			log.Printf("evtlogXML2JSON err=%v", err)
			continue
		}
		al := &datastore.LogEnt{
			Time: t.UnixNano(),
			Type: datastore.WindowsEventLog,
			Src:  src,
			Log:  j,
		}
		auditor.Audit(al)
		ret = append(ret, al)
	}
	return ret
}

// getEventTime :
func getEventTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		log.Printf(" err=%v", err)
		return time.Now()
	}
	return t.Local()
}

func evtlogXML2JSON(x *Event) (string, error) {
	edmap := make(map[string]interface{})
	for _, d := range x.EventData.Data {
		edmap[d.Name] = d.Text
	}
	m := map[string]interface{}{
		"Event": map[string]interface{}{
			"System": map[string]interface{}{
				"Channel":       x.System.Channel,
				"Computer":      x.System.Computer,
				"Correlation":   x.System.Correlation,
				"EventID":       x.System.EventID,
				"EventRecordID": x.System.EventRecordID,
				"Execution": map[string]interface{}{
					"ProcessID": x.System.Execution.ProcessID,
					"ThreadID":  x.System.Execution.ThreadID,
				},
				"Keywords": x.System.Keywords,
				"Level":    x.System.Level,
				"Opcode":   x.System.Opcode,
				"Provider": map[string]interface{}{
					"Guid": x.System.Provider.Guid,
					"Name": x.System.Provider.Name,
				},
				"Security": map[string]interface{}{
					"UserID": x.System.Security.UserID,
				},
				"Task": x.System.Task,
				"TimeCreated": map[string]interface{}{
					"SystemTime": x.System.TimeCreated.SystemTime,
				},
				"Version": x.System.Version,
			},
			"EventData": edmap,
		},
	}
	j, err := json.Marshal(&m)
	if err != nil {
		return "", err
	}
	return string(j), nil
}
