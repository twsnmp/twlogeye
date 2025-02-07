package logger

import (
	"context"
	"encoding/xml"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"fmt"
	"time"

	xj "github.com/basgys/goxml2json"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

// Windows Event Log XML format
type System struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	}
	EventID       int    `xml:"EventID"`
	Level         int    `xml:"Level"`
	EventRecordID int64  `xml:"EventRecordID"`
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
	Security      struct {
		UserID string `xml:"UserID,attr"`
	}
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	}
}

var reSystem = regexp.MustCompile(`<System.+System>`)
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
	s := new(System)
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\n", ""), "</Event>") {
		l := strings.TrimSpace(l) + "</Event>"
		if len(l) < 10 {
			continue
		}
		lsys := reSystem.FindString(l)
		err := xml.Unmarshal([]byte(lsys), s)
		if err != nil {
			log.Printf("xml err=%v", err)
			continue
		}
		t := getEventTime(s.TimeCreated.SystemTime)
		xml := strings.NewReader(l)
		j, err := xj.Convert(xml, xj.WithTypeConverter(xj.Int))
		if err != nil {
			log.Printf("xml2json err=%v", err)
			continue
		}
		al := &datastore.LogEnt{
			Time: t.UnixNano(),
			Type: datastore.WindowsEventLog,
			Src:  src,
			Log:  j.String(),
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
