package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	syslog "gopkg.in/mcuadros/go-syslog.v2"
)

func StartSyslogd(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.SyslogTCPPort == 0 && datastore.Config.SyslogUDPPort == 0 {
		return
	}
	syslogCh := make(syslog.LogPartsChannel, 20000)
	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(syslog.NewChannelHandler(syslogCh))
	if datastore.Config.SyslogUDPPort != 0 {
		_ = server.ListenUDP(fmt.Sprintf(":%d", datastore.Config.SyslogUDPPort))
	}
	if datastore.Config.SyslogTCPPort != 0 {
		_ = server.ListenTCP(fmt.Sprintf(":%d", datastore.Config.SyslogTCPPort))
	}
	_ = server.Boot()
	log.Printf("start syslogd")
	list := []*datastore.LogEnt{}
	timer := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop syslogd")
			server.Kill()
			return
		case sl := <-syslogCh:
			src := "unknown"
			if v, ok := sl["hostname"]; ok {
				if h, ok := v.(string); ok {
					src = h
				}
			}
			if s, err := json.Marshal(sl); err == nil {
				l := &datastore.LogEnt{
					Time: time.Now().UnixNano(),
					Type: datastore.Syslog,
					Log:  string(s),
					Src:  src,
				}
				list = append(list, l)
				auditor.Audit(l)
			} else {
				log.Printf("syslogd err=%v", err)
			}
		case <-timer.C:
			if len(list) > 0 {
				st := time.Now()
				datastore.SaveLogs("syslog", list)
				log.Printf("save syslog len=%d dur=%v", len(list), time.Since(st))
				list = []*datastore.LogEnt{}
			}
		}
	}
}
