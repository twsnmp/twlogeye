package logger

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"fmt"
	"net"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

func StartSnmpTrapd(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.SNMPTrapPort == 0 {
		return
	}
	log.Printf("start snmp trapd")
	datastore.LoadMIBDB()
	trapCh := make(chan *datastore.LogEnt, 20000)

	tl := gosnmp.NewTrapListener()
	tl.Params = &gosnmp.GoSNMP{}
	tl.Params.Version = gosnmp.Version2c
	tl.Params.Community = datastore.Config.TrapCommunity
	tl.OnNewTrap = func(s *gosnmp.SnmpPacket, u *net.UDPAddr) {
		var record = make(map[string]interface{})
		record["FromAddress"] = u.IP.String()
		record["Timestamp"] = s.Timestamp
		record["Enterprise"] = datastore.MIBDB.OIDToName(s.Enterprise)
		record["GenericTrap"] = s.GenericTrap
		record["SpecificTrap"] = s.SpecificTrap
		for _, vb := range s.Variables {
			key := datastore.MIBDB.OIDToName(vb.Name)
			val := datastore.GetMIBValueString(key, &vb, false)
			record[key] = val
		}
		js, err := json.Marshal(record)
		if err == nil {
			trapCh <- &datastore.LogEnt{
				Src:  u.IP.String(),
				Time: time.Now().UnixNano(),
				Log:  string(js),
			}
		}
	}
	defer tl.Close()
	go func() {
		if err := tl.Listen(fmt.Sprintf(":%d", datastore.Config.SNMPTrapPort)); err != nil {
			log.Printf("snmp trap listen err=%v", err)
		}
		log.Printf("close snmptrapd")
	}()
	list := []*datastore.LogEnt{}
	timer := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop snmptrapd")
			return
		case l := <-trapCh:
			list = append(list, l)
			auditor.Audit(l)
			log.Printf("trap log %+v", l)
		case <-timer.C:
			if len(list) > 0 {
				st := time.Now()
				datastore.SaveLogs("trap", list)
				log.Printf("save trap logs len=%d dur=%v", len(list), time.Since(st))
				list = []*datastore.LogEnt{}
			}
		}
	}
}
