package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"sync"

	"fmt"
	"net"
	"time"

	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/ipfix"
	"github.com/tehmaze/netflow/netflow5"
	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/read"
	"github.com/tehmaze/netflow/session"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

var netflowCh = make(chan *datastore.LogEnt, 20000)

func StartNetFlowd(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.NetFlowPort == 0 {
		return
	}
	log.Printf("start netflowd")
	var readSize = 2 << 16
	var addr *net.UDPAddr
	var err error
	if addr, err = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", datastore.Config.NetFlowPort)); err != nil {
		log.Fatalf("netflowd err=%v", err)
	}
	var server *net.UDPConn
	if server, err = net.ListenUDP("udp", addr); err != nil {
		log.Fatalf("netflowd err=%v", err)
	}
	defer server.Close()
	if err = server.SetReadBuffer(readSize); err != nil {
		log.Fatalf("netflowd err=%v", err)
	}
	go func() {
		for {
			decoders := make(map[string]*netflow.Decoder)
			buf := make([]byte, 8192)
			var remote *net.UDPAddr
			var octets int
			if octets, remote, err = server.ReadFromUDP(buf); err != nil {
				return
			}
			d, found := decoders[remote.String()]
			if !found {
				s := session.New()
				d = netflow.NewDecoder(s)
				decoders[remote.String()] = d
			}
			m, err := d.Read(bytes.NewBuffer(buf[:octets]))
			if err != nil {
				log.Printf("netflowd err=%v", err)
				continue
			}
			switch p := m.(type) {
			case *netflow5.Packet:
				logNetflow(p, remote.IP.String())
			case *netflow9.Packet:
				logNetflow9(p, remote.IP.String())
			case *ipfix.Message:
				logIPFIX(p, remote.IP.String())
			default:
				log.Printf("not suppoted netflow p=%+v", p)
			}
		}
	}()
	list := []*datastore.LogEnt{}
	timer := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop netflowd")
			return
		case l := <-netflowCh:
			list = append(list, l)
			auditor.Audit(l)
		case <-timer.C:
			if len(list) > 0 {
				st := time.Now()
				datastore.SaveLogs("netflow", list)
				log.Printf("save netflow logs len=%d dur=%v", len(list), time.Since(st))
				list = []*datastore.LogEnt{}
			}
		}
	}
}

func logIPFIX(p *ipfix.Message, src string) {
	for _, ds := range p.DataSets {
		if ds.Records == nil {
			continue
		}
		for _, dr := range ds.Records {
			var record = make(map[string]interface{})
			for _, f := range dr.Fields {
				if f.Translated != nil {
					if f.Translated.Name != "" {
						record[f.Translated.Name] = f.Translated.Value
						switch f.Translated.Name {
						case "protocolIdentifier":
							record["protocolStr"] = read.Protocol(f.Translated.Value.(uint8))
						case "tcpControlBits":
							record["tcpflagsStr"] = read.TCPFlags(uint8(f.Translated.Value.(uint16)))
						case "sourceMacAddress", "postSourceMacAddress":
							if mac, ok := f.Translated.Value.(net.HardwareAddr); ok {
								record["sourceMacAddress"] = mac.String()
							}
						case "destinationMacAddress", "postDestinationMacAddress":
							if mac, ok := f.Translated.Value.(net.HardwareAddr); ok {
								record["destinationMacAddress"] = mac.String()
							}
						}
					} else {
						record[fmt.Sprintf("%d.%d", f.Translated.EnterpriseNumber, f.Translated.InformationElementID)] = f.Bytes
					}
				} else {
					record["raw"] = f.Bytes
				}
			}
			s, err := json.Marshal(record)
			if err != nil {
				continue
			}
			netflowCh <- &datastore.LogEnt{
				Time: time.Now().UnixNano(),
				Type: datastore.NetFlow,
				Src:  src,
				Log:  string(s),
			}
		}
	}
}

func logNetflow(p *netflow5.Packet, src string) {
	var record = make(map[string]interface{})
	for _, r := range p.Records {
		record["srcAddr"] = r.SrcAddr
		record["srcPort"] = r.SrcPort
		record["dstAddr"] = r.DstAddr
		record["dstPort"] = r.DstPort
		record["nextHop"] = r.NextHop
		record["bytes"] = r.Bytes
		record["packets"] = r.Packets
		record["first"] = r.First
		record["last"] = r.Last
		record["tcpflags"] = r.TCPFlags
		record["tcpflagsStr"] = read.TCPFlags(r.TCPFlags)
		record["protocol"] = r.Protocol
		record["protocolStr"] = read.Protocol(r.Protocol)
		record["tos"] = r.ToS
		record["srcAs"] = r.SrcAS
		record["dstAs"] = r.DstAS
		record["srcMask"] = r.SrcMask
		record["dstMask"] = r.DstMask
		s, err := json.Marshal(record)
		if err != nil {
			log.Println(err)
			return
		}
		netflowCh <- &datastore.LogEnt{
			Time: time.Now().UnixNano(),
			Src:  src,
			Type: datastore.NetFlow,
			Log:  string(s),
		}
	}
}

func logNetflow9(p *netflow9.Packet, src string) {
	for _, ds := range p.DataFlowSets {
		if ds.Records == nil {
			continue
		}
		for _, dr := range ds.Records {
			var record = make(map[string]interface{})
			for _, f := range dr.Fields {
				if f.Translated != nil {
					if f.Translated.Name != "" {
						record[f.Translated.Name] = f.Translated.Value
						switch f.Translated.Name {
						case "protocolIdentifier":
							record["protocolStr"] = read.Protocol(f.Translated.Value.(uint8))
						case "tcpControlBits":
							record["tcpflagsStr"] = read.TCPFlags(uint8(f.Translated.Value.(uint16)))
						case "sourceMacAddress", "postSourceMacAddress":
							if mac, ok := f.Translated.Value.(net.HardwareAddr); ok {
								record["sourceMacAddress"] = mac.String()
							}
						case "destinationMacAddress", "postDestinationMacAddress":
							if mac, ok := f.Translated.Value.(net.HardwareAddr); ok {
								record["destinationMacAddress"] = mac.String()
							}
						}
					}
				} else {
					record["raw"] = f.Bytes
				}
			}
			s, err := json.Marshal(record)
			if err != nil {
				continue
			}
			netflowCh <- &datastore.LogEnt{
				Time: time.Now().UnixNano(),
				Src:  src,
				Type: datastore.NetFlow,
				Log:  string(s),
			}
		}
	}
}
