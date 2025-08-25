package reporter

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

var netflowReporterCh chan *datastore.NetflowLogEnt
var netflowReport *datastore.NetFlowReportEnt

type netflowSummaryEnt struct {
	Key     string
	Count   int
	Packets int64
	Bytes   int64
}

var netflowMACMap map[string]*netflowSummaryEnt
var netflowIPMap map[string]*netflowSummaryEnt
var netflowFlowMap map[string]*netflowSummaryEnt
var netflowProtocolMap map[string]int64
var netflowTCPFlagMap map[string]int64

func startNetflow(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start netflow reporter")
	defer wg.Done()
	timer := time.NewTicker(time.Second * 1)
	lastH := time.Now().Hour()
	netflowReport = &datastore.NetFlowReportEnt{}
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop entflow reporter")
			return
		case l := <-netflowReporterCh:
			processNetflowReport(l)
		case <-timer.C:
			h := time.Now().Hour()
			if lastH != h {
				saveNetflowReport()
			}

		}
	}
}

func SendNetflow(l *datastore.NetflowLogEnt) {
	netflowReporterCh <- l
}

func processNetflowReport(l *datastore.NetflowLogEnt) {
	var ok bool
	var srcMAC string
	var srcIP string
	// var dstMAC string
	var dstIP string
	var bytes float64
	var packets float64
	var sp float64
	var dp float64
	var protocol string
	var tcpFlags string
	if srcIP, ok = l.Log["srcAddr"].(string); !ok {
		// IPFIX
		if srcIP, ok = l.Log["sourceIPv4Address"].(string); !ok {
			if srcIP, ok = l.Log["sourceIPv6Address"].(string); !ok {
				return
			}
		}
		if dstIP, ok = l.Log["destinationIPv4Address"].(string); !ok {
			if dstIP, ok = l.Log["destinationIPv6Address"].(string); !ok {
				return
			}
		}
		if packets, ok = l.Log["packetDeltaCount"].(float64); !ok {
			return
		}
		if bytes, ok = l.Log["octetDeltaCount"].(float64); !ok {
			return
		}
		protocol = "unknown"
		var icmpTypeCode float64
		var pi float64
		if icmpTypeCode, ok = l.Log["icmpTypeCodeIPv6"].(float64); ok {
			protocol = "icmpv6"
			sp = float64(int(icmpTypeCode) / 256)
			dp = float64(int(icmpTypeCode) % 256)
			pi = 1
		} else if icmpTypeCode, ok = l.Log["icmpTypeCodeIPv4"].(float64); ok {
			protocol = "icmpv4"
			sp = float64(int(icmpTypeCode) / 256)
			dp = float64(int(icmpTypeCode) % 256)
			pi = 1
		} else if pi, ok = l.Log["protocolIdentifier"].(float64); ok {
			if sp, ok = l.Log["sourceTransportPort"].(float64); !ok {
				return
			}
			if dp, ok = l.Log["destinationTransportPort"].(float64); !ok {
				return
			}
			if int(pi) == 6 {
				if t, ok := l.Log["tcpflagsStr"]; !ok {
					var tfb float64
					if tfb, ok = l.Log["tcpControlBits"].(float64); ok {
						f := uint8(tfb)
						flags := []byte{}
						for i := uint8(0); i < 8; i++ {
							if f&0x01 > 0 {
								flags = append(flags, tcpFlags[8-i])
							} else {
								flags = append(flags, '.')
							}
							f >>= 1
						}
						tcpFlags = "[" + string(flags) + "]"
					}
				} else {
					tcpFlags = t.(string)
				}
				protocol = "tcp"
			} else if int(pi) == 17 {
				protocol = "udp"
			} else if int(pi) == 1 {
				protocol = "icmp"
			} else {
				if v, ok := l.Log["protocolStr"]; ok {
					protocol = v.(string)
				} else {
					protocol = fmt.Sprintf("%d", int(pi))
				}
			}
		}
		if v, ok := l.Log["sourceMacAddress"]; ok {
			if mac, ok := v.(string); ok {
				srcMAC = mac
			}
		}
	} else {
		// Netflow v5
		if sp, ok = l.Log["srcPort"].(float64); !ok {
			return
		}
		if dstIP, ok = l.Log["dstAddr"].(string); !ok {
			return
		}
		if dp, ok = l.Log["dstPort"].(float64); !ok {
			return
		}
		if packets, ok = l.Log["packets"].(float64); !ok {
			return
		}
		if bytes, ok = l.Log["bytes"].(float64); !ok {
			return
		}
		if protocol, ok = l.Log["protocolStr"].(string); !ok {
			if pi, ok := l.Log["protocol"].(float64); ok {
				switch pi {
				case 1:
					protocol = "icmp"
				case 2:
					protocol = "igmp"
				case 6:
					protocol = "tcp"
				case 17:
					protocol = "udp"
				default:
					protocol = fmt.Sprintf("%d", int(pi))
				}
			}
		}
		if v, ok := l.Log["sourceMacAddress"]; ok {
			if mac, ok := v.(string); ok {
				srcMAC = mac
			}
		}
		if tcpFlags, ok = l.Log["tcpflagsStr"].(string); !ok {
			tcpFlags = ""
		}
	}
	netflowReport.Bytes += int64(bytes)
	netflowReport.Packets += int64(packets)
	if srcMAC != "" {
		if _, ok := netflowMACMap[srcMAC]; !ok {
			netflowMACMap[srcMAC] = &netflowSummaryEnt{}
		}
		netflowMACMap[srcMAC].Count++
		netflowMACMap[srcMAC].Bytes += int64(bytes)
		netflowMACMap[srcMAC].Packets += int64(packets)
	}
	if srcIP == "" {
		return
	}
	if _, ok := netflowIPMap[srcIP]; !ok {
		netflowIPMap[srcIP] = &netflowSummaryEnt{}
	}
	netflowIPMap[srcIP].Count++
	netflowIPMap[srcIP].Bytes += int64(bytes)
	netflowIPMap[srcIP].Packets += int64(packets)
	if dstIP == "" {
		return
	}
	var flow string
	if !isGlobalUnicast(dstIP) || lessIP(srcIP, dstIP) {
		flow = srcIP + "\t" + dstIP
	} else {
		flow = dstIP + "\t" + srcIP
	}
	if _, ok := netflowFlowMap[flow]; !ok {
		netflowFlowMap[flow] = &netflowSummaryEnt{}
	}
	netflowFlowMap[flow].Bytes = int64(bytes)
	netflowFlowMap[flow].Packets = int64(packets)
	protocol = getProtocolName(protocol, int(sp), int(dp))
	netflowProtocolMap[protocol]++
	if tcpFlags != "" {
		netflowTCPFlagMap[tcpFlags]++
	}
}

func saveNetflowReport() {
	// make topList
	topMACPacketsList := []datastore.NetflowSummaryEnt{}
	topMACBytesList := []datastore.NetflowSummaryEnt{}
	for k, v := range netflowMACMap {
		topMACPacketsList = append(topMACPacketsList, datastore.NetflowSummaryEnt{Key: k, Value: v.Packets})
		topMACBytesList = append(topMACBytesList, datastore.NetflowSummaryEnt{Key: k, Value: v.Bytes})
	}
	sort.Slice(topMACPacketsList, func(i, j int) bool {
		return topMACPacketsList[i].Value > topMACPacketsList[j].Value
	})
	if len(topMACBytesList) > datastore.Config.ReportTopN {
		topMACBytesList = topMACBytesList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topMACBytesList, func(i, j int) bool {
		return topMACBytesList[i].Value > topMACBytesList[j].Value
	})
	if len(topMACBytesList) > datastore.Config.ReportTopN {
		topMACBytesList = topMACBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopMACPacketsList = topMACPacketsList
	netflowReport.TopMACBytesList = topMACBytesList

	topIPPacketsList := []datastore.NetflowSummaryEnt{}
	topIPBytesList := []datastore.NetflowSummaryEnt{}
	for k, v := range netflowIPMap {
		topIPPacketsList = append(topIPPacketsList, datastore.NetflowSummaryEnt{Key: k, Value: v.Packets})
		topIPBytesList = append(topIPBytesList, datastore.NetflowSummaryEnt{Key: k, Value: v.Bytes})
	}
	sort.Slice(topIPPacketsList, func(i, j int) bool {
		return topIPPacketsList[i].Value > topIPPacketsList[j].Value
	})
	if len(topIPPacketsList) > datastore.Config.ReportTopN {
		topIPPacketsList = topIPPacketsList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topIPBytesList, func(i, j int) bool {
		return topIPBytesList[i].Value > topIPBytesList[j].Value
	})
	if len(topIPBytesList) > datastore.Config.ReportTopN {
		topIPBytesList = topIPBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopIPPacketsList = topIPPacketsList
	netflowReport.TopIPBytesList = topIPBytesList

	topFlowPacketsList := []datastore.NetflowSummaryEnt{}
	topFlowBytesList := []datastore.NetflowSummaryEnt{}
	for k, v := range netflowFlowMap {
		topFlowPacketsList = append(topFlowPacketsList, datastore.NetflowSummaryEnt{Key: k, Value: v.Packets})
		topFlowBytesList = append(topFlowBytesList, datastore.NetflowSummaryEnt{Key: k, Value: v.Bytes})
	}
	sort.Slice(topFlowPacketsList, func(i, j int) bool {
		return topFlowPacketsList[i].Value > topFlowPacketsList[j].Value
	})
	if len(topFlowPacketsList) > datastore.Config.ReportTopN {
		topFlowPacketsList = topFlowPacketsList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topFlowBytesList, func(i, j int) bool {
		return topFlowBytesList[i].Value > topFlowBytesList[j].Value
	})
	if len(topFlowBytesList) > datastore.Config.ReportTopN {
		topFlowBytesList = topFlowBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopFlowPacketsList = topFlowPacketsList
	netflowReport.TopFlowBytesList = topFlowBytesList

	topProtocolList := []datastore.NetflowSummaryEnt{}
	for k, v := range netflowProtocolMap {
		topProtocolList = append(topProtocolList, datastore.NetflowSummaryEnt{Key: k, Value: int64(v)})
	}
	sort.Slice(topProtocolList, func(i, j int) bool {
		return topProtocolList[i].Value > topProtocolList[j].Value
	})
	if len(topProtocolList) > datastore.Config.ReportTopN {
		topProtocolList = topProtocolList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopProtocolList = topProtocolList

	topTCPFlagList := []datastore.NetflowSummaryEnt{}
	for k, v := range netflowTCPFlagMap {
		topTCPFlagList = append(topTCPFlagList, datastore.NetflowSummaryEnt{Key: k, Value: int64(v)})
	}
	sort.Slice(topTCPFlagList, func(i, j int) bool {
		return topTCPFlagList[i].Value > topTCPFlagList[j].Value
	})
	if len(topTCPFlagList) > datastore.Config.ReportTopN {
		topTCPFlagList = topTCPFlagList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopTCPFlagList = topTCPFlagList

	// Save trap Report
	datastore.SaveNetflowReport(netflowReport)
	// Clear report
	netflowMACMap = make(map[string]*netflowSummaryEnt)
	netflowIPMap = make(map[string]*netflowSummaryEnt)
	netflowProtocolMap = make(map[string]int64)
	netflowTCPFlagMap = make(map[string]int64)
	netflowFlowMap = make(map[string]*netflowSummaryEnt)
	netflowReport = &datastore.NetFlowReportEnt{}
}

func getProtocolName(prot string, sp, dp int) string {
	sv1, ok1 := datastore.GetServiceName(prot, sp)
	sv2, ok2 := datastore.GetServiceName(prot, dp)
	if ok1 {
		if ok2 {
			if sp < dp {
				return sv1
			}
			return sv2
		}
		return sv1
	} else if ok2 {
		return sv2
	}
	if strings.HasPrefix(prot, "icmp") || sp < dp {
		return fmt.Sprintf("%d/%s", sp, prot)
	}
	return fmt.Sprintf("%d/%s", dp, prot)

}

func isGlobalUnicast(ips string) bool {
	ip := net.ParseIP(ips)
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.To4() == nil {
		return true
	}
	last := make(net.IP, len(ip.To4()))
	mask := ip.DefaultMask()
	binary.BigEndian.PutUint32(last, binary.BigEndian.Uint32(ip.To4())|^binary.BigEndian.Uint32(net.IP(mask).To4()))
	return !ip.Equal(last)
}

func lessIP(ip1s, ip2s string) bool {
	ip1 := net.ParseIP(ip1s)
	ip2 := net.ParseIP(ip2s)
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] == ip2[i] {
			continue
		}
		if ip1[i] < ip2[i] {
			return true
		}
		return false
	}
	return true
}
