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
var netflowReport *datastore.NetflowReportEnt

type netflowSummaryEnt struct {
	Key     string
	Count   int
	Packets int
	Bytes   int64
}

var netflowMACMap map[string]*netflowSummaryEnt
var netflowIPMap map[string]*netflowSummaryEnt
var netflowFlowMap map[string]*netflowSummaryEnt
var netflowProtocolMap map[string]int
var netflowFumbleSrcMap map[string]int

func startNetflow(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.NetFlowPort == 0 {
		return
	}
	log.Printf("start netflow reporter")
	timer := time.NewTicker(time.Second * 1)
	lastT := getIntervalTime()
	netflowReport = &datastore.NetflowReportEnt{}
	netflowMACMap = make(map[string]*netflowSummaryEnt)
	netflowIPMap = make(map[string]*netflowSummaryEnt)
	netflowFlowMap = make(map[string]*netflowSummaryEnt)
	netflowProtocolMap = make(map[string]int)
	netflowFumbleSrcMap = make(map[string]int)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop entflow reporter")
			return
		case l := <-netflowReporterCh:
			processNetflowReport(l)
		case <-timer.C:
			t := getIntervalTime()
			if lastT != t {
				lastT = t
				st := time.Now()
				saveNetflowReport()
				log.Printf("save netflow report dur=%v", time.Since(st))
			}
		}
	}
}

func SendNetflow(l *datastore.NetflowLogEnt) {
	netflowReporterCh <- l
}

const tcpFlagData = "NCEUAPRSF"

func processNetflowReport(l *datastore.NetflowLogEnt) {
	var ok bool
	var srcMAC string
	var srcIP string
	// var dstMAC string
	var dstIP string
	var bytes int64
	var packets int64
	var sp int
	var dp int
	var protocol string
	var tcpFlags string
	var ip net.IP
	if ip, ok = l.Log["srcAddr"].(net.IP); !ok {
		// IPFIX
		if ip, ok = l.Log["sourceIPv4Address"].(net.IP); ok {
			srcIP = ip.String()
		} else if ip, ok = l.Log["sourceIPv6Address"].(net.IP); ok {
			srcIP = ip.String()
		} else {
			return
		}

		if ip, ok = l.Log["destinationIPv4Address"].(net.IP); ok {
			dstIP = ip.String()
		} else if ip, ok = l.Log["destinationIPv6Address"].(net.IP); ok {
			dstIP = ip.String()
		} else {
			return
		}
		if _, ok = l.Log["packetDeltaCount"]; !ok {
			return
		}
		packets = getNetflowInt64(l.Log["packetDeltaCount"])
		if _, ok = l.Log["octetDeltaCount"]; !ok {
			return
		}
		bytes = getNetflowInt64(l.Log["octetDeltaCount"])
		protocol = "unknown"
		var icmpTypeCode int
		var pi int
		if _, ok = l.Log["icmpTypeCodeIPv6"]; ok {
			icmpTypeCode = getNetflowInt(l.Log["icmpTypeCodeIPv6"])
			protocol = "icmpv6"
			sp = icmpTypeCode / 256
			dp = icmpTypeCode % 256
			pi = 1
		} else if _, ok = l.Log["icmpTypeCodeIPv4"]; ok {
			icmpTypeCode = getNetflowInt(l.Log["icmpTypeCodeIPv4"])
			protocol = "icmpv4"
			sp = icmpTypeCode / 256
			dp = icmpTypeCode % 256
			pi = 1
		} else if _, ok = l.Log["protocolIdentifier"]; ok {
			pi = getNetflowInt(l.Log["protocolIdentifier"])
			if _, ok = l.Log["sourceTransportPort"]; !ok {
				return
			}
			sp = getNetflowInt(l.Log["sourceTransportPort"])
			if _, ok = l.Log["destinationTransportPort"]; !ok {
				return
			}
			dp = getNetflowInt(l.Log["destinationTransportPort"])
			switch pi {
			case 6:
				if t, ok := l.Log["tcpflagsStr"]; !ok {
					var tfb float64
					if tfb, ok = l.Log["tcpControlBits"].(float64); ok {
						f := uint8(tfb)
						flags := []byte{}
						for i := uint8(0); i < 8; i++ {
							if f&0x01 > 0 {
								flags = append(flags, tcpFlagData[8-i])
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
			case 17:
				protocol = "udp"
			case 1:
				protocol = "icmp"
			default:
				if v, ok := l.Log["protocolStr"]; ok {
					protocol = v.(string)
				} else {
					protocol = fmt.Sprintf("%d", int(pi))
				}
			}
		}
		if mac, ok := l.Log["sourceMacAddress"].(string); ok {
			srcMAC = mac
		}
	} else {
		srcIP = ip.String()
		// Netflow v5
		if _, ok = l.Log["srcPort"]; !ok {
			return
		}
		sp = getNetflowInt(l.Log["srcPort"])
		if ip, ok = l.Log["dstAddr"].(net.IP); ok {
			dstIP = ip.String()
		} else {
			return
		}
		if _, ok = l.Log["dstPort"]; !ok {
			return
		}
		dp = getNetflowInt(l.Log["dstPort"])
		if _, ok = l.Log["packets"]; !ok {
			return
		}
		packets = getNetflowInt64(l.Log["packets"])
		if _, ok = l.Log["bytes"]; !ok {
			return
		}
		bytes = getNetflowInt64(l.Log["bytes"])
		if protocol, ok = l.Log["protocolStr"].(string); !ok {
			if _, ok := l.Log["protocol"]; ok {
				pi := getNetflowInt(l.Log["protocol"])
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
					protocol = fmt.Sprintf("%d", pi)
				}
			}
		}
		if mac, ok := l.Log["sourceMacAddress"].(string); ok {
			srcMAC = mac
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
		netflowMACMap[srcMAC].Packets += int(packets)
	}
	if srcIP == "" {
		return
	}
	if _, ok := netflowIPMap[srcIP]; !ok {
		netflowIPMap[srcIP] = &netflowSummaryEnt{}
	}
	netflowIPMap[srcIP].Count++
	netflowIPMap[srcIP].Bytes += int64(bytes)
	netflowIPMap[srcIP].Packets += int(packets)
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
	netflowFlowMap[flow].Count++
	netflowFlowMap[flow].Bytes = int64(bytes)
	netflowFlowMap[flow].Packets = int(packets)
	protocol = getProtocolName(protocol, int(sp), int(dp))
	netflowProtocolMap[protocol]++
	if src := isFumble(srcIP, dstIP, protocol, tcpFlags, int(packets)); src != "" {
		netflowFumbleSrcMap[src]++
	}
}

func getNetflowInt64(r interface{}) int64 {
	switch v := r.(type) {
	case uint64:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

func getNetflowInt(r interface{}) int {
	switch v := r.(type) {
	case uint64:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case uint32:
		return int(v)
	case int32:
		return int(v)
	case uint16:
		return int(v)
	case int16:
		return int(v)
	case uint8:
		return int(v)
	case int8:
		return int(v)
	}
	return 0

}

func saveNetflowReport() {
	netflowReport.Time = time.Now().UnixNano()
	// make topList
	topMACPacketsList := []datastore.NetflowPacketsSummaryEnt{}
	topMACBytesList := []datastore.NetflowBytesSummaryEnt{}
	for k, v := range netflowMACMap {
		topMACPacketsList = append(topMACPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
		topMACBytesList = append(topMACBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
	}
	sort.Slice(topMACPacketsList, func(i, j int) bool {
		return topMACPacketsList[i].Packets > topMACPacketsList[j].Packets
	})
	if len(topMACPacketsList) > datastore.Config.ReportTopN {
		topMACPacketsList = topMACPacketsList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topMACBytesList, func(i, j int) bool {
		return topMACBytesList[i].Bytes > topMACBytesList[j].Bytes
	})
	if len(topMACBytesList) > datastore.Config.ReportTopN {
		topMACBytesList = topMACBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopMACPacketsList = topMACPacketsList
	netflowReport.TopMACBytesList = topMACBytesList
	netflowReport.MACs = len(netflowMACMap)

	topIPPacketsList := []datastore.NetflowPacketsSummaryEnt{}
	topIPBytesList := []datastore.NetflowBytesSummaryEnt{}
	for k, v := range netflowIPMap {
		topIPPacketsList = append(topIPPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
		topIPBytesList = append(topIPBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
	}
	sort.Slice(topIPPacketsList, func(i, j int) bool {
		return topIPPacketsList[i].Packets > topIPPacketsList[j].Packets
	})
	if len(topIPPacketsList) > datastore.Config.ReportTopN {
		topIPPacketsList = topIPPacketsList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topIPBytesList, func(i, j int) bool {
		return topIPBytesList[i].Bytes > topIPBytesList[j].Bytes
	})
	if len(topIPBytesList) > datastore.Config.ReportTopN {
		topIPBytesList = topIPBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopIPPacketsList = topIPPacketsList
	netflowReport.TopIPBytesList = topIPBytesList
	netflowReport.IPs = len(netflowIPMap)

	topFlowPacketsList := []datastore.NetflowPacketsSummaryEnt{}
	topFlowBytesList := []datastore.NetflowBytesSummaryEnt{}
	for k, v := range netflowFlowMap {
		topFlowPacketsList = append(topFlowPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
		topFlowBytesList = append(topFlowBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
	}
	sort.Slice(topFlowPacketsList, func(i, j int) bool {
		return topFlowPacketsList[i].Packets > topFlowPacketsList[j].Packets
	})
	if len(topFlowPacketsList) > datastore.Config.ReportTopN {
		topFlowPacketsList = topFlowPacketsList[:datastore.Config.ReportTopN]
	}
	sort.Slice(topFlowBytesList, func(i, j int) bool {
		return topFlowBytesList[i].Bytes > topFlowBytesList[j].Bytes
	})
	if len(topFlowBytesList) > datastore.Config.ReportTopN {
		topFlowBytesList = topFlowBytesList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopFlowPacketsList = topFlowPacketsList
	netflowReport.TopFlowBytesList = topFlowBytesList
	netflowReport.Flows = len(netflowFlowMap)

	topProtocolList := []datastore.NetflowProtocolCountEnt{}
	for k, v := range netflowProtocolMap {
		topProtocolList = append(topProtocolList, datastore.NetflowProtocolCountEnt{Protocol: k, Count: v})
	}
	sort.Slice(topProtocolList, func(i, j int) bool {
		return topProtocolList[i].Count > topProtocolList[j].Count
	})
	if len(topProtocolList) > datastore.Config.ReportTopN {
		topProtocolList = topProtocolList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopProtocolList = topProtocolList
	netflowReport.Protocols = len(netflowProtocolMap)

	topFumbleSrcList := []datastore.NetflowIPCountEnt{}
	for k, v := range netflowFumbleSrcMap {
		topFumbleSrcList = append(topFumbleSrcList, datastore.NetflowIPCountEnt{IP: k, Count: v})
	}
	sort.Slice(topFumbleSrcList, func(i, j int) bool {
		return topFumbleSrcList[i].Count > topFumbleSrcList[j].Count
	})
	if len(topFumbleSrcList) > datastore.Config.ReportTopN {
		topFumbleSrcList = topFumbleSrcList[:datastore.Config.ReportTopN]
	}
	netflowReport.TopFumbleSrcList = topFumbleSrcList
	netflowReport.Fumbles = len(netflowFumbleSrcMap)
	// Save trap Report
	datastore.SaveNetflowReport(netflowReport)
	anomalyCh <- &anomalyChannelData{
		Time:   netflowReport.Time,
		Type:   "netflow",
		Vector: netflowReportToVector(netflowReport),
	}
	// Clear report
	netflowMACMap = make(map[string]*netflowSummaryEnt)
	netflowIPMap = make(map[string]*netflowSummaryEnt)
	netflowProtocolMap = make(map[string]int)
	netflowFumbleSrcMap = make(map[string]int)
	netflowFlowMap = make(map[string]*netflowSummaryEnt)
	netflowReport = &datastore.NetflowReportEnt{}
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

func isFumble(src, dst, prot, tcpFlag string, pkt int) string {
	if tcpFlag != "" {
		// Urget,Ack,Push,Reset ,Syn & Fin
		if strings.Contains(tcpFlag, "UAPRSF") || pkt < 5 {
			return src
		}
	}
	// ICMP 3
	if strings.HasPrefix(prot, "3/icmp") {
		return dst
	}
	return ""
}
