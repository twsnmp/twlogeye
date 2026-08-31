package reporter

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/twsnmp/twlogeye/datastore"
)

// RebuildReportsFromLogs scans historical logs from datastore (e.g. Parquet)
// for the given number of past days and builds interval reports into in-memory Badger DB.
func RebuildReportsFromLogs(days int) {
	if days <= 0 {
		days = 7
	}
	now := time.Now().UnixNano()
	startTime := now - int64(days)*24*3600*1000*1000*1000
	intervalNano := int64(datastore.Config.ReportInterval) * 60 * 1000 * 1000 * 1000
	if intervalNano <= 0 {
		intervalNano = 5 * 60 * 1000 * 1000 * 1000
	}

	st := time.Now()
	rebuildSyslogReports(startTime, now, intervalNano)
	rebuildNetflowReports(startTime, now, intervalNano)
	rebuildTrapReports(startTime, now, intervalNano)
	rebuildWindowsEventReports(startTime, now, intervalNano)
	rebuildOTelReports(startTime, now, intervalNano)
	rebuildMqttReports(startTime, now, intervalNano)
	log.Printf("rebuilt reports from logs in %v", time.Since(st))
}

// --- Syslog Rebuilder ---

func rebuildSyslogReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.SyslogReportEnt
	normalizeMap := make(map[string]int)
	normalizeErrorMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano
		topList := []datastore.LogSummaryEnt{}
		for k, v := range normalizeMap {
			topList = append(topList, datastore.LogSummaryEnt{LogPattern: k, Count: v})
		}
		sort.Slice(topList, func(i, j int) bool {
			return topList[i].Count > topList[j].Count
		})
		if len(topList) > datastore.Config.ReportTopN {
			topList = topList[:datastore.Config.ReportTopN]
		}
		report.TopList = topList
		report.Patterns = len(normalizeMap)

		topErrorList := []datastore.LogSummaryEnt{}
		for k, v := range normalizeErrorMap {
			topErrorList = append(topErrorList, datastore.LogSummaryEnt{LogPattern: k, Count: v})
		}
		sort.Slice(topErrorList, func(i, j int) bool {
			return topErrorList[i].Count > topErrorList[j].Count
		})
		if len(topErrorList) > datastore.Config.ReportTopN {
			topErrorList = topErrorList[:datastore.Config.ReportTopN]
		}
		report.TopErrorList = topErrorList
		report.ErrPatterns = len(normalizeErrorMap)

		datastore.SaveSyslogReport(report)
		normalizeMap = make(map[string]int)
		normalizeErrorMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("syslog", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.SyslogReportEnt{}
		}

		var sl map[string]any
		if err := json.Unmarshal([]byte(l.Log), &sl); err != nil {
			return true
		}

		var sv int
		if v, ok := sl["severity"]; ok {
			sv = getAnyInt(v)
		} else {
			return true
		}
		host, _ := sl["hostname"].(string)
		tag, ok := sl["tag"].(string)
		var message string
		if !ok {
			if tag, ok = sl["app_name"].(string); !ok {
				return true
			}
			for i, k := range []string{"proc_id", "msg_id", "message", "structured_data"} {
				if m, ok := sl[k].(string); ok && m != "" {
					if i > 0 {
						message += " "
					}
					message += m
				}
			}
		} else {
			if message, ok = sl["content"].(string); !ok {
				return true
			}
		}

		n := normalizeSyslog(fmt.Sprintf("%s %s %s", host, tag, message))
		normalizeMap[n]++
		switch {
		case sv < 4:
			normalizeErrorMap[n]++
			report.Error++
		case sv == 4:
			report.Warn++
		default:
			report.Normal++
		}
		return true
	})

	flush()
}

// --- Netflow Rebuilder ---

func rebuildNetflowReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.NetflowReportEnt

	macMap := make(map[string]*netflowSummaryEnt)
	ipMap := make(map[string]*netflowSummaryEnt)
	flowMap := make(map[string]*netflowSummaryEnt)
	protocolMap := make(map[string]int)
	fumbleSrcMap := make(map[string]int)
	hostMap := make(map[string]int)
	countryMap := make(map[string]int)
	locMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano

		topMACPacketsList := []datastore.NetflowPacketsSummaryEnt{}
		topMACBytesList := []datastore.NetflowBytesSummaryEnt{}
		for k, v := range macMap {
			topMACPacketsList = append(topMACPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
			topMACBytesList = append(topMACBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
		}
		sort.Slice(topMACPacketsList, func(i, j int) bool { return topMACPacketsList[i].Packets > topMACPacketsList[j].Packets })
		if len(topMACPacketsList) > datastore.Config.ReportTopN {
			topMACPacketsList = topMACPacketsList[:datastore.Config.ReportTopN]
		}
		sort.Slice(topMACBytesList, func(i, j int) bool { return topMACBytesList[i].Bytes > topMACBytesList[j].Bytes })
		if len(topMACBytesList) > datastore.Config.ReportTopN {
			topMACBytesList = topMACBytesList[:datastore.Config.ReportTopN]
		}
		report.TopMACPacketsList = topMACPacketsList
		report.TopMACBytesList = topMACBytesList
		report.MACs = len(macMap)

		topIPPacketsList := []datastore.NetflowPacketsSummaryEnt{}
		topIPBytesList := []datastore.NetflowBytesSummaryEnt{}
		for k, v := range ipMap {
			topIPPacketsList = append(topIPPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
			topIPBytesList = append(topIPBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
		}
		sort.Slice(topIPPacketsList, func(i, j int) bool { return topIPPacketsList[i].Packets > topIPPacketsList[j].Packets })
		if len(topIPPacketsList) > datastore.Config.ReportTopN {
			topIPPacketsList = topIPPacketsList[:datastore.Config.ReportTopN]
		}
		sort.Slice(topIPBytesList, func(i, j int) bool { return topIPBytesList[i].Bytes > topIPBytesList[j].Bytes })
		if len(topIPBytesList) > datastore.Config.ReportTopN {
			topIPBytesList = topIPBytesList[:datastore.Config.ReportTopN]
		}
		report.TopIPPacketsList = topIPPacketsList
		report.TopIPBytesList = topIPBytesList
		report.IPs = len(ipMap)

		topFlowPacketsList := []datastore.NetflowPacketsSummaryEnt{}
		topFlowBytesList := []datastore.NetflowBytesSummaryEnt{}
		for k, v := range flowMap {
			topFlowPacketsList = append(topFlowPacketsList, datastore.NetflowPacketsSummaryEnt{Key: k, Packets: v.Packets})
			topFlowBytesList = append(topFlowBytesList, datastore.NetflowBytesSummaryEnt{Key: k, Bytes: v.Bytes})
		}
		sort.Slice(topFlowPacketsList, func(i, j int) bool { return topFlowPacketsList[i].Packets > topFlowPacketsList[j].Packets })
		if len(topFlowPacketsList) > datastore.Config.ReportTopN {
			topFlowPacketsList = topFlowPacketsList[:datastore.Config.ReportTopN]
		}
		sort.Slice(topFlowBytesList, func(i, j int) bool { return topFlowBytesList[i].Bytes > topFlowBytesList[j].Bytes })
		if len(topFlowBytesList) > datastore.Config.ReportTopN {
			topFlowBytesList = topFlowBytesList[:datastore.Config.ReportTopN]
		}
		report.TopFlowPacketsList = topFlowPacketsList
		report.TopFlowBytesList = topFlowBytesList
		report.Flows = len(flowMap)

		topProtocolList := []datastore.NetflowKeyCountEnt{}
		for k, v := range protocolMap {
			topProtocolList = append(topProtocolList, datastore.NetflowKeyCountEnt{Key: k, Count: v})
		}
		sort.Slice(topProtocolList, func(i, j int) bool { return topProtocolList[i].Count > topProtocolList[j].Count })
		if len(topProtocolList) > datastore.Config.ReportTopN {
			topProtocolList = topProtocolList[:datastore.Config.ReportTopN]
		}
		report.TopProtocolList = topProtocolList
		report.Protocols = len(protocolMap)

		topFumbleSrcList := []datastore.NetflowKeyCountEnt{}
		for k, v := range fumbleSrcMap {
			topFumbleSrcList = append(topFumbleSrcList, datastore.NetflowKeyCountEnt{Key: k, Count: v})
		}
		sort.Slice(topFumbleSrcList, func(i, j int) bool { return topFumbleSrcList[i].Count > topFumbleSrcList[j].Count })
		if len(topFumbleSrcList) > datastore.Config.ReportTopN {
			topFumbleSrcList = topFumbleSrcList[:datastore.Config.ReportTopN]
		}
		report.TopFumbleSrcList = topFumbleSrcList
		report.Fumbles = len(fumbleSrcMap)

		topHostList := []datastore.NetflowKeyCountEnt{}
		for k, v := range hostMap {
			topHostList = append(topHostList, datastore.NetflowKeyCountEnt{Key: k, Count: v})
		}
		sort.Slice(topHostList, func(i, j int) bool { return topHostList[i].Count > topHostList[j].Count })
		if len(topHostList) > datastore.Config.ReportTopN {
			topHostList = topHostList[:datastore.Config.ReportTopN]
		}
		report.TopHostList = topHostList
		report.Hosts = len(hostMap)

		topLocList := []datastore.NetflowKeyCountEnt{}
		for k, v := range locMap {
			topLocList = append(topLocList, datastore.NetflowKeyCountEnt{Key: k, Count: v})
		}
		sort.Slice(topLocList, func(i, j int) bool { return topLocList[i].Count > topLocList[j].Count })
		if len(topLocList) > datastore.Config.ReportTopN {
			topLocList = topLocList[:datastore.Config.ReportTopN]
		}
		report.TopLocList = topLocList
		report.Locs = len(locMap)

		topCountryList := []datastore.NetflowKeyCountEnt{}
		for k, v := range countryMap {
			topCountryList = append(topCountryList, datastore.NetflowKeyCountEnt{Key: k, Count: v})
		}
		sort.Slice(topCountryList, func(i, j int) bool { return topCountryList[i].Count > topCountryList[j].Count })
		if len(topCountryList) > datastore.Config.ReportTopN {
			topCountryList = topCountryList[:datastore.Config.ReportTopN]
		}
		report.TopCountryList = topCountryList
		report.Country = len(countryMap)

		datastore.SaveNetflowReport(report)

		macMap = make(map[string]*netflowSummaryEnt)
		ipMap = make(map[string]*netflowSummaryEnt)
		flowMap = make(map[string]*netflowSummaryEnt)
		protocolMap = make(map[string]int)
		fumbleSrcMap = make(map[string]int)
		hostMap = make(map[string]int)
		countryMap = make(map[string]int)
		locMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("netflow", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.NetflowReportEnt{}
		}

		var nl map[string]any
		if err := json.Unmarshal([]byte(l.Log), &nl); err != nil {
			return true
		}

		var srcMAC string
		var srcIP string
		var dstIP string
		var bytes int64
		var packets int64
		var sp int
		var dp int
		var protocol string
		var pi int

		if s, ok := nl["sourceIPv4Address"].(string); ok {
			srcIP = s
		} else if s, ok := nl["sourceIPv6Address"].(string); ok {
			srcIP = s
		} else if s, ok := nl["srcAddr"].(string); ok {
			srcIP = s
		}

		if s, ok := nl["destinationIPv4Address"].(string); ok {
			dstIP = s
		} else if s, ok := nl["destinationIPv6Address"].(string); ok {
			dstIP = s
		} else if s, ok := nl["dstAddr"].(string); ok {
			dstIP = s
		}

		if v, ok := nl["octetDeltaCount"]; ok {
			bytes = getAnyInt64(v)
		} else if v, ok := nl["bytes"]; ok {
			bytes = getAnyInt64(v)
		}

		if v, ok := nl["packetDeltaCount"]; ok {
			packets = getAnyInt64(v)
		} else if v, ok := nl["packets"]; ok {
			packets = getAnyInt64(v)
		}

		if v, ok := nl["sourceTransportPort"]; ok {
			sp = getAnyInt(v)
		} else if v, ok := nl["srcPort"]; ok {
			sp = getAnyInt(v)
		}

		if v, ok := nl["destinationTransportPort"]; ok {
			dp = getAnyInt(v)
		} else if v, ok := nl["dstPort"]; ok {
			dp = getAnyInt(v)
		}

		if v, ok := nl["protocolIdentifier"]; ok {
			pi = getAnyInt(v)
		} else if v, ok := nl["protocol"]; ok {
			pi = getAnyInt(v)
		}

		if s, ok := nl["protocolStr"].(string); ok {
			protocol = s
		} else {
			switch pi {
			case 6:
				protocol = "tcp"
			case 17:
				protocol = "udp"
			case 1:
				protocol = "icmp"
			default:
				protocol = fmt.Sprintf("%d", pi)
			}
		}

		if s, ok := nl["sourceMacAddress"].(string); ok {
			srcMAC = s
		}

		report.Bytes += bytes
		report.Packets += packets

		if srcMAC != "" {
			if _, ok := macMap[srcMAC]; !ok {
				macMap[srcMAC] = &netflowSummaryEnt{}
			}
			macMap[srcMAC].Count++
			macMap[srcMAC].Bytes += bytes
			macMap[srcMAC].Packets += int(packets)
		}
		if srcIP != "" {
			if _, ok := ipMap[srcIP]; !ok {
				ipMap[srcIP] = &netflowSummaryEnt{}
			}
			ipMap[srcIP].Count++
			ipMap[srcIP].Bytes += bytes
			ipMap[srcIP].Packets += int(packets)
		}
		if dstIP != "" && srcIP != "" {
			var flow string
			if !isGlobalUnicast(dstIP) || lessIP(srcIP, dstIP) {
				flow = srcIP + "\t" + dstIP
			} else {
				flow = dstIP + "\t" + srcIP
			}
			if _, ok := flowMap[flow]; !ok {
				flowMap[flow] = &netflowSummaryEnt{}
			}
			flowMap[flow].Count++
			flowMap[flow].Bytes += bytes
			flowMap[flow].Packets += int(packets)

			protName := getProtocolName(protocol, sp, dp)
			protocolMap[protName]++
			if src := isFumble(srcIP, dstIP, pi, sp, int(packets)); src != "" {
				fumbleSrcMap[src]++
			}
		}

		if host, ok := nl["srcHost"].(string); ok {
			hostMap[host]++
		}
		if host, ok := nl["dstHost"].(string); ok {
			hostMap[host]++
		}
		if loc, ok := nl["srcLoc"].(string); ok {
			locMap[loc]++
		}
		if loc, ok := nl["dstLoc"].(string); ok {
			locMap[loc]++
		}
		if c, ok := nl["srcCountry"].(string); ok {
			countryMap[c]++
		}
		if c, ok := nl["dstCountry"].(string); ok {
			countryMap[c]++
		}

		return true
	})

	flush()
}

// --- Trap Rebuilder ---

func rebuildTrapReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.TrapReportEnt
	trapTypeMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano
		topList := []datastore.TrapSummaryEnt{}
		for k, v := range trapTypeMap {
			a := strings.SplitN(k, "\t", 2)
			if len(a) == 2 {
				topList = append(topList, datastore.TrapSummaryEnt{Sender: a[0], TrapType: a[1], Count: v})
			}
		}
		sort.Slice(topList, func(i, j int) bool {
			return topList[i].Count > topList[j].Count
		})
		if len(topList) > datastore.Config.ReportTopN {
			topList = topList[:datastore.Config.ReportTopN]
		}
		report.TopList = topList
		report.Types = len(trapTypeMap)

		datastore.SaveTrapReport(report)
		trapTypeMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("trap", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.TrapReportEnt{}
		}

		var tl map[string]any
		if err := json.Unmarshal([]byte(l.Log), &tl); err != nil {
			return true
		}

		fa, ok := tl["FromAddress"].(string)
		if !ok {
			fa = l.Src
		}
		var trapType string
		ent, ok := tl["Enterprise"].(string)
		if !ok || ent == "" {
			if tt, ok := tl["snmpTrapOID.0"].(string); ok {
				trapType = tt
			} else {
				return true
			}
		} else {
			gen := getAnyInt(tl["GenericTrap"])
			spe := getAnyInt(tl["SpecificTrap"])
			trapType = fmt.Sprintf("%s:%d:%d", ent, gen, spe)
		}

		k := fmt.Sprintf("%s\t%s", fa, trapType)
		trapTypeMap[k]++
		report.Count++
		return true
	})

	flush()
}

// --- Windows Event Rebuilder ---

type winEventLogRaw struct {
	Event struct {
		System struct {
			Computer string `json:"Computer"`
			Provider struct {
				Name string `json:"Name"`
			} `json:"Provider"`
			EventID int64 `json:"EventID"`
			Level   int64 `json:"Level"`
		} `json:"System"`
	} `json:"Event"`
	System struct {
		Computer string `json:"Computer"`
		Provider struct {
			Name string `json:"Name"`
		} `json:"Provider"`
		EventID int64 `json:"EventID"`
		Level   int64 `json:"Level"`
	} `json:"System"`
}

func rebuildWindowsEventReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.WindowsEventReportEnt
	typeMap := make(map[string]int)
	typeErrorMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano
		topList := []datastore.WindowsEventSummary{}
		for k, v := range typeMap {
			a := strings.SplitN(k, "\t", 3)
			if len(a) >= 3 {
				topList = append(topList, datastore.WindowsEventSummary{Computer: a[0], Provider: a[1], EventID: a[2], Count: v})
			}
		}
		sort.Slice(topList, func(i, j int) bool { return topList[i].Count > topList[j].Count })
		if len(topList) > datastore.Config.ReportTopN {
			topList = topList[:datastore.Config.ReportTopN]
		}
		report.TopList = topList
		report.Types = len(typeMap)

		topErrorList := []datastore.WindowsEventSummary{}
		for k, v := range typeErrorMap {
			a := strings.SplitN(k, "\t", 3)
			if len(a) >= 3 {
				topErrorList = append(topErrorList, datastore.WindowsEventSummary{Computer: a[0], Provider: a[1], EventID: a[2], Count: v})
			}
		}
		sort.Slice(topErrorList, func(i, j int) bool { return topErrorList[i].Count > topErrorList[j].Count })
		if len(topErrorList) > datastore.Config.ReportTopN {
			topErrorList = topErrorList[:datastore.Config.ReportTopN]
		}
		report.TopErrorList = topErrorList
		report.ErrorTypes = len(typeErrorMap)

		datastore.SaveWindowsEventReport(report)
		typeMap = make(map[string]int)
		typeErrorMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("windows", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.WindowsEventReportEnt{}
		}

		var wel winEventLogRaw
		if err := json.Unmarshal([]byte(l.Log), &wel); err != nil {
			return true
		}

		computer := wel.Event.System.Computer
		provider := wel.Event.System.Provider.Name
		eventID := wel.Event.System.EventID
		level := wel.Event.System.Level
		if computer == "" {
			computer = wel.System.Computer
			provider = wel.System.Provider.Name
			eventID = wel.System.EventID
			level = wel.System.Level
		}
		if computer == "" {
			computer = l.Src
		}

		key := fmt.Sprintf("%s\t%s\t%d", computer, provider, eventID)
		switch level {
		case 1, 2:
			report.Error++
			typeErrorMap[key]++
		case 3:
			report.Warn++
		default:
			report.Normal++
		}
		typeMap[key]++
		return true
	})

	flush()
}

// --- OTel Rebuilder ---

func rebuildOTelReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.OTelReportEnt
	hostMap := make(map[string]int)
	typeMap := make(map[string]int)
	errorTypeMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano
		topList := []datastore.OTelSummaryEnt{}
		for k, v := range typeMap {
			a := strings.SplitN(k, "\t", 4)
			if len(a) == 4 {
				topList = append(topList, datastore.OTelSummaryEnt{Host: a[0], Service: a[1], Scope: a[2], Severity: a[3], Count: v})
			}
		}
		sort.Slice(topList, func(i, j int) bool { return topList[i].Count > topList[j].Count })
		if len(topList) > datastore.Config.ReportTopN {
			topList = topList[:datastore.Config.ReportTopN]
		}
		topErrorList := []datastore.OTelSummaryEnt{}
		for k, v := range errorTypeMap {
			a := strings.SplitN(k, "\t", 4)
			if len(a) == 4 {
				topErrorList = append(topErrorList, datastore.OTelSummaryEnt{Host: a[0], Service: a[1], Scope: a[2], Severity: a[3], Count: v})
			}
		}
		sort.Slice(topErrorList, func(i, j int) bool { return topErrorList[i].Count > topErrorList[j].Count })
		if len(topErrorList) > datastore.Config.ReportTopN {
			topErrorList = topErrorList[:datastore.Config.ReportTopN]
		}
		report.TopList = topList
		report.TopErrorList = topErrorList
		report.Types = len(typeMap)
		report.Hosts = len(hostMap)
		report.ErrorTypes = len(errorTypeMap)

		datastore.SaveOTelReport(report)
		hostMap = make(map[string]int)
		typeMap = make(map[string]int)
		errorTypeMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("otel", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.OTelReportEnt{}
		}

		var ol datastore.OTelLogEnt
		if err := json.Unmarshal([]byte(l.Log), &ol); err != nil {
			return true
		}

		hostMap[ol.Host]++
		k := fmt.Sprintf("%s\t%s\t%s\t%s", ol.Host, ol.Service, ol.Scope, ol.SeverityText)
		typeMap[k]++
		switch {
		case ol.SeverityNumber <= 16 && ol.SeverityNumber > 12:
			report.Warn++
		case ol.SeverityNumber > 16:
			report.Error++
			errorTypeMap[k]++
		default:
			report.Normal++
		}
		return true
	})

	flush()
}

// --- MQTT Rebuilder ---

func rebuildMqttReports(startTime, endTime, intervalNano int64) {
	var currentSlot int64 = -1
	var report *datastore.MqttReportEnt
	typeMap := make(map[string]int)

	flush := func() {
		if currentSlot < 0 || report == nil {
			return
		}
		report.Time = currentSlot + intervalNano
		topList := []datastore.MqttSummaryEnt{}
		for k, v := range typeMap {
			a := strings.SplitN(k, "\t", 2)
			if len(a) == 2 {
				topList = append(topList, datastore.MqttSummaryEnt{ClientID: a[0], Topic: a[1], Count: v})
			}
		}
		sort.Slice(topList, func(i, j int) bool { return topList[i].Count > topList[j].Count })
		if len(topList) > datastore.Config.ReportTopN {
			topList = topList[:datastore.Config.ReportTopN]
		}
		report.TopList = topList
		report.Types = len(typeMap)

		datastore.SaveMqttReport(report)
		typeMap = make(map[string]int)
		report = nil
	}

	datastore.ForEachLog("mqtt", startTime, endTime, func(l *datastore.LogEnt) bool {
		slot := (l.Time / intervalNano) * intervalNano
		if slot != currentSlot {
			flush()
			currentSlot = slot
			report = &datastore.MqttReportEnt{}
		}

		var ml datastore.MqttLogEnt
		if err := json.Unmarshal([]byte(l.Log), &ml); err != nil {
			return true
		}

		k := fmt.Sprintf("%s\t%s", ml.ClientID, ml.Topic)
		typeMap[k]++
		report.Count++
		return true
	})

	flush()
}

// --- Helper utilities ---

func getAnyInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case uint64:
		return int(val)
	case string:
		var i int
		_, _ = fmt.Sscanf(val, "%d", &i)
		return i
	}
	return 0
}

func getAnyInt64(v any) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case uint64:
		return int64(val)
	case string:
		var i int64
		_, _ = fmt.Sscanf(val, "%d", &i)
		return i
	}
	return 0
}
