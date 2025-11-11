/*
Copyright © 2025 Masayuki Yamai <twsnmp@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

var noList bool

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report <report type> [<anomaly type>]",
	Short: "Get report",
	Long:  `Get report via api`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalln("twlogeye report <report type>")
		}
		st := getTime(startTime, 0)
		et := getTime(endTime, time.Now().UnixNano())
		switch args[0] {
		case "trap":
			getTrapReport(st, et)
		case "netflow":
			getNetflowReport(st, et)
		case "winevent":
			getWindowsEventReport(st, et)
		case "otel":
			getOTelReport(st, et)
		case "mqtt":
			getMqttReport(st, et)
		case "anomaly":
			if len(args) < 2 {
				log.Fatalln("twlogeye report anomaly <type>")
			}
			getAnomalyReport(args[1], st, et)
		case "monitor":
			getMonitorReport(st, et)
		case "last":
			if len(args) < 2 {
				log.Fatalln("twlogeye report last <type>")
			}
			switch args[1] {
			case "trap":
				getLastTrapReport()
			case "netflow":
				getLastNetflowReport()
			case "winevent":
				getLastWindowsEventReport()
			case "otel":
				getLastOTelReport()
			case "mqtt":
				getLastMqttReport()
			case "monitor":
				getLastMonitorReport()
			case "anomaly":
				getLastAnomalyReport()
			default:
				getLastSyslogReport()
			}
		default:
			getSyslogReport(st, et)
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	reportCmd.Flags().StringVar(&endTime, "end", "", "end date and time")
	reportCmd.Flags().BoolVar(&noList, "noList", false, "report summary only")
}

func getSyslogReport(st, et int64) {
	client := getClient()
	s, err := client.GetSyslogReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get syslog report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get syslog report err=%v", err)
		}
		fmt.Printf("%s syslog normal=%d warn=%d error=%d patterns=%d err_patterns=%d\n",
			getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
			r.GetPatterns(), r.GetErrPatterns())
		topList := r.GetTopList()
		if len(topList) > 0 && !noList {
			fmt.Println("Top syslog pattern list")
			fmt.Println("No.\tPattern\tCount")
			for i, t := range topList {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
			}
			fmt.Println("===")
			fmt.Println("Top error syslog pattern list")
			fmt.Println("No.\tPattern\tCount")
			for i, t := range r.GetTopErrorList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastSyslogReport() {
	client := getClient()
	r, err := client.GetLastSyslogReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last syslog report err=%v", err)
	}
	fmt.Printf("%s syslog normal=%d warn=%d error=%d patterns=%d err_patterns=%d\n",
		getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
		r.GetPatterns(), r.GetErrPatterns())
	topList := r.GetTopList()
	if len(topList) > 0 && !noList {
		fmt.Println("Top syslog pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range topList {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top error syslog pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getTrapReport(st, et int64) {
	client := getClient()
	s, err := client.GetTrapReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get trap report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get trap report err=%v", err)
		}
		fmt.Printf("%s trap count=%d types=%d\n", getReportTimeStr(r.GetTime()), r.GetCount(), r.GetTypes())
		list := r.GetTopList()
		if len(list) > 0 && !noList {
			fmt.Println("Top TRAP type list")
			fmt.Println("No.\tSender\tTrap Type\tCount")
			for i, t := range list {
				fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetSender(), t.GetTrapType(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastTrapReport() {
	client := getClient()
	r, err := client.GetLastTrapReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last trap report err=%v", err)
	}
	fmt.Printf("%s trap count=%d types=%d\n", getReportTimeStr(r.GetTime()), r.GetCount(), r.GetTypes())
	list := r.GetTopList()
	if len(list) > 0 && !noList {
		fmt.Println("Top TRAP type list")
		fmt.Println("No.\tSender\tTrap Type\tCount")
		for i, t := range list {
			fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetSender(), t.GetTrapType(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getNetflowReport(st, et int64) {
	client := getClient()
	s, err := client.GetNetflowReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get netflow report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get netflow report err=%v", err)
		}
		fmt.Printf("%s netflow packets=%d bytes=%d macs=%d ips=%d flows=%d prots=%d fumbles=%d\n",
			getReportTimeStr(r.GetTime()), r.GetPackets(), r.GetBytes(),
			r.GetMacs(), r.GetIps(), r.GetFlows(), r.GetProtocols(), r.GetFumbles())
		if r.GetPackets() > 0 && !noList {
			fmt.Println("Top MAC node packets list")
			fmt.Println("No.\tMAC\tPackets")
			for i, t := range r.GetTopMacPacketsList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
			}
			fmt.Println("Top MAC node bytes list")
			fmt.Println("No.\tMAC\tBytes")
			for i, t := range r.GetTopMacBytesList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
			}
			fmt.Println("Top IP node packets list")
			fmt.Println("No.\tIP\tPackets")
			for i, t := range r.GetTopIpPacketsList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
			}
			fmt.Println("Top IP node bytes list")
			fmt.Println("No.\tIP\tBytes")
			for i, t := range r.GetTopIpBytesList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
			}
			fmt.Println("Top flow packets list")
			fmt.Println("No.\tFlow\tPackets")
			for i, t := range r.GetTopFlowPacketsList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
			}
			fmt.Println("Top flow bytes list")
			fmt.Println("No.\tFlow\tBytes")
			for i, t := range r.GetTopFlowBytesList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
			}
			fmt.Println("Top protocol list")
			fmt.Println("No.\tProcottol\tCount")
			for i, t := range r.GetTopProtocolList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetProtocol(), t.GetCount())
			}
			fmt.Println("Top Fumble src list")
			fmt.Println("No.\tSrc\tCount")
			for i, t := range r.GetTopFumbleSrcList() {
				fmt.Printf("%d\t%s\t%d\n", i+1, t.GetIp(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastNetflowReport() {
	client := getClient()
	r, err := client.GetLastNetflowReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last netflow report err=%v", err)
	}
	fmt.Printf("%s netflow packets=%d bytes=%d macs=%d ips=%d flows=%d prots=%d fumbles=%d\n",
		getReportTimeStr(r.GetTime()), r.GetPackets(), r.GetBytes(),
		r.GetMacs(), r.GetIps(), r.GetFlows(), r.GetProtocols(), r.GetFumbles())
	if r.GetPackets() > 0 && !noList {
		fmt.Println("Top MAC node packets list")
		fmt.Println("No.\tMAC\tPackets")
		for i, t := range r.GetTopMacPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("Top MAC node bytes list")
		fmt.Println("No.\tMAC\tBytes")
		for i, t := range r.GetTopMacBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("Top IP node packets list")
		fmt.Println("No.\tIP\tPackets")
		for i, t := range r.GetTopIpPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("Top IP node bytes list")
		fmt.Println("No.\tIP\tBytes")
		for i, t := range r.GetTopIpBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("Top flow packets list")
		fmt.Println("No.\tFlow\tPackets")
		for i, t := range r.GetTopFlowPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("Top flow bytes list")
		fmt.Println("No.\tFlow\tBytes")
		for i, t := range r.GetTopFlowBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("Top protocol list")
		fmt.Println("No.\tProcottol\tCount")
		for i, t := range r.GetTopProtocolList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetProtocol(), t.GetCount())
		}
		fmt.Println("Top Fumble src list")
		fmt.Println("No.\tSrc\tCount")
		for i, t := range r.GetTopFumbleSrcList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetIp(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getWindowsEventReport(st, et int64) {
	client := getClient()
	s, err := client.GetWindowsEventReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get windows event report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get windows event report err=%v", err)
		}
		fmt.Printf("%s windows event normal=%d warn=%d error=%d types=%d error_types=%d\n",
			getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
			r.GetTypes(), r.GetErrorTypes())
		if len(r.GetTopList()) > 0 && !noList {
			fmt.Println("Top windows event list")
			fmt.Println("No.\tComputer\tProvider\tEventID\tCount")
			for i, t := range r.GetTopList() {
				fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
			}
			fmt.Println("Top error windows event list")
			fmt.Println("No.\tComputer\tProvider\tEventID\tCount")
			for i, t := range r.GetTopErrorList() {
				fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastWindowsEventReport() {
	client := getClient()
	r, err := client.GetLastWindowsEventReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last windows event report err=%v", err)
	}
	fmt.Printf("%s windows event normal=%d warn=%d error=%d types=%d error_types=%d\n",
		getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
		r.GetTypes(), r.GetErrorTypes())
	if len(r.GetTopList()) > 0 && !noList {
		fmt.Println("Top windows event list")
		fmt.Println("No.\tComputer\tProvider\tEventID\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
		fmt.Println("Top error windows event list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getOTelReport(st, et int64) {
	client := getClient()
	s, err := client.GetOTelReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get otel report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get otel report err=%v", err)
		}
		fmt.Printf("%s otel normal=%d warn=%d error=%d types=%d error_types=%d,hosts=%d,metrics=%d,traces=%d,traceids=%d\n",
			getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
			r.GetTypes(), r.GetErrorTypes(), r.GetHosts(), r.GetMericsCount(), r.GetTraceCount(), r.GetTraceIds())
		if len(r.GetTopList()) > 0 && !noList {
			fmt.Println("Top otel log list")
			fmt.Println("No.\tHost\tService\tScopre\tSeverity\tCount")
			for i, t := range r.GetTopList() {
				fmt.Printf("%d\t%s\t%s\t%s\t%s\t%d\n", i+1, t.GetHost(), t.GetService(), t.GetScope(), t.GetSeverity(), t.GetCount())
			}
			fmt.Println("Top error otel log list")
			fmt.Println("No.\tHost\tService\tScopre\tSeverity\tCount")
			for i, t := range r.GetTopErrorList() {
				fmt.Printf("%d\t%s\t%s\t%s\t%s\t%d\n", i+1, t.GetHost(), t.GetService(), t.GetScope(), t.GetSeverity(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastOTelReport() {
	client := getClient()
	r, err := client.GetLastOTelReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last otel report err=%v", err)
	}
	fmt.Printf("%s otel normal=%d warn=%d error=%d types=%d error_types=%d,hosts=%d,metrics=%d,traces=%d,traceids=%d\n",
		getReportTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError(),
		r.GetTypes(), r.GetErrorTypes(), r.GetHosts(), r.GetMericsCount(), r.GetTraceCount(), r.GetTraceIds())
	if len(r.GetTopList()) > 0 && !noList {
		fmt.Println("Top otel log list")
		fmt.Println("No.\tHost\tService\tScopre\tSeverity\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%s\t%d\n", i+1, t.GetHost(), t.GetService(), t.GetScope(), t.GetSeverity(), t.GetCount())
		}
		fmt.Println("Top error otel log list")
		fmt.Println("No.\tHost\tService\tScopre\tSeverity\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%s\t%d\n", i+1, t.GetHost(), t.GetService(), t.GetScope(), t.GetSeverity(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getMqttReport(st, et int64) {
	client := getClient()
	s, err := client.GetMqttReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get mqtt report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get mqtt report err=%v", err)
		}
		fmt.Printf("%s mqtt count=%d types=%d\n", getReportTimeStr(r.GetTime()), r.GetCount(), r.GetTypes())
		list := r.GetTopList()
		if len(list) > 0 && !noList {
			fmt.Println("Top MQTT publish info type list")
			fmt.Println("No.\tClinet ID\tTopic\tCount")
			for i, t := range list {
				fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetClientId(), t.GetTopic(), t.GetCount())
			}
			fmt.Println("===")
		}
	}
}

func getLastMqttReport() {
	client := getClient()
	r, err := client.GetLastMqttReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last mqtt report err=%v", err)
	}
	fmt.Printf("%s mqtt count=%d types=%d\n", getReportTimeStr(r.GetTime()), r.GetCount(), r.GetTypes())
	list := r.GetTopList()
	if len(list) > 0 && !noList {
		fmt.Println("Top MQTT client topic list")
		fmt.Println("No.\tClinet ID\tTopic\tCount")
		for i, t := range list {
			fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetClientId(), t.GetTopic(), t.GetCount())
		}
		fmt.Println("===")
	}
}

func getAnomalyReport(t string, st, et int64) {
	client := getClient()
	s, err := client.GetAnomalyReport(context.Background(), &api.AnomalyReportRequest{Type: t, Start: st, End: et})
	if err != nil {
		log.Fatalf("get anomaly report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get anomary report err=%v", err)
		}
		fmt.Printf("%s anomaly type=%s score=%.2f\n",
			getReportTimeStr(r.GetTime()), t, r.GetScore())
	}
}

func getLastAnomalyReport() {
	client := getClient()
	r, err := client.GetLastAnomalyReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last anomaly report err=%v", err)
	}
	fmt.Printf("%s anomaly report\n", getReportTimeStr(r.GetTime()))
	for _, s := range r.GetScoreList() {
		fmt.Printf("%s type=%s score=%.2f\n",
			getReportTimeStr(s.Time), s.Type, s.Score)
	}
}

func getMonitorReport(st, et int64) {
	client := getClient()
	s, err := client.GetMonitorReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get monitor report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get monitor report err=%v", err)
		}
		fmt.Printf("%s monitor cpu=%.2f%% mem=%.2f%% load=%.2f disk=%.2f%% net=%.2fBPS dbspeed=%.2fBPS dbsize=%d\n",
			getReportTimeStr(r.GetTime()), r.GetCpu(), r.GetMemory(), r.GetLoad(), r.GetDisk(), r.GetNet(), r.GetDbSpeed(), r.GetDbSize())
	}
}

func getLastMonitorReport() {
	client := getClient()
	r, err := client.GetLastMonitorReport(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get last monitor report err=%v", err)
	}
	fmt.Printf("%s monitor cpu=%.2f%% mem=%.2f%% load=%.2f disk=%.2f%% net=%.2fBPS dbspeed=%.2fBPS dbsize=%d\n",
		getReportTimeStr(r.GetTime()), r.GetCpu(), r.GetMemory(), r.GetLoad(), r.GetDisk(), r.GetNet(), r.GetDbSpeed(), r.GetDbSize())
}
