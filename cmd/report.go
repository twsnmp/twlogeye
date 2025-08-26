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

var reportType string

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Get report",
	Long:  `Get report via api`,
	Run: func(cmd *cobra.Command, args []string) {
		st := getTime(startTime, 0)
		et := getTime(endTime, time.Now().UnixNano())
		switch reportType {
		case "trap":
			getTrapReport(st, et)
		case "netflow":
			getNetflowReport(st, et)
		case "winevent":
			getWindowsEventReport(st, et)
		default:
			getSyslogReport(st, et)
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&reportType, "reportType", "syslog", "report type ")
	reportCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	reportCmd.Flags().StringVar(&endTime, "end", "", "end date and time")
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
		fmt.Printf("%s normal=%d warn=%d error=%d\n", getTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError())
		fmt.Println("===")
		fmt.Println("Top log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top error log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
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
		fmt.Printf("%s count=%d\n", getTimeStr(r.GetTime()), r.GetCount())
		fmt.Println("===")
		fmt.Println("Top TRAP type list")
		fmt.Println("No.\tSender\tTrap Type\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetSender(), t.GetTrapType(), t.GetCount())
		}
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
		fmt.Printf("%s packets=%d bytes=%d\n", getTimeStr(r.GetTime()), r.GetPackets(), r.GetBytes())
		fmt.Println("===")
		fmt.Println("Top MAC node packets list")
		fmt.Println("No.\tMAC\tPackets")
		for i, t := range r.GetTopMacPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top MAC node bytes list")
		fmt.Println("No.\tMAC\tBytes")
		for i, t := range r.GetTopMacBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top IP node packets list")
		fmt.Println("No.\tIP\tPackets")
		for i, t := range r.GetTopIpPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top IP node bytes list")
		fmt.Println("No.\tIP\tBytes")
		for i, t := range r.GetTopIpBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top flow packets list")
		fmt.Println("No.\tFlow\tPackets")
		for i, t := range r.GetTopFlowPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top flow bytes list")
		fmt.Println("No.\tFlow\tBytes")
		for i, t := range r.GetTopFlowBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top protocol list")
		fmt.Println("No.\tProcottol\tCount")
		for i, t := range r.GetTopProtocolList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top TCP flag list")
		fmt.Println("No.\tTCP Flag\tCount")
		for i, t := range r.GetTopTcpFlagList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetCount())
		}
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
		fmt.Printf("%s normal=%d warn=%d error=%d\n", getTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError())
		fmt.Println("===")
		fmt.Println("Top log pattern list")
		fmt.Println("No.\tComputer\tProvider\tEventID\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top error log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
	}
}
