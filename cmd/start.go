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
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/logger"
	"github.com/twsnmp/twlogeye/notify"
	"github.com/twsnmp/twlogeye/reporter"
	"github.com/twsnmp/twlogeye/server"
)

var syslogDst string
var trapDst string
var webhookDst string
var grokPat string

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start twlogeye",
	Long:  `Start twlogeye`,
	Run: func(cmd *cobra.Command, args []string) {
		if syslogDst != "" {
			datastore.Config.SyslogDst = strings.Split(syslogDst, ",")
		}
		if trapDst != "" {
			datastore.Config.TrapDst = strings.Split(trapDst, ",")
		}
		if webhookDst != "" {
			datastore.Config.WebhookDst = strings.Split(webhookDst, ",")
		}
		if grokPat != "" {
			datastore.Config.GrokPat = strings.Split(grokPat, ",")
		}
		start()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVarP(&datastore.Config.LogPath, "logPath", "l", "", "Log DB Path default: memory old option")
	startCmd.Flags().StringVarP(&datastore.Config.DBPath, "dbPath", "d", "", "DB Path default: memory")
	startCmd.Flags().IntVar(&datastore.Config.SyslogUDPPort, "syslogUDPPort", 0, "syslog UDP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SyslogUDPPort, "syslogTCPPort", 0, "syslog TCP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.NetFlowPort, "netflowPort", 0, "netflow port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SNMPTrapPort, "trapPort", 0, "SNMP TRAP recive port 0=disable")
	startCmd.Flags().StringVar(&datastore.Config.MIBPath, "mibPath", "", "SNMP Ext MIB Path")
	startCmd.Flags().IntVar(&datastore.Config.LogRetention, "logRetention", 48, "log retention(hours)")
	startCmd.Flags().IntVar(&datastore.Config.NotifyRetention, "notifyRetention", 7, "notify retention(days)")
	startCmd.Flags().IntVar(&datastore.Config.ReportRetention, "reportRetention", 7, "report retention(days)")
	startCmd.Flags().IntVar(&datastore.Config.ReportTopN, "reportTopN", 10, "report top n")
	startCmd.Flags().Float64Var(&datastore.Config.AnomalyReportThreshold, "anomalyReportThreshold", 0.0, "anomaly report threshold")
	startCmd.Flags().StringVar(&datastore.Config.ReportInterval, "reportInterval", "hour", "report interval (day,hour,minute)")
	startCmd.Flags().StringVar(&syslogDst, "syslogDst", "", "syslog dst")
	startCmd.Flags().StringVar(&syslogDst, "trapDst", "", "SNMP TRAP dst")
	startCmd.Flags().StringVar(&webhookDst, "webhhokDst", "", "Webhook dst URL")
	startCmd.Flags().StringVar(&datastore.Config.TrapCommunity, "trapCommunity", "", "SNMP TRAP Community")
	startCmd.Flags().StringVar(&datastore.Config.SigmaRules, "sigmaRules", "", "SIGMA rule path")
	startCmd.Flags().StringVar(&datastore.Config.SigmaConfigs, "sigmaConfigs", "", "SIGMA config path")
	startCmd.Flags().StringVar(&datastore.Config.NamedCaptures, "namedCaptures", "", "Named capture defs path")
	startCmd.Flags().StringVar(&datastore.Config.GrokDef, "grokDef", "", "GROK define file")
	startCmd.Flags().StringVar(&grokPat, "grokPat", "", "GROK patterns")
	startCmd.Flags().StringVar(&datastore.Config.WinEventLogChannel, "winEventLogChannel", "", "Windows eventlog channel")
	startCmd.Flags().IntVarP(&datastore.Config.WinEventLogCheckInterval, "winEventLogCheckInterval", "i", 0, "Windows evnetlog check interval")
	startCmd.Flags().IntVarP(&datastore.Config.WinEventLogCheckStart, "winEventLogCheckStart", "s", 0, "Windows evnetlog check start time (hours)")
	startCmd.Flags().StringVar(&datastore.Config.WinUser, "winUser", "", "Windows eventlog user")
	startCmd.Flags().StringVar(&datastore.Config.WinPassword, "winPassword", "", "Windows eventlog password")
	startCmd.Flags().StringVar(&datastore.Config.WinAuth, "winAuth", "", "Windows eventlog auth")
	startCmd.Flags().BoolVar(&datastore.Config.KeyValParse, "keyValParse", false, "Splunk Key value parse")
	startCmd.Flags().BoolVar(&datastore.Config.SigmaSkipError, "sigmaSkipError", false, "Skip sigma rule error")
	startCmd.Flags().BoolVar(&datastore.Config.Debug, "debug", false, "debug mode")
	startCmd.Flags().BoolVar(&datastore.Config.WinLogSJIS, "sjis", false, "Windows eventlog SHIT-JIS mode")
}

func start() {
	log.Printf("start confg=%+v", datastore.Config)
	var wg sync.WaitGroup
	datastore.OpenDB()
	auditor.Init()
	notify.Init()
	reporter.Init()
	ctx, cancel := context.WithCancel(context.Background())
	reporter.Start(ctx, &wg)
	wg.Add(1)
	go auditor.Start(ctx, &wg)
	wg.Add(1)
	go notify.Start(ctx, &wg)
	wg.Add(1)
	go logger.StartSyslogd(ctx, &wg)
	wg.Add(1)
	go logger.StartSnmpTrapd(ctx, &wg)
	wg.Add(1)
	go logger.StartNetFlowd(ctx, &wg)
	wg.Add(1)
	go logger.StartWinEventLogd(ctx, &wg)
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	wg.Add(1)
	go server.StartAPIServer(ctx, &wg, apiServerPort, apiServerCert, apiServerKey, apiCACert, sigterm)
	<-sigterm
	cancel()
	wg.Wait()
	datastore.CloseDB()
}
