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
	"github.com/spf13/viper"
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
	startCmd.Flags().StringVarP(&datastore.Config.DBPath, "dbPath", "d", "", "DB Path default: memory")
	startCmd.Flags().IntVar(&datastore.Config.SyslogUDPPort, "syslogUDPPort", 0, "syslog UDP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SyslogTCPPort, "syslogTCPPort", 0, "syslog TCP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.NetFlowPort, "netflowPort", 0, "netflow port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SNMPTrapPort, "trapPort", 0, "SNMP TRAP receive port 0=disable")
	startCmd.Flags().StringVar(&datastore.Config.MIBPath, "mibPath", "", "SNMP Ext MIB Path")
	startCmd.Flags().IntVar(&datastore.Config.LogRetention, "logRetention", 48, "log retention(hours)")
	startCmd.Flags().IntVar(&datastore.Config.NotifyRetention, "notifyRetention", 7, "notify retention(days)")
	startCmd.Flags().IntVar(&datastore.Config.ReportRetention, "reportRetention", 7, "report retention(days)")
	startCmd.Flags().IntVar(&datastore.Config.ReportTopN, "reportTopN", 10, "report top n")
	startCmd.Flags().IntVar(&datastore.Config.AnomalyNotifyDelay, "anomalyNotifyDelay", 24, "Grace period for sending notifications when detecting anomalies")
	startCmd.Flags().Float64Var(&datastore.Config.AnomalyReportThreshold, "anomalyReportThreshold", 0.0, "anomaly report threshold")
	startCmd.Flags().IntVar(&datastore.Config.ReportInterval, "reportInterval", 5, "report interval (minute)")
	startCmd.Flags().StringVar(&syslogDst, "syslogDst", "", "syslog dst")
	startCmd.Flags().StringVar(&trapDst, "trapDst", "", "SNMP TRAP dst")
	startCmd.Flags().StringVar(&webhookDst, "webhookDst", "", "Webhook dst URL")
	startCmd.Flags().StringVar(&datastore.Config.MCPEndpoint, "mcpEndpoint", "", "MCP server endpoint")
	startCmd.Flags().StringVar(&datastore.Config.MCPFrom, "mcpFrom", "", "MCP server from ip address list")
	startCmd.Flags().StringVar(&datastore.Config.MCPToken, "mcpToken", "", "MCP server token")
	startCmd.Flags().StringVar(&datastore.Config.TrapCommunity, "trapCommunity", "", "SNMP TRAP Community")
	startCmd.Flags().StringVar(&datastore.Config.SigmaRules, "sigmaRules", "", "SIGMA rule path")
	startCmd.Flags().StringVar(&datastore.Config.SigmaConfigs, "sigmaConfigs", "", "SIGMA config path")
	startCmd.Flags().StringVar(&datastore.Config.NamedCaptures, "namedCaptures", "", "Named capture defs path")
	startCmd.Flags().StringVar(&datastore.Config.GrokDef, "grokDef", "", "GROK define file")
	startCmd.Flags().StringVar(&grokPat, "grokPat", "", "GROK patterns")
	startCmd.Flags().StringVar(&datastore.Config.WinEventLogChannel, "winEventLogChannel", "", "Windows eventlog channel")
	startCmd.Flags().IntVarP(&datastore.Config.WinEventLogCheckInterval, "winEventLogCheckInterval", "i", 0, "Windows eventlog check interval")
	startCmd.Flags().IntVarP(&datastore.Config.WinEventLogCheckStart, "winEventLogCheckStart", "s", 0, "Windows eventlog check start time (hours)")
	startCmd.Flags().StringVar(&datastore.Config.WinUser, "winUser", "", "Windows eventlog user")
	startCmd.Flags().StringVar(&datastore.Config.WinPassword, "winPassword", "", "Windows eventlog password")
	startCmd.Flags().StringVar(&datastore.Config.WinAuth, "winAuth", "", "Windows eventlog auth")
	startCmd.Flags().BoolVar(&datastore.Config.KeyValParse, "keyValParse", false, "Splunk Key value parse")
	startCmd.Flags().BoolVar(&datastore.Config.SigmaSkipError, "sigmaSkipError", false, "Skip sigma rule error")
	startCmd.Flags().BoolVar(&datastore.Config.Debug, "debug", false, "debug mode")
	startCmd.Flags().BoolVar(&datastore.Config.WinLogSJIS, "sjis", false, "Windows eventlog SHIFT-JIS mode")
	startCmd.Flags().BoolVar(&datastore.Config.AnomalyUseTimeData, "anomalyUseTime", false, "Include weekends and hours in the vector data for anomaly detection")
	startCmd.Flags().IntVar(&datastore.Config.OTelHTTPPort, "otelHTTPPort", 0, "OpenTelemetry HTTP Port")
	startCmd.Flags().IntVar(&datastore.Config.OTelgRPCPort, "otelgRPCPort", 0, "OpenTelemetry gRPC Port")
	startCmd.Flags().StringVar(&datastore.Config.OTelFrom, "otelFrom", "", "OpenTelemetry client IPs")
	startCmd.Flags().StringVar(&datastore.Config.OTelCert, "otelCert", "", "OpenTelemetry server certificate")
	startCmd.Flags().StringVar(&datastore.Config.OTelKey, "otelKey", "", "OpenTelemetry server private key")
	startCmd.Flags().StringVar(&datastore.Config.OTelCA, "otelCA", "", "OpenTelemetry CA certificate")
	startCmd.Flags().IntVar(&datastore.Config.OTelRetention, "otelRetention", 48, "log retention(hours)")
	startCmd.Flags().IntVar(&datastore.Config.MqttTCPPort, "mqttTCPPort", 0, "MQTT TCP Port")
	startCmd.Flags().IntVar(&datastore.Config.MqttWSPort, "mqttWSPort", 0, "MQTT Websock Port")
	startCmd.Flags().StringVar(&datastore.Config.MqttFrom, "mqttFrom", "", "MQTT client IPs")
	startCmd.Flags().StringVar(&datastore.Config.MqttUsers, "mqttUsers", "", "MQTT user and password")
	startCmd.Flags().StringVar(&datastore.Config.MqttCert, "mqttCert", "", "MQTT server certificate")
	startCmd.Flags().StringVar(&datastore.Config.MqttKey, "mqttKey", "", "MQTT server private key")
	startCmd.Flags().StringVar(&datastore.Config.GeoIPDB, "geoIPDB", "", "Geo IP Database Path")
	startCmd.Flags().BoolVar(&datastore.Config.ResolveHostName, "resolveHostName", false, "Resolve Host Name")

	viper.BindPFlag("dbPath", startCmd.Flags().Lookup("dbPath"))
	viper.BindPFlag("syslogUDPPort", startCmd.Flags().Lookup("syslogUDPPort"))
	viper.BindPFlag("syslogTCPPort", startCmd.Flags().Lookup("syslogTCPPort"))
	viper.BindPFlag("netflowPort", startCmd.Flags().Lookup("netflowPort"))
	viper.BindPFlag("snmpTrapPort", startCmd.Flags().Lookup("trapPort"))
	viper.BindPFlag("mibPath", startCmd.Flags().Lookup("mibPath"))
	viper.BindPFlag("logRetention", startCmd.Flags().Lookup("logRetention"))
	viper.BindPFlag("notifyRetention", startCmd.Flags().Lookup("notifyRetention"))
	viper.BindPFlag("reportRetention", startCmd.Flags().Lookup("reportRetention"))
	viper.BindPFlag("reportTopN", startCmd.Flags().Lookup("reportTopN"))
	viper.BindPFlag("anomalyNotifyDelay", startCmd.Flags().Lookup("anomalyNotifyDelay"))
	viper.BindPFlag("anomalyReportThreshold", startCmd.Flags().Lookup("anomalyReportThreshold"))
	viper.BindPFlag("reportInterval", startCmd.Flags().Lookup("reportInterval"))
	viper.BindPFlag("mcpEndpoint", startCmd.Flags().Lookup("mcpEndpoint"))
	viper.BindPFlag("mcpFrom", startCmd.Flags().Lookup("mcpFrom"))
	viper.BindPFlag("mcpToken", startCmd.Flags().Lookup("mcpToken"))
	viper.BindPFlag("trapCommunity", startCmd.Flags().Lookup("trapCommunity"))
	viper.BindPFlag("sigmaRules", startCmd.Flags().Lookup("sigmaRules"))
	viper.BindPFlag("sigmaConfigs", startCmd.Flags().Lookup("sigmaConfigs"))
	viper.BindPFlag("namedCaptures", startCmd.Flags().Lookup("namedCaptures"))
	viper.BindPFlag("grokDef", startCmd.Flags().Lookup("grokDef"))
	viper.BindPFlag("winEventLogChannel", startCmd.Flags().Lookup("winEventLogChannel"))
	viper.BindPFlag("winEventLogCheckInterval", startCmd.Flags().Lookup("winEventLogCheckInterval"))
	viper.BindPFlag("winEventLogCheckStart", startCmd.Flags().Lookup("winEventLogCheckStart"))
	viper.BindPFlag("winUser", startCmd.Flags().Lookup("winUser"))
	viper.BindPFlag("winPassword", startCmd.Flags().Lookup("winPassword"))
	viper.BindPFlag("winAuth", startCmd.Flags().Lookup("winAuth"))
	viper.BindPFlag("keyValParse", startCmd.Flags().Lookup("keyValParse"))
	viper.BindPFlag("sigmaSkipError", startCmd.Flags().Lookup("sigmaSkipError"))
	viper.BindPFlag("debug", startCmd.Flags().Lookup("debug"))
	viper.BindPFlag("winLogSJIS", startCmd.Flags().Lookup("sjis"))
	viper.BindPFlag("anomalyUseTimeData", startCmd.Flags().Lookup("anomalyUseTime"))
	viper.BindPFlag("otelHTTPPort", startCmd.Flags().Lookup("otelHTTPPort"))
	viper.BindPFlag("otelgRPCPort", startCmd.Flags().Lookup("otelgRPCPort"))
	viper.BindPFlag("otelFrom", startCmd.Flags().Lookup("otelFrom"))
	viper.BindPFlag("otelCert", startCmd.Flags().Lookup("otelCert"))
	viper.BindPFlag("otelKey", startCmd.Flags().Lookup("otelKey"))
	viper.BindPFlag("otelCA", startCmd.Flags().Lookup("otelCA"))
	viper.BindPFlag("otelRetention", startCmd.Flags().Lookup("otelRetention"))
	viper.BindPFlag("mqttTCPPort", startCmd.Flags().Lookup("mqttTCPPort"))
	viper.BindPFlag("mqttWSPort", startCmd.Flags().Lookup("mqttWSPort"))
	viper.BindPFlag("mqttFrom", startCmd.Flags().Lookup("mqttFrom"))
	viper.BindPFlag("mqttUsers", startCmd.Flags().Lookup("mqttUsers"))
	viper.BindPFlag("mqttCert", startCmd.Flags().Lookup("mqttCert"))
	viper.BindPFlag("mqttKey", startCmd.Flags().Lookup("mqttKey"))
	viper.BindPFlag("geoIPDB", startCmd.Flags().Lookup("geoIPDB"))
	viper.BindPFlag("resolveHostName", startCmd.Flags().Lookup("resolveHostName"))
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
	wg.Add(1)
	go logger.StartOTeld(ctx, &wg)
	wg.Add(1)
	go logger.StartMqttd(ctx, &wg)
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	wg.Add(1)
	go server.StartAPIServer(ctx, &wg, apiServerPort, apiServerCert, apiServerKey, apiCACert, sigterm)
	wg.Add(1)
	go server.StartMCPServer(ctx, &wg, apiServerCert, apiServerKey, Version)
	<-sigterm
	cancel()
	wg.Wait()
	datastore.CloseDB()
}
