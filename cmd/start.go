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
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start twLogEye",
	Long:  `start twLogEye`,
	Run: func(cmd *cobra.Command, args []string) {
		start()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVarP(&datastore.Config.LogPath, "logPath", "l", "", "Log DB Path default: memory")
	startCmd.Flags().IntVar(&datastore.Config.SyslogUDPPort, "syslogUDPPort", 0, "syslog UDP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SyslogUDPPort, "syslogTCPPort", 0, "syslog TCP port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.NetFlowPort, "netflowPort", 0, "netflow port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SFlowPort, "slowPort", 0, "sFlow port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.SNMPTrapPort, "trapPort", 0, "SNMP TRAP recive port 0=disable")
	startCmd.Flags().IntVar(&datastore.Config.LogRetention, "logRetention", 48, "log retention(hours)")
	startCmd.Flags().IntVar(&datastore.Config.NotifyRetention, "notifyRetention", 30, "notify retention(days)")
	var syslogDst string
	startCmd.Flags().StringVar(&syslogDst, "syslogDst", "", "syslog dst")
	datastore.Config.SyslogDst = strings.Split(syslogDst, ",")
	var trapDst string
	startCmd.Flags().StringVar(&syslogDst, "trapDst", "", "SNMP TRAP dst")
	datastore.Config.TrapDst = strings.Split(trapDst, ",")
	startCmd.Flags().StringVar(&datastore.Config.TrapCommunity, "trapCommunity", "", "SNMP TRAP Community")

	startCmd.Flags().StringVar(&datastore.Config.SigmaConfig, "sigmaConfig", "", "SIGMA Config file")
	startCmd.Flags().StringVar(&datastore.Config.SigmaRules, "sigmaRules", "", "SIGMA rule path")
	startCmd.Flags().StringVar(&datastore.Config.GrokDef, "grokDef", "", "GROK define file")
	startCmd.Flags().StringVar(&datastore.Config.GrokPat, "grokPat", "", "GROK pattern")

	startCmd.Flags().StringVarP(&datastore.Config.WinEventLogType, "winEventLogType", "w", "", "Windows eventlog type")
	startCmd.Flags().IntVarP(&datastore.Config.WinEventLogCheckInterval, "winEventLogCheckInterval", "i", 30, "Windows evnetlog check interval")
}

func start() {
	log.Printf("start confg=%+v", datastore.Config)
	var wg sync.WaitGroup
	datastore.OpenLogDB()
	auditor.Init()
	notify.Init()
	ctx, cancel := context.WithCancel(context.Background())
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
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGTSTP)
	<-sigterm
	cancel()
	wg.Wait()
}
