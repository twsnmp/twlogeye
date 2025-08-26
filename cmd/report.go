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
	"time"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/client"
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
		client.SetClient(apiServer, apiCACert, apiClientCert, apiClientKey, apiServerPort)
		switch reportType {
		case "trap":
			client.GetTrapReport(st, et)
		case "netflow":
			client.GetNetflowReport(st, et)
		case "winevent":
			client.GetWindowsEventReport(st, et)
		default:
			client.GetSyslogReport(st, et)
		}
	},
}

func init() {
	rootCmd.AddCommand(logCmd)
	reportCmd.Flags().StringVar(&reportType, "reportType", "syslog", "report type ")
	reportCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	reportCmd.Flags().StringVar(&endTime, "end", "", "end date and time")
}
