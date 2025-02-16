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

var logtype string
var search string

// logCmd represents the log command
var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Search log",
	Long:  `Search log via api`,
	Run: func(cmd *cobra.Command, args []string) {
		st := getTime(startTime, 0)
		et := getTime(endTime, time.Now().UnixNano())
		client.SetClient(apiServer, apiCACert, apiClientCert, apiClientKey, apiServerPort)
		client.SearchLog(st, et, logtype, search)
	},
}

func init() {
	rootCmd.AddCommand(logCmd)
	logCmd.Flags().StringVar(&logtype, "logtype", "syslog", "log type ")
	logCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	logCmd.Flags().StringVar(&endTime, "end", "", "end date and time")
	logCmd.Flags().StringVar(&search, "search", "", "search text")
}
