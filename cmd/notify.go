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

	"github.com/araddon/dateparse"
	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

var level string
var startTime string
var endTime string

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Search notify",
	Long:  `Search notify via api`,
	Run: func(cmd *cobra.Command, args []string) {
		st := getTime(startTime, 0)
		et := getTime(endTime, time.Now().UnixNano())
		api.SetClient(apiServer, apiCACert, apiClientCert, apiClientKey, apiServerPort)
		api.SearchNotify(st, et, level)
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.Flags().StringVar(&level, "level", "", "notify level")
	notifyCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	notifyCmd.Flags().StringVar(&endTime, "end", "", "notify level")
}

func getTime(s string, dt int64) int64 {
	if t, err := dateparse.ParseLocal(s); err == nil {
		return t.UnixNano()
	}
	return dt
}
