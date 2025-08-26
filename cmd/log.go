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

var logtype string
var search string

// logCmd represents the log command
var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Search log",
	Long:  `Search log via api`,
	Run: func(cmd *cobra.Command, args []string) {
		searchLog()
	},
}

func init() {
	rootCmd.AddCommand(logCmd)
	logCmd.Flags().StringVar(&logtype, "logtype", "syslog", "log type ")
	logCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	logCmd.Flags().StringVar(&endTime, "end", "", "end date and time")
	logCmd.Flags().StringVar(&search, "search", "", "search text")
}

func searchLog() {
	st := getTime(startTime, 0)
	et := getTime(endTime, time.Now().UnixNano())
	client := getClient()
	s, err := client.SearchLog(context.Background(), &api.LogRequest{
		Logtype: logtype,
		Start:   st,
		End:     et,
		Search:  search,
	})
	if err != nil {
		log.Fatalf("search log err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("search log err=%v", err)
		}
		fmt.Printf("%s %s %s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLog())
	}
}
