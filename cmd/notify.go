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

var level string
var startTime string
var endTime string

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Search notify",
	Long:  `Search notify via api`,
	Run: func(cmd *cobra.Command, args []string) {
		searchNotify()
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.Flags().StringVar(&level, "level", "", "notify level")
	notifyCmd.Flags().StringVar(&startTime, "start", "", "start date and time")
	notifyCmd.Flags().StringVar(&endTime, "end", "", "notify level")
}

func searchNotify() {
	st := getTime(startTime, 0)
	et := getTime(endTime, time.Now().UnixNano())
	client := getClient()
	s, err := client.SearchNotify(context.Background(), &api.NofifyRequest{
		Start: st,
		End:   et,
		Level: level,
	})
	if err != nil {
		log.Fatalf("search notify err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("search notify err=%v", err)
		}
		fmt.Printf("---\n%s %s %s %s\n%s\n%s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLevel(), r.GetId(), r.GetTags(), r.GetTitle())
	}
}
