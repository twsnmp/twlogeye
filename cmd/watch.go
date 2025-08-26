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

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch notify",
	Long:  `Watch notify via api`,
	Run: func(cmd *cobra.Command, args []string) {
		watchNotify()
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
}

func watchNotify() {
	client := getClient()
	s, err := client.WatchNotify(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("watch notify err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("watch notify err=%v", err)
		}
		fmt.Printf("---\n%s %s %s %s\n%s\n%s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLevel(), r.GetId(), r.GetTags(), r.GetTitle())
	}
}
