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
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

// clearCmd represents the stop command
var clearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear DB of twlogeye",
	Long:  `Clear DB of twlogeye via api`,
	Run: func(cmd *cobra.Command, args []string) {
		switch len(args) {
		case 0:
			log.Fatalln("clear type [subtype]")
		case 1:
			if args[0] != "notify" {
				log.Fatalln("clear type [subtype]")
			}
			clear(args[0], "")
		default:
			clear(args[0], args[1])
		}
	},
}

func init() {
	rootCmd.AddCommand(clearCmd)
}

func clear(t, st string) {
	client := getClient()
	ret, err := client.ClearDB(context.Background(), &api.ClearRequest{Type: t, Subtype: st})
	if err != nil {
		log.Fatalf("clear err=%v", err)
	}
	fmt.Printf("clear ret=%s\n", ret.String())
}
