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

// reloadCmd represents the reload command
var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload rules",
	Long:  `Reload rules via api`,
	Run: func(cmd *cobra.Command, args []string) {
		reload()
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}

func reload() {
	client := getClient()
	ret, err := client.Reload(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("reload rules err=%v", err)
	}
	fmt.Printf("reload rules ret=%+v", ret)
}
