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
	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/client"
)

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch notify",
	Long:  `Watch notify via api`,
	Run: func(cmd *cobra.Command, args []string) {
		client.SetClient(apiServer, apiCACert, apiClientCert, apiClientKey, apiServerPort)
		client.WatchNotify()
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
}
