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
	"github.com/twsnmp/twlogeye/api"
)

// reloadCmd represents the reload command
var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "reload rules",
	Long:  `reload rules`,
	Run: func(cmd *cobra.Command, args []string) {
		api.SetClient(apiServer, apiCACert, apiClientCert, apiClientKey, apiServerPort)
		api.Reload()
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}
