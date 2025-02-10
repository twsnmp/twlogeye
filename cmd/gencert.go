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
	"log"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/datastore"
)

var cn string

// gencertCmd represents the gencert command
var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate TLS private key and cert",
	Long:  `Generate TLS private key and cert for gRPC server/client`,
	Run: func(cmd *cobra.Command, args []string) {
		hit := false
		if apiServerCert != "" && apiServerKey != "" {
			datastore.GenServerCert(apiServerCert, apiServerKey, cn)
			hit = true
		}
		if apiClientCert != "" && apiClientKey != "" {
			datastore.GenClientCert(apiClientCert, apiClientKey, cn)
			hit = true
		}
		if !hit {
			log.Fatalln("please set server or client cert")
		}
	},
}

func init() {
	rootCmd.AddCommand(gencertCmd)
	gencertCmd.Flags().StringVar(&cn, "cn", "twsnmp", "CN for client cert")
}
