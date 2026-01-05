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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/twsnmp/twlogeye/datastore"
)

var cfgFile string
var apiServer string
var apiServerPort int
var apiServerCert string
var apiClientCert string
var apiCACert string
var apiServerKey string
var apiClientKey string

var rootCmd = &cobra.Command{
	Use:   "twlogeye",
	Short: "AI-Native log server to monitor threats in logs",
	Long: `AI-Native log server to monitor threats in logs with sigma rules
Supported logs are
- syslog
- SNMP trap
- NetFlow/IPFIX
- Windows event log
- OpenTelemetry
- MQTT
You can find sigma rule here.
https://github.com/SigmaHQ/sigma

Support MCP server and webhook notify for AI
	`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./twlogeye.yaml)")
	rootCmd.PersistentFlags().IntVarP(&apiServerPort, "apiPort", "p", 8081, "API Server port")
	rootCmd.PersistentFlags().StringVar(&apiServer, "apiServer", "localhost", "server IP or host name")
	rootCmd.PersistentFlags().StringVar(&apiServerCert, "serverCert", "", "API server cert")
	rootCmd.PersistentFlags().StringVar(&apiClientCert, "clientCert", "", "API client cert")
	rootCmd.PersistentFlags().StringVar(&apiServerKey, "serverKey", "", "API server private key")
	rootCmd.PersistentFlags().StringVar(&apiClientKey, "clientKey", "", "API client private key")
	rootCmd.PersistentFlags().StringVar(&apiCACert, "caCert", "", "API CA cert")

	viper.BindPFlag("apiport", rootCmd.PersistentFlags().Lookup("apiPort"))
	viper.BindPFlag("apiserver", rootCmd.PersistentFlags().Lookup("apiServer"))
	viper.BindPFlag("servercert", rootCmd.PersistentFlags().Lookup("serverCert"))
	viper.BindPFlag("clientcert", rootCmd.PersistentFlags().Lookup("clientCert"))
	viper.BindPFlag("serverkey", rootCmd.PersistentFlags().Lookup("serverKey"))
	viper.BindPFlag("clientkey", rootCmd.PersistentFlags().Lookup("clientKey"))
	viper.BindPFlag("cacert", rootCmd.PersistentFlags().Lookup("caCert"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/")
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("twlogeye")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("twlogeye")
	viper.BindEnv("apiport")
	viper.BindEnv("apiserver")
	viper.BindEnv("servercert")
	viper.BindEnv("serverkey")
	viper.BindEnv("clientcert")
	viper.BindEnv("clientkey")
	viper.BindEnv("cacert")
	viper.BindEnv("mcpToken")

	if err := viper.ReadInConfig(); err == nil {
		if err := viper.Unmarshal(&datastore.Config); err != nil {
			log.Fatalln(err)
		}
	}
	if v := viper.GetInt("apiport"); v != 0 {
		apiServerPort = v
	}
	if v := viper.GetString("apiserver"); v != "" {
		apiServer = v
	}
	if v := viper.GetString("servercert"); v != "" {
		apiServerCert = v
	}
	if v := viper.GetString("serverkey"); v != "" {
		apiServerKey = v
	}
	if v := viper.GetString("clientcert"); v != "" {
		apiClientCert = v
	}
	if v := viper.GetString("clientkey"); v != "" {
		apiClientKey = v
	}
	if v := viper.GetString("cacert"); v != "" {
		apiCACert = v
	}
	if v := viper.GetString("mcpToken"); v != "" {
		datastore.Config.MCPToken = v
	}
}
