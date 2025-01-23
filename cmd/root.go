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
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/twsnmp/twlogeye/datastore"
)

var cfgFile string
var apiURL string

var rootCmd = &cobra.Command{
	Use:   "twlogeye",
	Short: "Eye-like log server to monitor threats in logs",
	Long: `Eye-like log server to monitor threats in logs
Supported logs are
- syslog
- NetFlow/IPFIX/sFlow
- Windows Event log
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
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8081", "gRPC URL")

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

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		if err := viper.Unmarshal(&datastore.Config); err != nil {
			log.Fatalln(err)
		}
	}
}
