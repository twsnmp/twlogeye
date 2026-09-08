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
)

var (
	serviceName        string
	serviceDisplayName string
	serviceDescription string
	serviceConfigFile  string
	serviceAutoStart   bool
)

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage twlogeye as a Windows service",
	Long:  `Manage twlogeye as a Windows service (install, remove, start, stop, status).`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install twlogeye as a Windows service",
	Run: func(cmd *cobra.Command, args []string) {
		runServiceInstall()
	},
}

var serviceRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"uninstall"},
	Short:   "Remove twlogeye Windows service",
	Run: func(cmd *cobra.Command, args []string) {
		runServiceRemove()
	},
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start twlogeye Windows service",
	Run: func(cmd *cobra.Command, args []string) {
		runServiceStart()
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop twlogeye Windows service",
	Run: func(cmd *cobra.Command, args []string) {
		runServiceStop()
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of twlogeye Windows service",
	Run: func(cmd *cobra.Command, args []string) {
		runServiceStatus()
	},
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceRemoveCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceStatusCmd)

	serviceCmd.PersistentFlags().StringVar(&serviceName, "name", "twlogeye", "Service name")

	serviceInstallCmd.Flags().StringVar(&serviceDisplayName, "displayName", "TWLogEye Threat Monitoring Service", "Service display name")
	serviceInstallCmd.Flags().StringVar(&serviceDescription, "description", "AI-Native log server to monitor threats in logs with sigma rules", "Service description")
	serviceInstallCmd.Flags().StringVar(&serviceConfigFile, "config", "", "Config file path for service (e.g. C:\\twlogeye\\twlogeye.yaml)")
	serviceInstallCmd.Flags().BoolVar(&serviceAutoStart, "autoStart", true, "Automatically start service on boot")
}
