/*
Copyright © 2024 Masayuki Yamai <twsnmp@gmail.com>

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
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/common-nighthawk/go-figure"
	"github.com/spf13/cobra"
)

var Version string
var Commit string
var Date string
var versionColor string

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show twlogeye version",
	Long:  `Show twlogeye version`,
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVar(&versionColor, "color", "", "Version color")
}

func printVersion() {
	colors := []string{"39", "49", "214", "196", "15", "192"}
	if versionColor == "" {
		versionColor = colors[int(time.Now().Unix())%len(colors)]
	}
	f := figure.NewFigure("TwLogEye", "roman", true)
	fs := f.String()
	logoBlock := lipgloss.NewStyle().
		MarginTop(1).
		MarginLeft(5).
		Padding(0, 1).
		Background(lipgloss.Color("0")).
		Foreground(lipgloss.Color(versionColor)).
		Render(strings.TrimSpace(fs))

	catBlock := lipgloss.NewStyle().
		Padding(0, 1).
		MarginBottom(1).
		Background(lipgloss.Color("0")).
		Foreground(lipgloss.Color(versionColor)).
		Render(cat + fmt.Sprintf("twlogeye v%s(%s) %s\n", Version, Commit, Date))

	fmt.Println(lipgloss.JoinVertical(lipgloss.Center, logoBlock, catBlock))
}

var cat = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@*++=##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@=   .......+%%@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@.  .... .**+*@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@:.. :-  ...:++.@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@:..-@#=:.... :*%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@+:*%%**=...:*####-..::+#%@@@@@@@@@@@@@
@@@@@@@@@@@@@@@%##%%%#%%%#####=.  ....-@@@@@@@@@@@
@@@@@@@@@@@@@@#*##%##%%#####%#*.   .... +@@@@@@@@@
@@@@@@@@@@@@@@@@@%%%%%%%%%%###*.    ...  =@@@@@@@@
@@@@@@@@@@@@@@@@@@@%%%%%%%%###-.   .:-:   +@@@@@@@
@@@@@@@@@@@@@@@@@@@@%%%%%####+.  .:=*-..  .@@@@@@@
@@@@@@@@@@@@@@@@@@%%%%%%##%###-:-*##=..    @@@@@@@
@@@@@@@@@@@@@@@@%%%%%%%%%%##%%%%%%*=..     @@@@@@@
@@@@@@@@@@@@@@@@%%%%%%%%%##%%%%%%*-..     -@@@@@@@
@@@@@@@@@@@@@@@@@%%%%%%%#%%%%%%#-.        *@@@@@@@
@@@@@@@@@@@@@@@@@@%%%%%%%%%%%+:.         .@@@@@@@@
@@@@@@@@@@@@@@@@@@@%%%%%%%#*+=:.......   %@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@%%@@%%%%%##=.....  -@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@%@@@%%%%%%%####+. .#@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%%@@@%%%%%%%%%%###*#@@@@@@@@@@
@@@@@@@@@@@@@@@@@%%@%%%@@@%%%%%%######*@@@@@@@@@@@
@@@@@@@@@@@@@@@@%@@%%#%@%%%%###%%%##*%#%@@@@@@@@@@
@@@@@@@@@@@@@@@@@@%%%@@%%%#**######**@@@@@@@@@@@@@
`
