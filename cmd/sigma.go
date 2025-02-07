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
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

// sigmaCmd represents the sigma command
var sigmaCmd = &cobra.Command{
	Use:   "sigma",
	Short: "Check sigma rules (list/stat/logsrc/field)",
	Long:  `Check sigma rules (list/stat/logsrc/field)`,
	Run: func(cmd *cobra.Command, args []string) {
		switch {
		case len(args) > 0 && args[0] == "stat":
			sigmaStat()
		case len(args) > 0 && args[0] == "logsrc":
			sigmaLogSrc()
		case len(args) > 0 && args[0] == "field":
			sigmaField()
		case len(args) > 0 && args[0] == "check":
			sigmaCheck()
		default:
			sigmaRuleList()
		}
	},
}

func init() {
	rootCmd.AddCommand(sigmaCmd)
	sigmaCmd.Flags().StringVar(&datastore.Config.SigmaRules, "sigmaRules", "", "SIGMA rule path")

}

func sigmaStat() {
	list := auditor.GetSigmaRuleEvaluators()
	logSrcMap := make(map[string]int)
	fieldMap := make(map[string]int)
	for _, e := range list {
		lsk := fmt.Sprintf("%s:%s:%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
		if _, ok := logSrcMap[lsk]; !ok {
			logSrcMap[lsk] = 0
		}
		logSrcMap[lsk]++
		for _, dsv := range e.Rule.Detection.Searches {
			for _, ems := range dsv.EventMatchers {
				for _, em := range ems {
					fk := lsk + ":" + em.Field
					if _, ok := fieldMap[fk]; !ok {
						fieldMap[fk] = 0
					}
					fieldMap[fk]++
				}
			}
		}
	}
	fmt.Printf("rules=%d logsrc=%d field=%d\n", len(list), len(logSrcMap), len(fieldMap))
}

func sigmaLogSrc() {
	list := auditor.GetSigmaRuleEvaluators()
	logSrcMap := make(map[string]int)
	for _, e := range list {
		lsk := fmt.Sprintf("%s_%s_%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
		if _, ok := logSrcMap[lsk]; !ok {
			logSrcMap[lsk] = 0
		}
		logSrcMap[lsk]++
	}
	for k, c := range logSrcMap {
		fmt.Printf("%s=%d\n", k, c)
	}
}

func sigmaField() {
	list := auditor.GetSigmaRuleEvaluators()
	fieldMap := make(map[string]int)
	for _, e := range list {
		lsk := fmt.Sprintf("%s_%s_%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
		for _, dsv := range e.Rule.Detection.Searches {
			for _, ems := range dsv.EventMatchers {
				for _, em := range ems {
					fk := lsk + ":" + em.Field
					if _, ok := fieldMap[fk]; !ok {
						fieldMap[fk] = 0
					}
					fieldMap[fk]++
				}
			}
		}
	}
	for k, c := range fieldMap {
		fmt.Printf("%s=%d\n", k, c)
	}
}

func sigmaRuleList() {
	list := auditor.GetSigmaRuleEvaluators()
	for _, e := range list {
		lsk := fmt.Sprintf("%s:%s:%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
		fmt.Printf("%s\t%s\t%s\t%s\n", e.ID, e.Level, lsk, e.Title)
	}
}

var regCheck1 = regexp.MustCompile(`condition:.+\s+of\s+\*?[a-zA-Z_0-9]+\*`)
var regCheck2 = regexp.MustCompile(`[0-9]+`)

func sigmaCheck() {
	total := 0
	skip := 0
	datastore.ForEachSigmaRules(func(c []byte, path string) {
		total++
		m := regCheck1.FindStringSubmatch(string(c))
		if len(m) > 0 {
			hit := false
			for _, s := range strings.Fields(m[0]) {
				if !strings.Contains(s, "*") {
					continue
				}
				if regCheck2.MatchString(s) {
					fmt.Printf("%s : %v\n", path, m)
					hit = true
				}
			}
			if hit {
				skip++
			}
		}

	})
	fmt.Printf("total=%d skip=%d\n", total, skip)
}
