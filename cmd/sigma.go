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
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
)

var (
	filterPack   string
	filterCustom bool
)

// sigmaCmd represents the sigma command
var sigmaCmd = &cobra.Command{
	Use:   "sigma",
	Short: "Check sigma rules (list|packs|stat|logsrc|field|check|test|convert-wazuh)",
	Long: `Check sigma rules (list|packs|stat|logsrc|field|check|test|convert-wazuh)
	list: list rules
	packs: list available embedded rule packs
	stat: stat rules
	logsrc: list log sources
	field: list fields
	check: check rule
	test: test rule args
	convert-wazuh: convert Wazuh rules XML to Sigma YAML
	convert-wazuh-decoder: convert Wazuh decoders XML to named-capture regex patterns
	`,
	Run: func(cmd *cobra.Command, args []string) {
		// no error  for sigma config and rule load
		datastore.Config.SigmaSkipError = true
		switch {
		case len(args) > 0 && args[0] == "packs":
			sigmaPacks()
		case len(args) > 0 && args[0] == "stat":
			sigmaStat()
		case len(args) > 0 && args[0] == "logsrc":
			sigmaLogSrc()
		case len(args) > 0 && args[0] == "field":
			sigmaField()
		case len(args) > 0 && args[0] == "check":
			sigmaCheck()
		case len(args) > 0 && args[0] == "test":
			sigmaTest(args)
		default:
			sigmaRuleList()
		}
	},
}

func init() {
	rootCmd.AddCommand(sigmaCmd)
	sigmaCmd.Flags().StringVar(&datastore.Config.SigmaRules, "sigmaRules", "", "SIGMA rule path")
	sigmaCmd.Flags().StringSliceVar(&datastore.Config.SigmaPacks, "sigmaPacks", nil, "SIGMA rule packs (e.g. windows-essential,linux-auth)")
	sigmaCmd.Flags().StringVar(&filterPack, "pack", "", "Filter rules by pack name")
	sigmaCmd.Flags().BoolVar(&filterCustom, "custom", false, "Filter custom (file/db) rules only")
}

func sigmaPacks() {
	packs := datastore.GetAvailableSigmaPacks()
	fmt.Printf("Available Rule Packs (%d):\n", len(packs))
	for _, p := range packs {
		count := 0
		if info, err := datastore.GetSigmaPackInfo(p, false); err == nil {
			count = info.RuleCount
		}
		fmt.Printf("  - %-20s (rules: %d)\n", p, count)
	}
}


func sigmaStat() {
	list := auditor.GetSigmaRuleEntries()
	logSrcMap := make(map[string]int)
	fieldMap := make(map[string]int)
	titleMap := make(map[string]int)
	sourceMap := make(map[string]int)
	for _, entry := range list {
		e := entry.Evaluator
		sourceMap[entry.Source]++
		if _, ok := titleMap[e.Title]; !ok {
			titleMap[e.Title] = 0
		}
		titleMap[e.Title]++
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
	dupTitle := 0
	for _, c := range titleMap {
		if c > 1 {
			dupTitle++
		}
	}
	fmt.Printf("rules=%d logsrc=%d field=%d dupTitle=%d\n", len(list), len(logSrcMap), len(fieldMap), dupTitle)
	fmt.Println("Sources:")
	for s, c := range sourceMap {
		fmt.Printf("  %-24s : %d\n", s, c)
	}
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
	list := auditor.GetSigmaRuleEntries()
	for _, entry := range list {
		if filterPack != "" {
			expected := "pack:" + filterPack
			if entry.Source != expected {
				continue
			}
		}
		if filterCustom {
			if strings.HasPrefix(entry.Source, "pack:") {
				continue
			}
		}
		e := entry.Evaluator
		lsk := fmt.Sprintf("%s:%s:%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
		fmt.Printf("%-24s\t%s\t%-8s\t%-20s\t%s\n", entry.Source, e.ID, e.Level, lsk, e.Title)
	}
}

var regCheck1 = regexp.MustCompile(`condition:.+\s+of\s+\*?[a-zA-Z_0-9]+\*`)
var regCheck2 = regexp.MustCompile(`[0-9]+`)

func sigmaCheck() {
	total := 0
	hits := 0
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
				hits++
			}
		}
	})
	fmt.Printf("total=%d hit=%d\n", total, hits)
}

func sigmaTest(args []string) {
	if len(args) < 2 {
		log.Fatalln("test data missing")
	}
	auditor.TestRule(args[1:])
}
