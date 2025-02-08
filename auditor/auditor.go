package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/elastic/go-grok"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/notify"
	"gopkg.in/yaml.v3"
)

var evaluators []*evaluator.RuleEvaluator
var grs []*grok.Grok
var auditorCh chan *datastore.LogEnt
var reloadCh chan bool
var watchChMap sync.Map

func Init(skipErr bool) bool {
	loadSigmaConfigs(skipErr)
	loadSigmaRules(skipErr)
	setGrok()
	loadNamedCaptures()
	auditorCh = make(chan *datastore.LogEnt, 20000)
	reloadCh = make(chan bool)
	return len(evaluators) > 0
}

func Start(ctx context.Context, wg *sync.WaitGroup) {
	log.Printf("start auditor")
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop auditor")
			return
		case <-reloadCh:
			evaluators = []*evaluator.RuleEvaluator{}
			loadSigmaRules(true)
		case l := <-auditorCh:
			if ev := matchSigmaRule(l); ev != nil {
				n := &datastore.NotifyEnt{
					Time:  l.Time,
					Src:   l.Src,
					Type:  l.Type,
					Log:   l.Log,
					ID:    ev.ID,
					Level: ev.Level,
					Title: ev.Title,
					Tags:  strings.Join(ev.Tags, ";"),
				}
				notify.Norify(n)
				datastore.SaveNotify(n)
				watchChMap.Range(func(k, v any) bool {
					if ch, ok := v.(chan *datastore.NotifyEnt); ok {
						ch <- n
					}
					return true
				})
				log.Printf("notify %s %s %s", n.Src, n.ID, n.Level)
			}
		}
	}
}

func Audit(l *datastore.LogEnt) {
	auditorCh <- l
}

func Reload() {
	reloadCh <- true
}

func AddWatch(id string) chan *datastore.NotifyEnt {
	ch := make(chan *datastore.NotifyEnt, 100)
	watchChMap.Store(id, ch)
	log.Printf("add watch id=%s", id)
	return ch
}

func DelWatch(id string) {
	if v, ok := watchChMap.LoadAndDelete(id); ok {
		if ch, ok := v.(chan *datastore.NotifyEnt); ok {
			log.Printf("delete watch id=%s", id)
			close(ch)
		}
	}
}

var sigmaConfigMap = make(map[string]*sigma.Config)

func getSigmaConfig(r *sigma.Rule) *sigma.Config {
	c := r.Logsource.Product
	if conf, ok := sigmaConfigMap[c]; ok {
		return conf
	}
	c += "_" + r.Logsource.Category
	if conf, ok := sigmaConfigMap[c]; ok {
		return conf
	}
	c += "_" + r.Logsource.Service
	if conf, ok := sigmaConfigMap[c]; ok {
		return conf
	}
	return nil
}

func loadSigmaRules(skipErr bool) {
	total := 0
	skip := 0
	fix := 0
	dup := 0
	idMap := make(map[string]bool)
	datastore.ForEachSigmaRules(func(c []byte, path string) {
		total++
		rule, err := sigma.ParseRule(c)
		if err != nil && strings.Contains(err.Error(), "'*'") {
			rule, err = autoFixSigmaRule(c, rule)
			if err == nil {
				fix++
			}
		}
		// check keywords not support
		for _, s := range rule.Detection.Searches {
			if len(s.Keywords) > 0 {
				err = fmt.Errorf("keywords not support")
				break
			}
		}
		if err != nil {
			skip++
			if skipErr {
				log.Printf("invalid rule %s %v", path, err)
				return
			} else {
				log.Fatalf("invalid rule %s %v", path, err)
			}
		}
		if rule.ID == "" {
			rule.ID = path
		}
		if _, ok := idMap[rule.ID]; ok {
			dup++
			return
		}
		idMap[rule.ID] = true
		config := getSigmaConfig(&rule)
		if config != nil {
			evaluators = append(evaluators, evaluator.ForRule(rule, evaluator.WithConfig(*config), evaluator.CaseSensitive))
		} else {
			evaluators = append(evaluators, evaluator.ForRule(rule, evaluator.CaseSensitive))
		}
	})
	log.Printf("load sigma rules total=%d skip=%d fix=%d dup=%d", total, skip, fix, dup)
}

func loadSigmaConfigs(skipErr bool) {
	sigmaConfigMap = make(map[string]*sigma.Config)
	datastore.ForEachSigmaConfig(func(k string, d []byte) {
		c, err := sigma.ParseConfig(d)
		if err != nil {
			if skipErr {
				log.Printf("sigma config parrse err=%v", err)
				return
			} else {
				log.Fatalf("sigma config parrse err=%v", err)
			}
		}
		log.Printf("load sigma config %s", k)
		sigmaConfigMap[k] = &c
	})
}

var regJSON = regexp.MustCompile(`^\s*{.+}\s*$`)
var regSplunk = regexp.MustCompile(`\s*([a-zA-Z_]+[a-zA-Z0-9_]+)=([^ ,;]+)`)
var namedCaptureRegList = []*regexp.Regexp{}

func matchSigmaRule(l *datastore.LogEnt) *evaluator.RuleEvaluator {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(l.Log), &data); err != nil {
		return nil
	}
	if l.Type == datastore.Syslog {
		if data == nil {
			data = make(map[string]interface{})
		}
		if v, ok := data["content"]; ok {
			if c, ok := v.(string); ok {
				// JSON
				notJSON := true
				if regJSON.MatchString(c) {
					var tmpData map[string]interface{}
					if err := json.Unmarshal([]byte(c), &tmpData); err == nil {
						notJSON = false
						for k, v := range tmpData {
							// use in content
							data[k] = v
						}
					}
				}
				if notJSON {
					if datastore.Config.KeyValParse {
						// Splunk key=val
						for _, m := range regSplunk.FindAllStringSubmatch(c, -1) {
							if len(m) > 2 {
								if f, err := strconv.ParseFloat(m[1], 64); err == nil {
									data[m[0]] = f
								} else {
									data[m[0]] = m[1]
								}
							}
						}
					}
					for _, r := range namedCaptureRegList {
						if match := r.FindStringSubmatch(c); match != nil {
							for i, k := range r.SubexpNames() {
								if i != 0 && k != "" {
									if f, err := strconv.ParseFloat(match[i], 64); err == nil {
										data[k] = f
									} else {
										data[k] = match[i]
									}
								}
							}
						}
					}
					for _, gr := range grs {
						if tmpData, err := gr.ParseString(c); err == nil {
							for k, v := range tmpData {
								data[k] = v
							}
						}
					}
				}
			}
		}
	}
	for _, ev := range evaluators {
		r, err := ev.Matches(context.Background(), data)
		if err != nil {
			log.Printf("sigma matches rule id=%s err=%+v", ev.Rule.ID, err)
			return nil
		}
		if r.Match {
			return ev
		}
	}
	return nil
}

func GetSigmaRuleEvaluators() []*evaluator.RuleEvaluator {
	loadSigmaConfigs(true)
	loadSigmaRules(true)
	return evaluators
}

func TestRule(args []string) {
	loadSigmaConfigs(true)
	loadSigmaRules(true)
	if len(evaluators) < 1 {
		log.Fatalln("no rule to test")
	}
	hit := false
	for _, l := range args {
		if e := matchSigmaRule(&datastore.LogEnt{
			Time: time.Now().UnixNano(),
			Log:  l,
		}); e != nil {
			lsk := fmt.Sprintf("%s:%s:%s", e.Logsource.Product, e.Logsource.Category, e.Logsource.Service)
			fmt.Printf("===\n%s\n%s\t%s\t%s\t%s\n", l, e.ID, e.Level, lsk, e.Title)
			hit = true
		}
	}
	if !hit {
		fmt.Println("===\nno rule maatch")
	}
}

var regexpGrok = regexp.MustCompile(`%\{.+\}`)

func setGrok() {
	if len(datastore.Config.GrokPat) < 1 {
		return
	}
	grokPatternDef := make(map[string]string)
	if datastore.Config.GrokDef != "" {
		c, err := os.ReadFile(datastore.Config.GrokDef)
		if err != nil {
			log.Fatalln(err)
		}
		for _, l := range strings.Split(string(c), "\n") {
			a := strings.SplitN(l, " ", 2)
			if len(a) != 2 {
				continue
			}
			grokPatternDef[a[0]] = a[1]
		}
	}
	for _, pat := range datastore.Config.GrokPat {
		gr, err := grok.NewComplete()
		if err != nil {
			log.Fatalln(err)
		}
		if !regexpGrok.MatchString(pat) {
			pat = fmt.Sprintf("%%{%s}", pat)
		}
		err = gr.Compile(pat, false)
		if err != nil {
			log.Fatalln(err)
		}
		grs = append(grs, gr)
	}
}

func loadNamedCaptures() {
	if datastore.Config.NamedCaptures == "" {
		return
	}
	c, err := os.ReadFile(datastore.Config.NamedCaptures)
	if err != nil {
		log.Fatalf("laodNameCaptures err=%v", err)
	}
	for _, l := range strings.Split(string(c), "\n") {
		namedCaptureRegList = append(namedCaptureRegList, regexp.MustCompile(l))
	}
}

func autoFixSigmaRule(c []byte, r sigma.Rule) (sigma.Rule, error) {
	var rule map[string]interface{}
	if err := yaml.Unmarshal(c, &rule); err != nil {
		return r, err
	}
	numReg := regexp.MustCompile(`\d+`)
	replaceMap := make(map[string]string)
	keys := []string{}
	for k, v := range rule {
		if k == "detection" {
			if m, ok := v.(map[string]interface{}); ok {
				for dk, dv := range m {
					if dk == "condition" {
						if cs, ok := dv.(string); ok {
							a := []string{}
							for _, f := range strings.Fields(cs) {
								if f != "1" && numReg.MatchString(f) {
									f = convertNumberToAlpha(f)
								}
								a = append(a, f)
							}
							replaceMap[cs] = strings.Join(a, " ")
							keys = append(keys, cs)
						}
					} else if numReg.MatchString(dk) {
						replaceMap[dk] = convertNumberToAlpha(dk)
						keys = append(keys, dk)
					}
				}
			}
		}
	}
	// sort length asc
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	s := string(c)
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, replaceMap[k])
	}
	return sigma.ParseRule([]byte(s))
}

func convertNumberToAlpha(input string) string {
	numToAlpha := map[rune]rune{
		'0': 'a',
		'1': 'b',
		'2': 'c',
		'3': 'd',
		'4': 'e',
		'5': 'f',
		'6': 'g',
		'7': 'h',
		'8': 'i',
		'9': 'j',
	}

	var builder strings.Builder

	for _, ch := range input {
		if replacement, exists := numToAlpha[ch]; exists {
			builder.WriteRune(replacement)
		} else {
			builder.WriteRune(ch)
		}
	}
	return builder.String()
}
