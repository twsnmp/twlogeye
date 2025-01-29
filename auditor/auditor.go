package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/elastic/go-grok"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/notify"
)

var evaluators []*evaluator.RuleEvaluator
var gr *grok.Grok
var auditorCh chan *datastore.LogEnt
var reloadCh chan bool
var watchChMap sync.Map

func Init() bool {
	loadSigmaRules()
	setGrok()
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
			loadSigmaRules()
		case l := <-auditorCh:
			if ev := matchSigmaRule(l); ev != nil {
				n := &datastore.NotifyEnt{
					Time:  l.Time,
					Src:   l.Src,
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

func getSigmaConfig() *sigma.Config {
	c, err := datastore.GetSigmaConfig()
	if err != nil {
		log.Fatalf("sigma config err=%v", err)
	}
	if c == nil {
		return nil
	}
	ret, err := sigma.ParseConfig(c)
	if err != nil {
		log.Fatalf("sigma config parrse err=%v", err)
	}
	return &ret
}

func loadSigmaRules() {
	config := getSigmaConfig()
	datastore.ForEachSigmaRules(func(c []byte, path string) {
		rule, err := sigma.ParseRule(c)
		if err != nil {
			log.Fatalf("invalid rule %s %s", path, err)
		}
		if rule.ID == "" {
			rule.ID = path
		}
		if config != nil {
			evaluators = append(evaluators, evaluator.ForRule(rule, evaluator.WithConfig(*config), evaluator.CaseSensitive))
		} else {
			evaluators = append(evaluators, evaluator.ForRule(rule, evaluator.CaseSensitive))
		}
	})
}

func matchSigmaRule(l *datastore.LogEnt) *evaluator.RuleEvaluator {
	var data interface{}
	if gr != nil {
		var err error
		data, err = gr.ParseString(l.Log)
		if err != nil {
			return nil
		}
	} else {
		if err := json.Unmarshal([]byte(l.Log), &data); err != nil {
			return nil
		}
	}
	for _, ev := range evaluators {
		r, err := ev.Matches(context.Background(), data)
		if err != nil {
			log.Printf("sigma matches err=%+v", err)
			return nil
		}
		if r.Match {
			return ev
		}
	}
	return nil
}

var regexpGrok = regexp.MustCompile(`%\{.+\}`)

func setGrok() {
	if datastore.Config.GrokPat == "" {
		return
	}
	var err error
	switch datastore.Config.GrokDef {
	case "full":
		gr, err = grok.NewComplete()
		if err != nil {
			log.Fatalln(err)
		}
	case "":
		gr = grok.New()
	default:
		if c, err := os.ReadFile(datastore.Config.GrokDef); err != nil {
			log.Fatalln(err)
		} else {
			gr = grok.New()
			for _, l := range strings.Split(string(c), "\n") {
				a := strings.SplitN(l, " ", 2)
				if len(a) != 2 {
					continue
				}
				gr.AddPattern(strings.TrimSpace(a[0]), strings.TrimSpace(a[1]))
			}
		}
	}
	pat := datastore.Config.GrokPat
	if !regexpGrok.MatchString(pat) {
		pat = fmt.Sprintf("%%{%s}", pat)
	}
	err = gr.Compile(pat, false)
	if err != nil {
		log.Fatalln(err)
	}
}
