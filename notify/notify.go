package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/twsnmp/twlogeye/datastore"
)

var notifyCh chan *datastore.NotifyEnt

func Init() {
	notifyCh = make(chan *datastore.NotifyEnt, 2000)
}

func Start(ctx context.Context, wg *sync.WaitGroup) {
	log.Println("start notify")
	syslogDst := []net.Conn{}
	trapDst := []*gosnmp.GoSNMP{}
	for _, d := range datastore.Config.SyslogDst {
		log.Printf("syslog dst %s", d)
		syslogDst = append(syslogDst, getSyslogDst(d))
	}
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	for _, d := range datastore.Config.TrapDst {
		log.Printf("trap dst %s", d)
		trapDst = append(trapDst, getTrapDst(d))
	}
	defer func() {
		for _, d := range syslogDst {
			d.Close()
		}
		for _, d := range trapDst {
			d.Conn.Close()
		}
		wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			log.Println("stop notify")
			return
		case n := <-notifyCh:
			s := fmt.Sprintf("<%d>%s %s twlogeye: src=%s,id=%s,tags=%s,title=%s",
				getSyslogLevel(n.Level), time.Now().Format("2006-01-02T15:04:05-07:00"), host, n.Src, n.ID, n.Tags, n.Title)
			for _, d := range syslogDst {
				d.Write([]byte(s))
			}
			for _, d := range trapDst {
				sendTrap(d, n)
			}
			webhook(n)
		}
	}
}

func Norify(n *datastore.NotifyEnt) {
	notifyCh <- n
}

func getSyslogLevel(l string) int {
	switch l {
	case "low":
		return 19*8 + 5 // notice
	case "medium":
		return 19*8 + 4 // warning
	case "high":
		return 19*8 + 3 // error
	case "critical":
		return 19*8 + 2 // critical
	//	case "informational", "info":
	default:
		return 19*8 + 6
	}
}

func getSyslogDst(d string) net.Conn {
	if !strings.Contains(d, ":") {
		d += ":514"
	}
	s, err := net.Dial("udp", d)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func getTrapDst(d string) *gosnmp.GoSNMP {
	port := 162
	a := strings.SplitN(d, ":", 2)
	if len(a) > 1 {
		d = a[0]
		if v, err := strconv.ParseInt(a[1], 10, 64); err == nil && v > 0 && v < 0xfffe {
			port = int(v)
		}
	}
	dst := &gosnmp.GoSNMP{
		Target:    d,
		Port:      uint16(port),
		Version:   gosnmp.Version2c,
		Community: datastore.Config.TrapCommunity,
		Timeout:   time.Second * 2,
		Retries:   0,
	}
	if err := dst.Connect(); err != nil {
		log.Fatalln(err)
	}
	return dst
}

func sendTrap(dst *gosnmp.GoSNMP, n *datastore.NotifyEnt) {
	vbs := []gosnmp.SnmpPDU{
		// TRAP OID
		{
			Name:  ".1.3.6.1.6.3.1.1.4.1.0",
			Type:  gosnmp.ObjectIdentifier,
			Value: ".1.3.6.1.4.1.17861.1.11.0.1",
		}, {
			Name:  "..1.3.6.1.4.1.17861.1.11.1.1.0",
			Type:  gosnmp.OctetString,
			Value: n.Src,
		}, {
			Name:  "..1.3.6.1.4.1.17861.1.11.1.2.0",
			Type:  gosnmp.OctetString,
			Value: n.Level,
		}, {
			Name:  "..1.3.6.1.4.1.17861.1.11.1.3.0",
			Type:  gosnmp.OctetString,
			Value: n.ID,
		}, {
			Name:  "..1.3.6.1.4.1.17861.1.11.1.4.0",
			Type:  gosnmp.OctetString,
			Value: n.Tags,
		}, {
			Name:  "..1.3.6.1.4.1.17861.1.11.1.5.0",
			Type:  gosnmp.OctetString,
			Value: n.Title,
		},
	}
	trap := gosnmp.SnmpTrap{
		Variables: vbs,
	}
	_, err := dst.SendTrap(trap)
	if err != nil {
		log.Println("send trap err=", err)
	}
}

type webHookNotifyEnt struct {
	// Log
	Time string `json:"Time"`
	Type string `json:"Type"`
	Log  string `json:"Log"`
	Src  string `json:"Src"`
	// Sigma rule
	ID    string `json:"ID"`
	Title string `json:"Title"`
	Tags  string `json:"Tags"`
	Level string `json:"Level"`
}

func webhook(n *datastore.NotifyEnt) {
	if len(datastore.Config.WebhookDst) < 1 {
		return
	}
	j, err := json.Marshal(&webHookNotifyEnt{
		Time:  time.Unix(0, n.Time).Format(time.RFC3339),
		Type:  n.Type.String(),
		Log:   n.Log,
		Src:   n.Src,
		ID:    n.ID,
		Title: n.Title,
		Tags:  n.Tags,
		Level: n.Level,
	})
	if err != nil {
		log.Printf("webhook err=%v", err)
		return
	}
	for _, url := range datastore.Config.WebhookDst {
		if err := postWebhook(url, j); err != nil {
			log.Printf("webhook err=%v", err)
		}
	}
}

func postWebhook(url string, j []byte) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: time.Second * time.Duration(2),
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook error %s", resp.Status)
	}
	return nil
}
