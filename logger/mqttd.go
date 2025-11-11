package logger

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync"

	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/reporter"
)

var mqttCh = make(chan *datastore.LogEnt, 20000)

func StartMqttd(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.MqttTCPPort == 0 && datastore.Config.MqttWSPort == 0 {
		return
	}
	log.Printf("start mqttd")
	startMqttServer()

	// defer server.Close()
	list := []*datastore.LogEnt{}
	timer := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ctx.Done():
			log.Printf("stop mqttd")
			return
		case l := <-mqttCh:
			list = append(list, l)
			auditor.Audit(l)
		case <-timer.C:
			if len(list) > 0 {
				st := time.Now()
				datastore.SaveLogs("mqtt", list)
				log.Printf("save mqtt logs len=%d dur=%v", len(list), time.Since(st))
				list = []*datastore.LogEnt{}
			}
		}
	}
}

func startMqttServer() *mqtt.Server {
	// Create the new MQTT Server.
	server := mqtt.New(nil)

	// Add twLogEye hook
	err := server.AddHook(new(mqttHook), nil)
	if err != nil {
		log.Fatal(err)
	}
	if datastore.Config.MqttFrom == "" && datastore.Config.MqttUsers == "" {
		// Allow all connections.
		if err := server.AddHook(new(auth.AllowHook), nil); err != nil {
			log.Fatal(err)
		}
	} else {
		authRules := &auth.Ledger{}
		for _, e := range strings.Split(datastore.Config.MqttUsers, ",") {
			a := strings.SplitN(e, ":", 2)
			if len(a) == 2 {
				authRules.Auth = append(authRules.Auth, auth.AuthRule{
					Username: auth.RString(a[0]),
					Password: auth.RString(a[1]),
					Allow:    true,
				})
			}
		}
		for _, e := range strings.Split(datastore.Config.MqttFrom, ",") {
			authRules.Auth = append(authRules.Auth, auth.AuthRule{
				Remote: auth.RString(e),
				Allow:  true,
			})
		}
		if err := server.AddHook(new(auth.Hook), &auth.Options{
			Ledger: authRules,
		}); err != nil {
			log.Fatal(err)

		}
	}
	var tlsConfig *tls.Config
	if datastore.Config.MqttCert != "" && datastore.Config.MqttKey != "" {
		cert, err := tls.LoadX509KeyPair(datastore.Config.MqttCert, datastore.Config.MqttKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	if datastore.Config.MqttTCPPort > 0 {
		tcp := listeners.NewTCP(listeners.Config{
			ID:        "tcp1",
			Address:   fmt.Sprintf(":%d", datastore.Config.MqttTCPPort),
			TLSConfig: tlsConfig,
		})
		if err := server.AddListener(tcp); err != nil {
			log.Fatal(err)
		}
	}
	if datastore.Config.MqttWSPort > 0 {
		ws := listeners.NewWebsocket(listeners.Config{
			ID:        "ws1",
			Address:   fmt.Sprintf(":%d", datastore.Config.MqttWSPort),
			TLSConfig: tlsConfig,
		})
		if err := server.AddListener(ws); err != nil {
			log.Fatal(err)
		}
	}
	go func() {
		err := server.Serve()
		if err != nil {
			log.Println(err)
		}
	}()
	return server
}

type mqttHook struct {
	mqtt.HookBase
}

func (h *mqttHook) ID() string {
	return "twlogeye-mqttd"
}

func (h *mqttHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnConnect,
		mqtt.OnDisconnect,
		mqtt.OnSubscribed,
		mqtt.OnUnsubscribed,
		mqtt.OnPublished,
	}, []byte{b})
}

func (h *mqttHook) Init(config any) error {
	log.Println("mqtt hook initialised")
	return nil
}

func (h *mqttHook) OnConnect(cl *mqtt.Client, pk packets.Packet) error {
	log.Printf("mqtt client connected client=%s", cl.ID)
	return nil
}

func (h *mqttHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	log.Printf("mqtt client disconnected client=%s,expire=%v,err=%v", cl.ID, expire, err)
}

func (h *mqttHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {
	log.Printf("mqtt subscribed client=%s qos=%v", cl.ID, reasonCodes)
}

func (h *mqttHook) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {
	log.Printf("mqtt unsubscribed client=%s", cl.ID)
}

func (h *mqttHook) OnPublished(cl *mqtt.Client, pk packets.Packet) {
	mqttCh <- &datastore.LogEnt{
		Time: time.Now().UnixNano(),
		Src:  fmt.Sprintf("%s:%s", cl.ID, pk.TopicName),
		Log:  string(pk.Payload),
	}
	reporter.SendMqtt(&datastore.MqttLogEnt{
		Time:     time.Now().UnixNano(),
		ClientID: cl.ID,
		Topic:    pk.TopicName,
	})
}
