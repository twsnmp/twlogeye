package logger

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/reporter"
)

func TestNetFlowd(t *testing.T) {
	// Setup in-memory DB for datastore
	datastore.Config.DBPath = ""
	datastore.Config.LogRetention = 24
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Setup auditor and reporter
	auditor.Init()
	reporter.Init()

	// Get free UDP port
	nfPort, err := getFreeUDPPort()
	if err != nil {
		t.Fatalf("failed to get free UDP port: %v", err)
	}

	datastore.Config.NetFlowPort = nfPort

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go StartNetFlowd(ctx, &wg)

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Send NetFlow v5 packet
	err = sendNetflowV5(nfPort)
	if err != nil {
		t.Fatalf("failed to send netflow: %v", err)
	}

	// Wait for processing and timer (1s)
	time.Sleep(2000 * time.Millisecond)

	cancel()
	wg.Wait()

	// Check if logs are saved
	count := 0
	datastore.ForEachLog("netflow", 0, 0, func(l *datastore.LogEnt) bool {
		t.Logf("Found netflow: %v", l)
		count++
		return true
	})
	if count < 1 {
		t.Errorf("expected at least 1 netflow, got %d", count)
	}
}

func sendNetflowV5(port int) error {
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer conn.Close()

	// Minimal NetFlow v5 header (24 bytes)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(5)) // version
	binary.Write(buf, binary.BigEndian, uint16(1)) // count
	binary.Write(buf, binary.BigEndian, uint32(0)) // sysUpTime
	binary.Write(buf, binary.BigEndian, uint32(0)) // unix_secs
	binary.Write(buf, binary.BigEndian, uint32(0)) // unix_nsecs
	binary.Write(buf, binary.BigEndian, uint32(0)) // flow_sequence
	binary.Write(buf, binary.BigEndian, uint8(0))  // engine_type
	binary.Write(buf, binary.BigEndian, uint8(0))  // engine_id
	binary.Write(buf, binary.BigEndian, uint16(0)) // sampling_interval

	// Minimal Flow Record (48 bytes)
	binary.Write(buf, binary.BigEndian, net.ParseIP("192.168.1.1").To4()) // srcAddr
	binary.Write(buf, binary.BigEndian, net.ParseIP("192.168.1.2").To4()) // dstAddr
	binary.Write(buf, binary.BigEndian, net.ParseIP("0.0.0.0").To4())     // nextHop
	binary.Write(buf, binary.BigEndian, uint16(0))                       // input
	binary.Write(buf, binary.BigEndian, uint16(0))                       // output
	binary.Write(buf, binary.BigEndian, uint32(100))                     // packets
	binary.Write(buf, binary.BigEndian, uint32(1000))                    // octets
	binary.Write(buf, binary.BigEndian, uint32(0))                       // first
	binary.Write(buf, binary.BigEndian, uint32(0))                       // last
	binary.Write(buf, binary.BigEndian, uint16(1234))                    // srcPort
	binary.Write(buf, binary.BigEndian, uint16(80))                      // dstPort
	binary.Write(buf, binary.BigEndian, uint8(0))                        // pad1
	binary.Write(buf, binary.BigEndian, uint8(0))                        // tcp_flags
	binary.Write(buf, binary.BigEndian, uint8(6))                        // prot (TCP)
	binary.Write(buf, binary.BigEndian, uint8(0))                        // tos
	binary.Write(buf, binary.BigEndian, uint16(0))                       // src_as
	binary.Write(buf, binary.BigEndian, uint16(0))                       // dst_as
	binary.Write(buf, binary.BigEndian, uint8(0))                        // src_mask
	binary.Write(buf, binary.BigEndian, uint8(0))                        // dst_mask
	binary.Write(buf, binary.BigEndian, uint16(0))                       // pad2

	_, err = conn.Write(buf.Bytes())
	return err
}
