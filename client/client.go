package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/twsnmp/twlogeye/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var client api.TWLogEyeServiceClient

func SetClient(ip, caCert, cert, key string, port int) error {
	var conn *grpc.ClientConn
	var err error
	address := fmt.Sprintf("%s:%d", ip, port)
	if caCert == "" {
		// not TLS
		conn, err = grpc.NewClient(
			address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	} else {
		if cert != "" && key != "" {
			// mTLS
			cert, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				log.Fatalf("failed to load client cert: %v", err)
			}
			ca := x509.NewCertPool()
			caBytes, err := os.ReadFile(caCert)
			if err != nil {
				log.Fatalf("failed to read ca cert  err=%v", err)
			}
			if ok := ca.AppendCertsFromPEM(caBytes); !ok {
				log.Fatalf("failed to parse %q", caCert)
			}
			tlsConfig := &tls.Config{
				ServerName:   "",
				Certificates: []tls.Certificate{cert},
				RootCAs:      ca,
			}
			conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			if err != nil {
				log.Fatalf("failed to connect  err=%v", err)
			}
		} else {
			// TLS
			creds, err := credentials.NewClientTLSFromFile(caCert, "")
			if err != nil {
				log.Fatalf("failed to load credentials: %v", err)
			}
			conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(creds))
			if err != nil {
				log.Fatalf("did not connect: %v", err)
			}
		}
	}
	if err != nil {
		return err
	}
	client = api.NewTWLogEyeServiceClient(conn)
	return nil
}

func Stop() {
	ret, err := client.Stop(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("stop err=%v", err)
	}
	log.Printf("stop ret=%+v", ret)
}

func Reload() {
	ret, err := client.Reload(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("reload rules err=%v", err)
	}
	log.Printf("reload rules ret=%+v", ret)
}

func WatchNotify() {
	s, err := client.WatchNotify(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("watch notify err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("watch notify err=%v", err)
		}
		fmt.Printf("---\n%s %s %s %s\n%s\n%s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLevel(), r.GetId(), r.GetTags(), r.GetTitle())
	}
}

func SearchNotify(st, et int64, level string) {
	s, err := client.SearchNotify(context.Background(), &api.NofifyRequest{
		Start: st,
		End:   et,
		Level: level,
	})
	if err != nil {
		log.Fatalf("search notify err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("search notify err=%v", err)
		}
		fmt.Printf("---\n%s %s %s %s\n%s\n%s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLevel(), r.GetId(), r.GetTags(), r.GetTitle())
	}
}

func SearchLog(st, et int64, logtype, search string) {
	s, err := client.SearchLog(context.Background(), &api.LogRequest{
		Logtype: logtype,
		Start:   st,
		End:     et,
		Search:  search,
	})
	if err != nil {
		log.Fatalf("search log err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("search log err=%v", err)
		}
		fmt.Printf("%s %s %s\n", getTimeStr(r.GetTime()), r.GetSrc(), r.GetLog())
	}
}

func getTimeStr(t int64) string {
	return time.Unix(0, t).Format(time.RFC3339Nano)
}

func GetSyslogReport(st, et int64) {
	s, err := client.GetSyslogReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get syslog report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get syslog report err=%v", err)
		}
		fmt.Printf("%s normal=%d warn=%d error=%d\n", getTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError())
		fmt.Println("===")
		fmt.Println("Top log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top error log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetLogPattern(), t.GetCount())
		}
	}
}

func GetTrapReport(st, et int64) {
	s, err := client.GetTrapReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get trap report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get trap report err=%v", err)
		}
		fmt.Printf("%s count=%d\n", getTimeStr(r.GetTime()), r.GetCount())
		fmt.Println("===")
		fmt.Println("Top TRAP type list")
		fmt.Println("No.\tSender\tTrap Type\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%d\n", i+1, t.GetSender(), t.GetTrapType(), t.GetCount())
		}
	}
}

func GetNetflowReport(st, et int64) {
	s, err := client.GetNetflowReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get netflow report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get netflow report err=%v", err)
		}
		fmt.Printf("%s packets=%d bytes=%d\n", getTimeStr(r.GetTime()), r.GetPackets(), r.GetBytes())
		fmt.Println("===")
		fmt.Println("Top MAC node packets list")
		fmt.Println("No.\tMAC\tPackets")
		for i, t := range r.GetTopMacPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top MAC node bytes list")
		fmt.Println("No.\tMAC\tBytes")
		for i, t := range r.GetTopMacBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top IP node packets list")
		fmt.Println("No.\tIP\tPackets")
		for i, t := range r.GetTopIpPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top IP node bytes list")
		fmt.Println("No.\tIP\tBytes")
		for i, t := range r.GetTopIpBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top flow packets list")
		fmt.Println("No.\tFlow\tPackets")
		for i, t := range r.GetTopFlowPacketsList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetPackets())
		}
		fmt.Println("===")
		fmt.Println("Top flow bytes list")
		fmt.Println("No.\tFlow\tBytes")
		for i, t := range r.GetTopFlowBytesList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetBytes())
		}
		fmt.Println("===")
		fmt.Println("Top protocol list")
		fmt.Println("No.\tProcottol\tCount")
		for i, t := range r.GetTopProtocolList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top TCP flag list")
		fmt.Println("No.\tTCP Flag\tCount")
		for i, t := range r.GetTopTcpFlagList() {
			fmt.Printf("%d\t%s\t%d\n", i+1, t.GetKey(), t.GetCount())
		}
	}
}

func GetWindowsEventReport(st, et int64) {
	s, err := client.GetWindowsEventReport(context.Background(), &api.ReportRequest{Start: st, End: et})
	if err != nil {
		log.Fatalf("get windows event report err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get windows event report err=%v", err)
		}
		fmt.Printf("%s normal=%d warn=%d error=%d\n", getTimeStr(r.GetTime()), r.GetNormal(), r.GetWarn(), r.GetError())
		fmt.Println("===")
		fmt.Println("Top log pattern list")
		fmt.Println("No.\tComputer\tProvider\tEventID\tCount")
		for i, t := range r.GetTopList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
		fmt.Println("===")
		fmt.Println("Top error log pattern list")
		fmt.Println("No.\tPattern\tCount")
		for i, t := range r.GetTopErrorList() {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", i+1, t.GetComputer(), t.GetProvider(), t.GetEventId(), t.GetCount())
		}
	}
}
