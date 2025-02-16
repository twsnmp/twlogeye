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
