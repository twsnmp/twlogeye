package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/araddon/dateparse"
	"github.com/twsnmp/twlogeye/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func getClient() api.TWLogEyeServiceClient {
	var conn *grpc.ClientConn
	var err error
	address := fmt.Sprintf("%s:%d", apiServer, apiServerPort)
	if apiCACert == "" {
		// not TLS
		conn, err = grpc.NewClient(
			address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	} else {
		if apiClientCert != "" && apiClientKey != "" {
			// mTLS
			cert, err := tls.LoadX509KeyPair(apiClientCert, apiClientKey)
			if err != nil {
				log.Fatalf("failed to load client cert: %v", err)
			}
			ca := x509.NewCertPool()
			caBytes, err := os.ReadFile(apiCACert)
			if err != nil {
				log.Fatalf("failed to read ca cert  err=%v", err)
			}
			if ok := ca.AppendCertsFromPEM(caBytes); !ok {
				log.Fatalf("failed to parse %q", apiCACert)
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
			creds, err := credentials.NewClientTLSFromFile(apiCACert, "")
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
		log.Fatalf("getClient err=%v", err)
	}
	return api.NewTWLogEyeServiceClient(conn)
}

func getTimeStr(t int64) string {
	return time.Unix(0, t).Format(time.RFC3339Nano)
}

func getReportTimeStr(t int64) string {
	return time.Unix(0, t).Format(time.DateTime)
}

func getTime(s string, dt int64) int64 {
	if t, err := dateparse.ParseLocal(s); err == nil {
		return t.UnixNano()
	}
	return dt
}
