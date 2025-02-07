package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type apiServer struct {
	UnimplementedTWLogEyeServiceServer
}

func NewAPIServer() *apiServer {
	return &apiServer{}
}

var _sigTerm chan os.Signal

func StartAPIServer(ctx context.Context, wg *sync.WaitGroup, port int, cert, key, caCert string, sigTerm chan os.Signal) {
	_sigTerm = sigTerm
	defer wg.Done()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("start API server err=%v", err)
	}
	var s *grpc.Server
	if cert == "" || key == "" {
		// not TLS
		log.Println("not TLS server")
		s = grpc.NewServer()
	} else if caCert != "" {
		// mTLS
		log.Println("mTLS server")
		cert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			log.Fatalf("failed to load key pair  err=%v", err)
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
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{cert},
			ClientCAs:    ca,
		}
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		// TLS
		log.Println("TLS server")
		creds, err := credentials.NewServerTLSFromFile(cert, key)
		if err != nil {
			log.Fatalf("failed to create credentials err=%v", err)
		}
		s = grpc.NewServer(grpc.Creds(creds))
	}
	RegisterTWLogEyeServiceServer(s, NewAPIServer())
	reflection.Register(s)
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(s, healthSrv)
	healthSrv.SetServingStatus("twlogeye", healthpb.HealthCheckResponse_SERVING)

	go func() {
		log.Printf("start API server port: %v", port)
		s.Serve(listener)
	}()

	<-ctx.Done()
	log.Println("stopping API server")
	s.Stop()
	log.Println("stop API server")

}

// RPC

func (s *apiServer) Stop(ctx context.Context, req *Empty) (*ControlResponse, error) {
	go func() {
		time.Sleep(time.Second)
		_sigTerm <- syscall.SIGINT
	}()
	return &ControlResponse{
		Ok:      true,
		Message: "twLogEye stopping",
	}, nil
}

func (s *apiServer) Reload(ctx context.Context, req *Empty) (*ControlResponse, error) {
	go func() {
		time.Sleep(time.Second)
		auditor.Reload()
	}()
	return &ControlResponse{
		Ok:      true,
		Message: "twLogEye reloading",
	}, nil
}

func (s *apiServer) WatchNotify(req *Empty, stream TWLogEyeService_WatchNotifyServer) error {
	id := fmt.Sprintf("%16x", time.Now().UnixNano())
	ch := auditor.AddWatch(id)
	defer auditor.DelWatch(id)
	for n := range ch {
		if err := stream.Send(&NotifyResponse{
			Time:  n.Time,
			Id:    n.ID,
			Title: n.Title,
			Tags:  n.Tags,
			Log:   n.Log,
			Level: n.Level,
			Src:   n.Src,
		}); err != nil {
			log.Printf("watch notify err=%v", err)
			break
		}
	}
	return nil
}

func (s *apiServer) SearchNotify(req *NofifyRequest, stream TWLogEyeService_SearchNotifyServer) error {
	level := req.GetLevel()
	datastore.ForEachNotify(req.GetStart(), req.GetEnd(), func(n *datastore.NotifyEnt) bool {
		if level != "" && level != n.Level {
			//Skip
			return true
		}
		if err := stream.Send(&NotifyResponse{
			Time:  n.Time,
			Id:    n.ID,
			Title: n.Title,
			Tags:  n.Tags,
			Log:   n.Log,
			Level: n.Level,
			Src:   n.Src,
		}); err != nil {
			log.Printf("search notify err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) SearchLog(req *LogRequest, stream TWLogEyeService_SearchLogServer) error {
	search := req.GetSearch()
	datastore.ForEachLog(req.GetLogtype(), req.GetStart(), req.GetEnd(), func(l *datastore.LogEnt) bool {
		if search != "" && !strings.Contains(l.Log, search) {
			return true
		}
		if err := stream.Send(&LogResponse{
			Time: l.Time,
			Log:  l.Log,
			Src:  l.Src,
		}); err != nil {
			log.Printf("search log err=%v", err)
			return false
		}
		return true
	})
	return nil
}
