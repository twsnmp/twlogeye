package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type apiServer struct {
	UnimplementedTWLogEyeServiceServer
}

func NewAPIServer() *apiServer {
	return &apiServer{}
}

func StartAPIServer(ctx context.Context, wg *sync.WaitGroup, port int, cert, key, ca string) {
	defer wg.Done()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("start API server err=%v", err)
	}
	s := grpc.NewServer()
	RegisterTWLogEyeServiceServer(s, NewAPIServer())
	reflection.Register(s)

	go func() {
		log.Printf("start API server port: %v", port)
		s.Serve(listener)
	}()

	<-ctx.Done()
	log.Println("stopping API server")
	go s.GracefulStop()
	time.Sleep(time.Second * 2)
	s.Stop()
	log.Println("stop API server")

}

// RPC

func (s *apiServer) Stop(ctx context.Context, req *Empty) (*ControlResponse, error) {
	go func() {
		time.Sleep(time.Second)
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
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
		}); err != nil {
			log.Printf("search log err=%v", err)
			return false
		}
		return true
	})
	return nil
}
