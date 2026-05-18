package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/twsnmp/twlogeye/api"
	"github.com/twsnmp/twlogeye/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGRPCServer(t *testing.T) {
	// Setup in-memory DB
	datastore.Config.DBPath = ""
	datastore.Config.LogRetention = 24
	datastore.OpenDB()
	defer datastore.CloseDB()

	// Start gRPC server on random port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	api.RegisterTWLogEyeServiceServer(s, NewAPIServer())
	
	go func() {
		if err := s.Serve(lis); err != nil {
			// t.Logf("server exited: %v", err)
		}
	}()
	defer s.Stop()

	// Setup client
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := api.NewTWLogEyeServiceClient(conn)

	// Test SearchLog (empty)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := client.SearchLog(ctx, &api.LogRequest{
		Logtype: "syslog",
		Start:   0,
		End:     time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("SearchLog RPC failed: %v", err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Error("expected EOF for empty search, got nil error")
	}

	// Insert data and test again
	now := time.Now().UnixNano()
	datastore.SaveLogs("syslog", []*datastore.LogEnt{
		{Time: now, Type: datastore.Syslog, Src: "127.0.0.1", Log: "test message"},
	})

	stream2, err := client.SearchLog(ctx, &api.LogRequest{
		Logtype: "syslog",
		Start:   0,
		End:     now + 1,
	})
	if err != nil {
		t.Fatalf("SearchLog RPC failed: %v", err)
	}
	resp, err := stream2.Recv()
	if err != nil {
		t.Fatalf("SearchLog Recv failed: %v", err)
	}
	if resp.Log != "test message" {
		t.Errorf("expected 'test message', got %s", resp.Log)
	}

	// Test ClearDB
	clearResp, err := client.ClearDB(ctx, &api.ClearRequest{
		Type:    "logs",
		Subtype: "syslog",
	})
	if err != nil {
		t.Fatalf("ClearDB failed: %v", err)
	}
	if !clearResp.Ok {
		t.Errorf("ClearDB failed: %s", clearResp.Message)
	}

	// Verify cleared
	stream3, err := client.SearchLog(ctx, &api.LogRequest{
		Logtype: "syslog",
		Start:   0,
		End:     now + 1,
	})
	if err != nil {
		t.Fatalf("SearchLog RPC failed: %v", err)
	}
	_, err = stream3.Recv()
	if err == nil {
		t.Error("expected EOF after clear, got nil error")
	}
}

func TestGetLastSyslogReport_NotFound(t *testing.T) {
	datastore.Config.DBPath = ""
	datastore.OpenDB()
	defer datastore.CloseDB()

	srv := NewAPIServer()
	_, err := srv.GetLastSyslogReport(context.Background(), &api.Empty{})
	if err == nil {
		t.Error("expected error for missing report, got nil")
	}
}
