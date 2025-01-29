package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var client TWLogEyeServiceClient

func SetClient(ip, cert string, port int) error {
	var conn *grpc.ClientConn
	var err error
	address := fmt.Sprintf("%s:%d", ip, port)
	if cert == "" {
		conn, err = grpc.NewClient(
			address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	} else {
		// TLS
		log.Fatalln("not supported now")
	}
	if err != nil {
		return err
	}
	client = NewTWLogEyeServiceClient(conn)
	return nil
}

func Stop() {
	ret, err := client.Stop(context.Background(), &Empty{})
	if err != nil {
		log.Fatalf("stop err=%v", err)
	}
	log.Printf("stop ret=%+v", ret)
}

func Reload() {
	ret, err := client.Reload(context.Background(), &Empty{})
	if err != nil {
		log.Fatalf("reload rules err=%v", err)
	}
	log.Printf("reload rules ret=%+v", ret)
}

func WatchNotify() {
	s, err := client.WatchNotify(context.Background(), &Empty{})
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
	s, err := client.SearchNotify(context.Background(), &NofifyRequest{
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
	s, err := client.SearchLog(context.Background(), &LogRequest{
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
