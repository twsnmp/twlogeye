package server

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

	"github.com/twsnmp/twlogeye/api"
	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type apiServer struct {
	api.UnimplementedTWLogEyeServiceServer
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
	api.RegisterTWLogEyeServiceServer(s, NewAPIServer())
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

func (s *apiServer) Stop(ctx context.Context, req *api.Empty) (*api.ControlResponse, error) {
	go func() {
		time.Sleep(time.Second)
		_sigTerm <- syscall.SIGINT
	}()
	return &api.ControlResponse{
		Ok:      true,
		Message: "twLogEye stopping",
	}, nil
}

func (s *apiServer) Reload(ctx context.Context, req *api.Empty) (*api.ControlResponse, error) {
	go func() {
		time.Sleep(time.Second)
		auditor.Reload()
	}()
	return &api.ControlResponse{
		Ok:      true,
		Message: "twLogEye reloading",
	}, nil
}

func (s *apiServer) WatchNotify(req *api.Empty, stream api.TWLogEyeService_WatchNotifyServer) error {
	id := fmt.Sprintf("%16x", time.Now().UnixNano())
	ch := auditor.AddWatch(id)
	defer auditor.DelWatch(id)
	for n := range ch {
		if err := stream.Send(&api.NotifyResponse{
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

func (s *apiServer) SearchNotify(req *api.NofifyRequest, stream api.TWLogEyeService_SearchNotifyServer) error {
	level := req.GetLevel()
	datastore.ForEachNotify(req.GetStart(), req.GetEnd(), func(n *datastore.NotifyEnt) bool {
		if level != "" && level != n.Level {
			//Skip
			return true
		}
		if err := stream.Send(&api.NotifyResponse{
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

func (s *apiServer) SearchLog(req *api.LogRequest, stream api.TWLogEyeService_SearchLogServer) error {
	search := req.GetSearch()
	datastore.ForEachLog(req.GetLogtype(), req.GetStart(), req.GetEnd(), func(l *datastore.LogEnt) bool {
		if search != "" && !strings.Contains(l.Log, search) {
			return true
		}
		if err := stream.Send(&api.LogResponse{
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

func (s *apiServer) GetSyslogReport(req *api.ReportRequest, stream api.TWLogEyeService_GetSyslogReportServer) error {
	datastore.ForEachSyslogReport(req.GetStart(), req.GetEnd(), func(l *datastore.SyslogReportEnt) bool {
		r := &api.SyslogReportEnt{
			Time:         l.Time,
			Normal:       int32(l.Normal),
			Warn:         int32(l.Warn),
			Error:        int32(l.Error),
			Patterns:     int32(l.Patterns),
			ErrPatterns:  int32(l.ErrPatterns),
			TopList:      []*api.LogSummaryEnt{},
			TopErrorList: []*api.LogSummaryEnt{},
		}
		for _, t := range l.TopList {
			r.TopList = append(r.TopList, &api.LogSummaryEnt{
				LogPattern: t.LogPattern,
				Count:      int32(t.Count),
			})
		}
		for _, t := range l.TopErrorList {
			r.TopErrorList = append(r.TopErrorList, &api.LogSummaryEnt{
				LogPattern: t.LogPattern,
				Count:      int32(t.Count),
			})
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get syslog report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetTrapReport(req *api.ReportRequest, stream api.TWLogEyeService_GetTrapReportServer) error {
	datastore.ForEachTrapReport(req.GetStart(), req.GetEnd(), func(l *datastore.TrapReportEnt) bool {
		r := &api.TrapReportEnt{
			Time:    l.Time,
			Count:   int32(l.Count),
			Types:   int32(l.Types),
			TopList: []*api.TrapSummaryEnt{},
		}
		for _, t := range l.TopList {
			r.TopList = append(r.TopList, &api.TrapSummaryEnt{
				Sender:   t.Sender,
				TrapType: t.TrapType,
				Count:    int32(t.Count),
			})
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get trap report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetNetflowReport(req *api.ReportRequest, stream api.TWLogEyeService_GetNetflowReportServer) error {
	datastore.ForEachNetflowReport(req.GetStart(), req.GetEnd(), func(l *datastore.NetflowReportEnt) bool {
		r := &api.NetflowReportEnt{
			Time:               l.Time,
			Packets:            l.Packets,
			Bytes:              l.Bytes,
			Macs:               int32(l.MACs),
			Ips:                int32(l.IPs),
			Flows:              int32(l.Flows),
			Protocols:          int32(l.Protocols),
			Fumbles:            int32(l.Fumbles),
			TopMacPacketsList:  []*api.NetflowPacketsSummaryEnt{},
			TopMacBytesList:    []*api.NetflowBytesSummaryEnt{},
			TopIpPacketsList:   []*api.NetflowPacketsSummaryEnt{},
			TopIpBytesList:     []*api.NetflowBytesSummaryEnt{},
			TopFlowPacketsList: []*api.NetflowPacketsSummaryEnt{},
			TopFlowBytesList:   []*api.NetflowBytesSummaryEnt{},
			TopProtocolList:    []*api.NetflowProtocolCountEnt{},
			TopFumbleSrcList:   []*api.NetflowIPCountEnt{},
		}
		for _, t := range l.TopMACPacketsList {
			r.TopMacPacketsList = append(r.TopMacPacketsList, &api.NetflowPacketsSummaryEnt{
				Key:     t.Key,
				Packets: int32(t.Packets),
			})
		}
		for _, t := range l.TopMACBytesList {
			r.TopMacBytesList = append(r.TopMacBytesList, &api.NetflowBytesSummaryEnt{
				Key:   t.Key,
				Bytes: t.Bytes,
			})
		}
		for _, t := range l.TopIPPacketsList {
			r.TopIpPacketsList = append(r.TopIpPacketsList, &api.NetflowPacketsSummaryEnt{
				Key:     t.Key,
				Packets: int32(t.Packets),
			})
		}
		for _, t := range l.TopIPBytesList {
			r.TopIpBytesList = append(r.TopIpBytesList, &api.NetflowBytesSummaryEnt{
				Key:   t.Key,
				Bytes: t.Bytes,
			})
		}
		for _, t := range l.TopFlowPacketsList {
			r.TopFlowPacketsList = append(r.TopFlowPacketsList, &api.NetflowPacketsSummaryEnt{
				Key:     t.Key,
				Packets: int32(t.Packets),
			})
		}
		for _, t := range l.TopFlowBytesList {
			r.TopFlowBytesList = append(r.TopFlowBytesList, &api.NetflowBytesSummaryEnt{
				Key:   t.Key,
				Bytes: t.Bytes,
			})
		}
		for _, t := range l.TopProtocolList {
			r.TopProtocolList = append(r.TopProtocolList, &api.NetflowProtocolCountEnt{
				Protocol: t.Protocol,
				Count:    int32(t.Count),
			})
		}
		for _, t := range l.TopFumbleSrcList {
			r.TopFumbleSrcList = append(r.TopFumbleSrcList, &api.NetflowIPCountEnt{
				Ip:    t.IP,
				Count: int32(t.Count),
			})
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get netflow report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetWindowsEventReport(req *api.ReportRequest, stream api.TWLogEyeService_GetWindowsEventReportServer) error {
	datastore.ForEachWindowsEventReport(req.GetStart(), req.GetEnd(), func(l *datastore.WindowsEventReportEnt) bool {
		r := &api.WindowsEventReportEnt{
			Time:         l.Time,
			Normal:       int32(l.Normal),
			Warn:         int32(l.Warn),
			Error:        int32(l.Error),
			Types:        int32(l.Types),
			ErrorTypes:   int32(l.ErrorTypes),
			TopList:      []*api.WindowsEventSummary{},
			TopErrorList: []*api.WindowsEventSummary{},
		}
		for _, t := range l.TopList {
			r.TopList = append(r.TopList, &api.WindowsEventSummary{
				Computer: t.Computer,
				Provider: t.Provider,
				EventId:  t.EeventID,
				Count:    int32(t.Count),
			})
		}
		for _, t := range l.TopErrorList {
			r.TopErrorList = append(r.TopErrorList, &api.WindowsEventSummary{
				Computer: t.Computer,
				Provider: t.Provider,
				EventId:  t.EeventID,
				Count:    int32(t.Count),
			})
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get windows event report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetAnomalyReport(req *api.ReportRequest, stream api.TWLogEyeService_GetAnomalyReportServer) error {
	datastore.ForEachAnomalyReport(req.GetStart(), req.GetEnd(), func(l *datastore.AnomalyReportEnt) bool {
		r := &api.AnomalyReportEnt{
			Time:    l.Time,
			Type:    l.Type,
			Score:   l.Score,
			Max:     l.Max,
			MaxTime: l.MaxTime,
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get anomaly report err=%v", err)
			return false
		}
		return true
	})
	return nil
}
