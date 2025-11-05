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
	"github.com/twsnmp/twlogeye/reporter"
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

func (s *apiServer) ClearDB(ctx context.Context, req *api.ClearRequest) (*api.ControlResponse, error) {
	st := time.Now()
	t := req.GetType()
	sub := req.GetSubtype()
	switch t {
	case "logs":
		datastore.ClearLog(sub)
	case "notify":
		datastore.ClearNotify()
	case "otel":
		datastore.DeleteAllOTelData()
	case "report":
		datastore.ClearReport(sub)
		if sub == "anomaly" {
			reporter.ClearAnomalyData()
		}
	}
	log.Printf("clear db %s %s dur=%v", t, sub, time.Since(st))
	return &api.ControlResponse{
		Ok:      true,
		Message: fmt.Sprintf("twlogeye clear %s %s", t, sub),
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

func (s *apiServer) GetLastSyslogReport(ctx context.Context, req *api.Empty) (*api.SyslogReportEnt, error) {
	l := datastore.GetLastSyslogReport()
	if l == nil {
		return nil, fmt.Errorf("syslog report not found")
	}
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
	return r, nil
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

func (s *apiServer) GetLastTrapReport(ctx context.Context, req *api.Empty) (*api.TrapReportEnt, error) {
	l := datastore.GetLastTrapReport()
	if l == nil {
		return nil, fmt.Errorf("trap report not found")
	}
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
	return r, nil
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

func (s *apiServer) GetLastNetflowReport(ctx context.Context, req *api.Empty) (*api.NetflowReportEnt, error) {
	l := datastore.GetLastNetflowReport()
	if l == nil {
		return nil, fmt.Errorf("netflow report not found")
	}
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
	return r, nil
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

func (s *apiServer) GetLastWindowsEventReport(ctx context.Context, req *api.Empty) (*api.WindowsEventReportEnt, error) {
	l := datastore.GetLastWindowsEventReport()
	if l == nil {
		return nil, fmt.Errorf("windows event report not found")
	}
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
	return r, nil
}

func (s *apiServer) GetOTelReport(req *api.ReportRequest, stream api.TWLogEyeService_GetOTelReportServer) error {
	datastore.ForEachOTelReport(req.GetStart(), req.GetEnd(), func(l *datastore.OTelReportEnt) bool {
		r := &api.OTelReportEnt{
			Time:         l.Time,
			Normal:       int32(l.Normal),
			Warn:         int32(l.Warn),
			Error:        int32(l.Error),
			Types:        int32(l.Types),
			ErrorTypes:   int32(l.ErrorTypes),
			TraceIds:     int32(l.TraceIDs),
			TraceCount:   int32(l.TraceCount),
			Hosts:        int32(l.Hosts),
			MericsCount:  int32(l.MericsCount),
			TopList:      []*api.OTelSummaryEnt{},
			TopErrorList: []*api.OTelSummaryEnt{},
		}
		for _, t := range l.TopList {
			r.TopList = append(r.TopList, &api.OTelSummaryEnt{
				Host:     t.Host,
				Service:  t.Service,
				Scope:    t.Scope,
				Severity: t.Severity,
				Count:    int32(t.Count),
			})
		}
		for _, t := range l.TopErrorList {
			r.TopErrorList = append(r.TopErrorList, &api.OTelSummaryEnt{
				Host:     t.Host,
				Service:  t.Service,
				Scope:    t.Scope,
				Severity: t.Severity,
				Count:    int32(t.Count),
			})
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get optel report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetLastOTelReport(ctx context.Context, req *api.Empty) (*api.OTelReportEnt, error) {
	l := datastore.GetLastOTelReport()
	if l == nil {
		return nil, fmt.Errorf("otel report not found")
	}
	r := &api.OTelReportEnt{
		Time:         l.Time,
		Normal:       int32(l.Normal),
		Warn:         int32(l.Warn),
		Error:        int32(l.Error),
		Types:        int32(l.Types),
		ErrorTypes:   int32(l.ErrorTypes),
		TraceIds:     int32(l.TraceIDs),
		TraceCount:   int32(l.TraceCount),
		Hosts:        int32(l.Hosts),
		MericsCount:  int32(l.MericsCount),
		TopList:      []*api.OTelSummaryEnt{},
		TopErrorList: []*api.OTelSummaryEnt{},
	}
	for _, t := range l.TopList {
		r.TopList = append(r.TopList, &api.OTelSummaryEnt{
			Host:     t.Host,
			Service:  t.Service,
			Scope:    t.Scope,
			Severity: t.Severity,
			Count:    int32(t.Count),
		})
	}
	for _, t := range l.TopErrorList {
		r.TopErrorList = append(r.TopErrorList, &api.OTelSummaryEnt{
			Host:     t.Host,
			Service:  t.Service,
			Scope:    t.Scope,
			Severity: t.Severity,
			Count:    int32(t.Count),
		})
	}
	return r, nil
}

func (s *apiServer) GetAnomalyReport(req *api.AnomalyReportRequest, stream api.TWLogEyeService_GetAnomalyReportServer) error {
	datastore.ForEachAnomalyReport(req.GetType(), req.GetStart(), req.GetEnd(), func(l *datastore.AnomalyReportEnt) bool {
		r := &api.AnomalyReportEnt{
			Time:  l.Time,
			Score: l.Score,
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get anomaly report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetLastAnomalyReport(ctx context.Context, req *api.Empty) (*api.LastAnomalyReportEnt, error) {
	r := &api.LastAnomalyReportEnt{
		Time:      time.Now().UnixNano(),
		ScoreList: []*api.LastAnomalyReportScore{},
	}
	for _, t := range []string{"syslog", "trap", "netflow", "winevent", "otel", "monitor"} {
		l := datastore.GetLastAnomalyReport(t)
		if l != nil {
			r.ScoreList = append(r.ScoreList, &api.LastAnomalyReportScore{
				Type:  t,
				Time:  l.Time,
				Score: l.Score,
			})
		}
	}
	return r, nil
}

func (s *apiServer) GetMonitorReport(req *api.ReportRequest, stream api.TWLogEyeService_GetMonitorReportServer) error {
	datastore.ForEachMonitorReport(req.GetStart(), req.GetEnd(), func(l *datastore.MonitorReportEnt) bool {
		r := &api.MonitorReportEnt{
			Time:    l.Time,
			Cpu:     l.CPU,
			Memory:  l.Memory,
			Load:    l.Load,
			Disk:    l.Disk,
			Net:     l.Net,
			Bytes:   l.Bytes,
			DbSpeed: l.DBSpeed,
			DbSize:  l.DBSize,
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get monitor report err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetLastMonitorReport(ctx context.Context, req *api.Empty) (*api.MonitorReportEnt, error) {
	l := datastore.GetLastMonitorReport()
	if l == nil {
		return nil, fmt.Errorf("monitor report not found")
	}
	r := &api.MonitorReportEnt{
		Time:    l.Time,
		Cpu:     l.CPU,
		Memory:  l.Memory,
		Load:    l.Load,
		Disk:    l.Disk,
		Net:     l.Net,
		Bytes:   l.Bytes,
		DbSpeed: l.DBSpeed,
		DbSize:  l.DBSize,
	}
	return r, nil
}

func (s *apiServer) GetOTelMetricList(req *api.Empty, stream api.TWLogEyeService_GetOTelMetricListServer) error {
	datastore.ForEachOTelMetric(func(id string, m *datastore.OTelMetricEnt) bool {
		r := &api.OTelMetricListEnt{
			Id:          id,
			Host:        m.Host,
			Service:     m.Service,
			Scope:       m.Scope,
			Name:        m.Name,
			Type:        m.Type,
			Description: m.Description,
			Unit:        m.Unit,
			Count:       int32(m.Count),
			First:       m.First,
			Last:        m.Last,
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get otel metric list err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetOTelMetric(ctx context.Context, req *api.IDRequest) (*api.OTelMetricEnt, error) {
	m := datastore.GetOTelMetric(req.GetId())
	if m == nil {
		return nil, fmt.Errorf("otel metric not found")
	}
	r := &api.OTelMetricEnt{
		Host:        m.Host,
		Service:     m.Service,
		Scope:       m.Scope,
		Name:        m.Name,
		Type:        m.Type,
		Description: m.Description,
		Unit:        m.Unit,
		DataPoints:  []*api.OTelMetricDataPointEnt{},
		Count:       int32(m.Count),
		First:       m.First,
		Last:        m.Last,
	}
	for _, d := range m.DataPoints {
		r.DataPoints = append(r.DataPoints, &api.OTelMetricDataPointEnt{
			Start:          d.Start,
			Time:           d.Time,
			Attributes:     d.Attributes,
			Count:          d.Count,
			BucketCounts:   d.BucketCounts,
			ExplicitBounds: d.ExplicitBounds,
			Sum:            d.Sum,
			Min:            d.Min,
			Max:            d.Max,
			Gauge:          d.Gauge,
			Positive:       d.Positive,
			Negative:       d.Negative,
			Scale:          d.Scale,
			ZeroCount:      d.ZeroCount,
			ZeroThreshold:  d.ZeroThreshold,
		})
	}
	return r, nil
}

func (s *apiServer) GetOTelTraceList(req *api.Empty, stream api.TWLogEyeService_GetOTelTraceListServer) error {
	datastore.ForEachOTelTrace(func(t *datastore.OTelTraceEnt) bool {
		r := &api.OTelTraceListEnt{
			TraceId: t.TraceID,
			Start:   t.Start,
			End:     t.End,
			Dur:     t.Dur,
			Last:    t.Last,
		}
		if err := stream.Send(r); err != nil {
			log.Printf("api get otel trace list err=%v", err)
			return false
		}
		return true
	})
	return nil
}

func (s *apiServer) GetOTelTrace(ctx context.Context, req *api.IDRequest) (*api.OTelTraceEnt, error) {
	t := datastore.GetOTelTrace(req.GetId())
	if t == nil {
		return nil, fmt.Errorf("otel trace not found")
	}
	r := &api.OTelTraceEnt{
		TraceId: t.TraceID,
		Start:   t.Start,
		End:     t.End,
		Dur:     t.Dur,
		Spans:   []*api.OTelTraceSpanEnt{},
		Last:    t.Last,
	}
	for _, s := range t.Spans {
		r.Spans = append(r.Spans, &api.OTelTraceSpanEnt{
			SpanId:       s.SpanID,
			ParentSpanId: s.ParentSpanID,
			Host:         s.Host,
			Service:      s.Service,
			Scope:        s.Scope,
			Name:         s.Name,
			Start:        s.Start,
			End:          s.End,
			Dur:          s.Dur,
			Attributes:   s.Attributes,
		})
	}
	return r, nil
}
