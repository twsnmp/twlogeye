package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/twsnmp/twlogeye/auditor"
	"github.com/twsnmp/twlogeye/datastore"
	"github.com/twsnmp/twlogeye/reporter"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"
)

var traceMap sync.Map
var otelFromMap sync.Map
var limitFrom bool

func StartOTeld(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if datastore.Config.OTelHTTPPort == 0 && datastore.Config.OTelgRPCPort == 0 {
		return
	}
	log.Printf("start oteld")
	datastore.LoadOTelMetric()
	setOTelFrom()
	f := otlpreceiver.NewFactory()
	config := createOTelConfig()
	componentID := component.MustNewID("otlp")
	settings := receiver.Settings{
		ID:                componentID,
		TelemetrySettings: componenttest.NewNopTelemetrySettings(),
	}
	mr, err := consumer.NewMetrics(handleMetrics)
	if err != nil {
		log.Printf("oteld err=%v", err)
		return
	}
	metricReceiver, err := f.CreateMetrics(ctx, settings, config, mr)
	if err != nil {
		log.Printf("Failed to create metrics receiver otlp: %v", err)
		return
	}

	tr, err := consumer.NewTraces(handleTraces)
	if err != nil {
		log.Printf("oteld err=%v", err)
		return
	}
	traceReceiver, err := f.CreateTraces(ctx, settings, config, tr)
	if err != nil {
		log.Printf("Failed to create traces receiver otlp: %v", err)
		return
	}

	lr, err := consumer.NewLogs(handleLogs)
	if err != nil {
		log.Printf("oteld err=%v", err)
		return
	}
	logReceiver, err := f.CreateLogs(ctx, settings, config, lr)
	if err != nil {
		log.Printf("Failed to create logs receiver otlp: %v", err)
		return
	}

	if err = metricReceiver.Start(ctx, nil); err != nil {
		log.Printf("oteld start metrics err=%v", err)
		return
	}
	if err = traceReceiver.Start(ctx, nil); err != nil {
		log.Printf("oteld start traces err=%v", err)
		return
	}
	if err = logReceiver.Start(ctx, nil); err != nil {
		log.Printf("oteld start logs err=%v", err)
		return
	}

	timer := time.NewTicker(time.Minute)
	lastSave := int64(0)
	for {
		select {
		case <-ctx.Done():
			if metricReceiver != nil {
				metricReceiver.Shutdown(ctx)
			}
			if traceReceiver != nil {
				traceReceiver.Shutdown(ctx)
			}
			if logReceiver != nil {
				logReceiver.Shutdown(ctx)
			}
			datastore.SaveOTelMetric()
			traceMap.Clear()
			log.Printf("stop oteld")
			return
		case <-timer.C:
			{
				setOTelFrom()
				delList := []string{}
				saveList := []*datastore.OTelTraceEnt{}
				et := time.Now().Add(time.Duration(-datastore.Config.OTelRetention-1) * time.Hour).UnixNano()
				maxLast := int64(0)
				traceMap.Range(func(key any, value any) bool {
					if t, ok := value.(*datastore.OTelTraceEnt); ok {
						if t.Last < et {
							delList = append(delList, key.(string))
						}
						if t.Last > lastSave {
							if maxLast < t.Last {
								maxLast = t.Last
							}
							saveList = append(saveList, t)
						}
					}
					return true
				})
				if len(saveList) > 0 {
					lastSave = maxLast
					datastore.UpdateOTelTrace(saveList)
				}
				if len(delList) > 0 {
					for _, tid := range delList {
						traceMap.Delete(tid)
					}
					log.Printf("delete otel trace len=%d ", len(delList))
				}
			}
		}
	}
}

const (
	defaultTracesURLPath  = "/v1/traces"
	defaultMetricsURLPath = "/v1/metrics"
	defaultLogsURLPath    = "/v1/logs"
)

func createOTelConfig() *otlpreceiver.Config {

	grpcCfg := configgrpc.NewDefaultServerConfig()
	grpcCfg.ReadBufferSize = 512 * 1024
	if datastore.Config.OTelgRPCPort > 0 {
		grpcCfg.NetAddr.Endpoint = fmt.Sprintf(":%d", datastore.Config.OTelgRPCPort)
	}

	httpCfg := confighttp.NewDefaultServerConfig()
	if datastore.Config.OTelHTTPPort > 0 {
		httpCfg.Endpoint = fmt.Sprintf(":%d", datastore.Config.OTelHTTPPort)
	}
	httpCfg.WriteTimeout = 0
	httpCfg.ReadHeaderTimeout = 0
	httpCfg.IdleTimeout = 0

	if datastore.Config.OTelCert != "" && datastore.Config.OTelKey != "" {
		tlsConfig := configtls.NewDefaultServerConfig()
		tlsConfig.CertFile = datastore.Config.OTelCert
		tlsConfig.KeyFile = datastore.Config.OTelKey

		if datastore.Config.OTelCA != "" {
			tlsConfig.CAFile = datastore.Config.OTelCA
			log.Println("otlp mTLS")
		} else {
			log.Println("otlp TLS")
		}
		httpCfg.TLS = configoptional.Some(tlsConfig)
		grpcCfg.TLS = configoptional.Some(tlsConfig)

	} else {
		httpCfg.TLS = configoptional.None[configtls.ServerConfig]()
		log.Println("otlp not TLS")
	}
	if datastore.Config.OTelgRPCPort > 0 {
		if datastore.Config.OTelHTTPPort > 0 {
			return &otlpreceiver.Config{
				Protocols: otlpreceiver.Protocols{
					GRPC: configoptional.Some(grpcCfg),
					HTTP: configoptional.Some(otlpreceiver.HTTPConfig{
						ServerConfig:   httpCfg,
						TracesURLPath:  defaultTracesURLPath,
						MetricsURLPath: defaultMetricsURLPath,
						LogsURLPath:    defaultLogsURLPath,
					}),
				},
			}
		}
		return &otlpreceiver.Config{
			Protocols: otlpreceiver.Protocols{
				GRPC: configoptional.Some(grpcCfg),
			},
		}
	}
	return &otlpreceiver.Config{
		Protocols: otlpreceiver.Protocols{
			HTTP: configoptional.Some(otlpreceiver.HTTPConfig{
				ServerConfig:   httpCfg,
				TracesURLPath:  defaultTracesURLPath,
				MetricsURLPath: defaultMetricsURLPath,
				LogsURLPath:    defaultLogsURLPath,
			}),
		},
	}
}

func setOTelFrom() {
	a := strings.Split(datastore.Config.OTelFrom, ",")
	otelFromMap.Clear()
	limitFrom = false
	for _, f := range a {
		if f != "" {
			otelFromMap.Store(f, true)
			limitFrom = true
		}
	}
}

func handleMetrics(ctx context.Context, md pmetric.Metrics) error {
	f := client.FromContext(ctx)
	service := "unknown"
	host := f.Addr.String()
	if limitFrom {
		if _, ok := otelFromMap.Load(host); !ok {
			return nil
		}
	}
	for _, rm := range md.ResourceMetrics().All() {
		if v, ok := rm.Resource().Attributes().Get("host.name"); ok {
			host = v.AsString()
		}
		if v, ok := rm.Resource().Attributes().Get("service.name"); ok {
			service = v.AsString()
		}
		for _, sm := range rm.ScopeMetrics().All() {
			for _, m := range sm.Metrics().All() {
				metric := datastore.FindOTelMetric(host, service, sm.Scope().Name(), m.Name())
				if metric != nil {
					metric.Count++
					metric.Last = time.Now().UnixNano()
				} else {
					metric = &datastore.OTelMetricEnt{
						Host:        host,
						Service:     service,
						Scope:       sm.Scope().Name(),
						Name:        m.Name(),
						Type:        m.Type().String(),
						First:       time.Now().UnixNano(),
						Last:        time.Now().UnixNano(),
						Description: m.Description(),
						Unit:        m.Unit(),
						Count:       1,
					}
					datastore.AddOTelMetric(metric)
					reporter.CountOTel("metrics")
				}
				addDataPoints(metric, &m)
			}
		}
	}
	return nil
}

func handleTraces(ctx context.Context, td ptrace.Traces) error {
	f := client.FromContext(ctx)
	host := f.Addr.String()
	if limitFrom {
		if _, ok := otelFromMap.Load(host); !ok {
			return nil
		}
	}
	service := "unknown"
	for _, rs := range td.ResourceSpans().All() {
		if v, ok := rs.Resource().Attributes().Get("service.name"); ok {
			service = v.AsString()
		}
		if v, ok := rs.Resource().Attributes().Get("host.name"); ok {
			host = v.AsString()
		}
		for _, ss := range rs.ScopeSpans().All() {
			scope := ss.Scope().Name()
			for _, s := range ss.Spans().All() {
				tid := s.TraceID().String()
				var trace *datastore.OTelTraceEnt
				if v, ok := traceMap.Load(tid); ok {
					if p, ok := v.(*datastore.OTelTraceEnt); ok {
						trace = p
					}
				}
				if trace == nil {
					trace = &datastore.OTelTraceEnt{
						TraceID: tid,
						Spans:   []datastore.OTelTraceSpanEnt{},
					}
					traceMap.Store(tid, trace)
					reporter.CountOTel("trace")
				}
				st := s.StartTimestamp().AsTime().UnixNano()
				et := s.EndTimestamp().AsTime().UnixNano()
				dur := float64(et-st) / (1000.0 * 1000.0 * 1000.0)
				trace.Spans = append(trace.Spans, datastore.OTelTraceSpanEnt{
					Name:         s.Name(),
					Service:      service,
					Host:         host,
					Scope:        scope,
					Attributes:   getAttributes(s.Attributes().AsRaw()),
					SpanID:       s.SpanID().String(),
					ParentSpanID: s.ParentSpanID().String(),
					Start:        st,
					End:          et,
					Dur:          dur,
				})
				if trace.Start == 0 || trace.Start > st {
					trace.Start = st
				}
				if trace.End < et {
					trace.End = et
				}
				if trace.Dur < dur {
					trace.Dur = dur
				}
				trace.Last = time.Now().UnixNano()
			}
		}
	}
	return nil
}

func handleLogs(ctx context.Context, ld plog.Logs) error {
	f := client.FromContext(ctx)
	host := f.Addr.String()
	if limitFrom {
		if _, ok := otelFromMap.Load(host); !ok {
			return nil
		}
	}
	logs := []*datastore.LogEnt{}
	service := "unknown"
	for _, rl := range ld.ResourceLogs().All() {
		if v, ok := rl.Resource().Attributes().Get("host.name"); ok {
			host = v.AsString()
		}
		if v, ok := rl.Resource().Attributes().Get("service.name"); ok {
			service = v.AsString()
		}
		for _, sl := range rl.ScopeLogs().All() {
			scope := sl.Scope().Name()

			for _, l := range sl.LogRecords().All() {
				otelLogEnt := datastore.OTelLogEnt{
					Host:           host,
					Service:        service,
					Scope:          scope,
					TraceID:        l.TraceID().String(),
					SpanID:         l.SpanID().String(),
					Event:          l.EventName(),
					SeverityText:   l.SeverityText(),
					SeverityNumber: int(l.SeverityNumber()),
					Body:           l.Body().AsString(),
				}
				if j, err := json.Marshal(&otelLogEnt); err == nil {
					logEnt := &datastore.LogEnt{
						Time: l.Timestamp().AsTime().UnixNano(),
						Type: datastore.OTelLog,
						Src:  host,
						Log:  string(j),
					}
					logs = append(logs, logEnt)
					auditor.Audit(logEnt)
					reporter.SendOTel(&otelLogEnt)
				}
			}
		}
	}
	if len(logs) > 0 {
		st := time.Now()
		datastore.SaveLogs("otelLog", logs)
		log.Printf("save otel logs len=%d dur=%v", len(logs), time.Since(st))
	}
	return nil
}

func addDataPoints(metric *datastore.OTelMetricEnt, m *pmetric.Metric) {
	metric.DataPoints = []*datastore.OTelMetricDataPointEnt{}
	t := m.Type().String()
	switch t {
	case "Histogram":
		for _, h := range m.Histogram().DataPoints().All() {
			dp := &datastore.OTelMetricDataPointEnt{
				Start:          h.StartTimestamp().AsTime().UnixNano(),
				Time:           h.Timestamp().AsTime().UnixNano(),
				Attributes:     getAttributes(h.Attributes().AsRaw()),
				Count:          h.Count(),
				BucketCounts:   h.BucketCounts().AsRaw(),
				ExplicitBounds: h.ExplicitBounds().AsRaw(),
			}
			if h.HasSum() {
				dp.Sum = h.Sum()
			}
			if h.HasMin() {
				dp.Min = h.Min()
			}
			if h.HasMax() {
				dp.Max = h.Max()
			}
			metric.DataPoints = append(metric.DataPoints, dp)
		}
	case "Sum":
		for _, s := range m.Sum().DataPoints().All() {
			dp := &datastore.OTelMetricDataPointEnt{
				Start:      s.StartTimestamp().AsTime().UnixNano(),
				Time:       s.Timestamp().AsTime().UnixNano(),
				Attributes: getAttributes(s.Attributes().AsRaw()),
			}
			switch s.ValueType().String() {
			case "Double":
				dp.Sum = s.DoubleValue()
			case "Int":
				dp.Sum = float64(s.IntValue())
			}
			metric.DataPoints = append(metric.DataPoints, dp)
		}
	case "Gauge":
		for _, g := range m.Gauge().DataPoints().All() {
			dp := &datastore.OTelMetricDataPointEnt{
				Start:      g.StartTimestamp().AsTime().UnixNano(),
				Time:       g.Timestamp().AsTime().UnixNano(),
				Attributes: getAttributes(g.Attributes().AsRaw()),
			}
			switch g.ValueType().String() {
			case "Double":
				dp.Gauge = g.DoubleValue()
			case "Int":
				dp.Gauge = float64(g.IntValue())
			}
			metric.DataPoints = append(metric.DataPoints, dp)
		}
	case "ExponentialHistogram":
		for _, eh := range m.ExponentialHistogram().DataPoints().All() {
			dp := &datastore.OTelMetricDataPointEnt{
				Start:      eh.StartTimestamp().AsTime().UnixNano(),
				Time:       eh.Timestamp().AsTime().UnixNano(),
				Attributes: getAttributes(eh.Attributes().AsRaw()),
				Count:      eh.Count(),
				Positive:   eh.Positive().BucketCounts().AsRaw(),
				Negative:   eh.Negative().BucketCounts().AsRaw(),
			}
			if eh.HasSum() {
				dp.Sum = eh.Sum()
			}
			if eh.HasMin() {
				dp.Min = eh.Min()
			}
			if eh.HasMax() {
				dp.Max = eh.Max()
			}
			metric.DataPoints = append(metric.DataPoints, dp)
		}
	default:
		log.Printf("uknown otel metric type %s %s %s %s", m.Name(), m.Type().String(), m.Unit(), m.Description())
	}
}

func getAttributes(m map[string]any) []string {
	ret := []string{}
	for k, v := range m {
		ret = append(ret, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(ret)
	return ret
}
