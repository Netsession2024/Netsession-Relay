package otlp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

type collector struct {
	collogs.UnimplementedLogsServiceServer
	colmetrics.UnimplementedMetricsServiceServer
	mu      sync.Mutex
	logs    []*logspb.ResourceLogs
	metrics []*metricspb.ResourceMetrics
	auth    []string
}

func (c *collector) Export(ctx context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	md, _ := metadata.FromIncomingContext(ctx)
	c.auth = append(c.auth, md.Get("authorization")...)
	c.logs = append(c.logs, r.ResourceLogs...)
	return &collogs.ExportLogsServiceResponse{}, nil
}

type metricsSrv struct {
	colmetrics.UnimplementedMetricsServiceServer
	c *collector
}

func (m *metricsSrv) Export(_ context.Context, r *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	m.c.metrics = append(m.c.metrics, r.ResourceMetrics...)
	return &colmetrics.ExportMetricsServiceResponse{}, nil
}

func startCollector(t *testing.T) (*collector, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	srv := grpc.NewServer()
	collogs.RegisterLogsServiceServer(srv, c)
	colmetrics.RegisterMetricsServiceServer(srv, &metricsSrv{c: c})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return c, ln.Addr().String()
}

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func report() (monitor.Report, []engineapi.RuleStat) {
	st := engineapi.Status{Version: "1.2.3", Started: t0.Add(-time.Hour), Mode: "active", Sending: true, VLANs: 2, Rules: 3, RX: 1000, Sent: 4000,
		Reasons: map[string]uint64{"unknown_port": 7},
		Alarms:  []engineapi.Alarm{{Kind: "loop", Key: "bc:23757", Count: 2, Last: t0}},
		VLANStats: []engineapi.VLANStat{{VID: 1101, Name: "Tisch 1", Group: "tische", In: 500, Out: 2000, LastIn: t0},
			{VID: 1102, Name: "Tisch 2", Group: "tische", In: 500, Out: 2000, LastIn: t0}}}
	return monitor.Build(st, nil, "web", true, t0), []engineapi.RuleStat{{ID: "bc:23757", RX: 900, Relayed: 800}}
}

func source() []Metric {
	rep, rules := report()
	return FromReport(rep, rules, []notify.Status{{Name: "Zabbix", Kind: "otlp", State: "ok", Sent: 5}}, t0, t0.Add(-time.Minute), true)
}

func attr(kvs []*commonpb.KeyValue, k string) *commonpb.AnyValue {
	for _, kv := range kvs {
		if kv.Key == k {
			return kv.Value
		}
	}
	return nil
}

func TestMetricNamesStable(t *testing.T) {
	var got []string
	for _, m := range source() {
		got = append(got, m.Name)
	}
	want := slices.Clone(MetricNames)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("metric names changed:\n got  %v\n want %v", got, MetricNames)
	}
	rep, _ := report()
	rep.EngineUp = 0
	for _, m := range FromReport(rep, nil, nil, t0, t0, false) {
		if m.Sum {
			t.Errorf("counter %s exported without engine", m.Name)
		}
	}
}

func TestGRPCMetricsAndLogs(t *testing.T) {
	c, addr := startCollector(t)
	res := Resource{ServiceName: "nsrelay", Version: "web", InstanceID: "abc", HostName: "relay01"}
	s, err := NewSender(addr, Config{Protocol: "grpc", Metrics: true, Logs: true, Interval: time.Minute, Resource: res,
		Headers: map[string]string{"Authorization": "Bearer geheim"}}, func(context.Context) []Metric { return source() })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.ExportMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	events := []notify.Event{
		{Time: t0, Type: notify.TypeAlarm, State: "open", Severity: notify.Warn, Kind: "foreign_relay", Key: "1102", VLAN: 1102, Text: "Fremdes Relay aktiv"},
		{Time: t0, Type: notify.TypeAudit, Severity: notify.Warn, Action: "emergency_stop", User: "alex", Text: "alex: Not-Aus ausgelöst"},
		{Time: t0, Type: notify.TypeAudit, Severity: notify.Notice, Action: "game.enable", User: "alex", Object: "flatout2", Text: "alex: Spiel eingeschaltet flatout2"},
	}
	if err := s.Send(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.metrics) < 1 || len(c.logs) != 1 {
		t.Fatalf("got %d metric exports, %d log exports", len(c.metrics), len(c.logs))
	}
	rm := c.metrics[0]
	if attr(rm.Resource.Attributes, "service.name").GetStringValue() != "nsrelay" || attr(rm.Resource.Attributes, "host.name").GetStringValue() != "relay01" {
		t.Errorf("resource %v", rm.Resource.Attributes)
	}
	var rx *metricspb.Metric
	for _, m := range rm.ScopeMetrics[0].Metrics {
		if m.Name == "nsrelay.rx" {
			rx = m
		}
	}
	sum := rx.GetSum()
	if sum == nil || !sum.IsMonotonic || sum.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE ||
		sum.DataPoints[0].GetAsInt() != 1000 || sum.DataPoints[0].StartTimeUnixNano != uint64(t0.Add(-time.Hour).UnixNano()) {
		t.Errorf("nsrelay.rx = %v", rx)
	}
	recs := c.logs[0].ScopeLogs[0].LogRecords
	if recs[0].SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_WARN || recs[0].SeverityText != "WARN" ||
		attr(recs[0].Attributes, "nsrelay.msgid").GetStringValue() != "alarm" || attr(recs[0].Attributes, "vlan").GetIntValue() != 1102 ||
		attr(recs[0].Attributes, "nsrelay.alarm.state").GetStringValue() != "open" || recs[0].Body.GetStringValue() != "Fremdes Relay aktiv" {
		t.Errorf("alarm record %v", recs[0])
	}
	if recs[1].SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_INFO2 || recs[2].SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_INFO ||
		attr(recs[2].Attributes, "nsrelay.audit.object").GetStringValue() != "flatout2" || attr(recs[2].Attributes, "user.name").GetStringValue() != "alex" {
		t.Errorf("audit records %v / %v", recs[1], recs[2])
	}
	if len(c.auth) == 0 || c.auth[0] != "Bearer geheim" {
		t.Errorf("header not sent: %v", c.auth)
	}
}

func TestHTTP(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/logs":
			var req collogs.ExportLogsServiceRequest
			if proto.Unmarshal(body, &req) == nil && r.Header.Get("Content-Type") == "application/x-protobuf" {
				paths[r.URL.Path] += len(req.ResourceLogs[0].ScopeLogs[0].LogRecords)
			}
		case "/v1/metrics":
			var req colmetrics.ExportMetricsServiceRequest
			if proto.Unmarshal(body, &req) == nil {
				paths[r.URL.Path] += len(req.ResourceMetrics[0].ScopeMetrics[0].Metrics)
			}
		}
	}))
	defer srv.Close()
	s, err := NewSender(srv.URL, Config{Protocol: "http", Logs: true, Metrics: true}, func(context.Context) []Metric { return source() })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Send(ctx, []notify.Event{{Time: t0, Type: notify.TypeTest, Text: "Test"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ExportMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if paths["/v1/logs"] != 1 || paths["/v1/metrics"] != len(MetricNames) {
		t.Errorf("http paths %v", paths)
	}
}

func TestCollectorDownDoesNotHang(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there
	s, err := NewSender(addr, Config{Protocol: "grpc", Logs: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Send(ctx, []notify.Event{{Time: t0, Type: notify.TypeTest}}); err == nil {
		t.Error("send to a dead collector succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("send blocked past the deadline")
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []struct {
		ep string
		c  Config
		ok bool
	}{
		{"192.0.2.1:4317", Config{Protocol: "grpc", Logs: true}, true},
		{"http://192.0.2.1:4318", Config{Protocol: "http", Metrics: true}, true},
		{"192.0.2.1", Config{Protocol: "grpc", Logs: true}, false},
		{"192.0.2.1:4318", Config{Protocol: "http", Logs: true}, false},
		{"192.0.2.1:4317", Config{Protocol: "grpc"}, false},
		{"192.0.2.1:4317", Config{Protocol: "grpc", Logs: true, Headers: map[string]string{"bad name": "x"}}, false},
	} {
		if err := Validate(c.ep, c.c); (err == nil) != c.ok {
			t.Errorf("Validate(%q, %+v) = %v", c.ep, c.c, err)
		}
	}
}
