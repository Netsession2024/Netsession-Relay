package web

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

type fakeCollector struct {
	collogs.UnimplementedLogsServiceServer
	mu   sync.Mutex
	recs []*logspb.LogRecord
	host string
}

func (c *fakeCollector) Export(_ context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rl := range r.ResourceLogs {
		for _, kv := range rl.Resource.Attributes {
			if kv.Key == "host.name" {
				c.host = kv.Value.GetStringValue()
			}
		}
		for _, sl := range rl.ScopeLogs {
			c.recs = append(c.recs, sl.LogRecords...)
		}
	}
	return &collogs.ExportLogsServiceResponse{}, nil
}

type fakeMetrics struct {
	colmetrics.UnimplementedMetricsServiceServer
}

func (fakeMetrics) Export(context.Context, *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	return &colmetrics.ExportMetricsServiceResponse{}, nil
}

func TestOTLPTarget(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeCollector{}
	srv := grpc.NewServer()
	collogs.RegisterLogsServiceServer(srv, c)
	colmetrics.RegisterMetricsServiceServer(srv, fakeMetrics{})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	_ = e.st.SetSetting(ctx, settingHostName, "relay01")
	id, err := e.st.SaveTarget(ctx, "test", store.Target{Kind: store.TargetOTLP, Name: "Collector", Enabled: true,
		Endpoint: ln.Addr().String(), Events: []string{"alarm", "audit"}, Config: map[string]any{"protocol": "grpc"}})
	if err != nil {
		t.Fatal(err)
	}
	e.ui.reloadOutputs(ctx)
	defer e.ui.CloseOutputs()
	if err := e.ui.notify.Test(ctx, id, notify.Event{Type: notify.TypeTest, User: "admin", Text: "Testmeldung von admin"}); err != nil {
		t.Fatal(err)
	}
	var down time.Time
	e.ui.watchOnce(ctx, &down, time.Now()) // foreign_relay of the fake engine opens
	for i := 0; i < 100; i++ {
		c.mu.Lock()
		n := len(c.recs)
		c.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.recs) < 2 || c.host != "relay01" {
		t.Fatalf("collector got %d records, host %q", len(c.recs), c.host)
	}
	if c.recs[1].SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_WARN {
		t.Errorf("alarm record severity %v", c.recs[1].SeverityNumber)
	}
}
