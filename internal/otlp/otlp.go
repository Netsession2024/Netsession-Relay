// Package otlp exports the relay's metrics and events with the OpenTelemetry protocol (OTLP), over gRPC or
// HTTP/protobuf, without the OTel SDK: the monitoring report is converted directly into OTLP messages
// (docs/05-monitoring-konzept.md, 4). One Sender per target.
package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip" // registers the gzip compressor
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

// Resource identifies this relay in every export.
type Resource struct {
	ServiceName string // always "nsrelay"
	Version     string
	InstanceID  string
	HostName    string
}

// Config of one OTLP target.
type Config struct {
	Protocol    string // grpc | http
	TLS         bool
	TLSCA       string
	SkipVerify  bool
	Headers     map[string]string
	Metrics     bool
	Logs        bool
	Interval    time.Duration // metrics; 10 s .. 5 min
	RuleMetrics bool
	Gzip        bool
	Resource    Resource
	Bind        netip.Addr
}

// Source builds the current metrics (called once per interval).
type Source func(ctx context.Context) []Metric

// Validate checks endpoint and config.
func Validate(endpoint string, c Config) error {
	switch c.Protocol {
	case "grpc":
		if h, p, err := net.SplitHostPort(endpoint); err != nil || h == "" || p == "" {
			return fmt.Errorf("OTLP gRPC endpoint %q: want host:port", endpoint)
		}
	case "http":
		u, err := url.Parse(endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("OTLP HTTP endpoint %q: want http(s)://host:port", endpoint)
		}
	default:
		return fmt.Errorf("protocol %q", c.Protocol)
	}
	if !c.Metrics && !c.Logs {
		return errors.New("neither metrics nor logs")
	}
	if c.TLSCA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.TLSCA)) {
		return errors.New("TLS CA: no certificate in PEM")
	}
	for k := range c.Headers {
		if k == "" || strings.ContainsAny(k, " :\r\n") {
			return fmt.Errorf("header name %q", k)
		}
	}
	return nil
}

// Sender is one OTLP target: logs through the notify queue, metrics on its own ticker.
type Sender struct {
	endpoint string
	c        Config
	source   Source

	conn    *grpc.ClientConn
	logsC   collogs.LogsServiceClient
	metC    colmetrics.MetricsServiceClient
	httpC   *http.Client
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	lastErr error // last metrics export result, for Status
	lastOK  time.Time
}

// NewSender builds the sender and starts the metrics ticker (if metrics are enabled).
func NewSender(endpoint string, c Config, source Source) (*Sender, error) {
	if err := Validate(endpoint, c); err != nil {
		return nil, err
	}
	if c.Interval < 10*time.Second {
		c.Interval = 30 * time.Second
	}
	if c.Interval > 5*time.Minute {
		c.Interval = 5 * time.Minute
	}
	if c.Resource.ServiceName == "" {
		c.Resource.ServiceName = "nsrelay"
	}
	s := &Sender{endpoint: endpoint, c: c, source: source, stop: make(chan struct{}), done: make(chan struct{})}
	var tlsConf *tls.Config
	if c.TLS {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.SkipVerify} //nolint:gosec // explicit, shown in the UI
		if c.TLSCA != "" {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(c.TLSCA))
			tlsConf.RootCAs = pool
		}
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if c.Bind.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: c.Bind.AsSlice()}
	}
	if c.Protocol == "grpc" {
		creds := insecure.NewCredentials()
		if tlsConf != nil {
			host, _, _ := net.SplitHostPort(endpoint)
			tlsConf.ServerName = host
			creds = credentials.NewTLS(tlsConf)
		}
		opts := []grpc.DialOption{grpc.WithTransportCredentials(creds),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", addr)
			})}
		if c.Gzip {
			opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor("gzip")))
		}
		conn, err := grpc.NewClient("passthrough:///"+endpoint, opts...) // lazy, reconnects by itself
		if err != nil {
			return nil, err
		}
		s.conn, s.logsC, s.metC = conn, collogs.NewLogsServiceClient(conn), colmetrics.NewMetricsServiceClient(conn)
	} else {
		tr := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: tlsConf, MaxIdleConns: 2, IdleConnTimeout: time.Minute}
		s.httpC = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}
	if c.Metrics && source != nil {
		go s.loop()
	} else {
		close(s.done)
	}
	return s, nil
}

// Reliable: OTLP answers every request.
func (s *Sender) Reliable() bool { return true }

func (s *Sender) loop() {
	defer close(s.done)
	t := time.NewTicker(s.c.Interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.ExportMetrics(ctx) // last state on shutdown
			cancel()
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.ExportMetrics(ctx)
			cancel()
		}
	}
}

// MetricsStatus returns the result of the last metrics export.
func (s *Sender) MetricsStatus() (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastOK, s.lastErr
}

func (s *Sender) withHeaders(ctx context.Context) context.Context {
	if len(s.c.Headers) == 0 {
		return ctx
	}
	kv := make([]string, 0, 2*len(s.c.Headers))
	for k, v := range s.c.Headers {
		kv = append(kv, strings.ToLower(k), v)
	}
	return metadata.AppendToOutgoingContext(ctx, kv...)
}

// ExportMetrics sends the current metrics once.
func (s *Sender) ExportMetrics(ctx context.Context) error {
	req := &colmetrics.ExportMetricsServiceRequest{ResourceMetrics: resourceMetrics(s.c.Resource, s.source(ctx), s.c.RuleMetrics)}
	var err error
	if s.metC != nil {
		var resp *colmetrics.ExportMetricsServiceResponse
		resp, err = s.metC.Export(s.withHeaders(ctx), req)
		if err == nil && resp.GetPartialSuccess().GetRejectedDataPoints() > 0 {
			err = fmt.Errorf("collector rejected %d data points: %s", resp.GetPartialSuccess().GetRejectedDataPoints(), resp.GetPartialSuccess().GetErrorMessage())
		}
	} else {
		err = s.postHTTP(ctx, "/v1/metrics", req)
	}
	s.mu.Lock()
	if err == nil {
		s.lastOK = time.Now()
	}
	s.lastErr = err
	s.mu.Unlock()
	return err
}

// Send exports a batch of events as log records (notify.Sender).
func (s *Sender) Send(ctx context.Context, batch []notify.Event) error {
	if !s.c.Logs {
		return nil
	}
	req := &collogs.ExportLogsServiceRequest{ResourceLogs: resourceLogs(s.c.Resource, batch)}
	if s.logsC != nil {
		resp, err := s.logsC.Export(s.withHeaders(ctx), req)
		if err != nil {
			return err
		}
		if n := resp.GetPartialSuccess().GetRejectedLogRecords(); n > 0 {
			return fmt.Errorf("collector rejected %d log records: %s", n, resp.GetPartialSuccess().GetErrorMessage())
		}
		return nil
	}
	return s.postHTTP(ctx, "/v1/logs", req)
}

func (s *Sender) postHTTP(ctx context.Context, path string, msg proto.Message) error {
	body, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	u := strings.TrimRight(s.endpoint, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	for k, v := range s.c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.httpC.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
}

// Close stops the metrics ticker (after a last export) and the connection.
func (s *Sender) Close() error {
	s.once.Do(func() { close(s.stop) })
	<-s.done
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
