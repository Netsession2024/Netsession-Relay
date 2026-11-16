// Package syslog sends relay events to syslog servers: UDP, TCP or TLS, RFC 5424 (with structured data) or
// RFC 3164. One Sender per target (docs/05-monitoring-konzept.md, 2.2).
package syslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

// Severities (RFC 5424 numbers).
const (
	Warning = 4
	Notice  = 5
	Info    = 6
)

var facilities = map[string]int{"kern": 0, "user": 1, "daemon": 3, "auth": 4, "local0": 16, "local1": 17, "local2": 18,
	"local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}

// Facilities lists the selectable facility names in UI order.
var Facilities = []string{"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "daemon", "user", "auth"}

// Config of one syslog target.
type Config struct {
	Transport     string // udp | tcp | tls
	Format        string // rfc5424 | rfc3164
	Facility      string // local0 ...
	TLSCA         string // PEM, optional
	TLSSkipVerify bool
	Host          string     // HOSTNAME field; "" = os.Hostname()
	Bind          netip.Addr // source address (MGMT); invalid = any
}

// Validate checks the endpoint and the config.
func Validate(endpoint string, c Config) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("syslog target %q: want host:port", endpoint)
	}
	switch c.Transport {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("transport %q", c.Transport)
	}
	switch c.Format {
	case "rfc5424", "rfc3164":
	default:
		return fmt.Errorf("format %q", c.Format)
	}
	if _, ok := facilities[c.Facility]; !ok {
		return fmt.Errorf("facility %q", c.Facility)
	}
	if c.TLSCA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.TLSCA)) {
		return errors.New("TLS CA: no certificate in PEM")
	}
	return nil
}

func severity(s notify.Severity) int {
	switch s {
	case notify.Warn:
		return Warning
	case notify.Notice:
		return Notice
	}
	return Info
}

// sdEscape escapes an SD-PARAM value (RFC 5424 6.3.3).
var sdEscape = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)

// Format5424 renders one RFC 5424 message with structured data [nsrelay@PEN ...].
func Format5424(e notify.Event, host, facility string) string {
	if host == "" {
		host = "-"
	}
	params := []string{"msgid=\"" + e.MsgID() + "\""}
	add := func(k, v string) {
		if v != "" {
			params = append(params, k+"=\""+sdEscape.Replace(v)+"\"")
		}
	}
	add("state", e.State)
	add("kind", e.Kind)
	add("key", e.Key)
	if e.VLAN > 0 {
		add("vlan", fmt.Sprint(e.VLAN))
	}
	add("action", e.Action)
	add("user", e.User)
	add("object", e.Object)
	sd := fmt.Sprintf("[nsrelay@%d %s]", notify.PEN, strings.Join(params, " "))
	msg := strings.ReplaceAll(e.Text, "\n", " ")
	return fmt.Sprintf("<%d>1 %s %s nsrelay %d %s %s %s", facilities[facility]*8+severity(e.Severity),
		e.Time.UTC().Format(time.RFC3339Nano), host, os.Getpid(), e.MsgID(), sd, msg)
}

// Format3164 renders one BSD-style message (local time, no structured data), at most 1024 bytes.
func Format3164(e notify.Event, host, facility string) string {
	if host == "" {
		host = "-"
	}
	msg := fmt.Sprintf("<%d>%s %s nsrelay[%d]: %s: %s", facilities[facility]*8+severity(e.Severity),
		e.Time.Local().Format(time.Stamp), host, os.Getpid(), e.MsgID(), strings.ReplaceAll(e.Text, "\n", " "))
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	return msg
}

// Sender is one syslog target. TCP and TLS keep their connection and reconnect after an error.
type Sender struct {
	endpoint string
	c        Config
	host     string
	tlsConf  *tls.Config

	mu   sync.Mutex
	conn net.Conn
}

// NewSender builds the sender of a target (no connection yet).
func NewSender(endpoint string, c Config) (*Sender, error) {
	if err := Validate(endpoint, c); err != nil {
		return nil, err
	}
	s := &Sender{endpoint: endpoint, c: c, host: c.Host}
	if s.host == "" {
		s.host, _ = os.Hostname()
	}
	if c.Transport == "tls" {
		host, _, _ := net.SplitHostPort(endpoint)
		s.tlsConf = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.TLSSkipVerify} //nolint:gosec // explicit, shown in the UI
		if c.TLSCA != "" {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(c.TLSCA))
			s.tlsConf.RootCAs = pool
		}
	}
	return s, nil
}

// Reliable: TCP and TLS confirm delivery to the kernel of the receiver, UDP does not.
func (s *Sender) Reliable() bool { return s.c.Transport != "udp" }

func (s *Sender) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if s.c.Bind.IsValid() {
		if s.c.Transport == "udp" {
			d.LocalAddr = &net.UDPAddr{IP: s.c.Bind.AsSlice()}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: s.c.Bind.AsSlice()}
		}
	}
	return d
}

func (s *Sender) connect(ctx context.Context) (net.Conn, error) {
	if s.conn != nil {
		return s.conn, nil
	}
	d := s.dialer()
	var conn net.Conn
	var err error
	switch s.c.Transport {
	case "tls":
		conn, err = (&tls.Dialer{NetDialer: d, Config: s.tlsConf}).DialContext(ctx, "tcp", s.endpoint)
	case "tcp":
		conn, err = d.DialContext(ctx, "tcp", s.endpoint)
	default:
		conn, err = d.DialContext(ctx, "udp", s.endpoint)
	}
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

func (s *Sender) frame(e notify.Event) []byte {
	msg := Format5424(e, s.host, s.c.Facility)
	if s.c.Format == "rfc3164" {
		msg = Format3164(e, s.host, s.c.Facility)
	} else if s.c.Transport == "udp" && len(msg) > 2048 {
		msg = msg[:2048]
	}
	switch s.c.Transport {
	case "tls":
		return []byte(fmt.Sprintf("%d %s", len(msg), msg)) // octet counting, RFC 5425
	case "tcp":
		return []byte(msg + "\n") // non-transparent framing, RFC 6587
	}
	return []byte(msg)
}

// Send writes the batch; on a write error the connection is dropped and rebuilt with the next batch.
func (s *Sender) Send(ctx context.Context, batch []notify.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	for _, e := range batch {
		if _, err := conn.Write(s.frame(e)); err != nil {
			_ = conn.Close()
			s.conn = nil
			return err
		}
	}
	return nil
}

// Close drops the connection.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
