// Package engineapi is the HTTP/JSON API between the web/CLI side and the engine over a Unix socket
// (default /run/nsrelay/engine.sock):
//
//	GET  /v1/status    engine status, counters, rule stats, alarms
//	POST /v1/validate  check a snapshot without applying it
//	POST /v1/apply     apply a snapshot (the engine also writes it to its snapshot file)
//	GET  /v1/events    server-sent events: "status" every 2 s, "alarm" when an alarm appears or repeats
package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
)

// DefaultSocket is the engine socket path.
const DefaultSocket = "/run/nsrelay/engine.sock"

// RuleStat is a per-rule counter.
type RuleStat struct {
	ID      string `json:"id"`
	RX      uint64 `json:"rx"`
	Relayed uint64 `json:"relayed"`
}

// Alarm mirrors engine.Alarm without importing the Linux engine.
type Alarm struct {
	Kind    string    `json:"kind"`
	Key     string    `json:"key"`
	Detail  string    `json:"detail"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Count   uint64    `json:"count"`
	AckedAt time.Time `json:"acked_at"`
	AckedBy string    `json:"acked_by,omitempty"`
}

// Player mirrors engine.Player: a sender of discovery packets for a rule.
type Player struct {
	Rule  string     `json:"rule"`
	Src   netip.Addr `json:"src"`
	VID   int        `json:"vid"`
	First time.Time  `json:"first"`
	Last  time.Time  `json:"last"`
	Count uint64     `json:"count"`
}

// Status is returned by GET /v1/status.
type Status struct {
	Version      string            `json:"version"`
	Started      time.Time         `json:"started"`
	Mode         string            `json:"mode"`    // snapshot mode, "" before the first snapshot
	Standby      bool              `json:"standby"` // dual-active guard
	Sending      bool              `json:"sending"`
	SnapshotHash string            `json:"snapshot_hash"`
	VLANs        int               `json:"vlans"`
	Rules        int               `json:"rules"`
	RX           uint64            `json:"rx"`
	Sent         uint64            `json:"sent"`
	Reasons      map[string]uint64 `json:"reasons"`
	RuleStats    []RuleStat        `json:"rule_stats"`
	Alarms       []Alarm           `json:"alarms"`
	TopUnknown   []PortCount       `json:"top_unknown_ports"`
	RXRate       uint64            `json:"rx_per_s"`   // frames/s received, last second
	SentRate     uint64            `json:"sent_per_s"` // frames/s sent, last second
	VLANStats    []VLANStat        `json:"vlan_stats"`
	SelfTest     []string          `json:"self_test,omitempty"`
}

// VLANStat is per-VLAN traffic.
type VLANStat struct {
	VID       int    `json:"vid"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Interface string `json:"interface"`
	In        uint64 `json:"in"`
	Out       uint64 `json:"out"`
	InRate    uint64 `json:"in_per_s"`
	// LastIn is when the VLAN last received a frame since the engine started (zero: nothing yet).
	LastIn time.Time `json:"last_in"`
}

// PortCount is a broadcast port without rule and how often it was seen.
type PortCount struct {
	Port  uint16 `json:"port"`
	Count uint32 `json:"count"`
}

// Result is returned by validate and apply.
type Result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Hash  string `json:"hash,omitempty"`
}

// Engine is what the server needs from the engine.
type Engine interface {
	Status() Status
	Validate(*compile.Snapshot) error
	Apply(*compile.Snapshot) error
	Players() []Player
	Ack(kind, by string) int
	FinderEngine
}

// Handler returns the HTTP handler for an engine.
func Handler(e Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, e.Status())
	})
	snapshotOp := func(op func(*compile.Snapshot) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var s compile.Snapshot
			if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&s); err != nil {
				writeJSON(w, http.StatusBadRequest, Result{Error: "bad snapshot: " + err.Error()})
				return
			}
			if err := op(&s); err != nil {
				writeJSON(w, http.StatusUnprocessableEntity, Result{Error: err.Error(), Hash: s.Hash})
				return
			}
			writeJSON(w, http.StatusOK, Result{OK: true, Hash: s.Hash})
		}
	}
	mux.HandleFunc("POST /v1/validate", snapshotOp(e.Validate))
	mux.HandleFunc("POST /v1/apply", snapshotOp(e.Apply))
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) { events(w, r, e) })
	mux.HandleFunc("GET /v1/players", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, e.Players())
	})
	mux.HandleFunc("POST /v1/alarms/ack", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Kind, By string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Kind == "" {
			writeJSON(w, http.StatusBadRequest, Result{Error: "kind missing"})
			return
		}
		n := e.Ack(req.Kind, req.By)
		writeJSON(w, http.StatusOK, map[string]int{"acked": n})
	})
	finderRoutes(mux, e)
	return mux
}

func events(w http.ResponseWriter, r *http.Request, e Engine) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	seen := map[string]uint64{}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		st := e.Status()
		for _, a := range st.Alarms {
			k := a.Kind + "|" + a.Key
			if seen[k] != a.Count {
				seen[k] = a.Count
				send(w, "alarm", a)
			}
		}
		st.Alarms = nil
		send(w, "status", st)
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

func send(w io.Writer, event string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Serve listens on the Unix socket path (replacing a stale socket file) until ctx is cancelled.
// The socket gets mode 0660; with gid >= 0 its group is set so the web container (non-root) can use it.
func Serve(ctx context.Context, path string, gid int, e Engine) error {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o660)
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			l.Close()
			return fmt.Errorf("socket group: %w", err)
		}
	}
	srv := &http.Server{Handler: Handler(e), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err = srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Client talks to the engine socket.
type Client struct {
	Socket string
	hc     *http.Client
}

// NewClient returns a client for the socket path.
func NewClient(socket string) *Client {
	return &Client{Socket: socket, hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

// Status fetches the engine status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/v1/status", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return st, fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

// Players fetches the recent discovery senders.
func (c *Client) Players(ctx context.Context) ([]Player, error) {
	var out []Player
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/v1/players", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// Ack acknowledges all alarms of a kind.
func (c *Client) Ack(ctx context.Context, kind, by string) error {
	b, _ := json.Marshal(map[string]string{"Kind": kind, "By": by})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://engine/v1/alarms/ack", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine: %s", resp.Status)
	}
	return nil
}

// Validate asks the engine to check a snapshot.
func (c *Client) Validate(ctx context.Context, s *compile.Snapshot) (Result, error) {
	return c.post(ctx, "/v1/validate", s)
}

// Apply sends a snapshot to the engine.
func (c *Client) Apply(ctx context.Context, s *compile.Snapshot) (Result, error) {
	return c.post(ctx, "/v1/apply", s)
}

func (c *Client) post(ctx context.Context, path string, s *compile.Snapshot) (Result, error) {
	var res Result
	b, err := json.Marshal(s)
	if err != nil {
		return res, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://engine"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return res, fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, fmt.Errorf("engine answer: %w", err)
	}
	return res, nil
}
