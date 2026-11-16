package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// FinderStart starts a port finder session (docs/02-plan.md 6.3).
type FinderStart struct {
	VIDs    []int  `json:"vids"`    // empty: all VLANs
	Src     string `json:"src"`     // optional sender IPv4
	Seconds int    `json:"seconds"` // 1..600
}

// FinderGroup is one destination/port seen during a session.
type FinderGroup struct {
	Kind   string       `json:"kind"`
	Group  string       `json:"group,omitempty"`
	Port   uint16       `json:"port"`
	Rule   string       `json:"rule,omitempty"`
	Count  uint64       `json:"count"`
	First  time.Time    `json:"first"`
	Last   time.Time    `json:"last"`
	MinLen int          `json:"min_len"`
	MaxLen int          `json:"max_len"`
	Srcs   []netip.Addr `json:"srcs"`
	VIDs   []int        `json:"vids"`
	New    bool         `json:"new"`
	Sample []byte       `json:"sample"` // base64 in JSON
}

// FinderStatus is the current or last session.
type FinderStatus struct {
	Active   bool          `json:"active"`
	Started  time.Time     `json:"started"`
	Until    time.Time     `json:"until"`
	VIDs     []int         `json:"vids"`
	Src      string        `json:"src,omitempty"`
	Frames   uint64        `json:"frames"`
	Captured int           `json:"captured"`
	Groups   []FinderGroup `json:"groups"`
}

// FinderEngine is the port finder part of the engine.
type FinderEngine interface {
	FinderStart(FinderStart) error
	FinderStop()
	Finder() FinderStatus
	FinderPcap(io.Writer) error
}

func finderRoutes(mux *http.ServeMux, e FinderEngine) {
	mux.HandleFunc("POST /v1/finder/start", func(w http.ResponseWriter, r *http.Request) {
		var req FinderStart
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, Result{Error: "bad request: " + err.Error()})
			return
		}
		if err := e.FinderStart(req); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, Result{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, Result{OK: true})
	})
	mux.HandleFunc("POST /v1/finder/stop", func(w http.ResponseWriter, r *http.Request) {
		e.FinderStop()
		writeJSON(w, http.StatusOK, Result{OK: true})
	})
	mux.HandleFunc("GET /v1/finder", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, e.Finder())
	})
	mux.HandleFunc("GET /v1/finder/pcap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		_ = e.FinderPcap(w)
	})
}

// FinderStart starts a port finder session.
func (c *Client) FinderStart(ctx context.Context, req FinderStart) error {
	b, _ := json.Marshal(req)
	return c.simplePost(ctx, "/v1/finder/start", b)
}

// FinderStop ends the running session.
func (c *Client) FinderStop(ctx context.Context) error {
	return c.simplePost(ctx, "/v1/finder/stop", nil)
}

func (c *Client) simplePost(ctx context.Context, path string, body []byte) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://engine"+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var res Result
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if res.Error != "" {
			return fmt.Errorf("%s", res.Error)
		}
		return fmt.Errorf("engine: %s", resp.Status)
	}
	return nil
}

// Finder fetches the port finder state.
func (c *Client) Finder(ctx context.Context) (FinderStatus, error) {
	var st FinderStatus
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/v1/finder", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return st, fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

// FinderPcap copies the capture of the last session to w.
func (c *Client) FinderPcap(ctx context.Context, w io.Writer) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/v1/finder/pcap", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("engine not reachable on %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine: %s", resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}
