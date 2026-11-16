package engineapi

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
)

type fake struct {
	applied string
	finder  FinderStart
	stopped bool
}

func (f *fake) FinderStart(r FinderStart) error {
	if r.Seconds > 600 {
		return errors.New("duration must be between 1 s and 10 min")
	}
	f.finder = r
	return nil
}
func (f *fake) FinderStop() { f.stopped = true }
func (f *fake) Finder() FinderStatus {
	return FinderStatus{Active: !f.stopped, Groups: []FinderGroup{{Kind: "broadcast", Port: 4711, Count: 3, Sample: []byte("hi")}}}
}
func (f *fake) FinderPcap(w io.Writer) error { _, err := w.Write([]byte("PCAP")); return err }

func (f *fake) Status() Status {
	return Status{Mode: "active", SnapshotHash: f.applied, Alarms: []Alarm{{Kind: "foreign_relay", Key: "1101", Count: 1}}}
}
func (f *fake) Validate(s *compile.Snapshot) error {
	if s.Mode == "broken" {
		return errors.New("broken snapshot")
	}
	return nil
}
func (f *fake) Players() []Player {
	return []Player{{Rule: "bc:23757", VID: 1101, Count: 3}}
}
func (f *fake) Ack(kind, by string) int {
	if kind == "foreign_relay" {
		return 2
	}
	return 0
}
func (f *fake) Apply(s *compile.Snapshot) error {
	if err := f.Validate(s); err != nil {
		return err
	}
	f.applied = s.Hash
	return nil
}

func TestClientServerOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "e.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fake{}
	go Serve(ctx, sock, -1, f)
	c := NewClient(sock)
	var st Status
	var err error
	for range 50 { // wait for the listener
		if st, err = c.Status(ctx); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || st.Mode != "active" {
		t.Fatalf("status: %+v %v", st, err)
	}
	res, err := c.Apply(ctx, &compile.Snapshot{Version: 1, Mode: "active", Hash: "abc"})
	if err != nil || !res.OK || f.applied != "abc" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	res, err = c.Validate(ctx, &compile.Snapshot{Mode: "broken"})
	if err != nil || res.OK || !strings.Contains(res.Error, "broken") {
		t.Fatalf("validate broken: %+v %v", res, err)
	}

	pl, err := c.Players(ctx)
	if err != nil || len(pl) != 1 || pl[0].Rule != "bc:23757" {
		t.Fatalf("players: %+v %v", pl, err)
	}
	if err := c.Ack(ctx, "foreign_relay", "op"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	if err := c.FinderStart(ctx, FinderStart{VIDs: []int{1101}, Src: "10.10.1.5", Seconds: 900}); err == nil || !strings.Contains(err.Error(), "10 min") {
		t.Fatalf("finder start too long: %v", err)
	}
	if err := c.FinderStart(ctx, FinderStart{VIDs: []int{1101}, Src: "10.10.1.5", Seconds: 300}); err != nil || f.finder.Src != "10.10.1.5" {
		t.Fatalf("finder start: %v %+v", err, f.finder)
	}
	fs, err := c.Finder(ctx)
	if err != nil || !fs.Active || len(fs.Groups) != 1 || string(fs.Groups[0].Sample) != "hi" {
		t.Fatalf("finder: %+v %v", fs, err)
	}
	var pc strings.Builder
	if err := c.FinderPcap(ctx, &pc); err != nil || pc.String() != "PCAP" {
		t.Fatalf("pcap: %q %v", pc.String(), err)
	}
	if err := c.FinderStop(ctx); err != nil || !f.stopped {
		t.Fatalf("finder stop: %v", err)
	}

	// event stream delivers an alarm and a status event
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/v1/events", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var events []string
	for sc.Scan() && len(events) < 2 {
		if strings.HasPrefix(sc.Text(), "event: ") {
			events = append(events, strings.TrimPrefix(sc.Text(), "event: "))
		}
	}
	if len(events) != 2 || events[0] != "alarm" || events[1] != "status" {
		t.Errorf("events = %v", events)
	}
}

func TestClientEngineDown(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "none.sock"))
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("err = %v", err)
	}
}
