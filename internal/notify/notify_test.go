package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

type fakeSender struct {
	mu       sync.Mutex
	got      []Event
	fail     error
	block    chan struct{}
	reliable bool
	closed   bool
}

func (f *fakeSender) Send(ctx context.Context, b []Event) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.got = append(f.got, b...)
	return nil
}
func (f *fakeSender) Reliable() bool { return f.reliable }
func (f *fakeSender) Close() error   { f.closed = true; return nil }
func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func newDispatcher(senders map[string]*fakeSender) *Dispatcher {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), map[string]Factory{
		store.TargetSyslog: func(t store.Target) (Sender, error) {
			if s := senders[t.Name]; s != nil {
				return s, nil
			}
			return nil, errors.New("no sender")
		},
	})
}

func target(id int64, name string, events ...string) store.Target {
	return store.Target{ID: id, Kind: store.TargetSyslog, Name: name, Enabled: true, Endpoint: "x:1", Events: events, Updated: "1"}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestPublishRoutesAndNeverBlocks(t *testing.T) {
	fast := &fakeSender{}
	slow := &fakeSender{block: make(chan struct{}), reliable: true}
	auditOnly := &fakeSender{}
	d := newDispatcher(map[string]*fakeSender{"fast": fast, "slow": slow, "audit": auditOnly})
	d.Reload([]store.Target{target(1, "fast", "alarm", "audit"), target(2, "slow", "alarm"), target(3, "audit", "audit")})
	defer func() { close(slow.block); d.Close() }()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		d.Publish(Event{Type: TypeAlarm, State: "open", Text: "x"})
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("Publish blocked: %v for 1000 events", el)
	}
	// every event is either delivered or counted as dropped (bounded queue, oldest first)
	waitFor(t, func() bool {
		for _, s := range d.Status() {
			if s.Name == "fast" && uint64(fast.count())+s.Dropped == 1000 && s.Queued == 0 {
				return true
			}
		}
		return false
	})
	if fast.count() < queueSize {
		t.Errorf("fast target got only %d", fast.count())
	}
	fast.mu.Lock()
	fast.got = nil
	fast.mu.Unlock()
	if auditOnly.count() != 0 {
		t.Error("audit-only target got alarms")
	}
	st := d.Status()
	var slowSt Status
	for _, s := range st {
		if s.Name == "slow" {
			slowSt = s
		}
	}
	if slowSt.Queued > queueSize || slowSt.Dropped == 0 {
		t.Errorf("slow target: queued %d dropped %d", slowSt.Queued, slowSt.Dropped)
	}
	d.Publish(Event{Type: TypeAudit, Text: "alex: Spiel eingeschaltet"})
	waitFor(t, func() bool { return auditOnly.count() == 1 })
	// test events only through Test, never through Publish
	d.Publish(Event{Type: TypeTest})
	if err := d.Test(context.Background(), 3, Event{Type: TypeTest, Text: "Test"}); err != nil {
		t.Fatal(err)
	}
	if auditOnly.count() != 2 {
		t.Errorf("audit target has %d events, want 2 (audit + test)", auditOnly.count())
	}
}

func TestReliableRetriesUnreliableDrops(t *testing.T) {
	rel := &fakeSender{fail: errors.New("connection refused"), reliable: true}
	unrel := &fakeSender{fail: errors.New("network unreachable")}
	d := newDispatcher(map[string]*fakeSender{"tcp": rel, "udp": unrel})
	d.Reload([]store.Target{target(1, "tcp", "alarm"), target(2, "udp", "alarm")})
	defer d.Close()
	d.Publish(Event{Type: TypeAlarm, Text: "a"})
	waitFor(t, func() bool {
		for _, s := range d.Status() {
			if s.Name == "udp" && s.Dropped == 1 && s.LastErr != "" {
				return true
			}
		}
		return false
	})
	// the reliable one keeps the event and delivers it once the target is back (retry after ~1-1.5 s)
	rel.mu.Lock()
	rel.fail = nil
	rel.mu.Unlock()
	waitFor(t, func() bool { return rel.count() == 1 })
}

func TestReloadAndStatus(t *testing.T) {
	a := &fakeSender{}
	d := newDispatcher(map[string]*fakeSender{"a": a})
	off := target(2, "b", "alarm")
	off.Enabled = false
	broken := target(3, "c", "alarm") // factory fails
	d.Reload([]store.Target{target(1, "a", "alarm"), off, broken})
	st := d.Status()
	if len(st) != 3 || st[1].State != "off" || st[2].State != "error" || st[2].LastErr == "" {
		t.Fatalf("status %+v", st)
	}
	total, failing, _ := Summary(st)
	if total != 2 || failing != 1 {
		t.Errorf("summary %d/%d", total, failing)
	}
	// removed target: worker stopped and sender closed
	d.Reload(nil)
	if !a.closed || len(d.Status()) != 0 {
		t.Error("worker not stopped on reload")
	}
	if err := d.Test(context.Background(), 1, Event{}); !errors.Is(err, ErrUnknownTarget) {
		t.Errorf("test on removed target: %v", err)
	}
}
