// Package notify delivers relay events (alarm opened/cleared, audit entries, test messages) to the monitoring
// targets (syslog, OTLP, SNMP traps). Each target has its own bounded queue and goroutine: Publish never blocks,
// a slow or dead target never slows down the web UI or the other targets (docs/05-monitoring-konzept.md, 3).
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// PEN is the IANA Private Enterprise Number used in syslog structured data and the SNMP tree. 32473 is the
// number reserved for documentation (RFC 5612) until Netsession has its own (decision E1).
const PEN = 32473

// Severity of an event; each output maps it to its own scale (syslog severity, OTLP SeverityNumber).
type Severity int

const (
	Info   Severity = iota // test
	Notice                 // audit, alarm cleared
	Warn                   // alarm opened, audit of a dangerous action
)

// Event types.
const (
	TypeAlarm = "alarm"
	TypeAudit = "audit"
	TypeTest  = "test"
)

// Event is one message for the targets.
type Event struct {
	Time     time.Time
	Type     string // alarm | audit | test
	State    string // alarm: open | clear
	Severity Severity
	Kind     string // alarm kind (foreign_relay, loop, storm, dual_active, vlan_silent, engine_down)
	Key      string // alarm key (rule/VLAN)
	VLAN     int    // 0 = no VLAN
	Action   string // audit action, e.g. game.enable
	User     string
	Object   string
	Text     string // finished German sentence
}

// MsgID is the short message id used by syslog and as an OTLP attribute.
func (e Event) MsgID() string { return e.Type }

// Sender delivers events to one target.
type Sender interface {
	Send(ctx context.Context, batch []Event) error
	// Reliable: the transport confirms delivery (TCP, TLS, gRPC, inform). Unreliable senders get one try.
	Reliable() bool
	Close() error
}

// Factory builds the sender of a target.
type Factory func(t store.Target) (Sender, error)

const (
	queueSize  = 256
	batchSize  = 50
	sendTime   = 5 * time.Second
	maxBackoff = 60 * time.Second
	maxAge     = 10 * time.Minute
	failAfter  = 2 * time.Minute // "Fehler" when the last try failed and nothing succeeded for this long
)

// Status is the runtime state of a target (memory only).
type Status struct {
	ID        int64
	Name      string
	Kind      string
	Enabled   bool
	State     string // ok | unconfirmed | error | off | waiting
	LastOK    time.Time
	LastErr   string
	LastErrAt time.Time
	Sent      uint64
	Dropped   uint64
	Queued    int
}

// Failing reports whether the target counts as failing (for the UI and the outputs_failing metric).
func (s Status) Failing() bool { return s.State == "error" }

type worker struct {
	t      store.Target
	sender Sender
	log    *slog.Logger

	mu      sync.Mutex
	queue   []Event
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	lastOK  time.Time
	lastErr string
	errAt   time.Time
	sent    uint64
	dropped uint64
}

func (w *worker) push(ev Event) {
	w.mu.Lock()
	if len(w.queue) >= queueSize {
		w.queue = w.queue[1:] // drop the oldest
		w.dropped++
	}
	w.queue = append(w.queue, ev)
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *worker) run() {
	defer close(w.done)
	backoff := time.Second
	for {
		select {
		case <-w.stop:
			return
		case <-w.wake:
		}
		for {
			w.mu.Lock()
			// events that waited too long are worthless (a dead target for 10 minutes)
			now := time.Now()
			for len(w.queue) > 0 && now.Sub(w.queue[0].Time) > maxAge {
				w.queue = w.queue[1:]
				w.dropped++
			}
			n := min(len(w.queue), batchSize)
			batch := append([]Event(nil), w.queue[:n]...)
			w.mu.Unlock()
			if n == 0 {
				break
			}
			ctx, cancel := context.WithTimeout(context.Background(), sendTime)
			err := w.sender.Send(ctx, batch)
			cancel()
			w.mu.Lock()
			if err == nil || !w.sender.Reliable() {
				// sent, or an unreliable transport: never retried
				w.queue = w.queue[min(n, len(w.queue)):]
			}
			if err != nil {
				w.lastErr, w.errAt = err.Error(), time.Now()
				if !w.sender.Reliable() {
					w.dropped += uint64(n)
				}
			} else {
				w.lastOK = time.Now()
				w.sent += uint64(n)
				backoff = time.Second
			}
			w.mu.Unlock()
			if err != nil && w.sender.Reliable() {
				w.log.Debug("monitoring target", "target", w.t.Name, "err", err)
				wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
				backoff = min(backoff*2, maxBackoff)
				select {
				case <-w.stop:
					return
				case <-time.After(wait):
				}
			}
		}
	}
}

func (w *worker) status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Status{ID: w.t.ID, Name: w.t.Name, Kind: w.t.Kind, Enabled: true, LastOK: w.lastOK, LastErr: w.lastErr,
		LastErrAt: w.errAt, Sent: w.sent, Dropped: w.dropped, Queued: len(w.queue)}
	switch {
	case !w.errAt.IsZero() && w.errAt.After(w.lastOK) && time.Since(w.lastOK) > failAfter:
		st.State = "error"
	case w.lastOK.IsZero() && w.errAt.IsZero():
		st.State = "waiting"
	case !w.sender.Reliable():
		st.State = "unconfirmed"
	default:
		st.State = "ok"
	}
	return st
}

// Dispatcher owns one worker per enabled target.
type Dispatcher struct {
	log       *slog.Logger
	factories map[string]Factory

	mu       sync.Mutex
	workers  map[int64]*worker
	targets  []store.Target
	setupErr map[int64]string // targets whose sender could not be built
}

// New creates a dispatcher; factories maps a target kind to its sender factory.
func New(log *slog.Logger, factories map[string]Factory) *Dispatcher {
	return &Dispatcher{log: log, factories: factories, workers: map[int64]*worker{}, setupErr: map[int64]string{}}
}

// Reload starts, restarts and stops workers so they match targets. A target is restarted when it changed
// (Updated); unchanged targets keep their queue and counters.
func (d *Dispatcher) Reload(targets []store.Target) {
	var stopping []*worker
	// workers are stopped outside the lock: a sender may read the status while it shuts down (OTLP sends
	// a last metrics export)
	defer func() {
		for _, w := range stopping {
			d.stopWorker(w)
		}
	}()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets = targets
	keep := map[int64]bool{}
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		keep[t.ID] = true
		if w := d.workers[t.ID]; w != nil && w.t.Updated == t.Updated {
			continue
		}
		if w := d.workers[t.ID]; w != nil {
			stopping = append(stopping, w)
		}
		delete(d.workers, t.ID)
		delete(d.setupErr, t.ID)
		f := d.factories[t.Kind]
		if f == nil {
			d.setupErr[t.ID] = "Art " + t.Kind + " wird noch nicht unterstützt"
			continue
		}
		s, err := f(t)
		if err != nil {
			d.setupErr[t.ID] = err.Error()
			continue
		}
		w := &worker{t: t, sender: s, log: d.log, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
		d.workers[t.ID] = w
		go w.run()
	}
	for id, w := range d.workers {
		if !keep[id] {
			stopping = append(stopping, w)
			delete(d.workers, id)
		}
	}
}

func (d *Dispatcher) stopWorker(w *worker) {
	close(w.stop)
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
	_ = w.sender.Close()
}

// Publish hands an event to every enabled target that wants its type. It never blocks.
func (d *Dispatcher) Publish(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	d.mu.Lock()
	ws := make([]*worker, 0, len(d.workers))
	for _, w := range d.workers {
		if w.t.Wants(ev.Type) && ev.Type != TypeTest {
			ws = append(ws, w)
		}
	}
	d.mu.Unlock()
	for _, w := range ws {
		w.push(ev)
	}
}

// ErrUnknownTarget is returned by Test for a target that is not running.
var ErrUnknownTarget = errors.New("target not active")

// Test sends one event synchronously to a single target (the "Testen" button) and returns the result.
func (d *Dispatcher) Test(ctx context.Context, id int64, ev Event) error {
	d.mu.Lock()
	w := d.workers[id]
	setup := d.setupErr[id]
	d.mu.Unlock()
	if setup != "" {
		return errors.New(setup)
	}
	if w == nil {
		return ErrUnknownTarget
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ctx, cancel := context.WithTimeout(ctx, sendTime)
	defer cancel()
	err := w.sender.Send(ctx, []Event{ev})
	w.mu.Lock()
	if err != nil {
		w.lastErr, w.errAt = err.Error(), time.Now()
	} else {
		w.lastOK = time.Now()
		w.sent++
	}
	w.mu.Unlock()
	return err
}

// Status returns the state of every configured target (disabled ones as "off").
func (d *Dispatcher) Status() []Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Status, 0, len(d.targets))
	for _, t := range d.targets {
		switch w := d.workers[t.ID]; {
		case !t.Enabled:
			out = append(out, Status{ID: t.ID, Name: t.Name, Kind: t.Kind, State: "off"})
		case d.setupErr[t.ID] != "":
			out = append(out, Status{ID: t.ID, Name: t.Name, Kind: t.Kind, Enabled: true, State: "error", LastErr: d.setupErr[t.ID]})
		case w != nil:
			out = append(out, w.status())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Close stops all workers; queued events get up to 3 s to go out.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	ws := d.workers
	d.workers = map[int64]*worker{}
	d.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for _, w := range ws {
		for time.Now().Before(deadline) {
			w.mu.Lock()
			n := len(w.queue)
			w.mu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		close(w.stop)
		<-w.done
		_ = w.sender.Close()
	}
}

// Summary counts targets for the monitoring report.
func Summary(st []Status) (total, failing int, dropped uint64) {
	for _, s := range st {
		if s.State == "off" {
			continue
		}
		total++
		if s.Failing() {
			failing++
		}
		dropped += s.Dropped
	}
	return
}

// String is used in logs only.
func (e Event) String() string { return fmt.Sprintf("%s/%s %s", e.Type, e.State, e.Text) }
