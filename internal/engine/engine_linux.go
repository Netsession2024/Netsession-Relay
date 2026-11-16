//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/netif"
	"github.com/Netsession2024/Netsession-Relay/internal/pkt"
)

const readTimeout = 500 * time.Millisecond

// receiver owns one packet socket and its goroutine.
type receiver struct {
	sock *packetSock
	vid  int
	stop atomic.Bool
	done chan struct{}
}

// state is swapped atomically on every snapshot change.
type state struct {
	table *Table
	out   []*packetSock // out[i] = socket of table.VLANs[i]
	index map[*packetSock]int
}

// Engine runs the data plane from a snapshot file.
type Engine struct {
	Path      string // snapshot file (active.json)
	Socket    string // engine API socket; empty = no API
	SocketGID int    // group of the socket (-1 = unchanged)
	Version   string
	Log       *slog.Logger
	Counters  Counters

	mu        sync.Mutex // serialises apply
	receivers map[string]*receiver
	st        atomic.Pointer[state]
	wg        sync.WaitGroup
	guard     *Guard
	mcast     *memberships
	alarmLog  map[string]time.Time
	started   time.Time
	selfTest  []string
	rates     atomic.Pointer[rateSample]
	prevRates rateSample
}

// rateSample holds per-second rates computed in everySecond.
type rateSample struct {
	rx, sent uint64
	vlanIn   map[int]uint64 // VID -> cumulative in (for the next delta)
	rxRate   uint64
	sentRate uint64
	vlanRate map[int]uint64
	lastIn   map[int]time.Time // VID -> when the in counter last grew
}

// Guard returns the protection state (alarms, standby) for status output.
func (e *Engine) Guard() *Guard { return e.guard }

// Run loads the snapshot, sets up interfaces and sockets and relays until ctx is cancelled.
// SIGHUP reloads the snapshot file.
func (e *Engine) Run(ctx context.Context) error {
	if e.Log == nil {
		e.Log = slog.Default()
	}
	e.receivers = map[string]*receiver{}
	e.guard = NewGuard(nil)
	e.mcast = newMemberships()
	e.alarmLog = map[string]time.Time{}
	e.started = time.Now()
	e.selfTest = netif.SelfTest()
	for _, f := range e.selfTest {
		e.Log.Warn("host self-test", "finding", f)
	}
	switch err := e.Reload(); {
	case errors.Is(err, os.ErrNotExist):
		e.Log.Warn("no snapshot yet, waiting for apply via the engine API", "path", e.Path)
	case err != nil:
		return err
	}
	if e.Socket != "" {
		go func() {
			if err := engineapi.Serve(ctx, e.Socket, e.SocketGID, e); err != nil {
				e.Log.Error("engine API stopped", "socket", e.Socket, "err", err)
			}
		}()
		e.Log.Info("engine API listening", "socket", e.Socket)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	stats := time.NewTicker(30 * time.Second)
	defer stats.Stop()
	second := time.NewTicker(time.Second)
	defer second.Stop()
	e.sendBeacons()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			e.shutdown()
			e.logStats()
			return nil
		case <-hup:
			if err := e.Reload(); err != nil {
				e.Log.Error("reload failed, keeping previous snapshot", "err", err)
			}
		case <-stats.C:
			e.logStats()
		case <-second.C:
			e.everySecond(n)
		}
	}
}

// Reload reads the snapshot file and applies it.
func (e *Engine) Reload() error {
	s, err := compile.ReadSnapshotFile(e.Path)
	if err != nil {
		return err
	}
	return e.apply(s)
}

// Validate checks a snapshot without touching interfaces (engine API).
func (e *Engine) Validate(s *compile.Snapshot) error {
	if s.Version != compile.SnapshotVersion {
		return fmt.Errorf("snapshot version %d, engine supports %d", s.Version, compile.SnapshotVersion)
	}
	if _, err := NewTable(s, nil); err != nil {
		return err
	}
	for _, v := range s.VLANs {
		if v.Attach == compile.AttachTrunk {
			if _, err := net.InterfaceByName(v.Parent); err != nil {
				return fmt.Errorf("VLAN %d: trunk interface %q: %w", v.VID, v.Parent, err)
			}
		} else if _, err := net.InterfaceByName(v.Device); err != nil {
			return fmt.Errorf("VLAN %d: interface %q: %w", v.VID, v.Device, err)
		}
	}
	return nil
}

// Apply applies a snapshot and persists it as the start configuration (engine API). If applying fails the
// previous snapshot stays active and on disk.
func (e *Engine) Apply(s *compile.Snapshot) error {
	if err := e.Validate(s); err != nil {
		return err
	}
	if err := e.apply(s); err != nil {
		return err
	}
	return compile.WriteSnapshotFile(e.Path, s)
}

// Players lists recent discovery senders (engine API).
func (e *Engine) Players() []engineapi.Player {
	list := e.guard.Players.List()
	out := make([]engineapi.Player, len(list))
	for i, p := range list {
		out[i] = engineapi.Player(p)
	}
	return out
}

// Ack acknowledges all alarms of a kind (engine API).
func (e *Engine) Ack(kind, by string) int {
	n := e.guard.Alarms.Ack(kind, by, time.Now())
	e.Log.Info("alarm acknowledged", "kind", kind, "by", by, "alarms", n)
	return n
}

// FinderStart starts a port finder session (engine API).
func (e *Engine) FinderStart(req engineapi.FinderStart) error {
	fr := FinderRequest{VIDs: req.VIDs, Duration: time.Duration(req.Seconds) * time.Second}
	if req.Src != "" {
		a, err := netip.ParseAddr(req.Src)
		if err != nil || !a.Is4() {
			return fmt.Errorf("bad sender address %q", req.Src)
		}
		fr.Src = a
	}
	if err := e.guard.Finder.Start(fr, time.Now()); err != nil {
		return err
	}
	e.Log.Info("port finder started", "vids", req.VIDs, "src", req.Src, "seconds", req.Seconds)
	return nil
}

// FinderStop ends the port finder session (engine API).
func (e *Engine) FinderStop() {
	e.guard.Finder.Stop(time.Now())
	e.Log.Info("port finder stopped")
}

// Finder reports the port finder state (engine API).
func (e *Engine) Finder() engineapi.FinderStatus {
	return FinderAPI(e.guard.Finder.Status(time.Now()))
}

// FinderPcap writes the capture of the last session (engine API).
func (e *Engine) FinderPcap(w io.Writer) error { return e.guard.Finder.WritePcap(w) }

// Status reports the engine state (engine API).
func (e *Engine) Status() engineapi.Status {
	st := engineapi.Status{Version: e.Version, Started: e.started, Standby: e.guard.Standby(),
		RX: e.Counters.RX.Load(), Sent: e.Counters.Sent.Load(),
		Reasons: e.Counters.ReasonCounts(), SelfTest: e.selfTest}
	if cur := e.st.Load(); cur != nil {
		snap := cur.table.Snapshot
		st.Mode, st.SnapshotHash, st.VLANs, st.Rules = snap.Mode, snap.Hash, len(snap.VLANs), len(snap.Rules)
		st.Sending = e.guard.Sending(time.Now()) && snap.Mode == compile.ModeActive
		for _, r := range cur.table.RuleStats() {
			st.RuleStats = append(st.RuleStats, engineapi.RuleStat{ID: r.ID, RX: r.RX, Relayed: r.Relayed})
		}
		rs := e.rates.Load()
		for _, v := range cur.table.VLANs {
			vs := engineapi.VLANStat{VID: v.VID, Name: v.Name, Group: v.Group, Interface: netif.LinkName(v.VLAN),
				In: e.Counters.VLANIn[v.VID&4095].Load(), Out: e.Counters.VLANOut[v.VID&4095].Load()}
			if rs != nil {
				vs.InRate, vs.LastIn = rs.vlanRate[v.VID], rs.lastIn[v.VID]
			}
			st.VLANStats = append(st.VLANStats, vs)
		}
		if rs != nil {
			st.RXRate, st.SentRate = rs.rxRate, rs.sentRate
		}
	}
	for _, a := range e.guard.Alarms.List() {
		st.Alarms = append(st.Alarms, engineapi.Alarm(a))
	}
	st.TopUnknown = topUnknown(&e.Counters, 10)
	return st
}

func topUnknown(c *Counters, n int) []engineapi.PortCount {
	var out []engineapi.PortCount
	for p := range c.UnknownPorts {
		if v := c.UnknownPorts[p].Load(); v > 0 {
			out = append(out, engineapi.PortCount{Port: uint16(p), Count: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// apply sets up interfaces and sockets for the snapshot and swaps the lookup table. VLANs that stay are not
// interrupted; removed VLANs lose their receiver and engine-created interface.
func (e *Engine) apply(s *compile.Snapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	macs := map[int]pkt.MAC{}
	links := map[int]netif.Link{}
	keep := map[string]bool{}
	for _, v := range s.VLANs {
		l, err := netif.Ensure(v)
		if err != nil {
			return err
		}
		links[v.VID] = l
		macs[v.VID] = l.MAC
		keep[l.Name] = true
	}
	tb, err := NewTable(s, macs)
	if err != nil {
		return err
	}
	for i := range tb.VLANs {
		tb.VLANs[i].Ifindex = links[tb.VLANs[i].VID].Index
	}
	// open sockets for new interfaces; their receivers start only after the new state is in place
	var starting []*receiver
	for _, v := range s.VLANs {
		l := links[v.VID]
		if r, ok := e.receivers[l.Name]; ok && r.sock.ifindex == l.Index {
			r.vid = v.VID
			continue
		}
		sock, err := openPacketSock(l.Name, l.Index, readTimeout)
		if err != nil {
			for _, r := range starting { // not started yet: just close
				r.sock.close()
				delete(e.receivers, r.sock.name)
			}
			return err
		}
		r := &receiver{sock: sock, vid: v.VID, done: make(chan struct{})}
		e.receivers[l.Name] = r
		starting = append(starting, r)
	}
	st := &state{table: tb, out: make([]*packetSock, len(tb.VLANs)), index: map[*packetSock]int{}}
	for i, v := range tb.VLANs {
		r := e.receivers[links[v.VID].Name]
		st.out[i] = r.sock
		st.index[r.sock] = i
	}
	old := e.st.Swap(st)
	for _, r := range starting {
		e.wg.Add(1)
		go e.receive(r)
	}
	if err := e.mcast.sync(tb); err != nil {
		e.Log.Warn("multicast membership", "err", err)
	}
	// stop receivers of removed interfaces (after the swap, so nothing sends to them any more)
	for name, r := range e.receivers {
		if !keep[name] {
			r.stop.Store(true)
			<-r.done
			r.sock.close()
			delete(e.receivers, name)
		}
	}
	deleted, err := netif.Cleanup(keep)
	if err != nil {
		e.Log.Warn("interface cleanup", "err", err)
	}
	oldHash := ""
	if old != nil {
		oldHash = old.table.Snapshot.Hash
	}
	e.Log.Info("snapshot applied", "hash", short(s.Hash), "previous", short(oldHash), "mode", s.Mode,
		"vlans", len(s.VLANs), "rules", len(s.Rules), "removed_links", deleted)
	return nil
}

func (e *Engine) receive(r *receiver) {
	defer e.wg.Done()
	defer close(r.done)
	buf := make([]byte, 2048)
	p := NewProcessor(&e.Counters, e.guard)
	for !r.stop.Load() {
		n, ok, err := r.sock.read(buf)
		if err != nil {
			if !r.stop.Load() {
				e.Log.Error("receive", "if", r.sock.name, "err", err)
				time.Sleep(time.Second)
			}
			continue
		}
		if !ok {
			continue
		}
		if n >= pkt.EthHeaderLen && buf[12] == BeaconEtherType>>8 && buf[13] == BeaconEtherType&0xff {
			if b, ok := ParseBeacon(buf[:n]); ok && e.guard.SeeBeacon(b, time.Now()) {
				e.Log.Warn("dual-active guard: another active relay started earlier, going to STANDBY",
					"if", r.sock.name, "peer_started", time.Unix(0, b.Started).UTC())
			}
			continue
		}
		// Receivers start before the first state is swapped in (apply opens sockets first): no state yet
		// means the frame arrived during the first apply and is skipped. Found on the live network on
		// 2026-11-16, where broadcasts arrive constantly.
		st := e.st.Load()
		if st == nil {
			continue
		}
		in, known := st.index[r.sock]
		if !known {
			continue
		}
		e.processSafe(p, st, in, buf[:n])
	}
}

// processSafe handles one frame; a panic is logged and counted instead of taking down the whole engine.
func (e *Engine) processSafe(p *Processor, st *state, in int, frame []byte) {
	defer func() {
		if r := recover(); r != nil {
			e.Counters.Reasons[DropParse].Add(1)
			e.Log.Error("panic while processing a frame (frame dropped)", "panic", r, "vlan_index", in, "len", len(frame))
		}
	}()
	p.Process(st.table, in, frame, func(out int, b []byte) error {
		return st.out[out].write(b)
	})
}

// everySecond runs the storm brake, the dual-active timeout, beacons, alarm logging and bucket GC.
func (e *Engine) everySecond(n int) {
	now := time.Now()
	st := e.st.Load()
	if st == nil {
		return
	}
	e.sampleRates(st)
	if id := e.guard.StormTick(st.table, &e.Counters, now); id != "" {
		e.Log.Error("storm brake: rule auto-paused for 60 s", "rule", id)
	}
	if e.guard.PeerTick(now) {
		e.Log.Warn("dual-active guard: earlier relay silent, leaving standby")
	}
	e.sendBeacons()
	for _, a := range e.guard.Alarms.List() {
		k := a.Kind + "|" + a.Key
		if last, ok := e.alarmLog[k]; !ok || (a.Last.After(last) && now.Sub(last) >= time.Minute) {
			e.Log.Warn("alarm", "kind", a.Kind, "key", a.Key, "count", a.Count, "detail", a.Detail)
			e.alarmLog[k] = now
		}
	}
	if n%60 == 0 {
		e.guard.GC(now)
		e.guard.Players.GC(now)
	}
}

func (e *Engine) sampleRates(st *state) {
	now := time.Now()
	cur := rateSample{rx: e.Counters.RX.Load(), sent: e.Counters.Sent.Load(), vlanIn: map[int]uint64{}, vlanRate: map[int]uint64{},
		lastIn: map[int]time.Time{}}
	prev := e.prevRates
	if prev.vlanIn != nil {
		cur.rxRate, cur.sentRate = cur.rx-prev.rx, cur.sent-prev.sent
	}
	for _, v := range st.table.VLANs {
		in := e.Counters.VLANIn[v.VID&4095].Load()
		cur.vlanIn[v.VID] = in
		if t, ok := prev.lastIn[v.VID]; ok {
			cur.lastIn[v.VID] = t
		}
		if p, ok := prev.vlanIn[v.VID]; ok {
			cur.vlanRate[v.VID] = in - p
			if in > p {
				cur.lastIn[v.VID] = now
			}
		} else if in > 0 {
			cur.lastIn[v.VID] = now
		}
	}
	e.prevRates = cur
	e.rates.Store(&cur)
}

// sendBeacons announces this engine on every VLAN (dual-active guard, docs/02-plan.md 4.4).
func (e *Engine) sendBeacons() {
	st := e.st.Load()
	if st == nil {
		return
	}
	b := e.guard.MyBeacon(st.table.Snapshot)
	for i, v := range st.table.VLANs {
		if err := st.out[i].write(BuildBeacon(v.MAC, b)); err != nil {
			e.Log.Debug("beacon", "vlan", v.VID, "err", err)
		}
	}
}

func (e *Engine) shutdown() {
	e.mcast.close()
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, r := range e.receivers {
		r.stop.Store(true)
		<-r.done
		r.sock.close()
		delete(e.receivers, name)
	}
	e.wg.Wait()
	// interfaces stay: a restart re-adopts them without flapping the links
}

func (e *Engine) logStats() {
	st := e.st.Load()
	if st == nil {
		return
	}
	attrs := []any{"rx", e.Counters.RX.Load(), "sent", e.Counters.Sent.Load(), "standby", e.guard.Standby()}
	for k, v := range e.Counters.ReasonCounts() {
		attrs = append(attrs, k, v)
	}
	e.Log.Info("stats", attrs...)
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ErrNotSupported is returned by Run on non-Linux systems.
var ErrNotSupported = errors.New("engine: only supported on Linux")
