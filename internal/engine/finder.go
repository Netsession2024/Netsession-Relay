package engine

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/pkt"
)

// Port finder limits (docs/02-plan.md 6.3).
const (
	FinderMaxDuration = 10 * time.Minute
	finderMaxGroups   = 512
	finderMaxSrcs     = 8
	finderSampleLen   = 64
	finderMaxFrames   = 4000            // frames kept for the pcap download
	finderMaxBytes    = 4 << 20         // and at most this many bytes
	finderNewAfter    = 5 * time.Second // groups first seen later than this after the start are "new"
)

// FinderRequest starts a sniffer session.
type FinderRequest struct {
	VIDs     []int         // empty: all VLANs
	Src      netip.Addr    // invalid: any sender
	Duration time.Duration // capped at FinderMaxDuration
}

// FinderGroup is all frames of one destination (broadcast or multicast group) and port.
type FinderGroup struct {
	Kind   string // "broadcast" | "multicast"
	Group  string // multicast group, empty for broadcast
	Port   uint16
	Rule   string // rule of the active snapshot, empty: no rule (unknown port)
	Count  uint64
	First  time.Time
	Last   time.Time
	MinLen int
	MaxLen int
	Srcs   []netip.Addr // first finderMaxSrcs senders
	VIDs   []int
	New    bool   // first seen more than finderNewAfter after the start
	Sample []byte // first bytes of the first payload
}

// FinderStatus is the state of the current (or last) session.
type FinderStatus struct {
	Active   bool
	Started  time.Time
	Until    time.Time
	VIDs     []int
	Src      netip.Addr
	Frames   uint64 // frames matching the filter
	Captured int    // frames kept for pcap
	Groups   []FinderGroup
}

type groupKey struct {
	group netip.Addr // zero for broadcast
	port  uint16
}

type capFrame struct {
	ts   time.Time
	data []byte
}

type finderSession struct {
	req     FinderRequest
	started time.Time
	until   time.Time
	vids    map[int]bool
	frames  uint64
	groups  map[groupKey]*FinderGroup
	caps    []capFrame
	bytes   int
}

// Finder records discovery traffic for the port finder. The zero value is ready; Observe costs one atomic
// load while no session runs.
type Finder struct {
	active atomic.Bool
	mu     sync.Mutex
	s      *finderSession
}

// ErrFinderDuration is returned for a session length outside 1 s .. FinderMaxDuration.
var ErrFinderDuration = errors.New("duration must be between 1 s and 10 min")

// Start begins a new session and drops the results of the previous one.
func (f *Finder) Start(req FinderRequest, now time.Time) error {
	if req.Duration < time.Second || req.Duration > FinderMaxDuration {
		return ErrFinderDuration
	}
	s := &finderSession{req: req, started: now, until: now.Add(req.Duration), groups: map[groupKey]*FinderGroup{}}
	if len(req.VIDs) > 0 {
		s.vids = map[int]bool{}
		for _, v := range req.VIDs {
			s.vids[v] = true
		}
	}
	f.mu.Lock()
	f.s = s
	f.mu.Unlock()
	f.active.Store(true)
	return nil
}

// Stop ends the session early; the results stay readable.
func (f *Finder) Stop(now time.Time) {
	f.mu.Lock()
	if f.s != nil && now.Before(f.s.until) {
		f.s.until = now
	}
	f.mu.Unlock()
	f.active.Store(false)
}

// Observe records one parsed frame received on VLAN vid. rule is the matching rule ID or "".
func (f *Finder) Observe(vid int, fr *pkt.Frame, raw []byte, rule string, now time.Time) {
	if !f.active.Load() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.s
	if s == nil {
		return
	}
	if !now.Before(s.until) {
		f.active.Store(false)
		return
	}
	if s.vids != nil && !s.vids[vid] {
		return
	}
	if s.req.Src.IsValid() && fr.Src != s.req.Src {
		return
	}
	s.frames++
	k := groupKey{port: fr.DstPort}
	kind := "broadcast"
	if fr.Dst.IsMulticast() {
		k.group, kind = fr.Dst, "multicast"
	}
	g := s.groups[k]
	if g == nil {
		if len(s.groups) >= finderMaxGroups {
			return
		}
		g = &FinderGroup{Kind: kind, Port: fr.DstPort, Rule: rule, First: now, MinLen: len(fr.Payload),
			New: now.Sub(s.started) > finderNewAfter}
		if k.group.IsValid() {
			g.Group = k.group.String()
		}
		g.Sample = append([]byte(nil), fr.Payload[:min(len(fr.Payload), finderSampleLen)]...)
		s.groups[k] = g
	}
	g.Count++
	g.Last = now
	g.MinLen, g.MaxLen = min(g.MinLen, len(fr.Payload)), max(g.MaxLen, len(fr.Payload))
	if len(g.Srcs) < finderMaxSrcs && !slices.Contains(g.Srcs, fr.Src) {
		g.Srcs = append(g.Srcs, fr.Src)
	}
	if !slices.Contains(g.VIDs, vid) {
		g.VIDs = append(g.VIDs, vid)
	}
	if len(s.caps) < finderMaxFrames && s.bytes+len(raw) <= finderMaxBytes {
		s.caps = append(s.caps, capFrame{ts: now, data: append([]byte(nil), raw...)})
		s.bytes += len(raw)
	}
}

// Status returns a copy of the session state, groups sorted by count.
func (f *Finder) Status(now time.Time) FinderStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.s
	if s == nil {
		return FinderStatus{}
	}
	st := FinderStatus{Active: now.Before(s.until), Started: s.started, Until: s.until, Src: s.req.Src,
		VIDs: slices.Clone(s.req.VIDs), Frames: s.frames, Captured: len(s.caps)}
	for _, g := range s.groups {
		c := *g
		c.Srcs, c.VIDs, c.Sample = slices.Clone(g.Srcs), slices.Clone(g.VIDs), slices.Clone(g.Sample)
		sort.Ints(c.VIDs)
		st.Groups = append(st.Groups, c)
	}
	sort.Slice(st.Groups, func(i, j int) bool {
		a, b := st.Groups[i], st.Groups[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Port < b.Port
	})
	return st
}

// WritePcap writes the captured frames as a classic pcap file (Ethernet link type), readable by Wireshark.
func (f *Finder) WritePcap(w io.Writer) error {
	f.mu.Lock()
	var caps []capFrame
	if f.s != nil {
		caps = slices.Clone(f.s.caps)
	}
	f.mu.Unlock()
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535) // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 1)     // LINKTYPE_ETHERNET
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	rec := make([]byte, 16)
	for _, c := range caps {
		binary.LittleEndian.PutUint32(rec[0:], uint32(c.ts.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(c.ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(c.data)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(c.data)))
		if _, err := w.Write(rec); err != nil {
			return err
		}
		if _, err := w.Write(c.data); err != nil {
			return err
		}
	}
	return nil
}

// FinderAPI converts a finder status for the engine API.
func FinderAPI(st FinderStatus) engineapi.FinderStatus {
	out := engineapi.FinderStatus{Active: st.Active, Started: st.Started, Until: st.Until, VIDs: st.VIDs,
		Frames: st.Frames, Captured: st.Captured, Groups: make([]engineapi.FinderGroup, len(st.Groups))}
	if st.Src.IsValid() {
		out.Src = st.Src.String()
	}
	for i, g := range st.Groups {
		out.Groups[i] = engineapi.FinderGroup(g)
	}
	return out
}
