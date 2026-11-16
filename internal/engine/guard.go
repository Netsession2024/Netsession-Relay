package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/maphash"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/pkt"
)

// Guard holds the protection state shared by all receive goroutines (docs/02-plan.md 4.3 steps 7-9, 4.4):
// loop detection (dedup), rate limits, storm brake, alarms and the dual-active guard.
// It survives snapshot changes.
type Guard struct {
	Now func() time.Time // injectable clock (tests)

	Instance [16]byte  // random per process
	Started  time.Time // process start, decides who yields on dual-active
	// Holdoff: nothing is sent before Started+Holdoff, so a second engine can see the first one's
	// beacon before it ever relays (default 1.5 s, beacons every second).
	Holdoff time.Duration

	Alarms  Alarms
	Players Players // who searches/hosts which game
	Finder  Finder  // port finder sessions (phase 8)

	dedup   [dedupShards]dedupShard
	buckets [bucketShards]bucketShard
	seed    maphash.Seed

	standby         atomic.Bool
	lastPeerActive  atomic.Int64 // unix nanos
	peerTimeout     time.Duration
	stormOverSecs   int
	lastSent        uint64
	lastRuleRelayed map[string]uint64
}

// NewGuard returns a guard with a fresh instance ID.
func NewGuard(now func() time.Time) *Guard {
	if now == nil {
		now = time.Now
	}
	g := &Guard{Now: now, Started: now(), Holdoff: 1500 * time.Millisecond, seed: maphash.MakeSeed(),
		peerTimeout: 10 * time.Second, lastRuleRelayed: map[string]uint64{}}
	_, _ = rand.Read(g.Instance[:])
	for i := range g.dedup {
		g.dedup[i].m = map[uint64]dedupEntry{}
	}
	for i := range g.buckets {
		g.buckets[i].m = map[bucketKey]*bucket{}
	}
	return g
}

// Sending reports whether the engine may send now (holdoff over and not in standby).
func (g *Guard) Sending(now time.Time) bool {
	return !g.standby.Load() && !now.Before(g.Started.Add(g.Holdoff))
}

// Standby reports whether the dual-active guard has put this engine into standby.
func (g *Guard) Standby() bool { return g.standby.Load() }

// ---- step 7: dedup across VLANs ----

const dedupShards = 32

type dedupEntry struct {
	vlan int
	at   int64
}

type dedupShard struct {
	mu sync.Mutex
	m  map[uint64]dedupEntry
}

// SeenElsewhere records the frame and reports whether the same datagram (source, ports, payload) arrived on
// a different VLAN within window - a loop or a second relay without original-IP marking.
func (g *Guard) SeenElsewhere(f *pkt.Frame, vlan int, now time.Time, window time.Duration) bool {
	var h maphash.Hash
	h.SetSeed(g.seed)
	a := f.Src.As4()
	h.Write(a[:])
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:], f.SrcPort)
	binary.BigEndian.PutUint16(ports[2:], f.DstPort)
	h.Write(ports[:])
	h.Write(f.Payload)
	key := h.Sum64()
	sh := &g.dedup[key%dedupShards]
	ts := now.UnixNano()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if e, ok := sh.m[key]; ok && ts-e.at <= window.Nanoseconds() && e.vlan != vlan {
		return true
	}
	sh.m[key] = dedupEntry{vlan: vlan, at: ts}
	if len(sh.m) > 4096 { // bounded memory: drop expired entries
		for k, e := range sh.m {
			if ts-e.at > window.Nanoseconds() {
				delete(sh.m, k)
			}
		}
	}
	return false
}

// ---- step 8: token buckets ----

const bucketShards = 32

type bucketKey struct {
	rule string
	src  netip.Addr
	port uint16
	vlan int // >0: per-VLAN bucket (rule/src/port empty)
}

type bucket struct {
	tokens float64
	last   int64
}

type bucketShard struct {
	mu sync.Mutex
	m  map[bucketKey]*bucket
}

func (g *Guard) take(k bucketKey, rate, burst int, now time.Time) bool {
	if rate <= 0 {
		return true
	}
	var h maphash.Hash
	h.SetSeed(g.seed)
	h.WriteString(k.rule)
	if k.src.IsValid() { // per-VLAN buckets have no source
		a := k.src.As4()
		h.Write(a[:])
	}
	sh := &g.buckets[(h.Sum64()+uint64(k.port)+uint64(k.vlan))%bucketShards]
	ts := now.UnixNano()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[k]
	if b == nil {
		b = &bucket{tokens: float64(burst), last: ts}
		sh.m[k] = b
	}
	b.tokens += float64(ts-b.last) / 1e9 * float64(rate)
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = ts
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// AllowFlow applies the per (rule, source IP, destination port) bucket.
func (g *Guard) AllowFlow(rule string, src netip.Addr, port uint16, rate, burst int, now time.Time) bool {
	return g.take(bucketKey{rule: rule, src: src, port: port}, rate, burst, now)
}

// AllowVLAN applies the per ingress VLAN bucket.
func (g *Guard) AllowVLAN(vid, rate, burst int, now time.Time) bool {
	return g.take(bucketKey{vlan: vid}, rate, burst, now)
}

// GC removes idle buckets (call about once a minute).
func (g *Guard) GC(now time.Time) {
	for i := range g.buckets {
		sh := &g.buckets[i]
		sh.mu.Lock()
		for k, b := range sh.m {
			if now.UnixNano()-b.last > int64(time.Minute) {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// ---- step 9: storm brake ----

// StormTick is called once per second. If the engine sent more than storm_pps for three consecutive seconds,
// the rule with the highest rate is paused for 60 seconds. It returns the paused rule ID (or "").
func (g *Guard) StormTick(t *Table, c *Counters, now time.Time) string {
	sent := c.Sent.Load()
	delta := sent - g.lastSent
	g.lastSent = sent
	var top *ruleRT
	var topRate uint64
	for _, r := range t.rules {
		v := r.relayed.Load()
		d := v - g.lastRuleRelayed[r.ID]
		g.lastRuleRelayed[r.ID] = v
		if d > topRate {
			top, topRate = r, d
		}
	}
	limit := uint64(t.Snapshot.Limits.StormPPS)
	if limit == 0 || delta <= limit {
		g.stormOverSecs = 0
		return ""
	}
	g.stormOverSecs++
	if g.stormOverSecs < 3 || top == nil {
		return ""
	}
	g.stormOverSecs = 0
	top.pausedUntil.Store(now.Add(60 * time.Second).UnixNano())
	g.Alarms.Raise(AlarmStorm, top.ID, now, "auto-paused for 60 s, %d frames/s total, rule relayed %d/s", delta, topRate)
	return top.ID
}

// ---- dual-active guard ----

// BeaconEtherType is the local-experimental EtherType used for relay beacons (IEEE 802 "local experimental 1").
const BeaconEtherType = 0x88B5

var beaconMagic = [4]byte{'N', 'S', 'R', 'L'}

// Beacon is the payload of a relay beacon frame.
type Beacon struct {
	Instance [16]byte
	Started  int64 // unix nanos
	Active   bool
	Hash     [8]byte // first bytes of the snapshot hash
}

const beaconLen = 4 + 1 + 16 + 8 + 1 + 8

// BuildBeacon returns a broadcast beacon frame sent from mac.
func BuildBeacon(mac pkt.MAC, b Beacon) []byte {
	f := make([]byte, pkt.EthHeaderLen+beaconLen, 64) // padded to minimum frame size by the NIC
	copy(f[0:6], pkt.BroadcastMAC[:])
	copy(f[6:12], mac[:])
	binary.BigEndian.PutUint16(f[12:14], BeaconEtherType)
	p := f[pkt.EthHeaderLen:]
	copy(p[0:4], beaconMagic[:])
	p[4] = 1 // version
	copy(p[5:21], b.Instance[:])
	binary.BigEndian.PutUint64(p[21:29], uint64(b.Started))
	if b.Active {
		p[29] = 1
	}
	copy(p[30:38], b.Hash[:])
	return f
}

// ParseBeacon decodes a beacon frame.
func ParseBeacon(f []byte) (Beacon, bool) {
	var b Beacon
	if len(f) < pkt.EthHeaderLen+beaconLen || binary.BigEndian.Uint16(f[12:14]) != BeaconEtherType {
		return b, false
	}
	p := f[pkt.EthHeaderLen:]
	if !bytes.Equal(p[0:4], beaconMagic[:]) || p[4] != 1 {
		return b, false
	}
	copy(b.Instance[:], p[5:21])
	b.Started = int64(binary.BigEndian.Uint64(p[21:29]))
	b.Active = p[29] == 1
	copy(b.Hash[:], p[30:38])
	return b, true
}

// MyBeacon returns this engine's beacon for the given snapshot.
func (g *Guard) MyBeacon(s *compile.Snapshot) Beacon {
	b := Beacon{Instance: g.Instance, Started: g.Started.UnixNano(),
		Active: s.Mode == compile.ModeActive && !g.standby.Load()}
	copy(b.Hash[:], s.Hash)
	return b
}

// SeeBeacon processes a received beacon. If an active engine that started earlier is seen, this engine goes
// to standby (returns true when that state is entered).
func (g *Guard) SeeBeacon(b Beacon, now time.Time) bool {
	if b.Instance == g.Instance || !b.Active {
		return false
	}
	mine := g.Started.UnixNano()
	earlier := b.Started < mine || (b.Started == mine && bytes.Compare(b.Instance[:], g.Instance[:]) < 0)
	if !earlier {
		return false // the other one yields
	}
	g.lastPeerActive.Store(now.UnixNano())
	if g.standby.CompareAndSwap(false, true) {
		g.Alarms.Raise(AlarmDualActive, "peer", now, "another active relay (started %s) seen, going to standby",
			time.Unix(0, b.Started).UTC().Format(time.RFC3339))
		return true
	}
	return false
}

// PeerTick leaves standby when the earlier engine has been silent for the peer timeout (10 s).
// Returns true when standby is left.
func (g *Guard) PeerTick(now time.Time) bool {
	if !g.standby.Load() {
		return false
	}
	if now.UnixNano()-g.lastPeerActive.Load() > g.peerTimeout.Nanoseconds() {
		g.standby.Store(false)
		return true
	}
	return false
}

// ---- alarms ----

// Alarm kinds.
const (
	AlarmForeignRelay = "foreign_relay"
	AlarmLoop         = "loop"
	AlarmStorm        = "storm"
	AlarmDualActive   = "dual_active"
)

// Alarm is an aggregated alarm (same kind + key). An acknowledged alarm stays acknowledged while it keeps
// occurring; after a quiet gap of ackResetAfter it counts as a new incident and is open again.
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

const ackResetAfter = 60 * time.Second

// Alarms aggregates alarms in memory; the web part persists them (phase 4/7).
type Alarms struct {
	mu sync.Mutex
	m  map[string]*Alarm
}

// Raise records an alarm and reports whether it is new.
func (a *Alarms) Raise(kind, key string, now time.Time, format string, args ...any) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]*Alarm{}
	}
	id := kind + "|" + key
	if x, ok := a.m[id]; ok {
		if !x.AckedAt.IsZero() && now.Sub(x.Last) > ackResetAfter {
			x.AckedAt, x.AckedBy = time.Time{}, "" // quiet gap: a new incident
		}
		x.Last = now
		x.Count++
		return false
	}
	a.m[id] = &Alarm{Kind: kind, Key: key, Detail: sprintf(format, args...), First: now, Last: now, Count: 1}
	return true
}

// Ack acknowledges all alarms of a kind and returns how many were affected.
func (a *Alarms) Ack(kind, by string, now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, x := range a.m {
		if x.Kind == kind {
			x.AckedAt, x.AckedBy = now, by
			n++
		}
	}
	return n
}

// List returns all alarms, newest first.
func (a *Alarms) List() []Alarm {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Alarm, 0, len(a.m))
	for _, x := range a.m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}
