// Package engine is the packet data plane: per-packet decisions (this file, portable and unit-tested on every
// OS) and the Linux runtime with AF_PACKET sockets (engine_linux.go).
//
// Processing order per received frame (docs/02-plan.md, 4.3):
//
//  1. frame from an own or partner MAC                -> drop own_mac
//  2. DHCP ports 67/68, source 0.0.0.0                 -> drop blocked
//  3. source IP not in the ingress VLAN's network      -> drop foreign_relay (in another VLAN's network) or src_subnet
//  4. look up the rule by (broadcast | multicast group, destination port); none -> count unknown port
//  5. target VLANs from the rule's flows (never the ingress VLAN)
//  6. payload size 1..payload_max
//  7. same datagram seen on another VLAN within dedup_ms -> drop loop (alarm)
//  8. token buckets per (rule, source IP, port) and per ingress VLAN -> drop rate
//  9. rule auto-paused by the storm brake -> drop auto_paused
//     engine not sending (observe/paused mode, standby, start holdoff) -> drop mode
//  10. fan-out: build one frame per target VLAN
package engine

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/pkt"
)

// Reason is why a frame was not relayed (or Relayed).
type Reason int

// Reasons. Keep in sync with reasonNames.
const (
	Relayed Reason = iota
	DropParse
	DropOwnMAC
	DropBlocked
	DropForeignRelay
	DropSrcSubnet
	DropNotBroadcast
	DropUnknownPort
	DropNoTarget
	DropSize
	DropTTL
	DropMode // engine in observe/paused/standby/holdoff: nothing is sent
	DropLoop
	DropRate
	DropAutoPaused
	numReasons
)

var reasonNames = [numReasons]string{
	"relayed", "parse", "own_mac", "blocked", "foreign_relay", "src_subnet", "not_broadcast",
	"unknown_port", "no_target", "size", "ttl", "mode", "loop", "rate", "auto_paused",
}

func (r Reason) String() string {
	if r < 0 || r >= numReasons {
		return fmt.Sprintf("reason(%d)", int(r))
	}
	return reasonNames[r]
}

// VLANRuntime is a snapshot VLAN plus what the runtime learned about its interface.
type VLANRuntime struct {
	compile.VLAN
	Index     int // position in Table.VLANs
	Ifindex   int // kernel interface index (0 in unit tests)
	MAC       pkt.MAC
	Broadcast netip.Addr // directed broadcast of CIDR
}

type ruleRT struct {
	compile.Rule
	group netip.Addr // multicast only
	// targets[in] = VLAN indexes a frame arriving on VLAN in is sent to
	targets     [][]int
	rx          atomic.Uint64
	relayed     atomic.Uint64
	pausedUntil atomic.Int64 // storm brake, unix nanos
}

type mcastKey struct {
	group netip.Addr
	port  uint16
}

// Table is the immutable lookup structure built from a snapshot. The engine swaps tables atomically.
type Table struct {
	Snapshot *compile.Snapshot
	VLANs    []VLANRuntime
	Mode     string

	ownMACs   map[pkt.MAC]bool
	broadcast [65536]*ruleRT
	multicast map[mcastKey]*ruleRT
	rules     []*ruleRT
}

// NewTable builds the lookup table. macs maps VLAN ID -> interface MAC (from the runtime; may be empty in tests).
func NewTable(s *compile.Snapshot, macs map[int]pkt.MAC) (*Table, error) {
	t := &Table{Snapshot: s, Mode: s.Mode, ownMACs: map[pkt.MAC]bool{}, multicast: map[mcastKey]*ruleRT{}}
	groupVLANs := map[string][]int{}
	for i, v := range s.VLANs {
		rt := VLANRuntime{VLAN: v, Index: i, MAC: macs[v.VID], Broadcast: pkt.SubnetBroadcast(v.CIDR)}
		t.VLANs = append(t.VLANs, rt)
		groupVLANs[v.Group] = append(groupVLANs[v.Group], i)
		if rt.MAC != (pkt.MAC{}) {
			t.ownMACs[rt.MAC] = true
		}
	}
	for _, p := range s.Peers {
		for _, m := range p.MACs {
			hw, err := parseMAC(m)
			if err != nil {
				return nil, fmt.Errorf("peer %s: %w", p.Name, err)
			}
			t.ownMACs[hw] = true
		}
	}
	for _, r := range s.Rules {
		rt := &ruleRT{Rule: r, targets: make([][]int, len(t.VLANs))}
		for in, v := range t.VLANs {
			seen := map[int]bool{}
			for _, e := range r.Flows {
				if e.Src != v.Group {
					continue
				}
				for _, out := range groupVLANs[e.Dst] {
					if out != in && !seen[out] {
						seen[out] = true
						rt.targets[in] = append(rt.targets[in], out)
					}
				}
			}
		}
		ps, err := parsePorts(r.Ports)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		switch r.Kind {
		case gamedb.KindBroadcast:
			for _, p := range ps {
				if t.broadcast[p] != nil {
					return nil, fmt.Errorf("rule %s: port %d already used by %s", r.ID, p, t.broadcast[p].ID)
				}
				t.broadcast[p] = rt
			}
		case gamedb.KindMulticast:
			g, err := netip.ParseAddr(r.Group)
			if err != nil || !g.Is4() || !g.IsMulticast() {
				return nil, fmt.Errorf("rule %s: bad group %q", r.ID, r.Group)
			}
			rt.group = g
			for _, p := range ps {
				t.multicast[mcastKey{g, p}] = rt
			}
		default:
			return nil, fmt.Errorf("rule %s: kind %q", r.ID, r.Kind)
		}
		t.rules = append(t.rules, rt)
	}
	return t, nil
}

// Counters are engine-wide statistics. All fields are safe for concurrent use.
type Counters struct {
	RX           atomic.Uint64
	Sent         atomic.Uint64 // frames sent (one received frame may produce several)
	Reasons      [numReasons]atomic.Uint64
	UnknownPorts [65536]atomic.Uint32 // broadcasts on ports without a rule (port finder, phase 8)
	VLANIn       [4096]atomic.Uint64  // frames received per VLAN ID (after the kernel filter)
	VLANOut      [4096]atomic.Uint64  // frames sent per VLAN ID
}

// Emit sends a built frame out of the VLAN with the given table index. The frame buffer is only valid
// during the call.
type Emit func(vlanIndex int, frame []byte) error

// Processor handles frames for one receive goroutine. It owns a reusable output buffer and is not safe
// for concurrent use; create one per goroutine.
type Processor struct {
	C   *Counters
	G   *Guard // nil: steps 7-9 and the dual-active guard are skipped (unit tests of the basic pipeline)
	buf []byte
}

// NewProcessor returns a processor that counts into c and protects with g.
func NewProcessor(c *Counters, g *Guard) *Processor {
	return &Processor{C: c, G: g, buf: make([]byte, 0, 2048)}
}

// Process decides about one frame received on VLAN index in and calls emit for every target VLAN.
// It returns the reason for the frame as a whole (Relayed if at least one copy was sent).
func (p *Processor) Process(t *Table, in int, frame []byte, emit Emit) Reason {
	p.C.RX.Add(1)
	if vid := t.VLANs[in].VID; vid > 0 && vid < 4096 {
		p.C.VLANIn[vid].Add(1)
	}
	r := p.process(t, in, frame, emit)
	p.C.Reasons[r].Add(1)
	return r
}

func (p *Processor) process(t *Table, in int, frame []byte, emit Emit) Reason {
	f, err := pkt.Parse(frame)
	if err != nil {
		return DropParse
	}
	// 1. own or partner frames
	if t.ownMACs[f.SrcMAC] {
		return DropOwnMAC
	}
	// 2. fixed block list
	if f.DstPort == 67 || f.DstPort == 68 || f.SrcPort == 67 || f.SrcPort == 68 || f.Src.IsUnspecified() {
		return DropBlocked
	}
	vin := &t.VLANs[in]
	// 3. source subnet
	if !vin.CIDR.Contains(f.Src) {
		for i := range t.VLANs {
			if i != in && t.VLANs[i].CIDR.Contains(f.Src) {
				if p.G != nil {
					p.G.Alarms.Raise(AlarmForeignRelay, fmt.Sprintf("%d", vin.VID), p.G.Now(),
						"VLAN %d (%s) receives frames from %s (network of VLAN %d): another relay is active",
						vin.VID, vin.Name, f.Src, t.VLANs[i].VID)
				}
				return DropForeignRelay
			}
		}
		return DropSrcSubnet
	}
	// 4. rule lookup
	var rule *ruleRT
	switch {
	case f.Dst.IsMulticast():
		rule = t.multicast[mcastKey{f.Dst, f.DstPort}]
	case f.Dst == pkt.LimitedBroadcast || f.Dst == vin.Broadcast:
		rule = t.broadcast[f.DstPort]
		if rule == nil {
			p.C.UnknownPorts[f.DstPort].Add(1)
		}
	default:
		return DropNotBroadcast
	}
	if p.G != nil && p.G.Finder.active.Load() {
		id := ""
		if rule != nil {
			id = rule.ID
		}
		p.G.Finder.Observe(vin.VID, &f, frame, id, p.G.Now())
	}
	if rule == nil {
		return DropUnknownPort
	}
	rule.rx.Add(1)
	if p.G != nil {
		p.G.Players.Seen(rule.ID, f.Src, vin.VID, p.G.Now())
	}
	// 5. targets
	targets := rule.targets[in]
	if len(targets) == 0 {
		return DropNoTarget
	}
	// 6. size
	if len(f.Payload) == 0 || len(f.Payload) > rule.PayloadMax {
		return DropSize
	}
	if rule.TTLMode == gamedb.TTLDecrement {
		if f.TTL <= 1 {
			return DropTTL
		}
		f.TTL--
	}
	if g := p.G; g != nil {
		now := g.Now()
		// 7. loop detection across VLANs
		if dms := t.Snapshot.Limits.DedupMS; dms > 0 && g.SeenElsewhere(&f, in, now, time.Duration(dms)*time.Millisecond) {
			g.Alarms.Raise(AlarmLoop, rule.ID, now, "same datagram from %s:%d seen on several VLANs (loop or second relay)", f.Src, f.SrcPort)
			return DropLoop
		}
		// 8. rate limits
		if !g.AllowFlow(rule.ID, f.Src, f.DstPort, rule.RatePPS, rule.RateBurst, now) {
			return DropRate
		}
		vr, vb := cmpOr(vin.RatePPS, t.Snapshot.Limits.VLANPPS), cmpOr(vin.Burst, t.Snapshot.Limits.VLANBurst)
		if !g.AllowVLAN(vin.VID, vr, vb, now) {
			return DropRate
		}
		// 9. storm brake
		if rule.pausedUntil.Load() > now.UnixNano() {
			return DropAutoPaused
		}
		if !g.Sending(now) {
			return DropMode
		}
	}
	if t.Mode != compile.ModeActive {
		return DropMode
	}
	// 10. fan-out
	sent := false
	limited := f.Dst == pkt.LimitedBroadcast
	orig := f
	for _, out := range targets {
		vout := &t.VLANs[out]
		f = orig
		f.SrcMAC = vout.MAC
		if rule.Kind == gamedb.KindMulticast {
			f.DstMAC = pkt.MulticastMAC(f.Dst)
		} else {
			f.DstMAC = pkt.BroadcastMAC
			switch rule.DstMode {
			case gamedb.DstLimited:
				f.Dst = pkt.LimitedBroadcast
			case gamedb.DstSubnet:
				f.Dst = vout.Broadcast
			default: // keep
				if !limited {
					f.Dst = vout.Broadcast
				}
			}
		}
		if rule.SourceMode != gamedb.SourceOriginal && vout.RelayIP.IsValid() {
			f.Src = vout.RelayIP
		}
		b, err := pkt.Build(p.buf, &f)
		if err != nil {
			continue
		}
		p.buf = b[:0]
		if emit(out, b) == nil {
			sent = true
			p.C.Sent.Add(1)
			p.C.VLANOut[vout.VID&4095].Add(1)
		}
	}
	if !sent {
		return DropNoTarget
	}
	rule.relayed.Add(1)
	return Relayed
}

// RuleStats is a per-rule counter snapshot.
type RuleStats struct {
	ID      string
	RX      uint64
	Relayed uint64
}

// RuleStats returns counters of all rules in snapshot order.
func (t *Table) RuleStats() []RuleStats {
	out := make([]RuleStats, 0, len(t.rules))
	for _, r := range t.rules {
		out = append(out, RuleStats{r.ID, r.rx.Load(), r.relayed.Load()})
	}
	return out
}

// ReasonCounts returns the reason counters as a map (for logs and the API).
func (c *Counters) ReasonCounts() map[string]uint64 {
	m := map[string]uint64{}
	for i := range c.Reasons {
		if v := c.Reasons[i].Load(); v > 0 {
			m[Reason(i).String()] = v
		}
	}
	return m
}

func cmpOr(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
