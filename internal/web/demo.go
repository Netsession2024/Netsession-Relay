package web

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
)

// DemoEngine is a fake engine for working on the UI without a relay host (nsrelay web -demo). It accepts
// snapshots like the real engine and invents plausible, changing traffic: busy and silent tables, counters per
// rule, unknown ports and alarms that come and go. It never touches the network.
type DemoEngine struct {
	mu      sync.Mutex
	started time.Time
	last    time.Time
	snap    *compile.Snapshot
	rx      uint64
	sent    uint64
	vlanIn  map[int]float64
	vlanOut map[int]float64
	ruleRX  map[string]float64
	ruleTX  map[string]float64
	reasons map[string]float64
	unknown map[uint16]float64
	acked   map[string]string // alarm kind -> who acknowledged
	finder  demoFinder
}

// NewDemoEngine returns a demo engine without a snapshot.
func NewDemoEngine() *DemoEngine {
	now := time.Now()
	return &DemoEngine{started: now.Add(-3*time.Hour - 12*time.Minute), last: now, vlanIn: map[int]float64{}, vlanOut: map[int]float64{},
		ruleRX: map[string]float64{}, ruleTX: map[string]float64{}, reasons: map[string]float64{}, unknown: map[uint16]float64{}, acked: map[string]string{}}
}

// Validate accepts every snapshot.
func (d *DemoEngine) Validate(_ context.Context, s *compile.Snapshot) (engineapi.Result, error) {
	return engineapi.Result{OK: true, Hash: s.Hash}, nil
}

// Apply stores the snapshot; mode, VLANs and rules of the status follow it.
func (d *DemoEngine) Apply(_ context.Context, s *compile.Snapshot) (engineapi.Result, error) {
	d.mu.Lock()
	d.snap = s
	d.mu.Unlock()
	return engineapi.Result{OK: true, Hash: s.Hash}, nil
}

// Ack marks a demo alarm kind as seen (until it stops and comes back).
func (d *DemoEngine) Ack(_ context.Context, kind, by string) error {
	d.mu.Lock()
	d.acked[kind] = by
	d.mu.Unlock()
	return nil
}

// Players invents a few searching and hosting PCs on the first rules.
func (d *DemoEngine) Players(context.Context) ([]engineapi.Player, error) {
	d.mu.Lock()
	s := d.snap
	d.mu.Unlock()
	if s == nil || len(s.Rules) == 0 || len(s.VLANs) < 3 {
		return nil, nil
	}
	now := time.Now()
	var out []engineapi.Player
	for i := 0; i < 6 && i < len(s.Rules); i++ {
		v := s.VLANs[1+i%(len(s.VLANs)-1)]
		ip := v.CIDR.Addr().As4()
		ip[3] = byte(100 + i*7)
		out = append(out, engineapi.Player{Rule: s.Rules[i].ID, Src: netip.AddrFrom4(ip), VID: v.VID,
			First: now.Add(-time.Duration(3+i*4) * time.Minute), Last: now.Add(-time.Duration(i) * time.Second), Count: uint64(40 + i*13)})
	}
	// a game server scanner in the last network (like a Discord notifier): .99 queries many games
	last := s.VLANs[len(s.VLANs)-1]
	ip := last.CIDR.Addr().As4()
	ip[3] = 99
	for i := 6; i < 12 && i < len(s.Rules); i++ {
		out = append(out, engineapi.Player{Rule: s.Rules[i].ID, Src: netip.AddrFrom4(ip), VID: last.VID,
			First: now.Add(-9 * time.Minute), Last: now.Add(-time.Duration(40+i) * time.Second), Count: 3})
	}
	return out, nil
}

// wave is a slow, repeatable pseudo-random value in 0..1 for a slot (VLAN, rule) at a time.
func wave(slot int, t float64) float64 {
	v := math.Sin(t/17+float64(slot)*1.7)*0.5 + math.Sin(t/5.3+float64(slot)*0.9)*0.3 + math.Sin(t/1.9+float64(slot)*2.3)*0.2
	return (v + 1) / 2
}

// Status advances the simulation to now and reports it.
func (d *DemoEngine) Status(context.Context) (engineapi.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	dt := now.Sub(d.last).Seconds()
	d.last = now
	t := now.Sub(d.started).Seconds()
	st := engineapi.Status{Version: "demo", Started: d.started, Reasons: map[string]uint64{}}
	if d.snap == nil {
		return st, nil
	}
	s := d.snap
	st.Mode, st.SnapshotHash, st.VLANs, st.Rules = s.Mode, s.Hash, len(s.VLANs), len(s.Rules)
	sending := s.Mode == compile.ModeActive
	st.Sending = sending

	// FlatOut is the busiest, the first two rules follow, every third rule sees a little traffic
	var rxRate, sentRate float64
	for i, r := range s.Rules {
		var rate float64
		flatout := slices.ContainsFunc(r.Specs, func(id string) bool { return strings.HasPrefix(id, "flatout") })
		switch {
		case flatout:
			rate = 12 + 40*wave(i, t)
		case i < 2:
			rate = 4 + 20*wave(i, t)
		case i%3 == 0:
			rate = 9 * wave(i, t) * wave(i+40, t)
			if rate < 1.5 {
				rate = 0
			}
		}
		d.ruleRX[r.ID] += rate * dt
		rxRate += rate
		if sending {
			copies := rate * float64(max(len(s.VLANs)-1, 1))
			d.ruleTX[r.ID] += copies * dt
			sentRate += copies
		}
		st.RuleStats = append(st.RuleStats, engineapi.RuleStat{ID: r.ID, RX: uint64(d.ruleRX[r.ID]), Relayed: uint64(d.ruleTX[r.ID])})
	}

	// tables: some loud, some silent now and then, table 9 silent all the time
	var vlanSum float64
	rates := make([]float64, len(s.VLANs))
	for i, v := range s.VLANs {
		w := wave(v.VID, t)
		rate := 40 * w * w
		if i%7 == 4 || w < 0.18 {
			rate = 0
		}
		rates[i] = rate
		vlanSum += rate
	}
	noise := 6 + 10*wave(99, t) // broadcasts without a rule
	for i, v := range s.VLANs {
		if vlanSum > 0 {
			rates[i] = rates[i] / vlanSum * (rxRate + noise)
		}
		d.vlanIn[v.VID] += rates[i] * dt
		if sending {
			d.vlanOut[v.VID] += (rxRate - rates[i]*rxRate/(rxRate+noise)) * dt
		}
		st.VLANStats = append(st.VLANStats, engineapi.VLANStat{VID: v.VID, Name: v.Name, Group: v.Group, Interface: fmt.Sprintf("%s.%d", v.Parent, v.VID),
			In: uint64(d.vlanIn[v.VID]), Out: uint64(d.vlanOut[v.VID]), InRate: uint64(rates[i] + 0.5), LastIn: time.Now()})
	}
	d.rx += uint64((rxRate + noise) * dt)
	d.sent += uint64(sentRate * dt)
	st.RX, st.Sent = d.rx, d.sent
	st.RXRate, st.SentRate = uint64(rxRate+noise+0.5), uint64(sentRate+0.5)

	d.reasons["unknown_port"] += noise * 0.7 * dt
	d.reasons["not_broadcast"] += noise * 0.3 * dt
	if !sending {
		d.reasons["mode"] += rxRate * dt
	} else {
		d.reasons["rate"] += 0.05 * rxRate * dt
	}
	for k, v := range d.reasons {
		if v >= 1 {
			st.Reasons[k] = uint64(v)
		}
	}
	for i, p := range []uint16{25601, 17500, 54915, 3702} {
		d.unknown[p] += noise * dt / float64(2+i*3)
		if n := uint32(d.unknown[p]); n > 0 {
			st.TopUnknown = append(st.TopUnknown, engineapi.PortCount{Port: p, Count: n})
		}
	}

	// alarms: a foreign relay in two VLANs for 50 s of every 90 s, a storm brake for 25 s of every 150 s
	phase := int(t) % 90
	if phase < 50 && len(s.VLANs) > 3 {
		for _, v := range s.VLANs[2:4] {
			st.Alarms = append(st.Alarms, engineapi.Alarm{Kind: "foreign_relay", Key: fmt.Sprint(v.VID), Count: uint64(40 + phase*3),
				Detail: fmt.Sprintf("VLAN %d bekommt Kopien von 10.10.254.51 (02:00:00:00:00:51)", v.VID),
				First:  now.Add(-time.Duration(phase) * time.Second), Last: now})
		}
	}
	if p := int(t) % 150; p > 100 && p < 125 && len(s.Rules) > 0 {
		st.Alarms = append(st.Alarms, engineapi.Alarm{Kind: "storm", Key: s.Rules[0].ID, Count: uint64(p - 100),
			Detail: fmt.Sprintf("Regel %s: mehr als 500 Pakete/s, pausiert für 30 s", s.Rules[0].ID),
			First:  now.Add(-time.Duration(p-100) * time.Second), Last: now})
	}
	for i := range st.Alarms {
		if by, ok := d.acked[st.Alarms[i].Kind]; ok {
			st.Alarms[i].AckedAt, st.Alarms[i].AckedBy = now, by
		}
	}
	if len(st.Alarms) == 0 {
		d.acked = map[string]string{} // all quiet: the next incident is open again
	}
	return st, nil
}
