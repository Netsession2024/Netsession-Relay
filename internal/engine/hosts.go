package engine

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Player is one sender of discovery packets for a rule ("who searches / hosts what").
type Player struct {
	Rule  string     `json:"rule"`
	Src   netip.Addr `json:"src"`
	VID   int        `json:"vid"`
	First time.Time  `json:"first"`
	Last  time.Time  `json:"last"`
	Count uint64     `json:"count"`
}

type playerKey struct {
	rule string
	src  netip.Addr
	vid  int
}

// Players remembers recent discovery senders. Memory is bounded: at most maxPlayers entries, entries silent for
// playerTTL are removed by GC; when full, the oldest entry is replaced.
type Players struct {
	mu sync.Mutex
	m  map[playerKey]*Player
}

const (
	maxPlayers = 8192
	playerTTL  = 15 * time.Minute
)

// Seen records one discovery packet.
func (p *Players) Seen(rule string, src netip.Addr, vid int, now time.Time) {
	k := playerKey{rule, src, vid}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[playerKey]*Player{}
	}
	if e := p.m[k]; e != nil {
		e.Last = now
		e.Count++
		return
	}
	if len(p.m) >= maxPlayers {
		var oldest playerKey
		var at time.Time
		for kk, e := range p.m {
			if at.IsZero() || e.Last.Before(at) {
				oldest, at = kk, e.Last
			}
		}
		delete(p.m, oldest)
	}
	p.m[k] = &Player{Rule: rule, Src: src, VID: vid, First: now, Last: now, Count: 1}
}

// GC removes entries silent for longer than the TTL.
func (p *Players) GC(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.m {
		if now.Sub(e.Last) > playerTTL {
			delete(p.m, k)
		}
	}
}

// List returns all entries, most recently active first.
func (p *Players) List() []Player {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Player, 0, len(p.m))
	for _, e := range p.m {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}
