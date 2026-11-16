package web

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
)

// demoFinder fakes a port finder session: a known game, Steam noise and, after a few seconds, an unknown port.
type demoFinder struct {
	req            engineapi.FinderStart
	started, until time.Time
}

// FinderStart starts a fake session.
func (d *DemoEngine) FinderStart(_ context.Context, req engineapi.FinderStart) error {
	if req.Seconds < 1 || req.Seconds > 600 {
		return errors.New("duration must be between 1 s and 10 min")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	d.finder = demoFinder{req: req, started: now, until: now.Add(time.Duration(req.Seconds) * time.Second)}
	return nil
}

// FinderStop ends the fake session.
func (d *DemoEngine) FinderStop(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now := time.Now(); now.Before(d.finder.until) {
		d.finder.until = now
	}
	return nil
}

// Finder reports invented results that grow with the session time.
func (d *DemoEngine) Finder(context.Context) (engineapi.FinderStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f := d.finder
	if f.started.IsZero() {
		return engineapi.FinderStatus{}, nil
	}
	now := time.Now()
	end := now
	if f.until.Before(end) {
		end = f.until
	}
	el := end.Sub(f.started).Seconds()
	st := engineapi.FinderStatus{Active: now.Before(f.until), Started: f.started, Until: f.until, VIDs: f.req.VIDs, Src: f.req.Src}
	vid := 1101
	if len(f.req.VIDs) > 0 {
		vid = f.req.VIDs[0]
	}
	src := netip.MustParseAddr("10.10.1.23")
	if a, err := netip.ParseAddr(f.req.Src); err == nil {
		src = a
	}
	add := func(g engineapi.FinderGroup, after, every float64) {
		if el < after {
			return
		}
		g.Count = uint64((el-after)/every) + 1
		g.First = f.started.Add(time.Duration(after * float64(time.Second)))
		g.Last = g.First.Add(time.Duration(float64(g.Count-1) * every * float64(time.Second)))
		g.Srcs, g.VIDs, g.New = []netip.Addr{src}, []int{vid}, after > 5
		st.Groups = append(st.Groups, g)
		st.Frames += g.Count
	}
	rule := ""
	if d.snap != nil {
		for _, r := range d.snap.Rules {
			if r.Ports == "23757" {
				rule = r.ID
			}
		}
	}
	add(engineapi.FinderGroup{Kind: "broadcast", Port: 27036, MinLen: 42, MaxLen: 42, Sample: []byte("\xff\xff\xff\xff!L_\xa0\x00\x00\x00\x00\x08")}, 0.5, 5)
	add(engineapi.FinderGroup{Kind: "broadcast", Port: 23757, Rule: rule, MinLen: 24, MaxLen: 24, Sample: []byte("FO2\x00query\x00\x00\x00\x01")}, 9, 1)
	add(engineapi.FinderGroup{Kind: "broadcast", Port: 41234, MinLen: 64, MaxLen: 88, Sample: []byte("ZOOM-LAN\x01\x00\x00\x00UC-Host\x00")}, 14, 2)
	st.Captured = int(min(st.Frames, 4000))
	return st, nil
}

// FinderPcap writes an empty capture (pcap header only).
func (d *DemoEngine) FinderPcap(_ context.Context, w io.Writer) error {
	_, err := w.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0})
	return err
}
