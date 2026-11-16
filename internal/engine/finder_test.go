package engine

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestFinder(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	tb := newTable(t, testSnapshot(defaultRules()...))
	p := NewProcessor(&Counters{}, g)
	emit := func(int, []byte) error { return nil }

	// no session: nothing recorded
	p.Process(tb, t1, frame("10.10.1.10", "255.255.255.255", 50000, 4711, []byte("x")), emit)
	if st := g.Finder.Status(c.now()); st.Active || len(st.Groups) != 0 {
		t.Fatalf("recorded without session: %+v", st)
	}
	if err := g.Finder.Start(FinderRequest{Duration: 11 * time.Minute}, c.now()); err == nil {
		t.Fatal("11 minutes accepted")
	}
	// session on table 1 only, one sender
	if err := g.Finder.Start(FinderRequest{VIDs: []int{1101}, Src: netip.MustParseAddr("10.10.1.10"), Duration: time.Minute}, c.now()); err != nil {
		t.Fatal(err)
	}
	p.Process(tb, t1, frame("10.10.1.10", "255.255.255.255", 50000, 23757, []byte("FO2-query")), emit) // known rule
	p.Process(tb, t1, frame("10.10.1.10", "10.10.1.255", 50000, 4711, []byte("HELLO-unknown-game")), emit)
	p.Process(tb, t1, frame("10.10.1.11", "255.255.255.255", 50000, 4711, []byte("other sender")), emit) // filtered: src
	p.Process(tb, t2, frame("10.10.2.10", "255.255.255.255", 50000, 4711, []byte("other vlan")), emit)   // filtered: vlan
	c.add(10 * time.Second)
	p.Process(tb, t1, frame("10.10.1.10", "224.0.2.60", 50000, 4445, []byte("[MOTD]x[/MOTD]")), emit) // multicast, new
	p.Process(tb, t1, frame("10.10.1.10", "255.255.255.255", 50000, 4711, []byte("HELLO")), emit)

	st := g.Finder.Status(c.now())
	if !st.Active || st.Frames != 4 || st.Captured != 4 || len(st.Groups) != 3 {
		t.Fatalf("status: active=%v frames=%d captured=%d groups=%d", st.Active, st.Frames, st.Captured, len(st.Groups))
	}
	top := st.Groups[0]
	if top.Port != 4711 || top.Count != 2 || top.Rule != "" || top.MinLen != 5 || top.MaxLen != 18 || top.New ||
		string(top.Sample) != "HELLO-unknown-game" || len(top.VIDs) != 1 || top.VIDs[0] != 1101 {
		t.Errorf("unknown port group: %+v", top)
	}
	var mc, known *FinderGroup
	for i := range st.Groups {
		switch st.Groups[i].Port {
		case 4445:
			mc = &st.Groups[i]
		case 23757:
			known = &st.Groups[i]
		}
	}
	if mc == nil || mc.Kind != "multicast" || mc.Group != "224.0.2.60" || !mc.New || mc.Rule != "mc:224.0.2.60:4445" {
		t.Errorf("multicast group: %+v", mc)
	}
	if known == nil || known.Rule != "bc:23757" || known.New {
		t.Errorf("known group: %+v", known)
	}

	// pcap: global header + 4 records
	var b bytes.Buffer
	if err := g.Finder.WritePcap(&b); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	if binary.LittleEndian.Uint32(raw) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(raw[20:]) != 1 {
		t.Fatalf("pcap header % x", raw[:24])
	}
	n, off := 0, 24
	for off < len(raw) {
		l := int(binary.LittleEndian.Uint32(raw[off+8:]))
		off += 16 + l
		n++
	}
	if n != 4 || off != len(raw) {
		t.Errorf("pcap records = %d, end %d of %d", n, off, len(raw))
	}

	// expiry: inactive, results stay; stop keeps results too
	c.add(time.Minute)
	p.Process(tb, t1, frame("10.10.1.10", "255.255.255.255", 50000, 4711, []byte("late")), emit)
	if st := g.Finder.Status(c.now()); st.Active || st.Frames != 4 || len(st.Groups) != 3 {
		t.Errorf("after expiry: active=%v frames=%d", st.Active, st.Frames)
	}
	if g.Finder.active.Load() {
		t.Error("fast path still on after expiry")
	}
	_ = g.Finder.Start(FinderRequest{Duration: time.Minute}, c.now())
	g.Finder.Stop(c.now())
	if st := g.Finder.Status(c.now()); st.Active || len(st.Groups) != 0 {
		t.Errorf("after restart+stop: %+v", st)
	}
}
