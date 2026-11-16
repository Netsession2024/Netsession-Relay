package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/pkt"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)} }
func guardAt(c *fakeClock) *Guard        { g := NewGuard(c.now); g.Holdoff = 0; return g }
func limitsSnapshot(s *compile.Snapshot) *compile.Snapshot {
	s.Limits = compile.DefaultLimits
	return s
}

func process(p *Processor, tb *Table, in int, b []byte) Reason {
	return p.Process(tb, in, b, func(int, []byte) error { return nil })
}

func TestRateLimitPerFlow(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	tb := newTable(t, limitsSnapshot(testSnapshot(defaultRules()...)))
	p := NewProcessor(&Counters{}, g)
	b := frame("10.10.1.10", "255.255.255.255", 50000, 23757, []byte("q"))
	relayed := 0
	for range 1000 { // 1000 frames in the same instant: only the burst (10) passes
		if process(p, tb, t1, b) == Relayed {
			relayed++
		}
	}
	if relayed != 10 {
		t.Fatalf("relayed %d of 1000 at once, want burst 10", relayed)
	}
	c.add(time.Second) // rate 5/s refills 5 tokens
	relayed = 0
	for range 100 {
		if process(p, tb, t1, b) == Relayed {
			relayed++
		}
	}
	if relayed != 5 {
		t.Errorf("after 1 s relayed %d, want 5", relayed)
	}
	if p.C.Reasons[DropRate].Load() == 0 {
		t.Error("rate drops not counted")
	}
	// another source has its own bucket
	if r := process(p, tb, t1, frame("10.10.1.11", "255.255.255.255", 50000, 23757, []byte("q"))); r != Relayed {
		t.Errorf("second source: %v", r)
	}
}

func TestRateLimitPerVLAN(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	s := limitsSnapshot(testSnapshot(defaultRules()...))
	s.Limits.VLANPPS, s.Limits.VLANBurst = 3, 3
	tb := newTable(t, s)
	p := NewProcessor(&Counters{}, g)
	relayed := 0
	for i := range 10 { // 10 different sources, each within its flow budget
		src := netip.AddrFrom4([4]byte{10, 10, 1, byte(20 + i)}).String()
		if process(p, tb, t1, frame(src, "255.255.255.255", 50000, 23757, []byte("q"))) == Relayed {
			relayed++
		}
	}
	if relayed != 3 {
		t.Errorf("relayed %d, want VLAN burst 3", relayed)
	}
}

func TestLoopDetection(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	// a datagram whose source fits both VLANs is impossible after step 3, so emulate a loop with a /16 that
	// covers both lab VLANs on the second VLAN (misconfigured switch: same broadcast domain twice)
	s := limitsSnapshot(testSnapshot(defaultRules()...))
	tb := newTable(t, s)
	p := NewProcessor(&Counters{}, g)
	b := frame("10.10.1.10", "255.255.255.255", 50000, 23757, []byte("same"))
	f, _ := pkt.Parse(b)
	if g.SeenElsewhere(&f, t1, c.now(), 200*time.Millisecond) {
		t.Fatal("first sighting reported as loop")
	}
	if !g.SeenElsewhere(&f, t2, c.now().Add(50*time.Millisecond), 200*time.Millisecond) {
		t.Error("same datagram on another VLAN within window not detected")
	}
	if g.SeenElsewhere(&f, t1, c.now().Add(60*time.Millisecond), 200*time.Millisecond) {
		t.Error("repeat on the original VLAN is not a loop (rate limit handles it)")
	}
	if g.SeenElsewhere(&f, t1, c.now().Add(time.Second), 200*time.Millisecond) {
		t.Error("outside the window is not a loop")
	}
	_ = tb
	_ = p
}

func TestForeignRelayAlarm(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	tb := newTable(t, limitsSnapshot(testSnapshot(defaultRules()...)))
	p := NewProcessor(&Counters{}, g)
	for range 3 {
		if r := process(p, tb, t1, frame("10.10.2.99", "255.255.255.255", 1, 23757, []byte("x"))); r != DropForeignRelay {
			t.Fatalf("reason %v", r)
		}
	}
	al := g.Alarms.List()
	if len(al) != 1 || al[0].Kind != AlarmForeignRelay || al[0].Count != 3 || al[0].Key != "1101" {
		t.Errorf("alarms = %+v", al)
	}
}

func TestHoldoffAndStandby(t *testing.T) {
	c := newClock()
	g := NewGuard(c.now) // default holdoff 1.5 s
	tb := newTable(t, limitsSnapshot(testSnapshot(defaultRules()...)))
	p := NewProcessor(&Counters{}, g)
	b := func() []byte { return frame("10.10.1.10", "255.255.255.255", 50000, 23757, []byte(c.now().String())) }
	if r := process(p, tb, t1, b()); r != DropMode {
		t.Errorf("during holdoff: %v", r)
	}
	c.add(2 * time.Second)
	if r := process(p, tb, t1, b()); r != Relayed {
		t.Errorf("after holdoff: %v", r)
	}
	// an engine that started earlier is active -> standby
	other := Beacon{Started: g.Started.Add(-time.Hour).UnixNano(), Active: true}
	other.Instance[0] = 0xEE
	if !g.SeeBeacon(other, c.now()) || !g.Standby() {
		t.Fatal("did not enter standby")
	}
	if r := process(p, tb, t1, b()); r != DropMode {
		t.Errorf("in standby: %v", r)
	}
	if g.MyBeacon(tb.Snapshot).Active {
		t.Error("standby engine announces itself as active")
	}
	// earlier engine goes silent -> back to active after 10 s
	c.add(5 * time.Second)
	if g.PeerTick(c.now()) {
		t.Error("left standby too early")
	}
	c.add(6 * time.Second)
	if !g.PeerTick(c.now()) || g.Standby() {
		t.Error("did not leave standby after peer timeout")
	}
}

func TestLaterEngineDoesNotYield(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	later := Beacon{Started: g.Started.Add(time.Minute).UnixNano(), Active: true}
	later.Instance[0] = 1
	if g.SeeBeacon(later, c.now()) || g.Standby() {
		t.Error("earlier engine yielded to a later one")
	}
	inactive := Beacon{Started: g.Started.Add(-time.Minute).UnixNano(), Active: false}
	inactive.Instance[0] = 2
	if g.SeeBeacon(inactive, c.now()) {
		t.Error("yielded to a standby/observe engine")
	}
	self := g.MyBeacon(&compile.Snapshot{Mode: compile.ModeActive})
	if g.SeeBeacon(self, c.now()) {
		t.Error("yielded to itself")
	}
}

func TestBeaconRoundTrip(t *testing.T) {
	g := NewGuard(nil)
	b := g.MyBeacon(&compile.Snapshot{Mode: compile.ModeActive, Hash: "0123456789abcdef"})
	f := BuildBeacon(pkt.MAC{2, 0, 0, 0, 0, 1}, b)
	got, ok := ParseBeacon(f)
	if !ok || got != b {
		t.Fatalf("round trip: ok=%v %+v != %+v", ok, got, b)
	}
	if _, ok := ParseBeacon(f[:20]); ok {
		t.Error("short beacon accepted")
	}
	f[14] = 'X'
	if _, ok := ParseBeacon(f); ok {
		t.Error("bad magic accepted")
	}
}

func TestStormBrake(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	s := limitsSnapshot(testSnapshot(defaultRules()...))
	s.Limits.StormPPS = 100
	tb := newTable(t, s)
	cnt := &Counters{}
	fo := tb.rules[0] // bc:23757
	for sec := 1; sec <= 3; sec++ {
		cnt.Sent.Add(500)
		fo.relayed.Add(200)
		tb.rules[1].relayed.Add(10)
		c.add(time.Second)
		id := g.StormTick(tb, cnt, c.now())
		if sec < 3 && id != "" {
			t.Fatalf("paused after %d s", sec)
		}
		if sec == 3 && id != "bc:23757" {
			t.Fatalf("paused %q, want the loudest rule bc:23757", id)
		}
	}
	p := NewProcessor(cnt, g)
	if r := process(p, tb, t1, frame("10.10.1.10", "255.255.255.255", 1, 23757, []byte("x"))); r != DropAutoPaused {
		t.Errorf("paused rule: %v", r)
	}
	if r := process(p, tb, t1, frame("10.10.1.10", "255.255.255.255", 1, 27015, []byte("x"))); r != Relayed {
		t.Errorf("other rule must keep working: %v", r)
	}
	c.add(61 * time.Second)
	if r := process(p, tb, t1, frame("10.10.1.10", "255.255.255.255", 1, 23757, []byte("y"))); r != Relayed {
		t.Errorf("after 60 s: %v", r)
	}
	if al := g.Alarms.List(); len(al) != 1 || al[0].Kind != AlarmStorm {
		t.Errorf("alarms %+v", al)
	}
	// quiet seconds reset the counter
	cnt.Sent.Add(10)
	if id := g.StormTick(tb, cnt, c.now()); id != "" || g.stormOverSecs != 0 {
		t.Error("quiet second did not reset")
	}
}

func TestGuardGC(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	g.AllowFlow("r", netip.MustParseAddr("10.10.1.1"), 1, 5, 10, c.now())
	c.add(2 * time.Minute)
	g.GC(c.now())
	n := 0
	for i := range g.buckets {
		n += len(g.buckets[i].m)
	}
	if n != 0 {
		t.Errorf("%d buckets left after GC", n)
	}
}

func BenchmarkProcessGuarded(b *testing.B) {
	g := NewGuard(nil)
	g.Holdoff = 0
	s := testSnapshot(defaultRules()...)
	s.Limits = compile.Limits{DedupMS: 200} // no VLAN limit
	for i := range s.Rules {
		s.Rules[i].RatePPS = 0 // no flow limit: measure the full relay path incl. dedup
	}
	tb, _ := NewTable(s, nil)
	p := NewProcessor(&Counters{}, g)
	fr := frame("10.10.1.10", "255.255.255.255", 50000, 23757, make([]byte, 106))
	emit := func(int, []byte) error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		p.Process(tb, t1, fr, emit)
	}
}

func TestAlarmAck(t *testing.T) {
	c := newClock()
	var a Alarms
	a.Raise(AlarmForeignRelay, "1101", c.now(), "x")
	a.Raise(AlarmForeignRelay, "1102", c.now(), "x")
	a.Raise(AlarmLoop, "bc:1", c.now(), "x")
	if n := a.Ack(AlarmForeignRelay, "op", c.now()); n != 2 {
		t.Fatalf("acked %d", n)
	}
	// keeps occurring without a pause: stays acknowledged
	c.add(10 * time.Second)
	a.Raise(AlarmForeignRelay, "1101", c.now(), "x")
	for _, x := range a.List() {
		if x.Kind == AlarmForeignRelay && (x.AckedAt.IsZero() || x.AckedBy != "op") {
			t.Errorf("continuing alarm lost its acknowledgement: %+v", x)
		}
		if x.Kind == AlarmLoop && !x.AckedAt.IsZero() {
			t.Error("other kind acknowledged too")
		}
	}
	// quiet for longer than 60 s, then again: new incident, open again
	c.add(2 * time.Minute)
	a.Raise(AlarmForeignRelay, "1101", c.now(), "x")
	for _, x := range a.List() {
		if x.Kind == AlarmForeignRelay && x.Key == "1101" && !x.AckedAt.IsZero() {
			t.Error("new incident after a quiet gap is still acknowledged")
		}
	}
}

func TestPlayers(t *testing.T) {
	c := newClock()
	g := guardAt(c)
	tb := newTable(t, limitsSnapshot(testSnapshot(defaultRules()...)))
	p := NewProcessor(&Counters{}, g)
	for range 3 {
		process(p, tb, t1, frame("10.10.1.10", "255.255.255.255", 50000, 23757, []byte("q")))
	}
	process(p, tb, t2, frame("10.10.2.20", "10.10.2.255", 23757, 23757, make([]byte, 106)))
	process(p, tb, t1, frame("10.10.1.10", "255.255.255.255", 1, 4711, []byte("unknown port")))
	process(p, tb, t1, frame("10.10.2.99", "255.255.255.255", 1, 23757, []byte("foreign")))
	list := g.Players.List()
	if len(list) != 2 {
		t.Fatalf("players %+v", list)
	}
	for _, pl := range list {
		if pl.Rule != "bc:23757" || (pl.VID == 1101 && pl.Count != 3) {
			t.Errorf("player %+v", pl)
		}
	}
	c.add(16 * time.Minute)
	g.Players.GC(c.now())
	if n := len(g.Players.List()); n != 0 {
		t.Errorf("%d players after GC", n)
	}
	var ps Players
	for i := range maxPlayers + 10 {
		ps.Seen("r", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 1, c.now().Add(time.Duration(i)))
	}
	if n := len(ps.List()); n != maxPlayers {
		t.Errorf("table not bounded: %d", n)
	}
}
