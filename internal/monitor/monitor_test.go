package monitor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
)

func status(now time.Time) engineapi.Status {
	return engineapi.Status{Version: "v1", Started: now.Add(-time.Hour), Mode: "active", Sending: true, SnapshotHash: "abc",
		VLANs: 3, Rules: 7, RX: 100, Sent: 50, RXRate: 4, SentRate: 2,
		Reasons: map[string]uint64{"relayed": 50, "rate": 3, "unknown_port": 47},
		Alarms: []engineapi.Alarm{
			{Kind: "loop", Key: "bc:23757", Count: 4, First: now.Add(-2 * time.Minute), Last: now.Add(-time.Minute)},
			{Kind: "loop", Key: "bc:27015", Count: 1, First: now.Add(-time.Hour), Last: now.Add(-time.Hour)}, // too old
			{Kind: "foreign_relay", Key: "1101", Count: 9, Last: now, AckedAt: now, AckedBy: "op"},
		},
		VLANStats: []engineapi.VLANStat{
			{VID: 1101, Name: "Tisch 1", Group: "tische", In: 10, LastIn: now.Add(-30 * time.Second)},
			{VID: 1102, Name: "Tisch \"2\"", Group: "tische", In: 0}, // never received since start an hour ago
		},
		RuleStats: []engineapi.RuleStat{{ID: "bc:23757", RX: 5, Relayed: 4}},
	}
}

func TestBuild(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := Build(status(now), nil, "w1", true, now)
	if r.EngineUp != 1 || r.Sending != 1 || r.UptimeS != 3600 || r.Mode != "active" {
		t.Fatalf("basics: %+v", r)
	}
	if _, ok := r.Drops["relayed"]; ok || r.Drops["rate"] != 3 {
		t.Fatalf("drops: %v", r.Drops)
	}
	if l := r.Alarms["loop"]; l.Active != 1 || l.Count != 5 || len(l.Keys) != 1 || l.Keys[0] != "bc:23757" {
		t.Fatalf("loop: %+v", l)
	}
	if f := r.Alarms["foreign_relay"]; f.Active != 0 || f.Acked != 1 {
		t.Fatalf("foreign_relay: %+v", f)
	}
	if s := r.Alarms["vlan_silent"]; s.Active != 1 || s.Keys[0] != "1102" {
		t.Fatalf("vlan_silent: %+v", s)
	}
	if r.AlarmsActive != 2 {
		t.Fatalf("alarms_active = %d", r.AlarmsActive)
	}
	if v := r.VLANList[0]; v.SilentS != 30 || v.Silent != 0 || v.LastIn == 0 {
		t.Fatalf("vlan 1101: %+v", v)
	}
	if v := r.VLANList[1]; v.SilentS != 3600 || v.Silent != 1 || v.LastIn != 0 {
		t.Fatalf("vlan 1102: %+v", v)
	}
	// without an active event nothing is "silent"
	if r := Build(status(now), nil, "w1", false, now); r.Alarms["vlan_silent"].Active != 0 || r.AlarmsActive != 1 {
		t.Fatalf("no event: %+v", r.Alarms)
	}
	// every kind is present in JSON even without incidents
	b, _ := json.Marshal(Build(engineapi.Status{}, nil, "w1", false, now))
	for _, k := range Kinds {
		if !strings.Contains(string(b), `"`+k+`":{"active":0`) {
			t.Fatalf("kind %s missing: %s", k, b)
		}
	}
}

func TestBuildEngineDown(t *testing.T) {
	r := Build(engineapi.Status{}, errors.New("dial unix: no such file"), "w1", true, time.Now())
	if r.EngineUp != 0 || r.EngineError == "" || len(r.Alarms) != len(Kinds) || r.VLANList == nil {
		t.Fatalf("%+v", r)
	}
}

func TestPrometheus(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := status(now)
	var b strings.Builder
	if err := WritePrometheus(&b, Build(st, nil, "w1", true, now), st.RuleStats); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"nsrelay_engine_up 1\n",
		`nsrelay_dropped_frames_total{reason="rate"} 3`,
		`nsrelay_alarms_active{kind="loop"} 1`,
		`nsrelay_alarms_active{kind="vlan_silent"} 1`,
		`nsrelay_vlan_received_frames_total{vid="1102",name="Tisch \"2\"",group="tische"} 0`,
		`nsrelay_rule_relayed_frames_total{rule="bc:23757"} 4`,
		"# TYPE nsrelay_sent_frames_total counter\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "nsrelay_") {
			t.Errorf("bad line %q", line)
		}
	}
}
