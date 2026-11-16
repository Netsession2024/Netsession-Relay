package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// readEvents reads n "status" events from an open event stream.
func readEvents(t *testing.T, body io.Reader, n int) []liveView {
	t.Helper()
	var out []liveView
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: ") && event == "status":
			var v liveView
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &v); err != nil {
				t.Fatalf("event is not JSON: %v", err)
			}
			out = append(out, v)
			if len(out) == n {
				return out
			}
		}
	}
	t.Fatalf("stream ended after %d of %d events: %v", len(out), n, sc.Err())
	return nil
}

func TestLiveEvents(t *testing.T) {
	e := setup(t)
	view, _ := e.client("view")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.srv.URL+"/api/v1/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := view.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("events = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// the first event comes at once, the following ones from the hub
	evs := readEvents(t, resp.Body, 3)
	v := evs[2]
	if !v.EngineOK || v.State.Key != "observe" || v.State.Label != "Beobachten" || v.State.Relaying {
		t.Errorf("state %+v", v.State)
	}
	if v.RXRate != 1204 || v.GamesOn == 0 || len(v.Enabled) != v.GamesOn || len(v.VLANs) != 4 {
		t.Errorf("view: rx %d, games on %d, enabled %d, vlans %d", v.RXRate, v.GamesOn, len(v.Enabled), len(v.VLANs))
	}
	if len(v.Alarms) != 1 || v.Alarms[0].Title != "Fremdes Relay aktiv" || !strings.Contains(v.Alarms[0].Hint, "Erwartet") {
		t.Errorf("alarms %+v", v.Alarms)
	}
	var t1 vlanView
	for _, x := range v.VLANs {
		if x.VID == 1101 {
			t1 = x
		}
	}
	if !t1.Alarm || t1.Status != "Alarm" || t1.Key != "1" {
		t.Errorf("VLAN 1101 %+v", t1)
	}
	if len(v.Busy) != 1 || !strings.Contains(v.Busy[0].Names, "FlatOut") || v.Busy[0].Ports != "23757" {
		t.Errorf("busy %+v", v.Busy)
	}

	// without a session the stream answers 401, so the script can tell "logged out" from "server gone"
	anon, _ := e.client("")
	req2, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/api/v1/events", nil)
	req2.Header.Set("Accept", "text/event-stream")
	r2, err := anon.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous events = %d", r2.StatusCode)
	}
}

func TestLiveEngineDown(t *testing.T) {
	e := setup(t)
	e.eng.down = true
	v := e.ui.liveNow(context.Background())
	if v.EngineOK || v.State.Key != "down" || v.State.Tone != "danger" || v.State.CanStop {
		t.Errorf("state %+v", v.State)
	}
	if len(v.VLANs) != 4 || v.VLANs[0].Status != "still" {
		t.Errorf("configured VLANs must stay visible: %+v", v.VLANs)
	}
	if b, err := json.Marshal(v); err != nil || !strings.Contains(string(b), `"alarms":[]`) {
		t.Errorf("JSON lists must not be null: %v %.200s", err, b)
	}
}

func TestStateOf(t *testing.T) {
	for _, c := range []struct {
		st       engineapi.Status
		ok       bool
		key      string
		relaying bool
		canStop  bool
	}{
		{engineapi.Status{Mode: "active", Sending: true}, true, "active", true, true},
		{engineapi.Status{Mode: "active"}, true, "holdoff", false, true},
		{engineapi.Status{Mode: "active", Standby: true}, true, "standby", false, true},
		{engineapi.Status{Mode: "observe"}, true, "observe", false, true},
		{engineapi.Status{Mode: "paused"}, true, "paused", false, false},
		{engineapi.Status{}, true, "none", false, false},
		{engineapi.Status{Mode: "active", Sending: true}, false, "down", false, false},
	} {
		s := stateOf(c.st, c.ok)
		if s.Key != c.key || s.Relaying != c.relaying || s.CanStop != c.canStop || s.Headline == "" || s.Text == "" || s.Icon == "" {
			t.Errorf("stateOf(%+v, %v) = %+v", c.st, c.ok, s)
		}
	}
}

func TestDiagnose(t *testing.T) {
	on := store.GameRow{Enabled: true}
	on.RelayNeeded = "yes"
	off := on
	off.Enabled = false
	rule := func(rx, relayed uint64) []ruleView {
		return []ruleView{{Rule: compile.Rule{ID: "bc:23757", Ports: "23757"}, RX: rx, Relayed: relayed}}
	}
	live := func(st engineapi.Status) *liveView { return &liveView{EngineOK: true, State: stateOf(st, true)} }
	active := engineapi.Status{Mode: "active", Sending: true}
	for _, c := range []struct {
		name  string
		g     store.GameRow
		rules []ruleView
		v     *liveView
		tone  string
		title string
	}{
		{"all fine", on, rule(10, 40), live(active), "ok", "Am Relay liegt es nicht"},
		{"game off", off, nil, live(active), "danger", "Spiel ist aus"},
		{"observe", on, rule(10, 0), live(engineapi.Status{Mode: "observe"}), "danger", "Relay beobachtet nur"},
		{"nothing received", on, rule(0, 0), live(active), "warn", "Noch keine Suchanfrage gesehen"},
		{"received, not copied", on, rule(10, 0), live(active), "danger", "Es geht keine Kopie raus"},
		{"no rule", on, nil, live(active), "danger", "Keine Regel im Relay"},
	} {
		steps, verdict := diagnose(c.g, c.rules, c.v)
		if verdict.Tone != c.tone || verdict.Title != c.title || len(steps) != 5 {
			t.Errorf("%s: verdict %+v, %d steps", c.name, verdict, len(steps))
		}
	}
	nolan := on
	nolan.RelayNeeded = "no"
	if steps, verdict := diagnose(nolan, nil, live(active)); len(steps) != 0 || verdict.Tone != "neutral" {
		t.Errorf("no LAN mode: %+v", verdict)
	}
}

func TestNewPagesAndFragment(t *testing.T) {
	e := setup(t)
	admin, csrf := e.client("admin")
	for path, want := range map[string]string{
		"/verlauf":                       "einblenden", // the link that shows the hidden logins
		"/verlauf?anmeldungen=1":         "Anmeldungen ausblenden",
		"/notaus":                        "Relay pausieren",
		"/spiele/flatout2":               "Wird es gefunden?",
		"/spiele/flatout2?teil=diagnose": "Relay beobachtet nur",
		"/system":                        "Betriebsart wechseln",
		"/netz":                          "Wer sieht wessen Spiele",
		"/spiele":                        `data-rules="bc:23757"`,
		"/":                              `data-live="state.headline"`,
	} {
		code, body := get(t, admin, e.srv.URL+path)
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("GET %s = %d, misses %q", path, code, want)
		}
		if strings.Contains(path, "teil=") && strings.Contains(body, "<html") {
			t.Errorf("GET %s must be a fragment", path)
		}
	}
	// /verlauf hides plain logins by default
	if _, body := get(t, admin, e.srv.URL+"/verlauf"); strings.Contains(body, ">Angemeldet<") {
		t.Error("/verlauf shows logins without ?anmeldungen=1")
	}
	// a form may name the page to return to, but only a local one
	for back, want := range map[string]string{"/spiele/flatout2": "/spiele/flatout2", "//evil.example/x": "/spiele", "https://evil.example": "/spiele"} {
		noRedirect := &http.Client{Jar: admin.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r, err := noRedirect.PostForm(e.srv.URL+"/spiele/flatout2", url.Values{"csrf": {csrf}, "on": {"1"}, "back": {back}})
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if loc := r.Header.Get("Location"); !strings.HasPrefix(loc, want+"?") {
			t.Errorf("back=%q redirects to %q", back, loc)
		}
	}
	// roles: the history is for admins, the stop page for operators
	op, _ := e.client("op")
	if code, _ := get(t, op, e.srv.URL+"/verlauf"); code != 403 {
		t.Errorf("operator on /verlauf = %d", code)
	}
	if code, _ := get(t, op, e.srv.URL+"/notaus"); code != 200 {
		t.Errorf("operator on /notaus = %d", code)
	}
	view, _ := e.client("view")
	if code, _ := get(t, view, e.srv.URL+"/notaus"); code != 403 {
		t.Errorf("viewer on /notaus = %d", code)
	}
	if _, body := get(t, view, e.srv.URL+"/spiele"); strings.Contains(body, `role="switch"`) || strings.Contains(body, `href="/notaus"`) {
		t.Error("viewer gets switches or the stop button")
	}
}

// The demo engine follows applied snapshots and its numbers move.
func TestDemoEngine(t *testing.T) {
	e := setup(t)
	demo := NewDemoEngine()
	ctx := context.Background()
	if st, _ := demo.Status(ctx); st.Mode != "" || len(st.VLANStats) != 0 {
		t.Errorf("demo engine without snapshot: %+v", st)
	}
	res, err := control.Apply(ctx, e.st, demo, "test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := demo.Status(ctx)
	time.Sleep(30 * time.Millisecond)
	b, _ := demo.Status(ctx)
	if a.SnapshotHash != res.Snapshot.Hash || a.Mode != res.Snapshot.Mode || len(a.VLANStats) != len(res.Snapshot.VLANs) || len(a.RuleStats) != len(res.Snapshot.Rules) {
		t.Errorf("demo status does not follow the snapshot: %+v", a)
	}
	if b.RX < a.RX || b.RXRate == 0 {
		t.Errorf("demo traffic does not move: %d -> %d, rate %d", a.RX, b.RX, b.RXRate)
	}
}
