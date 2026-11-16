package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

type fakeEngine struct {
	down    bool
	applied []*compile.Snapshot
	acked   []string
	finder  *engineapi.FinderStart
}

func (f *fakeEngine) Status(context.Context) (engineapi.Status, error) {
	if f.down {
		return engineapi.Status{}, errors.New("engine not reachable")
	}
	st := engineapi.Status{Version: "test", Started: time.Now(), Mode: "observe", RXRate: 1204, SentRate: 0,
		Alarms: []engineapi.Alarm{{Kind: "foreign_relay", Key: "1101", Detail: "VLAN 1101 receives frames from 10.10.2.99", Count: 3, Last: time.Now()},
			{Kind: "loop", Key: "bc:23757", Detail: "loop seen", Count: 2, AckedAt: time.Now(), AckedBy: "op"}},
		TopUnknown: []engineapi.PortCount{{Port: 4711, Count: 9}},
		VLANStats:  []engineapi.VLANStat{{VID: 1100, Name: "Gameserver", Group: "gameserver", In: 10, InRate: 2}, {VID: 1101, Name: "Tisch 1", Group: "tische"}},
		RuleStats:  []engineapi.RuleStat{{ID: "bc:23757", RX: 5, Relayed: 4}}}
	if n := len(f.applied); n > 0 {
		st.SnapshotHash = f.applied[n-1].Hash
		st.Mode = f.applied[n-1].Mode
	}
	return st, nil
}
func (f *fakeEngine) Players(context.Context) ([]engineapi.Player, error) {
	if f.down {
		return nil, errors.New("engine not reachable")
	}
	return []engineapi.Player{{Rule: "bc:23757", Src: netip.MustParseAddr("10.10.1.10"), VID: 1101, First: time.Now(), Last: time.Now(), Count: 7}}, nil
}
func (f *fakeEngine) FinderStart(_ context.Context, req engineapi.FinderStart) error {
	f.finder = &req
	return nil
}
func (f *fakeEngine) FinderStop(context.Context) error { f.finder = nil; return nil }
func (f *fakeEngine) Finder(context.Context) (engineapi.FinderStatus, error) {
	if f.down {
		return engineapi.FinderStatus{}, errors.New("engine not reachable")
	}
	if f.finder == nil {
		return engineapi.FinderStatus{}, nil
	}
	now := time.Now()
	return engineapi.FinderStatus{Active: true, Started: now.Add(-20 * time.Second), Until: now.Add(time.Minute), VIDs: f.finder.VIDs,
		Frames: 9, Captured: 9, Groups: []engineapi.FinderGroup{
			{Kind: "broadcast", Port: 41234, Count: 6, First: now.Add(-10 * time.Second), Last: now, MinLen: 64, MaxLen: 88,
				Srcs: []netip.Addr{netip.MustParseAddr("10.10.1.23")}, VIDs: []int{1101}, New: true, Sample: []byte("ZOOM-LAN")},
			{Kind: "broadcast", Port: 27036, Count: 3, First: now.Add(-19 * time.Second), Last: now, MinLen: 42, MaxLen: 42},
		}}, nil
}
func (f *fakeEngine) FinderPcap(_ context.Context, w io.Writer) error {
	_, err := w.Write([]byte("PCAPDATA"))
	return err
}
func (f *fakeEngine) Ack(_ context.Context, kind, by string) error {
	f.acked = append(f.acked, kind+"/"+by)
	return nil
}
func (f *fakeEngine) Validate(_ context.Context, s *compile.Snapshot) (engineapi.Result, error) {
	return engineapi.Result{OK: true, Hash: s.Hash}, nil
}
func (f *fakeEngine) Apply(_ context.Context, s *compile.Snapshot) (engineapi.Result, error) {
	f.applied = append(f.applied, s)
	return engineapi.Result{OK: true, Hash: s.Hash}, nil
}

type env struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	eng *fakeEngine
	ui  *Server
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if _, err := control.Init(ctx, st, "test", "lab", "trunk0", false); err != nil {
		t.Fatal(err)
	}
	for name, role := range map[string]string{"admin": "admin", "op": "operator", "view": "viewer"} {
		h, _ := auth.Hash("pw-" + name)
		if err := st.SetLocalUser(ctx, "test", name, h, role); err != nil {
			t.Fatal(err)
		}
	}
	eng := &fakeEngine{}
	ui, err := New(st, eng, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatal(err)
	}
	ui.LiveInterval = 20 * time.Millisecond
	srv := httptest.NewServer(ui)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, eng: eng, ui: ui}
}

// client logs in and returns a client with session cookie plus the CSRF token.
func (e *env) client(name string) (*http.Client, string) {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if name == "" {
		return c, ""
	}
	resp, err := c.PostForm(e.srv.URL+"/login/local", url.Values{"name": {name}, "password": {"pw-" + name}})
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`data-csrf="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		e.t.Fatalf("login as %s failed (status %d): %.300s", name, resp.StatusCode, body)
	}
	return c, string(m[1])
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPagesRender(t *testing.T) {
	e := setup(t)
	c, _ := e.client("admin")
	for _, down := range []bool{false, true} {
		e.eng.down = down
		for _, p := range []string{"/", "/spiele", "/spiele/flatout2", "/spiele/flatout4", "/netz", "/system", "/verlauf", "/notaus", "/dev/komponenten", "/api/v1/status", "/spieler", "/spieler?teil=tabelle", "/finder", "/finder?teil=ergebnis", "/finder/neu?kind=multicast&group=239.1.2.3&port=5000"} {
			code, body := get(t, c, e.srv.URL+p)
			if code != 200 {
				t.Errorf("GET %s (engine down=%v) = %d: %.300s", p, down, code, body)
			}
			if strings.Contains(body, "template:") || strings.Contains(body, "<no value>") {
				t.Errorf("GET %s has template residue", p)
			}
		}
	}
	e.eng.down = false
	_, body := get(t, c, e.srv.URL+"/")
	for _, want := range []string{"Relay <em>Übersicht</em>", `class="bar"`, "Fremdes Relay aktiv", "Tisch 1", "4711", "1 204"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview misses %q", want)
		}
	}
	if code, _ := get(t, c, e.srv.URL+"/spiele/gibtsnicht"); code != 404 {
		t.Errorf("unknown game = %d", code)
	}
}

func TestLoginAndLockout(t *testing.T) {
	e := setup(t)
	anon, _ := e.client("")
	resp, err := anon.Get(e.srv.URL + "/spiele")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/login" {
		t.Errorf("anonymous request not redirected to /login: %s", resp.Request.URL)
	}
	for i := 0; i < store.MaxFailed; i++ {
		r, _ := anon.PostForm(e.srv.URL+"/login/local", url.Values{"name": {"admin"}, "password": {"falsch"}})
		r.Body.Close()
	}
	r, _ := anon.PostForm(e.srv.URL+"/login/local", url.Values{"name": {"admin"}, "password": {"pw-admin"}})
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), "gesperrt") {
		t.Error("account not locked after repeated failures")
	}
	log, _ := e.st.AuditLog(context.Background(), 20)
	if !slices.ContainsFunc(log, func(a store.AuditEntry) bool { return a.Action == "login.locked" }) {
		t.Error("lockout not in audit log")
	}
}

func TestRolesAndCSRF(t *testing.T) {
	e := setup(t)
	view, vcsrf := e.client("view")
	if code, _ := get(t, view, e.srv.URL+"/system"); code != 403 {
		t.Errorf("viewer on /system = %d", code)
	}
	r, _ := view.PostForm(e.srv.URL+"/spiele/flatout2", url.Values{"csrf": {vcsrf}, "on": {"0"}})
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("viewer toggling = %d", r.StatusCode)
	}
	op, _ := e.client("op")
	r, _ = op.PostForm(e.srv.URL+"/spiele/flatout2", url.Values{"csrf": {"wrong"}, "on": {"0"}})
	r.Body.Close()
	if r.StatusCode != 403 || len(e.eng.applied) != 0 {
		t.Errorf("wrong CSRF = %d, applied %d", r.StatusCode, len(e.eng.applied))
	}
}

func TestToggleGameAppliesToEngine(t *testing.T) {
	e := setup(t)
	op, csrf := e.client("op")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/spiele/flatout2", strings.NewReader(url.Values{"on": {"0"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := op.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var a applyAnswer
	_ = json.NewDecoder(resp.Body).Decode(&a)
	resp.Body.Close()
	if !a.OK || a.Enabled || a.Revision != 1 || len(e.eng.applied) != 1 {
		t.Fatalf("answer %+v, applied %d", a, len(e.eng.applied))
	}
	// flatout1 still shares 23757, so the rule stays but lists only flatout1
	for _, r := range e.eng.applied[0].Rules {
		if r.Ports == "23757" && slices.Contains(r.Specs, "flatout2") {
			t.Error("flatout2 still in the snapshot")
		}
	}
	log, _ := e.st.AuditLog(context.Background(), 5)
	if !slices.ContainsFunc(log, func(a store.AuditEntry) bool { return a.Action == "game.disable" && a.User == "op" }) {
		t.Error("toggle not audited with the operator name")
	}
}

func TestAdminActions(t *testing.T) {
	e := setup(t)
	admin, csrf := e.client("admin")
	post := func(path string, v url.Values) {
		v.Set("csrf", csrf)
		r, err := admin.PostForm(e.srv.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	post("/system/mode", url.Values{"mode": {"observe"}})
	post("/netz/1103", url.Values{"on": {"0"}})
	post("/system/notaus", url.Values{})
	if n := len(e.eng.applied); n != 3 || e.eng.applied[2].Mode != "paused" || len(e.eng.applied[1].VLANs) != 3 {
		t.Fatalf("applied %d snapshots", n)
	}
	post("/system/rollback/1", url.Values{})
	if last := e.eng.applied[len(e.eng.applied)-1]; last.Mode != "observe" || len(last.VLANs) != 4 {
		t.Errorf("rollback to revision 1 gave mode %s with %d VLANs", last.Mode, len(last.VLANs))
	}
	resp, err := admin.Get(e.srv.URL + "/system/backup")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(b), "SQLite format 3") {
		t.Errorf("backup download = %d, %d bytes", resp.StatusCode, len(b))
	}
}

// Brand rule 2 (docs/02-plan.md 6.4): own CSS uses tokens only, no colour literals.
func TestCSSUsesTokensOnly(t *testing.T) {
	css, err := fs.ReadFile(staticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(`).FindAll(css, -1); len(m) > 0 {
		t.Errorf("app.css contains colour literals: %q", m)
	}
	for _, banned := range []string{"backdrop-filter", "font-family: system-ui", "-apple-system"} {
		if strings.Contains(string(css), banned) {
			t.Errorf("app.css contains %q (generic look, rule 15)", banned)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := setup(t)
	resp, err := http.Get(e.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers %v", resp.Header)
	}
}

func TestPlayersAndAlarmAck(t *testing.T) {
	e := setup(t)
	view, vcsrf := e.client("view")
	code, body := get(t, view, e.srv.URL+"/spieler")
	if code != 200 || !strings.Contains(body, "10.10.1.10") || !strings.Contains(body, "FlatOut") || !strings.Contains(body, "Tisch 1") {
		t.Fatalf("/spieler = %d: %.400s", code, body)
	}
	code, frag := get(t, view, e.srv.URL+"/spieler?teil=tabelle")
	if code != 200 || strings.Contains(frag, "<html") || !strings.Contains(frag, "10.10.1.10") {
		t.Errorf("fragment = %d: %.200s", code, frag)
	}
	// overview: open alarm counted, acknowledged loop only under "Gesehen"; viewers get no button
	_, ov := get(t, view, e.srv.URL+"/")
	if !strings.Contains(ov, "Gesehen, läuft noch") || strings.Contains(ov, `action="/alarme/`) {
		t.Error("viewer overview: seen list missing or ack button shown")
	}
	r, _ := view.PostForm(e.srv.URL+"/alarme/foreign_relay/gesehen", url.Values{"csrf": {vcsrf}})
	r.Body.Close()
	if r.StatusCode != 403 || len(e.eng.acked) != 0 {
		t.Errorf("viewer ack = %d, acked %v", r.StatusCode, e.eng.acked)
	}
	op, csrf := e.client("op")
	_, ov = get(t, op, e.srv.URL+"/")
	if !strings.Contains(ov, `action="/alarme/foreign_relay/gesehen"`) {
		t.Error("operator overview without ack button")
	}
	r, _ = op.PostForm(e.srv.URL+"/alarme/foreign_relay/gesehen", url.Values{"csrf": {csrf}})
	r.Body.Close()
	if len(e.eng.acked) != 1 || e.eng.acked[0] != "foreign_relay/op" {
		t.Errorf("acked %v", e.eng.acked)
	}
	r, _ = op.PostForm(e.srv.URL+"/alarme/erfunden/gesehen", url.Values{"csrf": {csrf}})
	r.Body.Close()
	if len(e.eng.acked) != 1 {
		t.Error("unknown alarm kind passed to the engine")
	}
	log, _ := e.st.AuditLog(context.Background(), 5)
	if !slices.ContainsFunc(log, func(a store.AuditEntry) bool { return a.Action == "alarm.ack" && a.User == "op" }) {
		t.Error("ack not audited")
	}
	// live model: open and seen separated
	v := e.srv.Config.Handler.(*Server).liveNow(context.Background())
	if len(v.Alarms) != 1 || len(v.Seen) != 1 || v.Seen[0].By != "op" {
		t.Errorf("live alarms %d seen %d", len(v.Alarms), len(v.Seen))
	}
}

func TestMonitoring(t *testing.T) {
	e := setup(t)
	anon := &http.Client{}
	if code, _ := get(t, anon, e.srv.URL+"/api/v1/monitoring"); code != 404 {
		t.Fatalf("without configured token = %d, want 404", code)
	}
	admin, csrf := e.client("admin")
	if _, body := get(t, admin, e.srv.URL+"/system"); !strings.Contains(body, "noch keins") {
		t.Error("system page does not say that no token exists")
	}
	op, opcsrf := e.client("op")
	r, _ := op.PostForm(e.srv.URL+"/system/monitoring-token", url.Values{"csrf": {opcsrf}})
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("operator created a token: %d", r.StatusCode)
	}
	r, err := admin.PostForm(e.srv.URL+"/system/monitoring-token", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	m := regexp.MustCompile(`id="monitor-token">([A-Za-z0-9_-]+)<`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("token not shown: %.300s", b)
	}
	tok := string(m[1])
	if _, body := get(t, admin, e.srv.URL+"/system"); strings.Contains(body, tok) || !strings.Contains(body, "eingerichtet") {
		t.Error("token shown again or state missing")
	}
	call := func(path, tok string) (int, string) {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := call("/api/v1/monitoring", ""); code != 401 {
		t.Errorf("no token = %d", code)
	}
	if code, _ := call("/metrics", tok+"x"); code != 401 {
		t.Errorf("wrong token = %d", code)
	}
	code, body := call("/api/v1/monitoring", tok)
	var rep map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &rep) != nil || rep["engine_up"] != float64(1) {
		t.Fatalf("monitoring = %d: %.300s", code, body)
	}
	if a := rep["alarms"].(map[string]any)["foreign_relay"].(map[string]any); a["active"] != float64(1) {
		t.Errorf("foreign_relay = %v", a)
	}
	code, body = call("/metrics", tok)
	if code != 200 || !strings.Contains(body, "nsrelay_engine_up 1") || !strings.Contains(body, `nsrelay_alarms_active{kind="loop"} 0`) {
		t.Errorf("metrics = %d: %.300s", code, body)
	}
	e.eng.down = true
	if _, body = call("/api/v1/monitoring", tok); !strings.Contains(body, `"engine_up":0`) {
		t.Errorf("engine down: %.200s", body)
	}
}

func TestPortFinder(t *testing.T) {
	e := setup(t)
	view, _ := e.client("view")
	if code, _ := get(t, view, e.srv.URL+"/finder"); code != 403 {
		t.Errorf("viewer /finder = %d", code)
	}
	op, csrf := e.client("op")
	code, body := get(t, op, e.srv.URL+"/finder")
	if code != 200 || !strings.Contains(body, "Noch keine Sitzung") || !strings.Contains(body, `href="/finder"`) {
		t.Fatalf("/finder = %d: %.300s", code, body)
	}
	if !strings.Contains(body, "4711") {
		t.Error("top unknown ports missing")
	}
	r, _ := op.PostForm(e.srv.URL+"/finder/start", url.Values{"csrf": {csrf}, "vid": {"1101"}, "src": {"kein-ip"}, "minuten": {"5"}})
	r.Body.Close()
	if e.eng.finder != nil {
		t.Fatal("bad IP accepted")
	}
	r, _ = op.PostForm(e.srv.URL+"/finder/start", url.Values{"csrf": {csrf}, "vid": {"1101", "1102"}, "minuten": {"99"}})
	r.Body.Close()
	if e.eng.finder == nil || e.eng.finder.Seconds != 600 || len(e.eng.finder.VIDs) != 2 {
		t.Fatalf("start: %+v", e.eng.finder)
	}
	_, frag := get(t, op, e.srv.URL+"/finder?teil=ergebnis")
	if strings.Contains(frag, "<html") || !strings.Contains(frag, "41234") || !strings.Contains(frag, "Spiel anlegen") ||
		strings.Contains(frag, "27036") || !strings.Contains(frag, "1 Ziele mit bekanntem Lärm") || !strings.Contains(frag, "ZOOM-LAN.") {
		t.Errorf("fragment: %.900s", frag)
	}
	if _, frag = get(t, op, e.srv.URL+"/finder?teil=ergebnis&laerm=1"); !strings.Contains(frag, "Steam (Lärm)") {
		t.Error("noise not shown on request")
	}
	resp, _ := op.Get(e.srv.URL + "/finder/mitschnitt.pcap")
	pc, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(pc) != "PCAPDATA" || !strings.Contains(resp.Header.Get("Content-Disposition"), ".pcap") {
		t.Errorf("pcap = %q %v", pc, resp.Header)
	}
	if _, form := get(t, op, e.srv.URL+"/finder/neu?kind=broadcast&port=41234"); !strings.Contains(form, `value="41234"`) {
		t.Error("new game form not prefilled")
	}
	// create: invalid id shows the form again, then a valid one is created, enabled and applied
	r, _ = op.PostForm(e.srv.URL+"/finder/neu", url.Values{"csrf": {csrf}, "name": {"Zoom Test"}, "id": {"Böse ID"}, "kind": {"broadcast"}, "ports": {"41234"}, "direction": {"query"}})
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 422 || !strings.Contains(string(b), "Kennung") {
		t.Errorf("invalid id = %d", r.StatusCode)
	}
	applied := len(e.eng.applied)
	r, _ = op.PostForm(e.srv.URL+"/finder/neu", url.Values{"csrf": {csrf}, "name": {"FlatOut: Ultimate Carnage (ZOOM)"}, "kind": {"broadcast"}, "ports": {"41234"}, "direction": {"both"}, "enable": {"1"}})
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(string(b), "angelegt und eingeschaltet") {
		t.Fatalf("create = %d: %.300s", r.StatusCode, b)
	}
	if !strings.HasSuffix(r.Request.URL.Path, "/spiele/flatout_ultimate_carnage_zoom") || len(e.eng.applied) != applied+1 {
		t.Errorf("redirect %s, applied %d", r.Request.URL.Path, len(e.eng.applied)-applied)
	}
	games, _ := e.st.Games(context.Background())
	i := slices.IndexFunc(games, func(g store.GameRow) bool { return g.ID == "flatout_ultimate_carnage_zoom" })
	if i < 0 || games[i].Origin != "sniffer" || !games[i].Enabled || games[i].Confidence != "low" {
		t.Fatalf("stored game: %+v", games[i])
	}
	// same id again: refused
	r, _ = op.PostForm(e.srv.URL+"/finder/neu", url.Values{"csrf": {csrf}, "name": {"FlatOut: Ultimate Carnage (ZOOM)"}, "kind": {"broadcast"}, "ports": {"41234"}})
	r.Body.Close()
	if r.StatusCode != 422 {
		t.Errorf("duplicate = %d", r.StatusCode)
	}
	r, _ = op.PostForm(e.srv.URL+"/finder/stop", url.Values{"csrf": {csrf}})
	r.Body.Close()
	if e.eng.finder != nil {
		t.Error("stop not passed on")
	}
}
