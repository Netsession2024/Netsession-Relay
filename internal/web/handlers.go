package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// ---- Übersicht ----

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ev, _ := s.Store.ActiveEvent(r.Context())
	s.render(w, r, "overview", "Übersicht", "overview", map[string]any{"Event": ev})
}

// ---- Spiele ----

type gameRow struct {
	store.GameRow
	Ports   string
	Pinned  bool
	RuleIDs string // space separated, for the live counters
	RX      uint64
	Unsure  bool
}

func gameRowOf(g store.GameRow, idx *ruleIndex, v *liveView) gameRow {
	var ports []string
	for _, d := range g.Discovery {
		ports = append(ports, d.Ports)
	}
	row := gameRow{GameRow: g, Ports: strings.Join(ports, ", "), Pinned: strings.HasPrefix(g.ID, "flatout"),
		Unsure: g.Confidence == "low" || g.RelayNeeded == "unknown"}
	var ids []string
	for _, rv := range rulesFor(idx, g.ID, v) {
		ids = append(ids, rv.ID)
		row.RX += rv.RX
	}
	row.RuleIDs = strings.Join(ids, " ")
	return row
}

type gamesData struct {
	FlatOut, Games, NoLAN  []gameRow
	On, Off, Unsure, Total int
	CanSwitch              bool
}

func (s *Server) games(w http.ResponseWriter, r *http.Request) {
	games, err := s.Store.Games(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	live := s.liveNow(r.Context())
	idx := s.rules(r.Context(), live.Hash)
	d := gamesData{CanSwitch: store.RoleRank(sessionFrom(r).User.Role) >= store.RoleRank(store.RoleOperator)}
	sort.SliceStable(games, func(i, j int) bool { return strings.ToLower(games[i].Name) < strings.ToLower(games[j].Name) })
	for _, g := range games {
		row := gameRowOf(g, idx, live)
		switch {
		case g.RelayNeeded == "no":
			d.NoLAN = append(d.NoLAN, row)
			continue
		case row.Pinned: // FlatOut family on top (decision 2026-11-16)
			d.FlatOut = append(d.FlatOut, row)
		default:
			d.Games = append(d.Games, row)
		}
		d.Total++
		if g.Enabled {
			d.On++
		} else {
			d.Off++
		}
		if row.Unsure {
			d.Unsure++
		}
	}
	s.renderLive(w, r, "games", "Spiele", "games", &d, live)
}

type gameDetail struct {
	Game      gameRow
	Rules     []ruleView
	Steps     []diagStep
	Verdict   diagStep
	CanSwitch bool
}

type ruleView struct {
	compile.Rule
	RX, Relayed uint64
}

func (s *Server) game(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	games, err := s.Store.Games(ctx)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	i := slices.IndexFunc(games, func(g store.GameRow) bool { return g.ID == id })
	if i < 0 {
		s.fail(w, r, http.StatusNotFound, "Dieses Spiel gibt es nicht.")
		return
	}
	live := s.liveNow(ctx)
	idx := s.rules(ctx, live.Hash)
	d := &gameDetail{Game: gameRowOf(games[i], idx, live), Rules: rulesFor(idx, id, live),
		CanSwitch: store.RoleRank(sessionFrom(r).User.Role) >= store.RoleRank(store.RoleOperator)}
	d.Steps, d.Verdict = diagnose(games[i], d.Rules, live)
	if r.URL.Query().Get("teil") == "diagnose" { // fragment for the live refresh
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := s.tpl["game"].ExecuteTemplate(w, "diagnose", d); err != nil {
			s.Log.Error("render", "page", "game/diagnose", "err", err)
		}
		return
	}
	s.renderLive(w, r, "game", d.Game.Name, "games", d, live)
}

type applyAnswer struct {
	OK       bool     `json:"ok"`
	Enabled  bool     `json:"enabled"`
	Message  string   `json:"message,omitempty"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Revision int64    `json:"revision,omitempty"`
}

// applyNow compiles and applies after a change; warnings except shared ports are reported.
func (s *Server) applyNow(r *http.Request, note string) applyAnswer {
	res, err := control.Apply(r.Context(), s.Store, s.Engine, s.actor(r), note, false)
	s.dropRuleIndex()
	a := applyAnswer{OK: err == nil, Revision: res.Revision}
	for _, w := range res.Warnings {
		if w.Code != compile.WarnSharedPort {
			a.Warnings = append(a.Warnings, w.Message)
		}
	}
	if err != nil {
		a.Error = err.Error()
	}
	return a
}

func (s *Server) toggleGame(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	on := r.PostFormValue("on") == "1"
	path := backPath(r, "/spiele")
	name := id
	if games, err := s.Store.Games(r.Context()); err == nil {
		if i := slices.IndexFunc(games, func(g store.GameRow) bool { return g.ID == id }); i >= 0 {
			name = games[i].Name
		}
	}
	if err := s.Store.SetGameEnabled(r.Context(), s.actor(r), id, on); err != nil {
		s.answer(w, r, path, applyAnswer{Error: err.Error()})
		return
	}
	verb := "aus"
	if on {
		verb = "an"
	}
	a := s.applyNow(r, fmt.Sprintf("%s %s", id, verb))
	a.Enabled = on
	if a.OK {
		a.Message = fmt.Sprintf("%s ist %s (Revision %d).", name, verb, a.Revision)
	}
	s.Log.Info("game toggled", "user", s.actor(r), "game", id, "on", on, "ok", a.OK)
	s.answer(w, r, path, a)
}

// backPath is where a form wants to return to (hidden field "back"); only local paths are accepted.
func backPath(r *http.Request, def string) string {
	p := r.PostFormValue("back")
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\?#\r\n") {
		return p
	}
	return def
}

func (s *Server) answer(w http.ResponseWriter, r *http.Request, path string, a applyAnswer) {
	if wantsJSON(r) {
		code := http.StatusOK
		if a.Error != "" {
			code = http.StatusUnprocessableEntity
		}
		writeJSON(w, code, a)
		return
	}
	var err error
	if a.Error != "" {
		err = errors.New(a.Error)
	}
	back(w, r, path, a.Message, err)
}

// ---- Netz ----

type vlanRow struct {
	store.VLANConfig
	Key   string
	Iface string
	Live  vlanView
}

type matrixRow struct {
	Src   string
	Cells []bool
}

type profileView struct {
	Name    string
	Default bool
	Groups  []string
	Rows    []matrixRow
}

// matrix turns the edges of a flow profile into a table source group x destination group.
func matrix(p store.ProfileConfig, groups []string) profileView {
	for _, e := range p.Edges {
		for _, g := range []string{e.Src, e.Dst} {
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
	}
	v := profileView{Name: p.Name, Default: p.Default, Groups: groups}
	for _, src := range groups {
		row := matrixRow{Src: src}
		for _, dst := range groups {
			row.Cells = append(row.Cells, slices.Contains(p.Edges, compile.Edge{Src: src, Dst: dst}))
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}

func (s *Server) network(w http.ResponseWriter, r *http.Request) {
	c, err := s.Store.ExportConfig(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	live := s.liveNow(r.Context())
	var rows []vlanRow
	var groups []string
	on := 0
	for _, v := range c.VLANs {
		row := vlanRow{VLANConfig: v, Key: tableKey(v.Name, v.Group), Iface: v.Device}
		if v.Attach == compile.AttachTrunk {
			row.Iface = fmt.Sprintf("%s.%d", v.Parent, v.VID)
		}
		if i := slices.IndexFunc(live.VLANs, func(x vlanView) bool { return x.VID == v.VID }); i >= 0 {
			row.Live = live.VLANs[i]
		}
		if v.Enabled {
			on++
		}
		if !slices.Contains(groups, v.Group) {
			groups = append(groups, v.Group)
		}
		rows = append(rows, row)
	}
	var profiles []profileView
	for _, p := range c.Profiles {
		profiles = append(profiles, matrix(p, slices.Clone(groups)))
	}
	s.renderLive(w, r, "network", "Netz", "network", map[string]any{"VLANs": rows, "Profiles": profiles, "On": on, "Total": len(rows)}, live)
}

func (s *Server) toggleVLAN(w http.ResponseWriter, r *http.Request) {
	vid, err := strconv.Atoi(r.PathValue("vid"))
	if err != nil {
		s.answer(w, r, "/netz", applyAnswer{Error: "VLAN-ID ungültig."})
		return
	}
	on := r.PostFormValue("on") == "1"
	if err := s.Store.SetVLANEnabled(r.Context(), s.actor(r), vid, on); err != nil {
		s.answer(w, r, "/netz", applyAnswer{Error: err.Error()})
		return
	}
	a := s.applyNow(r, fmt.Sprintf("VLAN %d %v", vid, map[bool]string{true: "an", false: "aus"}[on]))
	a.Enabled = on
	if a.OK {
		a.Message = fmt.Sprintf("VLAN %d ist %s.", vid, map[bool]string{true: "an", false: "aus"}[on])
	}
	s.answer(w, r, "/netz", a)
}

// ---- System, Verlauf ----

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	mode, _ := s.Store.Setting(r.Context(), store.SettingMode, compile.ModeActive)
	tok, _ := s.Store.Setting(r.Context(), settingMonitorToken, "")
	s.render(w, r, "system", "System", "system", map[string]any{"Mode": mode, "MonitorSet": tok != ""})
}

type auditView struct {
	TS     string
	User   string
	Text   string
	Object string
	Mono   bool // object is technical (IP, id)
	Tone   string
}

var auditTexts = map[string]string{
	"login":             "Angemeldet",
	"login.failed":      "Anmeldung fehlgeschlagen",
	"login.locked":      "Konto gesperrt (zu viele Fehlversuche)",
	"game.enable":       "Spiel eingeschaltet",
	"game.disable":      "Spiel ausgeschaltet",
	"vlan.enable":       "Netz eingeschaltet",
	"vlan.disable":      "Netz ausgeschaltet",
	"mode.set":          "Betriebsart geändert",
	"apply":             "Stand angewendet",
	"apply.rejected":    "Stand von der Engine abgelehnt",
	"rollback":          "Zurückgerollt",
	"config.import":     "Konfiguration importiert",
	"user.set_password": "Passwort gesetzt",
	"emergency_stop":    "Not-Aus ausgelöst",
	"backup.download":   "Backup heruntergeladen",
	"monitor.token":     "Monitoring-Token neu erzeugt",
	"alarm.ack":         "Alarm als gesehen markiert",
	"finder.start":      "Port-Finder gestartet",
	"finder.pcap":       "Mitschnitt heruntergeladen",
	"game.create":       "Spiel angelegt",
}

func auditOf(a store.AuditEntry) auditView {
	v := auditView{TS: a.TS, User: a.User, Text: auditTexts[a.Action], Object: a.Object}
	if v.Text == "" {
		v.Text = a.Action
	}
	switch a.Action {
	case "login", "login.failed", "login.locked", "game.enable", "game.disable", "backup.download":
		v.Mono = true
	case "vlan.enable", "vlan.disable":
		v.Object = "VLAN " + a.Object
		v.Mono = true
	case "mode.set":
		v.Object = modeName(a.Before) + " → " + modeName(a.After)
	case "emergency_stop":
		v.Object = "Relay pausiert"
	case "apply", "apply.rejected", "rollback":
		v.Object = strings.Replace(a.Object, "revision", "Revision", 1)
	case "user.set_password":
		v.Object = "Konto " + a.Object
	}
	switch a.Action {
	case "emergency_stop", "apply.rejected", "login.locked":
		v.Tone = "danger"
	case "login.failed", "rollback":
		v.Tone = "warn"
	}
	return v
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	revs, _ := s.Store.Revisions(ctx, 30)
	withLogins := r.URL.Query().Get("anmeldungen") == "1"
	raw, _ := s.Store.AuditLog(ctx, 400)
	var audit []auditView
	hidden := 0
	for _, a := range raw {
		if !withLogins && a.Action == "login" {
			hidden++
			continue
		}
		if len(audit) < 100 {
			audit = append(audit, auditOf(a))
		}
	}
	s.render(w, r, "history", "Verlauf", "history", map[string]any{"Revisions": revs, "Audit": audit, "Logins": withLogins, "Hidden": hidden})
}

// emergencyConfirm is the confirmation page for the emergency stop (the header button opens it as a dialog
// when JavaScript runs).
func (s *Server) emergencyConfirm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "notaus", "Not-Aus", "", nil)
}

func (s *Server) setMode(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	path := backPath(r, "/system")
	if err := s.Store.SetMode(r.Context(), s.actor(r), mode); err != nil {
		back(w, r, path, "", err)
		return
	}
	a := s.applyNow(r, "Betriebsart "+modeName(mode))
	if a.OK {
		a.Message = "Betriebsart ist jetzt " + modeName(mode) + "."
	}
	s.answer(w, r, path, a)
}

func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.SetMode(r.Context(), s.actor(r), compile.ModePaused); err != nil {
		back(w, r, "/", "", err)
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "emergency_stop", "engine", "", "paused")
	s.Log.Warn("emergency stop", "user", s.actor(r))
	a := s.applyNow(r, "Not-Aus")
	if a.OK {
		a.Message = "Not-Aus: Relay pausiert. Wieder einschalten kann ein Admin unter System."
	}
	s.answer(w, r, "/", a)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		back(w, r, "/verlauf", "", errors.New("Revision ungültig."))
		return
	}
	res, err := control.Rollback(r.Context(), s.Store, s.Engine, s.actor(r), id)
	s.dropRuleIndex()
	if err != nil {
		back(w, r, "/verlauf", "", err)
		return
	}
	back(w, r, "/verlauf", fmt.Sprintf("Auf Revision %d zurückgerollt (neu: %d).", id, res.Revision), nil)
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp("", "nsrelay-dl-")
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(dir)
	path, err := control.Backup(r.Context(), s.Store, dir, 0)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "backup.download", filepath.Base(path), "", "")
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(path)+`"`)
	http.ServeFile(w, r, path)
}

// ---- Komponenten (design reference) and API ----

func (s *Server) components(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "components", "Komponenten", "", nil)
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	st, err := s.Engine.Status(ctx)
	out := map[string]any{"version": s.Version, "engine": st}
	if err != nil {
		out["engine_error"] = err.Error()
	}
	if ev, err := s.Store.ActiveEvent(ctx); err == nil {
		out["event"] = ev
	}
	writeJSON(w, http.StatusOK, out)
}
