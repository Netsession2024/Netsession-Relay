package web

import (
	"cmp"
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
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
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
	Checked string // newest verification result (works|fails|partial) or ""
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

// gameGroup is one block of the games list.
type gameGroup struct {
	Key, Title, Sub string
	Rows            []gameRow
}

type gamesData struct {
	Groups         []gameGroup // with traffic, games, platforms, network services
	NoPorts        []gameRow   // ports unknown: nothing to switch yet
	NoLAN          []gameRow   // no LAN broadcast at all
	On, Off, Total int
	Checked        int    // games with a test entry
	View           string // an | aus | alle
	CanSwitch      bool
}

// gamesView reads which games the list shows: "an" (default, the working list during a LAN), "aus" or "alle".
func gamesView(r *http.Request) string {
	q := r.URL.Query()
	switch v := cmp.Or(q.Get("zeige"), q.Get("filter")); v {
	case "aus", "alle":
		return v
	case "all":
		return "alle"
	}
	return "an"
}

func (s *Server) games(w http.ResponseWriter, r *http.Request) {
	games, err := s.Store.Games(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	live := s.liveNow(r.Context())
	idx := s.rules(r.Context(), live.Hash)
	d := gamesData{View: gamesView(r), CanSwitch: store.RoleRank(sessionFrom(r).User.Role) >= store.RoleRank(store.RoleOperator)}
	// FlatOut family first inside its group (decision 2026-11-16), then by name
	sort.SliceStable(games, func(i, j int) bool {
		pi, pj := strings.HasPrefix(games[i].ID, "flatout"), strings.HasPrefix(games[j].ID, "flatout")
		if pi != pj {
			return pi
		}
		return strings.ToLower(games[i].Name) < strings.ToLower(games[j].Name)
	})
	latest, _ := s.Store.LatestVerifications(r.Context())
	d.Checked = len(latest)
	hot := gameGroup{Key: "hot", Title: "Mit Verkehr", Sub: "Für diese Spiele kam seit dem Start der Engine etwas an."}
	plain := gameGroup{Key: "game", Title: "Spiele"}
	platform := gameGroup{Key: "platform", Title: "Plattformen", Sub: "Gemeinsame Technik, deckt viele Spiele ab (Steam, DirectPlay, GameSpy …)."}
	service := gameGroup{Key: "service", Title: "Netzdienste", Sub: "Kein Spiel. Nur einschalten, wenn du weißt warum."}
	for _, g := range games {
		row := gameRowOf(g, idx, live)
		row.Checked = latest[g.ID].Result
		if g.RelayNeeded == "no" {
			d.NoLAN = append(d.NoLAN, row)
			continue
		}
		d.Total++
		if g.Enabled {
			d.On++
		} else {
			d.Off++
		}
		switch {
		case len(g.Discovery) == 0 && !g.Enabled:
			d.NoPorts = append(d.NoPorts, row)
		case g.Enabled && row.RX > 0:
			hot.Rows = append(hot.Rows, row)
		case g.Category == gamedb.CategoryPlatform:
			platform.Rows = append(platform.Rows, row)
		case g.Category == gamedb.CategoryGame || g.Category == "":
			plain.Rows = append(plain.Rows, row)
		default:
			service.Rows = append(service.Rows, row)
		}
	}
	sort.SliceStable(hot.Rows, func(i, j int) bool { return hot.Rows[i].RX > hot.Rows[j].RX })
	for _, g := range []gameGroup{hot, plain, platform, service} {
		if len(g.Rows) > 0 {
			d.Groups = append(d.Groups, g)
		}
	}
	s.renderLive(w, r, "games", "Spiele", "games", &d, live)
}

type gameDetail struct {
	Game          gameRow
	Rules         []ruleView
	Steps         []diagStep
	Verdict       diagStep
	CanSwitch     bool
	CanAdmin      bool
	Profile       string   // flow profile of the game in the active event ("" = default)
	Profiles      []string // all profile names
	Default       string   // name of the default profile
	Verifications []store.Verification
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
	d.CanAdmin = store.RoleRank(sessionFrom(r).User.Role) >= store.RoleRank(store.RoleAdmin)
	d.Verifications, _ = s.Store.Verifications(ctx, id)
	if c, err := s.Store.ExportConfig(ctx); err == nil {
		for _, p := range c.Profiles {
			d.Profiles = append(d.Profiles, p.Name)
			if p.Default {
				d.Default = p.Name
			}
		}
		for _, g := range c.Games {
			if g.ID == id {
				d.Profile = g.FlowProfile
			}
		}
	}
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
	Games   []string // names of the switched-on games using this profile
	Reading string   // one row put into words, as a reading aid
}

// vlanGroupView is the networks of one group, in the order of the configuration.
type vlanGroupView struct {
	Name string
	Rows []vlanRow
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
		if v.Reading == "" {
			var to []string
			for i, on := range row.Cells {
				if on {
					to = append(to, groupName(groups[i]))
				}
			}
			if len(to) > 0 {
				v.Reading = fmt.Sprintf("Zeile „%s“: Rufe von dort gehen nach %s.", groupName(src), strings.Join(to, ", "))
			}
		}
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
	var byGroup []vlanGroupView
	groupN := map[string]int{}
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
			byGroup = append(byGroup, vlanGroupView{Name: v.Group})
		}
		gi := slices.Index(groups, v.Group)
		byGroup[gi].Rows = append(byGroup[gi].Rows, row)
		groupN[v.Group]++
		rows = append(rows, row)
	}
	names := map[string]string{}
	if games, err := s.Store.Games(r.Context()); err == nil {
		for _, g := range games {
			names[g.ID] = g.Name
		}
	}
	var profiles []profileView
	for _, p := range c.Profiles {
		v := matrix(p, slices.Clone(groups))
		for _, g := range c.Games {
			if g.FlowProfile == p.Name || (g.FlowProfile == "" && p.Default) {
				v.Games = append(v.Games, cmp.Or(names[g.ID], g.ID))
			}
		}
		slices.Sort(v.Games)
		profiles = append(profiles, v)
	}
	s.renderLive(w, r, "network", "Netz", "network", map[string]any{"VLANs": rows, "Groups": byGroup, "GroupN": groupN,
		"Profiles": profiles, "On": on, "Total": len(rows)}, live)
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
	s.render(w, r, "system", "System", "system", s.systemData(r))
}

// systemData is the view model of the system page (also used when a new monitoring token is shown).
func (s *Server) systemData(r *http.Request) map[string]any {
	mode, _ := s.Store.Setting(r.Context(), store.SettingMode, compile.ModeActive)
	tok, _ := s.Store.Setting(r.Context(), settingMonitorToken, "")
	services, _ := s.Store.Services(r.Context())
	total, failing, _ := s.outputStats()
	return map[string]any{"Mode": mode, "MonitorSet": tok != "", "Targets": total, "TargetsFailing": failing,
		"Syslog": s.syslogTarget(r.Context()), "Services": services, "ServiceIP": r.URL.Query().Get("dienst"),
		"Resume": s.resumeMode(r), "ResumeName": modeName(s.resumeMode(r))}
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
	"login":                 "Angemeldet",
	"login.failed":          "Anmeldung fehlgeschlagen",
	"login.locked":          "Konto gesperrt (zu viele Fehlversuche)",
	"game.enable":           "Spiel eingeschaltet",
	"game.disable":          "Spiel ausgeschaltet",
	"vlan.enable":           "Netz eingeschaltet",
	"vlan.disable":          "Netz ausgeschaltet",
	"vlan.create":           "Netz angelegt",
	"vlan.update":           "Netz geändert",
	"vlan.delete":           "Netz gelöscht",
	"mode.set":              "Betriebsart geändert",
	"apply":                 "Stand angewendet",
	"apply.rejected":        "Stand von der Engine abgelehnt",
	"rollback":              "Zurückgerollt",
	"config.import":         "Konfiguration importiert",
	"user.set_password":     "Passwort gesetzt",
	"emergency_stop":        "Not-Aus ausgelöst",
	"emergency_release":     "Not-Aus aufgehoben",
	"backup.download":       "Backup heruntergeladen",
	"monitor.token":         "Monitoring-Token neu erzeugt",
	"alarm.ack":             "Alarm als gesehen markiert",
	"finder.start":          "Port-Finder gestartet",
	"finder.pcap":           "Mitschnitt heruntergeladen",
	"game.create":           "Spiel angelegt",
	"game.update":           "Spiel geändert",
	"game.delete":           "Spiel gelöscht",
	"game.profile":          "Profil eines Spiels gewählt",
	"profile.edges":         "Profil geändert",
	"profile.create":        "Profil angelegt",
	"profile.delete":        "Profil gelöscht",
	"profile.default":       "Standardprofil gesetzt",
	"profile.rename":        "Profil umbenannt",
	"game.verify":           "Spiel geprüft",
	"game.verify_delete":    "Prüfung gelöscht",
	"config.export":         "Konfiguration exportiert",
	"syslog.set":            "Syslog-Ziel geändert",
	"monitor.target.create": "Monitoring-Ziel angelegt",
	"monitor.target.update": "Monitoring-Ziel geändert",
	"monitor.target.delete": "Monitoring-Ziel gelöscht",
	"monitor.target.test":   "Testmeldung gesendet",
	"snmp.agent.set":        "SNMP-Agent geändert",
	"monitor.host":          "Name für das Monitoring geändert",
	"service.set":           "Als Dienst markiert",
	"service.delete":        "Dienst-Markierung entfernt",
}

func auditOf(a store.AuditEntry) auditView {
	v := auditView{TS: a.TS, User: a.User, Text: auditTexts[a.Action], Object: a.Object}
	if v.Text == "" {
		v.Text = a.Action
	}
	switch a.Action {
	case "login", "login.failed", "login.locked", "game.enable", "game.disable", "backup.download":
		v.Mono = true
	case "vlan.enable", "vlan.disable", "vlan.create", "vlan.update", "vlan.delete":
		v.Object = "VLAN " + a.Object
		v.Mono = true
	case "mode.set":
		v.Object = modeName(a.Before) + " → " + modeName(a.After)
	case "emergency_stop":
		v.Object = "Relay pausiert"
	case "emergency_release":
		v.Object = "zurück auf " + modeName(a.After)
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
// settingModeBeforeStop holds the mode that was set when the emergency stop was pressed. While it is set and
// the mode is still "paused", an operator may switch the relay back on (decision 2026-11-16).
const settingModeBeforeStop = "mode_before_stop"

// resumeMode returns the mode an operator may restore after an emergency stop, or "".
func (s *Server) resumeMode(r *http.Request) string {
	mode, _ := s.Store.Setting(r.Context(), store.SettingMode, compile.ModeActive)
	prev, _ := s.Store.Setting(r.Context(), settingModeBeforeStop, "")
	if mode != compile.ModePaused || (prev != compile.ModeActive && prev != compile.ModeObserve) {
		return ""
	}
	return prev
}

func (s *Server) emergencyConfirm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "notaus", "Not-Aus", "", map[string]any{"Resume": s.resumeMode(r), "ResumeName": modeName(s.resumeMode(r))})
}

// emergencyRelease switches the relay back to the mode it had before the emergency stop (operator and up).
func (s *Server) emergencyRelease(w http.ResponseWriter, r *http.Request) {
	prev := s.resumeMode(r)
	if prev == "" {
		back(w, r, "/", "", errors.New("Das Relay ist nicht durch Not-Aus pausiert. Die Betriebsart ändert ein Admin unter System."))
		return
	}
	if err := s.Store.SetMode(r.Context(), s.actor(r), prev); err != nil {
		back(w, r, "/", "", err)
		return
	}
	_ = s.Store.SetSetting(r.Context(), settingModeBeforeStop, "")
	_ = s.Store.Audit(r.Context(), s.actor(r), "emergency_release", "engine", compile.ModePaused, prev)
	s.Log.Warn("emergency stop released", "user", s.actor(r), "mode", prev)
	a := s.applyNow(r, "Not-Aus aufgehoben")
	if a.OK {
		a.Message = "Relay wieder an: " + modeName(prev) + "."
	}
	s.answer(w, r, "/", a)
}

func (s *Server) setMode(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	path := backPath(r, "/system")
	if err := s.Store.SetMode(r.Context(), s.actor(r), mode); err != nil {
		back(w, r, path, "", err)
		return
	}
	_ = s.Store.SetSetting(r.Context(), settingModeBeforeStop, "") // an admin decided: no operator release
	a := s.applyNow(r, "Betriebsart "+modeName(mode))
	if a.OK {
		a.Message = "Betriebsart ist jetzt " + modeName(mode) + "."
	}
	s.answer(w, r, path, a)
}

func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	if prev, _ := s.Store.Setting(r.Context(), store.SettingMode, compile.ModeActive); prev != compile.ModePaused {
		_ = s.Store.SetSetting(r.Context(), settingModeBeforeStop, prev)
	}
	if err := s.Store.SetMode(r.Context(), s.actor(r), compile.ModePaused); err != nil {
		back(w, r, "/", "", err)
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "emergency_stop", "engine", "", "paused")
	s.Log.Warn("emergency stop", "user", s.actor(r))
	a := s.applyNow(r, "Not-Aus")
	if a.OK {
		a.Message = "Not-Aus: Relay pausiert. Wieder einschalten: Not-Aus-Seite, ab Operator."
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
