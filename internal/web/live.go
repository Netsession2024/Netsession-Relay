package web

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/control"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// The live view is the single source for everything that changes while a page is open: the templates render
// it on page load and GET /api/v1/events sends the same structure as JSON every LiveInterval. All wording is
// made here, so the JavaScript only copies text into the page.

// stateView is the operating state in words.
type stateView struct {
	Key      string `json:"key"`   // active | observe | paused | standby | holdoff | down | none
	Tone     string `json:"tone"`  // ok | info | warn | danger | neutral
	Icon     string `json:"icon"`  // sprite name
	Label    string `json:"label"` // short, for the header chip
	Headline string `json:"headline"`
	Text     string `json:"text"`
	// Relaying: copies are being sent right now.
	Relaying bool `json:"relaying"`
	// CanStop: an emergency stop makes sense (something is configured and it is not paused already).
	CanStop bool `json:"can_stop"`
}

func stateOf(st engineapi.Status, engineOK bool) stateView {
	switch {
	case !engineOK:
		return stateView{Key: "down", Tone: "danger", Icon: "alert", Label: "Engine weg", Headline: "Engine antwortet nicht",
			Text: "Die Weboberfläche erreicht die Engine nicht. Ob gerade weitergeleitet wird, ist unbekannt. Prüfe den Container nsrelay-engine-1."}
	case st.Mode == "":
		return stateView{Key: "none", Tone: "neutral", Icon: "info", Label: "Leer", Headline: "Noch keine Konfiguration",
			Text: "Die Engine hat noch keinen Stand bekommen. Schalte ein Spiel oder wähle unter System eine Betriebsart."}
	case st.Mode == compile.ModePaused:
		return stateView{Key: "paused", Tone: "warn", Icon: "pause", Label: "Pausiert", Headline: "Relay ist pausiert",
			Text: "Es wird nichts weitergeleitet. Spiele aus anderen Netzen werden nicht gefunden."}
	case st.Mode == compile.ModeObserve:
		return stateView{Key: "observe", Tone: "info", Icon: "eye", Label: "Beobachten", Headline: "Relay beobachtet nur", CanStop: true,
			Text: "Es zählt mit und sendet nichts. Über dieses Relay findet niemand ein Spiel."}
	case st.Standby:
		return stateView{Key: "standby", Tone: "warn", Icon: "pause", Label: "Standby", Headline: "Zweites Relay aktiv, dieses hält still", CanStop: true,
			Text: "Ein anderes Relay war zuerst da und sendet. Dieses übernimmt, sobald das andere 10 Sekunden schweigt."}
	case !st.Sending:
		return stateView{Key: "holdoff", Tone: "warn", Icon: "pause", Label: "Startet", Headline: "Relay startet", CanStop: true,
			Text: "Es prüft kurz, ob schon ein anderes Relay sendet, und legt dann los."}
	}
	return stateView{Key: "active", Tone: "ok", Icon: "check", Label: "Aktiv", Headline: "Relay leitet weiter", Relaying: true, CanStop: true,
		Text: "Spiele-Broadcasts werden zwischen den Netzen kopiert."}
}

type vlanView struct {
	VID     int    `json:"vid"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"` // in the configuration
	Running bool   `json:"running"` // known to the engine
	Alarm   bool   `json:"alarm"`
	InRate  uint64 `json:"in_per_s"`
	In      uint64 `json:"in"`
	Out     uint64 `json:"out"`
	Status  string `json:"status"` // state of the tile: Verkehr | still | aus | Alarm | nicht im Relay
	Label   string `json:"label"`  // word shown on the tile: the status, or the name of the alarm
	// AlarmKind is the alarm this network is part of ("" = none); the tile links to that alarm card.
	AlarmKind string `json:"alarm_kind,omitempty"`
	Interface string `json:"-"`
}

type busyRow struct {
	Rule    string `json:"rule"`
	Names   string `json:"names"`          // short: first game, "+N" for the others on the same port
	Game    string `json:"game,omitempty"` // id of the first game, for the link
	All     string `json:"all,omitempty"`  // every game on this rule
	Ports   string `json:"ports"`
	Rate    uint64 `json:"per_s"`
	RX      uint64 `json:"rx"`
	Relayed uint64 `json:"relayed"`
}

type reasonView struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

// alarmGroup aggregates alarms of one kind (e.g. a foreign relay seen in 16 VLANs) into one entry.
type alarmGroup struct {
	Kind   string     `json:"kind"`
	Title  string     `json:"title"`
	Hint   string     `json:"hint,omitempty"`
	Keys   []string   `json:"-"`
	Nets   []alarmNet `json:"nets"`  // affected networks (keys that are VLAN ids)
	Where  string     `json:"where"` // the keys that are not networks (rules), "" if there are none
	Count  uint64     `json:"count"`
	Last   time.Time  `json:"last"`
	Detail string     `json:"detail"`
	Acked  bool       `json:"acked"`
	By     string     `json:"acked_by,omitempty"`
}

// alarmNet is one network an alarm concerns; the alarm card links to its tile.
type alarmNet struct {
	VID  int    `json:"vid"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// alarmShort is the alarm name as it fits on a network tile.
var alarmShort = map[string]string{
	"foreign_relay": "Fremdes Relay",
	"loop":          "Schleife",
	"storm":         "Sturm-Bremse",
	"dual_active":   "Zweites Relay",
}

type liveView struct {
	TS         time.Time             `json:"ts"`
	Demo       bool                  `json:"demo,omitempty"`
	EngineOK   bool                  `json:"engine_ok"`
	State      stateView             `json:"state"`
	Mode       string                `json:"mode"`
	Hash       string                `json:"hash"`
	NeedsApply bool                  `json:"needs_apply"`
	RXRate     uint64                `json:"rx_per_s"`
	SentRate   uint64                `json:"sent_per_s"`
	RX         uint64                `json:"rx"`
	Sent       uint64                `json:"sent"`
	RuleCount  int                   `json:"rule_count"`
	VLANCount  int                   `json:"vlan_count"`
	GamesOn    int                   `json:"games_on"`
	GamesTotal int                   `json:"games_total"`
	Enabled    []string              `json:"enabled"` // ids of games switched on
	Alarms     []alarmGroup          `json:"alarms"`  // open
	Seen       []alarmGroup          `json:"seen"`    // acknowledged, still occurring
	VLANs      []vlanView            `json:"vlans"`
	Rules      []engineapi.RuleStat  `json:"rules"`
	Busy       []busyRow             `json:"busy"`
	Unknown    []engineapi.PortCount `json:"unknown"`
	Reasons    []reasonView          `json:"reasons"`
	Engine     engineapi.Status      `json:"-"`
	ruleRX     map[string]uint64     // for the hub: counters of this sample
	games      map[string]store.GameRow
}

var alarmTitles = map[string]string{
	"foreign_relay": "Fremdes Relay aktiv",
	"loop":          "Schleife erkannt",
	"storm":         "Sturm-Bremse hat eine Regel pausiert",
	"dual_active":   "Zweites Relay entdeckt",
}

var alarmHints = map[string]string{
	"loop":        "Pakete kreisen. Die betroffene Regel ist gebremst. Suche ein zweites Relay oder eine Brücke zwischen den Netzen.",
	"storm":       "Zu viele Pakete auf einem Port. Die Regel pausiert und läuft von selbst wieder an.",
	"dual_active": "Zwei Relays für dieselben Netze. Eins von beiden muss aus.",
}

func groupAlarms(alarms []engineapi.Alarm, mode string) []alarmGroup {
	byKind := map[string]*alarmGroup{}
	var order []string
	for _, a := range alarms {
		g := byKind[a.Kind]
		if g == nil {
			g = &alarmGroup{Kind: a.Kind, Title: alarmTitles[a.Kind], Hint: alarmHints[a.Kind]}
			if g.Title == "" {
				g.Title = a.Kind
			}
			if a.Kind == "foreign_relay" {
				g.Hint = "Ein anderes Gerät leitet dieselben Broadcasts weiter. Läuft es weiter, darf dieses Relay nicht aktiv sein."
				if mode == compile.ModeObserve {
					g.Hint = "Erwartet, solange die OPNsense-Boxen parallel laufen."
				}
			}
			byKind[a.Kind] = g
			order = append(order, a.Kind)
		}
		if len(g.Keys) == 0 {
			g.Acked, g.By = true, a.AckedBy
		}
		if a.AckedAt.IsZero() {
			g.Acked = false // one open alarm keeps the whole group open
		} else if g.By == "" {
			g.By = a.AckedBy
		}
		g.Keys = append(g.Keys, a.Key)
		g.Count += a.Count
		if a.Last.After(g.Last) || g.Detail == "" {
			g.Last, g.Detail = a.Last, a.Detail
		}
	}
	out := make([]alarmGroup, 0, len(order))
	for _, k := range order {
		g := byKind[k]
		sort.Strings(g.Keys)
		g.Where = strings.Join(g.Keys, " · ")
		g.Nets = []alarmNet{}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

var reasonLabels = map[string]string{
	"relayed":       "Weitergeleitet",
	"parse":         "Kein lesbares UDP-Paket",
	"own_mac":       "Eigene Kopie (ignoriert)",
	"blocked":       "Absender gesperrt",
	"foreign_relay": "Kopie eines fremden Relays",
	"src_subnet":    "Absender passt nicht zum Netz",
	"not_broadcast": "Kein Broadcast",
	"unknown_port":  "Port ohne Spiel",
	"no_target":     "Kein Ziel-Netz",
	"size":          "Paket zu groß",
	"ttl":           "TTL abgelaufen",
	"mode":          "Nicht gesendet (Betriebsart)",
	"loop":          "Schleifenschutz",
	"rate":          "Limit erreicht",
	"auto_paused":   "Regel pausiert (Sturm-Bremse)",
}

// ruleIndex maps compiled rules to games. It is cached per engine snapshot hash.
type ruleIndex struct {
	hash   string
	byRule map[string]compile.Rule
	byGame map[string][]compile.Rule
}

func (s *Server) rules(ctx context.Context, hash string) *ruleIndex {
	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	if s.ruleIdx != nil && hash != "" && s.ruleIdx.hash == hash {
		return s.ruleIdx
	}
	idx := &ruleIndex{hash: hash, byRule: map[string]compile.Rule{}, byGame: map[string][]compile.Rule{}}
	// dry run: compiles the current configuration, sends nothing
	if res, err := control.Apply(ctx, s.Store, s.Engine, "", "", true); err == nil && res.Snapshot != nil {
		for _, r := range res.Snapshot.Rules {
			idx.byRule[r.ID] = r
			for _, g := range r.Specs {
				idx.byGame[g] = append(idx.byGame[g], r)
			}
		}
	}
	s.ruleIdx = idx
	return idx
}

func (s *Server) dropRuleIndex() {
	s.ruleMu.Lock()
	s.ruleIdx = nil
	s.ruleMu.Unlock()
}

// liveNow builds the live view from the engine status and the database.
func (s *Server) liveNow(ctx context.Context) *liveView {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := s.Engine.Status(ctx)
	v := &liveView{TS: time.Now(), Demo: s.Demo, EngineOK: err == nil, Engine: st, Mode: st.Mode, Hash: st.SnapshotHash,
		RXRate: st.RXRate, SentRate: st.SentRate, RX: st.RX, Sent: st.Sent, RuleCount: st.Rules, VLANCount: st.VLANs,
		Enabled: []string{}, Alarms: []alarmGroup{}, VLANs: []vlanView{}, Busy: []busyRow{},
		Rules: st.RuleStats, Unknown: st.TopUnknown, Reasons: []reasonView{},
		ruleRX: map[string]uint64{}, games: map[string]store.GameRow{}}
	v.State = stateOf(st, v.EngineOK)
	groups := groupAlarms(st.Alarms, st.Mode)
	if v.Rules == nil {
		v.Rules = []engineapi.RuleStat{}
	}
	if v.Unknown == nil {
		v.Unknown = []engineapi.PortCount{}
	}

	games, _ := s.Store.Games(ctx)
	for _, g := range games {
		v.games[g.ID] = g
		if g.RelayNeeded != "no" { // games without LAN broadcast cannot be switched
			v.GamesTotal++
		}
		if g.Enabled {
			v.GamesOn++
			v.Enabled = append(v.Enabled, g.ID)
		}
	}

	// VLANs: configuration first (so switched-off tables stay visible), engine counters merged in
	// which alarm a network is part of: an open one wins over an acknowledged one
	alarmOf := map[string]string{}
	for _, open := range []bool{false, true} {
		for _, a := range st.Alarms {
			if a.AckedAt.IsZero() == open {
				alarmOf[a.Key] = a.Kind
			}
		}
	}
	stats := map[int]engineapi.VLANStat{}
	for _, x := range st.VLANStats {
		stats[x.VID] = x
	}
	seen := map[int]bool{}
	addVLAN := func(vid int, name, group string, enabled bool) {
		x, running := stats[vid]
		seen[vid] = true
		t := vlanView{VID: vid, Name: name, Group: group, Key: tableKey(name, group), Enabled: enabled, Running: running,
			InRate: x.InRate, In: x.In, Out: x.Out, Interface: x.Interface, AlarmKind: alarmOf[strconv.Itoa(vid)]}
		t.Alarm = t.AlarmKind != ""
		switch {
		case !enabled:
			t.Status = "aus"
		case t.Alarm:
			t.Status = "Alarm"
		case !running && v.EngineOK:
			t.Status = "nicht im Relay"
		case t.InRate > 0:
			t.Status = "Verkehr"
		default:
			t.Status = "still"
		}
		t.Label = t.Status
		if t.Status == "Alarm" {
			t.Label = cmp.Or(alarmShort[t.AlarmKind], alarmTitles[t.AlarmKind], t.AlarmKind)
		} else {
			t.AlarmKind = ""
		}
		v.VLANs = append(v.VLANs, t)
	}
	if c, err := s.Store.ExportConfig(ctx); err == nil {
		for _, x := range c.VLANs {
			addVLAN(x.VID, x.Name, x.Group, x.Enabled)
		}
	}
	for _, x := range st.VLANStats {
		if !seen[x.VID] {
			addVLAN(x.VID, x.Name, x.Group, true)
		}
	}

	// alarms: keys that are networks become links to the tiles, the rest stays as text
	for _, g := range groups {
		var rest []string
		for _, k := range g.Keys {
			vid, err := strconv.Atoi(k)
			i := slices.IndexFunc(v.VLANs, func(x vlanView) bool { return err == nil && x.VID == vid })
			if i < 0 {
				rest = append(rest, k)
				continue
			}
			g.Nets = append(g.Nets, alarmNet{VID: vid, Name: v.VLANs[i].Name, Key: v.VLANs[i].Key})
		}
		sort.Slice(g.Nets, func(i, j int) bool { return g.Nets[i].VID < g.Nets[j].VID })
		g.Where = strings.Join(rest, " · ")
		if g.Acked {
			v.Seen = append(v.Seen, g)
		} else {
			v.Alarms = append(v.Alarms, g)
		}
	}

	if revs, _ := s.Store.Revisions(ctx, 1); len(revs) > 0 && v.EngineOK && st.SnapshotHash != "" && revs[0].AppliedOK &&
		revs[0].Hash != st.SnapshotHash {
		v.NeedsApply = true
	}

	// games with traffic: rules that have received something, busiest first
	idx := s.rules(ctx, st.SnapshotHash)
	rates := s.hub.rates()
	for _, rs := range st.RuleStats {
		v.ruleRX[rs.ID] = rs.RX
		if rs.RX == 0 {
			continue
		}
		row := busyRow{Rule: rs.ID, Names: rs.ID, RX: rs.RX, Relayed: rs.Relayed, Rate: rates[rs.ID]}
		if r, ok := idx.byRule[rs.ID]; ok {
			row.Ports = r.Ports
			refs := gameRefs(r.Specs, v.games)
			if len(refs) > 0 {
				row.Game, row.Names = refs[0].ID, shortName(refs[0].Name)
				if n := len(refs) - 1; n > 0 {
					row.Names += fmt.Sprintf(" +%d", n)
				}
				var all []string
				for _, g := range refs {
					all = append(all, g.Name)
				}
				row.All = strings.Join(all, " · ")
			}
		}
		v.Busy = append(v.Busy, row)
	}
	sort.SliceStable(v.Busy, func(i, j int) bool {
		a, b := v.Busy[i], v.Busy[j]
		if a.Rate != b.Rate {
			return a.Rate > b.Rate
		}
		return a.RX > b.RX
	})
	if len(v.Busy) > 6 {
		v.Busy = v.Busy[:6]
	}

	for k, n := range st.Reasons {
		if k == "relayed" {
			continue
		}
		label := reasonLabels[k]
		if label == "" {
			label = k
		}
		v.Reasons = append(v.Reasons, reasonView{Key: k, Label: label, Count: n})
	}
	sort.Slice(v.Reasons, func(i, j int) bool {
		if v.Reasons[i].Count != v.Reasons[j].Count {
			return v.Reasons[i].Count > v.Reasons[j].Count
		}
		return v.Reasons[i].Key < v.Reasons[j].Key
	})
	return v
}

// ---- hub: one engine poll for all open pages ----

// The engine has its own event stream on the Unix socket. The web part does not relay it but asks for the
// status once per interval while at least one page is open: the same code path as the page render, it works
// with every Engine implementation (tests, demo), and the stream also carries database state (games on).
type liveHub struct {
	mu      sync.Mutex
	subs    map[chan []byte]struct{}
	running bool
	prevRX  map[string]uint64
	prevAt  time.Time
	rate    map[string]uint64
	rateAt  time.Time
}

func (h *liveHub) rates() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Since(h.rateAt) > 10*time.Second {
		return nil
	}
	return h.rate
}

// sample stores the per-rule rates derived from two consecutive polls.
func (h *liveHub) sample(v *liveView) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := v.TS
	if dt := now.Sub(h.prevAt).Seconds(); h.prevRX != nil && dt > 0.01 && dt < 30 && v.EngineOK {
		rate := map[string]uint64{}
		for id, rx := range v.ruleRX {
			if p, ok := h.prevRX[id]; ok && rx > p {
				rate[id] = uint64(float64(rx-p)/dt + 0.5)
			}
		}
		h.rate, h.rateAt = rate, now
	}
	if v.EngineOK {
		h.prevRX, h.prevAt = v.ruleRX, now
	}
}

func (s *Server) subscribe() chan []byte {
	h := s.hub
	ch := make(chan []byte, 1)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	start := !h.running
	h.running = true
	h.mu.Unlock()
	if start {
		go s.runHub()
	}
	return ch
}

func (s *Server) unsubscribe(ch chan []byte) {
	s.hub.mu.Lock()
	delete(s.hub.subs, ch)
	s.hub.mu.Unlock()
}

func (s *Server) runHub() {
	h := s.hub
	t := time.NewTicker(s.interval())
	defer t.Stop()
	for range t.C {
		h.mu.Lock()
		if len(h.subs) == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
		v := s.liveNow(context.Background())
		h.sample(v)
		for i := range v.Busy {
			v.Busy[i].Rate = h.rate[v.Busy[i].Rule]
		}
		b, err := json.Marshal(v)
		if err != nil {
			continue
		}
		h.mu.Lock()
		for ch := range h.subs {
			select {
			case ch <- b:
			default: // slow reader: drop the old sample, keep the new one
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- b:
				default:
				}
			}
		}
		h.mu.Unlock()
	}
}

func (s *Server) interval() time.Duration {
	if s.LiveInterval > 0 {
		return s.LiveInterval
	}
	return 2 * time.Second
}

// apiEvents is the live stream for open pages (server-sent events): one "status" event at once, then one per
// interval. The browser reconnects by itself; "retry" sets the pause.
func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no") // reverse proxies must not buffer the stream
	ch := s.subscribe()
	defer s.unsubscribe(ch)
	first, _ := json.Marshal(s.liveNow(r.Context()))
	fmt.Fprintf(w, "retry: 3000\nevent: status\ndata: %s\n\n", first)
	fl.Flush()
	// the session can end while the stream is open
	check := time.NewTicker(time.Minute)
	defer check.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-check.C:
			if c, err := r.Cookie(cookieName); err != nil {
				return
			} else if _, err := s.Store.SessionByToken(r.Context(), c.Value); err != nil {
				fmt.Fprint(w, "event: bye\ndata: {}\n\n")
				fl.Flush()
				return
			}
		case b := <-ch:
			if _, err := fmt.Fprintf(w, "event: status\ndata: %s\n\n", b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// ---- diagnosis: why is a game not found? ----

type diagStep struct {
	Tone  string // ok | warn | danger | neutral
	Icon  string
	Title string
	Text  string
}

func step(tone, title, text string) diagStep {
	icon := map[string]string{"ok": "check", "warn": "alert", "danger": "alert", "neutral": "dash"}[tone]
	return diagStep{Tone: tone, Icon: icon, Title: title, Text: text}
}

// diagnose walks the chain a discovery packet takes, from the switch in the UI to the copy on the wire.
func diagnose(g store.GameRow, rules []ruleView, v *liveView) (steps []diagStep, verdict diagStep) {
	var rx, relayed uint64
	for _, r := range rules {
		rx += r.RX
		relayed += r.Relayed
	}
	switch g.RelayNeeded {
	case "no":
		verdict = step("neutral", "Nichts zu relayen", "Dieses Spiel sucht nicht per Broadcast. Das Relay kann hier nicht helfen. Lies die Hinweise unten.")
		return nil, verdict
	case "unknown":
		steps = append(steps, step("warn", "Ports nicht belegt", "Welche Ports das Spiel für die LAN-Suche nutzt, ist nicht sicher. Schau unter Übersicht in „Unbekannte Ports“, während jemand den LAN-Browser öffnet."))
	}
	bad := -1
	add := func(s diagStep) {
		steps = append(steps, s)
		if bad < 0 && (s.Tone == "danger" || s.Tone == "warn") {
			bad = len(steps) - 1
		}
	}
	if g.Enabled {
		add(step("ok", "Spiel ist an", "Im aktiven Event eingeschaltet."))
	} else {
		add(step("danger", "Spiel ist aus", "Schalte es oben ein. Das wirkt sofort."))
	}
	switch {
	case !g.Enabled:
		add(step("neutral", "Regel im Relay", "Entsteht, sobald das Spiel an ist."))
	case len(rules) == 0:
		add(step("danger", "Keine Regel im Relay", "Das Spiel ist an, aber es entsteht keine Regel. Es hat keine Broadcast-Ports hinterlegt."))
	default:
		var ports []string
		for _, r := range rules {
			ports = append(ports, r.Ports)
		}
		add(step("ok", "Regel im Relay", "UDP "+strings.Join(ports, ", ")+" wird zwischen den Netzen kopiert."))
	}
	st := v.State
	if st.Relaying {
		add(step("ok", "Relay leitet weiter", st.Text))
	} else {
		tone := "danger"
		if st.Key == "holdoff" {
			tone = "warn"
		}
		add(step(tone, st.Headline, st.Text))
	}
	switch {
	case !v.EngineOK || len(rules) == 0:
		add(step("neutral", "Suchanfragen kommen an", "Lässt sich gerade nicht prüfen."))
	case rx == 0:
		add(step("warn", "Noch keine Suchanfrage gesehen", "Seit dem Start der Engine kam auf diesen Ports nichts an. Öffnet jemand im Spiel den LAN-Browser? Sonst: zweite Netzwerkkarte oder VPN am PC abschalten, Firewall prüfen."))
	default:
		add(step("ok", "Suchanfragen kommen an", formatNum(rx)+" Pakete seit dem Start der Engine."))
	}
	switch {
	case !v.EngineOK || len(rules) == 0 || rx == 0:
		add(step("neutral", "Kopien gehen raus", "Erst prüfbar, wenn Suchanfragen ankommen."))
	case relayed == 0 && st.Relaying:
		add(step("danger", "Es geht keine Kopie raus", "Pakete kommen an, werden aber nicht kopiert. Prüfe unter Netz, ob die Ziel-Netze an sind, und unter System die verworfenen Pakete."))
	case relayed == 0:
		add(step("neutral", "Kopien gehen raus", "Keine, weil das Relay gerade nicht weiterleitet."))
	default:
		add(step("ok", "Kopien gehen raus", formatNum(relayed)+" Pakete in andere Netze kopiert."))
	}
	if bad >= 0 {
		verdict = steps[bad]
		return steps, verdict
	}
	verdict = step("ok", "Am Relay liegt es nicht", "Suchanfragen kommen an und werden kopiert. Findet trotzdem niemand das Spiel, liegt es am Spielverkehr danach (siehe unten) oder am PC.")
	return steps, verdict
}

// rulesFor returns the rules a game ends up in, with counters.
func rulesFor(idx *ruleIndex, id string, v *liveView) []ruleView {
	var out []ruleView
	for _, r := range idx.byGame[id] {
		rv := ruleView{Rule: r}
		if i := slices.IndexFunc(v.Rules, func(s engineapi.RuleStat) bool { return s.ID == r.ID }); i >= 0 {
			rv.RX, rv.Relayed = v.Rules[i].RX, v.Rules[i].Relayed
		}
		out = append(out, rv)
	}
	return out
}

// gameRef names a game for a link.
type gameRef struct {
	ID   string
	Name string
}

// gameRefs lists the games that share a rule (same port): switched-on games first, then by name.
func gameRefs(ids []string, games map[string]store.GameRow) []gameRef {
	out := make([]gameRef, 0, len(ids))
	on := map[string]bool{}
	for _, id := range ids {
		g, ok := games[id]
		if !ok {
			out = append(out, gameRef{ID: id, Name: id})
			continue
		}
		on[id] = g.Enabled
		out = append(out, gameRef{ID: id, Name: g.Name})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if on[out[i].ID] != on[out[j].ID] {
			return on[out[i].ID]
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// shortName cuts a database name down to the first title: "ARMA 2 / Operation Arrowhead / DayZ Mod" becomes
// "ARMA 2", "TrackMania 2 (Canyon/Stadium)" becomes "TrackMania 2". The full name stays one tap away.
func shortName(name string) string {
	for _, sep := range []string{" / ", " ("} {
		if i := strings.Index(name, sep); i > 2 {
			name = name[:i]
		}
	}
	return name
}

// alarmNetsText sums up the open alarms for the key figure: how many networks they concern.
func alarmNetsText(list []alarmGroup) string {
	seen := map[int]bool{}
	for _, g := range list {
		for _, n := range g.Nets {
			seen[n.VID] = true
		}
	}
	switch len(seen) {
	case 0:
		return "siehe unten"
	case 1:
		return "betrifft 1 Netz"
	}
	return fmt.Sprintf("betrifft %d Netze", len(seen))
}
