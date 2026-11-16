package web

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

// playerRow is one sender of discovery packets as shown on /spieler.
type playerRow struct {
	Games   string
	GameID  string // first game, for the link
	VLAN    string
	Key     string
	VID     int
	IP      string
	Role    string // "hostet" | "sucht" | "aktiv"
	RoleCls string
	First   time.Time
	Last    time.Time
	Count   uint64
}

// players shows who searches and hosts which game ("Wer spielt was"), refreshed live via a fragment.
func (s *Server) players(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := s.playerRows(ctx)
	d := map[string]any{"Rows": rows, "Err": err != nil}
	if r.URL.Query().Get("teil") == "tabelle" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.tpl["players"].ExecuteTemplate(w, "players-table", d); err != nil {
			s.Log.Error("render players fragment", "err", err)
		}
		return
	}
	s.render(w, r, "players", "Spieler", "players", d)
}

func (s *Server) playerRows(ctx context.Context) ([]playerRow, error) {
	list, err := s.Engine.Players(ctx)
	if err != nil {
		return nil, err
	}
	st, _ := s.Engine.Status(ctx)
	idx := s.rules(ctx, st.SnapshotHash)
	games, _ := s.Store.Games(ctx)
	byID := map[string]string{}
	dirs := map[string]map[string]bool{}
	for _, g := range games {
		byID[g.ID] = g.Name
		dirs[g.ID] = map[string]bool{}
		for _, d := range g.Discovery {
			dirs[g.ID][d.Direction] = true
		}
	}
	vlanName := map[int]string{}
	vlanGroup := map[int]string{}
	if c, err := s.Store.ExportConfig(ctx); err == nil {
		for _, v := range c.VLANs {
			vlanName[v.VID], vlanGroup[v.VID] = v.Name, v.Group
		}
	}
	rows := make([]playerRow, 0, len(list))
	for _, p := range list {
		row := playerRow{VID: p.VID, IP: p.Src.String(), First: p.First, Last: p.Last, Count: p.Count,
			VLAN: vlanName[p.VID], Key: tableKey(vlanName[p.VID], vlanGroup[p.VID])}
		if row.VLAN == "" {
			row.VLAN = "VLAN"
		}
		row.Role, row.RoleCls = "aktiv", "role-search"
		var names []string
		if rule, ok := idx.byRule[p.Rule]; ok {
			for _, id := range rule.Specs {
				names = append(names, byID[id])
				if row.GameID == "" {
					row.GameID = id
				}
			}
			row.Role, row.RoleCls = roleOf(rule.Specs, dirs)
		}
		if len(names) == 0 {
			names = []string{p.Rule}
		}
		row.Games = strings.Join(names, ", ")
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Games != rows[j].Games {
			return rows[i].Games < rows[j].Games
		}
		return rows[i].Last.After(rows[j].Last)
	})
	return rows, nil
}

// roleOf says what a sender on this rule does: only "announce" games host, only "query" games search,
// "both" (FlatOut) cannot be told apart from the packet alone.
func roleOf(ids []string, dirs map[string]map[string]bool) (string, string) {
	host, search := false, false
	for _, id := range ids {
		d := dirs[id]
		host = host || d["announce"]
		search = search || d["query"]
		if d["both"] || d[""] {
			return "aktiv", "role-search"
		}
	}
	switch {
	case host && !search:
		return "hostet", "role-host"
	case search && !host:
		return "sucht", "role-search"
	}
	return "aktiv", "role-search"
}

// ackAlarm acknowledges all alarms of a kind ("Gesehen").
func (s *Server) ackAlarm(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if _, known := alarmTitles[kind]; !known {
		s.answer(w, r, "/", applyAnswer{Error: "Diesen Alarm gibt es nicht."})
		return
	}
	if err := s.Engine.Ack(r.Context(), kind, s.actor(r)); err != nil {
		s.answer(w, r, "/", applyAnswer{Error: "Die Engine antwortet nicht: " + err.Error()})
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "alarm.ack", kind, "", "")
	s.answer(w, r, "/", applyAnswer{OK: true, Message: alarmTitles[kind] + ": als gesehen markiert."})
}
