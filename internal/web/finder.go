package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/portspec"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// noisePorts are broadcasts every LAN has; the port finder can hide them (docs/02-plan.md 6.3).
var noisePorts = map[uint16]string{
	137: "NetBIOS", 138: "NetBIOS", 1900: "SSDP", 3702: "WS-Discovery", 5353: "mDNS", 5355: "LLMNR",
	17500: "Dropbox", 27036: "Steam", 57621: "Spotify", 6646: "McAfee", 1947: "Sentinel",
}

// gameHint is a game of the database that uses a port, with its state in the active event.
type gameHint struct {
	ID, Name string
	On       bool
}

type finderRow struct {
	Dest     string
	Kind     string
	Group    string
	Port     uint16
	Rule     string
	Games    []gameHint // games of the active rule, or of the database for an unknown port
	Noise    string
	Count    uint64
	Interval string
	Size     string
	Srcs     string
	Nets     string
	New      bool
	Offset   string
	Hex      string
	ASCII    string
}

type unknownRow struct {
	Port  uint16
	Count uint32
	Noise string
	Games []gameHint
}

type finderView struct {
	Status    engineapi.FinderStatus
	Err       bool
	Rows      []finderRow
	Hidden    int
	ShowNoise bool
	Left      string
	Unknown   []unknownRow
	VLANs     []store.VLANConfig
	Picked    map[int]bool
}

// portGames finds database games whose discovery uses kind/group/port.
func portGames(games []store.GameRow, kind, group string, port uint16) []gameHint {
	var out []gameHint
	for _, g := range games {
		for _, d := range g.Discovery {
			if d.Kind != kind || (kind == gamedb.KindMulticast && d.Group != group) {
				continue
			}
			ps, err := portspec.Parse(d.Ports)
			if err == nil && ps.Contains(port) {
				out = append(out, gameHint{ID: g.ID, Name: g.Name, On: g.Enabled})
				break
			}
		}
	}
	return out
}

func hexASCII(b []byte) (string, string) {
	var h, a strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			h.WriteByte(' ')
		}
		fmt.Fprintf(&h, "%02x", c)
		if c >= 0x20 && c < 0x7f {
			a.WriteByte(c)
		} else {
			a.WriteByte('.')
		}
	}
	return h.String(), a.String()
}

func (s *Server) finderData(ctx context.Context, showNoise bool) finderView {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	v := finderView{ShowNoise: showNoise, Picked: map[int]bool{}}
	fs, err := s.Engine.Finder(ctx)
	v.Err = err != nil
	v.Status = fs
	games, _ := s.Store.Games(ctx)
	names := map[string]gameHint{}
	for _, g := range games {
		names[g.ID] = gameHint{ID: g.ID, Name: g.Name, On: g.Enabled}
	}
	st, _ := s.Engine.Status(ctx)
	idx := s.rules(ctx, st.SnapshotHash)
	vlanName := map[int]string{}
	if c, err := s.Store.ExportConfig(ctx); err == nil {
		v.VLANs = c.VLANs
		for _, x := range c.VLANs {
			vlanName[x.VID] = x.Name
		}
	}
	for _, id := range fs.VIDs {
		v.Picked[id] = true
	}
	if fs.Active {
		v.Left = fmt.Sprintf("%d:%02d", int(time.Until(fs.Until).Seconds())/60, int(time.Until(fs.Until).Seconds())%60)
	}
	for _, g := range fs.Groups {
		row := finderRow{Kind: g.Kind, Group: g.Group, Port: g.Port, Rule: g.Rule, Count: g.Count, New: g.New,
			Noise: noisePorts[g.Port], Dest: "Broadcast"}
		if g.Kind == gamedb.KindMulticast {
			row.Dest, row.Noise = g.Group, ""
		}
		if row.Noise != "" && !showNoise {
			v.Hidden++
			continue
		}
		if r, ok := idx.byRule[g.Rule]; ok {
			for _, id := range r.Specs {
				if h, ok := names[id]; ok {
					row.Games = append(row.Games, h)
				}
			}
		} else {
			row.Games = portGames(games, g.Kind, g.Group, g.Port)
		}
		if g.Count > 1 {
			row.Interval = fmt.Sprintf("%.1f s", g.Last.Sub(g.First).Seconds()/float64(g.Count-1))
		}
		row.Size = fmt.Sprintf("%d B", g.MinLen)
		if g.MaxLen != g.MinLen {
			row.Size = fmt.Sprintf("%d–%d B", g.MinLen, g.MaxLen)
		}
		srcs := make([]string, len(g.Srcs))
		for i, a := range g.Srcs {
			srcs[i] = a.String()
		}
		row.Srcs = strings.Join(srcs, ", ")
		nets := make([]string, len(g.VIDs))
		for i, id := range g.VIDs {
			nets[i] = vlanName[id]
			if nets[i] == "" {
				nets[i] = fmt.Sprintf("VLAN %d", id)
			}
		}
		row.Nets = strings.Join(nets, ", ")
		row.Offset = fmt.Sprintf("+%d s", int(g.First.Sub(fs.Started).Seconds()))
		row.Hex, row.ASCII = hexASCII(g.Sample)
		v.Rows = append(v.Rows, row)
	}
	for _, p := range st.TopUnknown {
		v.Unknown = append(v.Unknown, unknownRow{Port: p.Port, Count: p.Count, Noise: noisePorts[p.Port],
			Games: portGames(games, gamedb.KindBroadcast, "", p.Port)})
	}
	return v
}

// finder is the port finder page; ?teil=ergebnis returns only the live part.
func (s *Server) finder(w http.ResponseWriter, r *http.Request) {
	v := s.finderData(r.Context(), r.URL.Query().Get("laerm") == "1")
	if r.URL.Query().Get("teil") == "ergebnis" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.tpl["finder"].ExecuteTemplate(w, "finder-result", v); err != nil {
			s.Log.Error("render finder fragment", "err", err)
		}
		return
	}
	s.render(w, r, "finder", "Port-Finder", "finder", v)
}

func (s *Server) finderStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		back(w, r, "/finder", "", err)
		return
	}
	req := engineapi.FinderStart{Src: strings.TrimSpace(r.PostFormValue("src"))}
	for _, x := range r.PostForm["vid"] {
		if id, err := strconv.Atoi(x); err == nil {
			req.VIDs = append(req.VIDs, id)
		}
	}
	if req.Src != "" {
		if a, err := netip.ParseAddr(req.Src); err != nil || !a.Is4() {
			back(w, r, "/finder", "", fmt.Errorf("„%s“ ist keine IPv4-Adresse", req.Src))
			return
		}
	}
	mins, _ := strconv.Atoi(r.PostFormValue("minuten"))
	req.Seconds = max(1, min(mins, 10)) * 60
	if err := s.Engine.FinderStart(r.Context(), req); err != nil {
		back(w, r, "/finder", "", fmt.Errorf("Port-Finder startet nicht: %v", err))
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "finder.start", fmt.Sprint(req.VIDs), "", req.Src)
	back(w, r, "/finder", "Port-Finder läuft. Jetzt das Spiel starten und den LAN-Browser öffnen.", nil)
}

func (s *Server) finderStop(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.FinderStop(r.Context()); err != nil {
		back(w, r, "/finder", "", err)
		return
	}
	back(w, r, "/finder", "Port-Finder gestoppt. Die Ergebnisse bleiben bis zum nächsten Start.", nil)
}

func (s *Server) finderPcap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_ = s.Store.Audit(ctx, s.actor(r), "finder.pcap", "", "", "")
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="nsrelay-finder-%s.pcap"`, time.Now().Format("20060102-150405")))
	if err := s.Engine.FinderPcap(ctx, w); err != nil {
		s.Log.Warn("finder pcap", "err", err)
	}
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

func slug(name string) string {
	r := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss")
	s := strings.Trim(slugRE.ReplaceAllString(r.Replace(strings.ToLower(name)), "_"), "_")
	if s == "" || s[0] == '_' {
		s = "spiel_" + s
	}
	return s
}

func germanGameError(err error) string {
	e := err.Error()
	switch {
	case strings.Contains(e, "exists"):
		return "Diese Kennung gibt es schon. Bitte eine andere wählen."
	case strings.Contains(e, "invalid id"):
		return "Die Kennung darf nur Kleinbuchstaben, Ziffern und _ enthalten."
	case strings.Contains(e, "name missing"):
		return "Bitte einen Namen eingeben."
	case strings.Contains(e, "blocked"):
		return "DHCP (67/68) wird nie weitergeleitet."
	}
	return "Das Spiel passt nicht: " + e
}
