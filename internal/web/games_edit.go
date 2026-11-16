package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// gameForm is the create/edit form of a game (operator and up). Values stay strings so a rejected form is
// shown again as typed.
type gameForm struct {
	New        bool
	From       string // "finder" when opened from the port finder (origin sniffer)
	ID, Name   string
	Aliases    string // comma separated
	Category   string
	Confidence string
	Notes      string
	Enable     bool
	Specs      []specForm
	Origin     string // edit: seed | custom | sniffer | import
	Err        string
}

// specForm is one discovery row. Adv carries the fields the form does not show (source/dst/TTL mode, rate,
// payload limit) as JSON, so editing a seed game keeps them.
type specForm struct {
	Kind, Ports, Group, Direction string
	Adv                           string
}

// emptySpecRows is the number of blank discovery rows offered below the existing ones.
const emptySpecRows = 2

func blankSpec() specForm { return specForm{Kind: gamedb.KindBroadcast, Direction: "both"} }

func (f *gameForm) pad() {
	for range emptySpecRows {
		f.Specs = append(f.Specs, blankSpec())
	}
}

func (s *Server) gameNewForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := gameForm{New: true, From: q.Get("from"), Category: gamedb.CategoryGame, Confidence: "low", Enable: true}
	if q.Get("port") != "" {
		sp := specForm{Kind: q.Get("kind"), Ports: q.Get("port"), Group: q.Get("group"), Direction: "both"}
		if sp.Kind != gamedb.KindMulticast {
			sp.Kind, sp.Group = gamedb.KindBroadcast, ""
		}
		f.Specs = append(f.Specs, sp)
	}
	f.pad()
	s.render(w, r, "game-edit", "Spiel anlegen", "games", f)
}

// finderNewForm keeps the old port-finder link working.
func (s *Server) finderNewForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("from", "finder")
	http.Redirect(w, r, "/spiele/neu?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) gameEditForm(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.Game(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Dieses Spiel gibt es nicht.")
		return
	}
	f := gameForm{ID: g.ID, Name: g.Name, Aliases: strings.Join(g.Aliases, ", "), Category: g.Category,
		Confidence: g.Confidence, Notes: g.Notes, Enable: g.Enabled, Origin: g.Origin}
	for _, sp := range g.Discovery {
		adv := sp
		adv.Kind, adv.Ports, adv.Group, adv.Direction = "", "", "", ""
		var a string
		if adv != (gamedb.Spec{}) {
			b, _ := json.Marshal(adv)
			a = string(b)
		}
		f.Specs = append(f.Specs, specForm{Kind: sp.Kind, Ports: sp.Ports, Group: sp.Group, Direction: sp.Direction, Adv: a})
	}
	f.pad()
	s.render(w, r, "game-edit", g.Name+" bearbeiten", "games", f)
}

// readGameForm reads the posted form. The port finder used to post a single spec without index (kind, ports,
// group, direction); that is still accepted as row 0.
func readGameForm(r *http.Request, isNew bool) gameForm {
	_ = r.ParseForm()
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	f := gameForm{New: isNew, From: v("from"), ID: v("id"), Name: v("name"), Aliases: v("aliases"),
		Category: v("category"), Confidence: v("confidence"), Notes: v("notes"), Enable: v("enable") == "1"}
	if v("ports") != "" {
		f.Specs = append(f.Specs, specForm{Kind: v("kind"), Ports: v("ports"), Group: v("group"), Direction: v("direction")})
	}
	for i := 0; i < 32; i++ {
		k := strconv.Itoa(i)
		if _, ok := r.PostForm["kind"+k]; !ok {
			break
		}
		f.Specs = append(f.Specs, specForm{Kind: v("kind" + k), Ports: v("ports" + k), Group: v("group" + k),
			Direction: v("direction" + k), Adv: v("adv" + k)})
	}
	return f
}

// game builds the game from the form; base is the stored game when editing (keeps game ports, sources …).
func (f gameForm) game(base gamedb.Game, actor string) (gamedb.Game, string) {
	g := base
	g.ID, g.Name, g.Notes = f.ID, f.Name, f.Notes
	if f.Category != "" {
		g.Category = f.Category
	}
	if g.Category == "" {
		g.Category = gamedb.CategoryGame
	}
	if f.Confidence != "" {
		g.Confidence = f.Confidence
	}
	if g.Confidence == "" {
		g.Confidence = "low"
	}
	if g.SourceIP == "" {
		g.SourceIP = gamedb.SourceOriginal
	}
	g.Aliases = nil
	for _, a := range strings.Split(f.Aliases, ",") {
		if a = strings.TrimSpace(a); a != "" {
			g.Aliases = append(g.Aliases, a)
		}
	}
	g.Discovery = nil
	for i, sp := range f.Specs {
		if sp.Ports == "" {
			continue
		}
		var spec gamedb.Spec
		if sp.Adv != "" {
			if err := json.Unmarshal([]byte(sp.Adv), &spec); err != nil {
				return g, fmt.Sprintf("Zeile %d: interne Felder beschädigt, bitte die Seite neu laden.", i+1)
			}
		}
		spec.Kind, spec.Ports, spec.Direction, spec.Group = sp.Kind, sp.Ports, sp.Direction, ""
		if sp.Kind == gamedb.KindMulticast {
			spec.Group = sp.Group
		}
		if spec.Direction == "" {
			spec.Direction = "both"
		}
		g.Discovery = append(g.Discovery, spec)
	}
	switch {
	case len(g.Discovery) > 0:
		g.RelayNeeded = gamedb.RelayYes
	case base.RelayNeeded == gamedb.RelayNo:
		g.RelayNeeded = gamedb.RelayNo
	default:
		return g, "Bitte mindestens einen UDP-Port eintragen."
	}
	if g.RelayNeeded != gamedb.RelayYes {
		g.DefaultEnabled = false
	}
	src := "Web-UI"
	if f.From == "finder" {
		src = "Port-Finder"
	}
	g.Sources = append(g.Sources, fmt.Sprintf("%s %s (%s)", src, time.Now().Format("2006-01-02"), actor))
	return g, ""
}

func (s *Server) gameCreate(w http.ResponseWriter, r *http.Request) {
	f := readGameForm(r, true)
	if strings.HasPrefix(r.URL.Path, "/finder/") {
		f.From = "finder"
	}
	if f.ID == "" {
		f.ID = slug(f.Name)
	}
	reject := func(msg string) {
		f.Err = msg
		f.pad()
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "game-edit", "Spiel anlegen", "games", f)
	}
	if f.ID == "neu" {
		reject("Die Kennung „neu“ ist reserviert.")
		return
	}
	g, msg := f.game(gamedb.Game{}, s.actor(r))
	if msg != "" {
		reject(msg)
		return
	}
	origin := "custom"
	if f.From == "finder" {
		origin = "sniffer"
	}
	if err := s.Store.AddGame(r.Context(), s.actor(r), origin, g); err != nil {
		reject(germanGameError(err))
		return
	}
	msg = f.Name + " angelegt (aus)."
	if f.Enable {
		if err := s.Store.SetGameEnabled(r.Context(), s.actor(r), g.ID, true); err == nil {
			if a := s.applyNow(r, g.ID+" angelegt und an"); a.OK {
				msg = fmt.Sprintf("%s angelegt und eingeschaltet (Revision %d).", f.Name, a.Revision)
			} else {
				msg = f.Name + " angelegt, Anwenden fehlgeschlagen: " + a.Error
			}
		}
	}
	http.Redirect(w, r, "/spiele/"+url.PathEscape(g.ID)+"?ok="+urlQuery(msg), http.StatusSeeOther)
}

func (s *Server) gameUpdate(w http.ResponseWriter, r *http.Request) {
	cur, err := s.Store.Game(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Dieses Spiel gibt es nicht.")
		return
	}
	f := readGameForm(r, false)
	f.ID, f.Origin, f.Enable = cur.ID, cur.Origin, cur.Enabled
	reject := func(msg string) {
		f.Err = msg
		f.pad()
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "game-edit", cur.Name+" bearbeiten", "games", f)
	}
	g, msg := f.game(cur.Game, s.actor(r))
	if msg != "" {
		reject(msg)
		return
	}
	if err := s.Store.UpdateGame(r.Context(), s.actor(r), g); err != nil {
		reject(germanGameError(err))
		return
	}
	msg = g.Name + " gespeichert."
	if cur.Enabled {
		if a := s.applyNow(r, g.ID+" geändert"); a.OK {
			msg = fmt.Sprintf("%s gespeichert und angewendet (Revision %d).", g.Name, a.Revision)
		} else {
			msg = g.Name + " gespeichert, Anwenden fehlgeschlagen: " + a.Error
		}
	}
	http.Redirect(w, r, "/spiele/"+url.PathEscape(g.ID)+"?ok="+urlQuery(msg), http.StatusSeeOther)
}

func (s *Server) gameDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := s.Store.Game(r.Context(), id)
	if err != nil {
		back(w, r, "/spiele", "", errors.New("Dieses Spiel gibt es nicht."))
		return
	}
	if err := s.Store.DeleteGame(r.Context(), s.actor(r), id); err != nil {
		if errors.Is(err, store.ErrSeedGame) {
			err = errors.New("Spiele aus der Spiele-Datenbank lassen sich nicht löschen, nur ausschalten.")
		}
		back(w, r, "/spiele/"+url.PathEscape(id), "", err)
		return
	}
	msg := cur.Name + " gelöscht."
	if cur.Enabled {
		if a := s.applyNow(r, id+" gelöscht"); !a.OK {
			msg = cur.Name + " gelöscht, Anwenden fehlgeschlagen: " + a.Error
		}
	}
	back(w, r, "/spiele", msg, nil)
}
