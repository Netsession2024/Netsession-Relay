package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Netsession2024/Netsession-Relay/internal/gamedb"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// Verifications ("tested at event X") and the YAML exports (docs/02-plan.md 8.3, phase 10): after an event the
// checked games go back into games/games.yaml by commit.

func resultName(r string) string {
	switch r {
	case store.ResultWorks:
		return "Geht"
	case store.ResultFails:
		return "Geht nicht"
	case store.ResultPartial:
		return "Teilweise"
	}
	return r
}

func resultTone(r string) string {
	switch r {
	case store.ResultWorks:
		return "ok"
	case store.ResultFails:
		return "danger"
	}
	return "warn"
}

// resultIcon is the sprite icon that goes with a result (colour never stands alone).
func resultIcon(r string) string {
	if r == store.ResultWorks {
		return "check"
	}
	return "alert"
}

// resultBadge is the word on the badge of a game whose newest test has this result.
func resultBadge(r string) string {
	switch r {
	case store.ResultWorks:
		return "verifiziert"
	case store.ResultFails:
		return "geht nicht"
	case store.ResultPartial:
		return "teilweise"
	}
	return r
}

func (s *Server) verifyAdd(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path := "/spiele/" + url.PathEscape(id)
	v := store.Verification{GameID: id, Result: r.PostFormValue("result"), Variant: r.PostFormValue("variant"), Note: r.PostFormValue("note")}
	if err := s.Store.AddVerification(r.Context(), s.actor(r), v); err != nil {
		if errors.Is(err, store.ErrInvalid) {
			err = errors.New("Bitte ein Ergebnis wählen.")
		}
		back(w, r, path, "", err)
		return
	}
	back(w, r, path, "Prüfung eingetragen: "+resultName(v.Result)+".", nil)
}

func (s *Server) verifyDelete(w http.ResponseWriter, r *http.Request) {
	path := "/spiele/" + url.PathEscape(r.PathValue("id"))
	vid, _ := strconv.ParseInt(r.PathValue("vid"), 10, 64)
	if err := s.Store.DeleteVerification(r.Context(), s.actor(r), vid); err != nil {
		back(w, r, path, "", errors.New("Diesen Eintrag gibt es nicht."))
		return
	}
	back(w, r, path, "Prüfung gelöscht.", nil)
}

// gamesYAML writes games in the seed format of games/games.yaml; the verifications of each game go into a
// comment above it (the seed format itself has no field for them).
func gamesYAML(games []gamedb.Game, ver map[string][]store.Verification) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Netsession Relay - export %s, seed format of games/games.yaml.\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "# Paste the entries into games/games.yaml (replace the old entry with the same id) and commit.\n\n")
	for _, g := range games {
		for _, v := range ver[g.ID] {
			line := fmt.Sprintf("# verified %s, %s: %s", v.TS[:min(10, len(v.TS))], v.Event, v.Result)
			if v.Variant != "" {
				line += " (" + v.Variant + ")"
			}
			if v.Note != "" {
				line += " - " + v.Note
			}
			fmt.Fprintln(&b, line+" ["+v.User+"]")
		}
		enc := yaml.NewEncoder(&b)
		enc.SetIndent(2)
		if err := enc.Encode([]gamedb.Game{g}); err != nil {
			return nil, err
		}
		enc.Close()
		b.WriteString("\n")
	}
	return b.Bytes(), nil
}

func sendYAML(w http.ResponseWriter, name string, body []byte) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// gameYAML exports one game.
func (s *Server) gameYAML(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.Game(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Dieses Spiel gibt es nicht.")
		return
	}
	vs, _ := s.Store.Verifications(r.Context(), g.ID)
	body, err := gamesYAML([]gamedb.Game{g.Game}, map[string][]store.Verification{g.ID: vs})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	sendYAML(w, g.ID+".yaml", body)
}

// changedGamesYAML exports every game that was checked at an event or differs from the seed (own games,
// locally edited seed games): exactly what should go back into games/games.yaml.
func (s *Server) changedGamesYAML(w http.ResponseWriter, r *http.Request) {
	games, err := s.Store.Games(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	all, _ := s.Store.Verifications(r.Context(), "")
	ver := map[string][]store.Verification{}
	for _, v := range all {
		ver[v.GameID] = append(ver[v.GameID], v)
	}
	var list []gamedb.Game
	for _, g := range games {
		if len(ver[g.ID]) > 0 || g.Origin != "seed" || g.LocallyModified {
			list = append(list, g.Game)
		}
	}
	body, err := gamesYAML(list, ver)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	sendYAML(w, "spiele-geprueft-"+time.Now().Format("2006-01-02")+".yaml", body)
}

// configYAML exports the active configuration (VLANs, profiles, games of the event) as YAML.
func (s *Server) configYAML(w http.ResponseWriter, r *http.Request) {
	c, err := s.Store.ExportConfig(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Netsession Relay - configuration of event %q, exported %s.\n# Restore: nsrelay admin import <file>\n",
		c.Event, time.Now().Format("2006-01-02 15:04"))
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	enc.Close()
	_ = s.Store.Audit(r.Context(), s.actor(r), "config.export", c.Event, "", "yaml")
	sendYAML(w, "nsrelay-konfiguration-"+time.Now().Format("2006-01-02")+".yaml", b.Bytes())
}
