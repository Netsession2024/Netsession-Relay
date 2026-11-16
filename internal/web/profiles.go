package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// Flow profiles: which VLAN group sees the games of which group (admin, page Netz). A game uses the default
// profile unless one is picked on its page.

// germanProfileError turns store errors into UI texts.
func germanProfileError(err error) error {
	switch {
	case errors.Is(err, store.ErrExists):
		return errors.New("Ein Profil mit diesem Namen gibt es schon.")
	case errors.Is(err, store.ErrInvalid):
		return errors.New("Profilname: Kleinbuchstaben, Ziffern, _ und -, höchstens 32 Zeichen.")
	case errors.Is(err, store.ErrDefaultProfile):
		return errors.New("Das Standardprofil lässt sich nicht löschen. Mach erst ein anderes zum Standard.")
	case errors.Is(err, store.ErrNotFound):
		return errors.New("Dieses Profil gibt es nicht.")
	}
	return err
}

// profileSave stores the checked cells of the matrix form (fields e = "src>dst").
func (s *Server) profileSave(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = r.ParseForm()
	var edges []compile.Edge
	for _, v := range r.PostForm["e"] {
		src, dst, ok := strings.Cut(v, ">")
		if !ok || src == "" || dst == "" {
			continue
		}
		edges = append(edges, compile.Edge{Src: src, Dst: dst})
	}
	if err := s.Store.SetProfileEdges(r.Context(), s.actor(r), name, edges); err != nil {
		back(w, r, "/netz", "", germanProfileError(err))
		return
	}
	a := s.applyNow(r, "Profil "+name+" geändert")
	if a.OK {
		a.Message = fmt.Sprintf("Profil %s gespeichert und angewendet.", name)
	}
	s.answer(w, r, "/netz", a)
}

func (s *Server) profileCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	if name == "neu" {
		back(w, r, "/netz", "", errors.New("Der Name „neu“ ist reserviert."))
		return
	}
	if err := s.Store.AddProfile(r.Context(), s.actor(r), name, r.PostFormValue("copy")); err != nil {
		back(w, r, "/netz", "", germanProfileError(err))
		return
	}
	back(w, r, "/netz", "Profil "+name+" angelegt. Noch nutzt es kein Spiel.", nil)
}

func (s *Server) profileDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Store.DeleteProfile(r.Context(), s.actor(r), name); err != nil {
		back(w, r, "/netz", "", germanProfileError(err))
		return
	}
	a := s.applyNow(r, "Profil "+name+" gelöscht")
	if a.OK {
		a.Message = "Profil " + name + " gelöscht. Spiele damit nutzen jetzt das Standardprofil."
	}
	s.answer(w, r, "/netz", a)
}

func (s *Server) profileDefault(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Store.SetDefaultProfile(r.Context(), s.actor(r), name); err != nil {
		back(w, r, "/netz", "", germanProfileError(err))
		return
	}
	a := s.applyNow(r, "Standardprofil "+name)
	if a.OK {
		a.Message = "Profil " + name + " ist jetzt Standard."
	}
	s.answer(w, r, "/netz", a)
}

// gameProfile sets the profile of a switched-on game ("" = default).
func (s *Server) gameProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path := "/spiele/" + url.PathEscape(id)
	if err := s.Store.SetGameProfile(r.Context(), s.actor(r), id, r.PostFormValue("profile")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = errors.New("Das Profil lässt sich nur für ein eingeschaltetes Spiel wählen.")
		}
		back(w, r, path, "", err)
		return
	}
	a := s.applyNow(r, id+" Profil")
	if a.OK {
		a.Message = "Profil geändert und angewendet."
	}
	s.answer(w, r, path, a)
}

// profileEdge switches one cell of the matrix (fields src, dst, on=1|0).
func (s *Server) profileEdge(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	e := compile.Edge{Src: r.PostFormValue("src"), Dst: r.PostFormValue("dst")}
	on := r.PostFormValue("on") == "1"
	if e.Src == "" || e.Dst == "" {
		s.answer(w, r, "/netz", applyAnswer{Error: "Zelle ungültig."})
		return
	}
	if err := s.Store.SetProfileEdge(r.Context(), s.actor(r), name, e, on); err != nil {
		s.answer(w, r, "/netz", applyAnswer{Error: germanProfileError(err).Error()})
		return
	}
	a := s.applyNow(r, fmt.Sprintf("Profil %s: %s → %s %v", name, e.Src, e.Dst, map[bool]string{true: "an", false: "aus"}[on]))
	a.Enabled = on
	if a.OK {
		verb := "gehen jetzt nach"
		if !on {
			verb = "gehen nicht mehr nach"
		}
		a.Message = fmt.Sprintf("Spiele aus %s %s %s (Profil %s).", groupName(e.Src), verb, groupName(e.Dst), name)
	}
	s.answer(w, r, "/netz", a)
}

func (s *Server) profileRename(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	to := strings.ToLower(strings.TrimSpace(r.PostFormValue("to")))
	if to == "neu" {
		back(w, r, "/netz", "", errors.New("Der Name „neu“ ist reserviert."))
		return
	}
	if err := s.Store.RenameProfile(r.Context(), s.actor(r), name, to); err != nil {
		back(w, r, "/netz", "", germanProfileError(err))
		return
	}
	a := s.applyNow(r, "Profil "+name+" → "+to)
	if a.OK {
		a.Message = "Profil heißt jetzt " + to + "."
	}
	s.answer(w, r, "/netz", a)
}
