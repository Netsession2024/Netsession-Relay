// Package web serves the admin UI (server-rendered Go templates in the Netsession brand, docs/02-plan.md 6.4),
// the JSON API, login and roles.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Engine is what the web part needs from the engine (engineapi.Client, or a fake in tests).
type Engine interface {
	Status(context.Context) (engineapi.Status, error)
	Validate(context.Context, *compile.Snapshot) (engineapi.Result, error)
	Apply(context.Context, *compile.Snapshot) (engineapi.Result, error)
	Players(context.Context) ([]engineapi.Player, error)
	Ack(ctx context.Context, kind, by string) error
	FinderStart(context.Context, engineapi.FinderStart) error
	FinderStop(context.Context) error
	Finder(context.Context) (engineapi.FinderStatus, error)
	FinderPcap(context.Context, io.Writer) error
}

// Server is the web part.
type Server struct {
	Store   *store.Store
	Engine  Engine
	Log     *slog.Logger
	Version string
	// Secure sets the Secure flag on cookies (behind the TLS reverse proxy).
	Secure bool
	// Demo marks the UI when the engine is the built-in fake (nsrelay web -demo).
	Demo bool
	// LiveInterval is the pause between two live samples (default 2 s).
	LiveInterval time.Duration

	tpl     map[string]*template.Template
	mux     *http.ServeMux
	hub     *liveHub
	ruleMu  sync.Mutex
	ruleIdx *ruleIndex
}

const cookieName = "nsrelay_session"

// New builds the server and parses all templates.
func New(st *store.Store, eng Engine, log *slog.Logger, version string) (*Server, error) {
	s := &Server{Store: st, Engine: eng, Log: log, Version: version, tpl: map[string]*template.Template{},
		hub: &liveHub{subs: map[chan []byte]struct{}{}}}
	funcs := template.FuncMap{
		"static":   func(p string) string { return "/static/" + p + "?v=" + version },
		"icon":     icon,
		"join":     strings.Join,
		"short":    func(h string) string { return shortHash(h) },
		"num":      formatNum,
		"hasRole":  func(u store.User, role string) bool { return store.RoleRank(u.Role) >= store.RoleRank(role) },
		"tableKey": tableKey,
		"modeName": modeName,
		"add":      func(a, b int) int { return a + b },
		"ts":       timeTag,
		"dict":     dict,
		"roleName": roleName,
		"group":    groupName,
		"kindName": kindName,
		"dirName":  dirName,
		"confName": confName,
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", p)
		if err != nil {
			return nil, err
		}
		s.tpl[name] = t
	}
	s.routes()
	return s, nil
}

// ServeHTTP implements http.Handler with security headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	fileServer := http.StripPrefix("/static/", http.FileServerFS(static))
	m.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	}))
	m.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/ns/logo/favicon.ico", http.StatusMovedPermanently)
	})
	m.HandleFunc("GET /healthz", s.healthz)
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("GET /login/local", s.loginPage)
	m.HandleFunc("POST /login/local", s.loginLocal)
	m.HandleFunc("POST /logout", s.logout)

	m.Handle("GET /{$}", s.need(store.RoleViewer, s.overview))
	m.Handle("GET /spiele", s.need(store.RoleViewer, s.games))
	m.Handle("GET /spiele/{id}", s.need(store.RoleViewer, s.game))
	m.Handle("POST /spiele/{id}", s.need(store.RoleOperator, s.toggleGame))
	m.Handle("GET /netz", s.need(store.RoleAdmin, s.network))
	m.Handle("POST /netz/{vid}", s.need(store.RoleAdmin, s.toggleVLAN))
	m.Handle("GET /system", s.need(store.RoleAdmin, s.system))
	m.Handle("POST /system/mode", s.need(store.RoleAdmin, s.setMode))
	m.Handle("POST /system/notaus", s.need(store.RoleOperator, s.emergencyStop))
	m.Handle("POST /system/rollback/{id}", s.need(store.RoleAdmin, s.rollback))
	m.Handle("GET /system/backup", s.need(store.RoleAdmin, s.downloadBackup))
	m.Handle("GET /notaus", s.need(store.RoleOperator, s.emergencyConfirm))
	m.Handle("GET /verlauf", s.need(store.RoleAdmin, s.history))
	m.Handle("GET /protokoll", http.RedirectHandler("/verlauf", http.StatusSeeOther))
	m.Handle("GET /api/v1/events", s.need(store.RoleViewer, s.apiEvents))
	m.Handle("GET /spieler", s.need(store.RoleViewer, s.players))
	m.Handle("POST /alarme/{kind}/gesehen", s.need(store.RoleOperator, s.ackAlarm))
	m.Handle("GET /finder", s.need(store.RoleOperator, s.finder))
	m.Handle("POST /finder/start", s.need(store.RoleOperator, s.finderStart))
	m.Handle("POST /finder/stop", s.need(store.RoleOperator, s.finderStop))
	m.Handle("GET /finder/mitschnitt.pcap", s.need(store.RoleOperator, s.finderPcap))
	m.Handle("GET /finder/neu", s.need(store.RoleOperator, s.finderNewForm))
	m.Handle("POST /finder/neu", s.need(store.RoleOperator, s.finderNewGame))
	m.Handle("GET /dev/komponenten", s.need(store.RoleViewer, s.components))
	m.Handle("GET /api/v1/status", s.need(store.RoleViewer, s.apiStatus))
	m.Handle("GET /api/v1/monitoring", s.monitorAuth(s.apiMonitoring))
	m.Handle("GET /metrics", s.monitorAuth(s.metrics))
	m.Handle("POST /system/monitoring-token", s.need(store.RoleAdmin, s.newMonitorToken))
	s.mux = m
}

// ---- sessions, roles, CSRF ----

type ctxKey struct{}

func sessionFrom(r *http.Request) store.Session {
	se, _ := r.Context().Value(ctxKey{}).(store.Session)
	return se
}

// need wraps a handler: valid session, minimum role, CSRF token on writes.
func (s *Server) need(role string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var se store.Session
		if err == nil {
			se, err = s.Store.SessionByToken(r.Context(), c.Value)
		}
		if err != nil {
			if wantsJSON(r) || strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Nicht angemeldet."})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if store.RoleRank(se.User.Role) < store.RoleRank(role) {
			s.fail(w, r, http.StatusForbidden, "Dafür fehlt dir die Rolle "+roleName(role)+".")
			return
		}
		if r.Method == http.MethodPost {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf")
			}
			if tok == "" || tok != se.CSRF {
				s.fail(w, r, http.StatusForbidden, "Sitzung abgelaufen oder Formular veraltet. Lade die Seite neu.")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, se)))
	})
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) actor(r *http.Request) string { return sessionFrom(r).User.Name }

// ---- rendering ----

// page is the data every template gets.
type page struct {
	Title   string
	Nav     string
	User    store.User
	CSRF    string
	Version string
	Flash   string
	Error   string
	Engine  engineapi.Status
	EngErr  string
	Live    *liveView
	Demo    bool
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	s.renderLive(w, r, name, title, nav, data, nil)
}

// renderLive renders a page; live is the live view the handler already fetched (nil: fetch it here).
func (s *Server) renderLive(w http.ResponseWriter, r *http.Request, name, title, nav string, data any, live *liveView) {
	se := sessionFrom(r)
	p := page{Title: title, Nav: nav, User: se.User, CSRF: se.CSRF, Version: s.Version, Data: data, Demo: s.Demo,
		Flash: r.URL.Query().Get("ok"), Error: r.URL.Query().Get("fehler")}
	if se.ID != "" {
		if live == nil {
			live = s.liveNow(r.Context())
		}
		p.Live, p.Engine = live, live.Engine
		if !live.EngineOK {
			p.EngErr = "Engine nicht erreichbar."
		}
	}
	t := s.tpl[name]
	if t == nil {
		http.Error(w, "template "+name+" missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", p); err != nil {
		s.Log.Error("render", "page", name, "err", err)
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if wantsJSON(r) {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	w.WriteHeader(code)
	s.render(w, r, "error", "Fehler", "", msg)
}

// back redirects to a page with a flash message (ok) or error (fehler).
func back(w http.ResponseWriter, r *http.Request, path, okMsg string, err error) {
	q := "?ok=" + urlQuery(okMsg)
	if err != nil {
		q = "?fehler=" + urlQuery(err.Error())
	}
	http.Redirect(w, r, path+q, http.StatusSeeOther)
}

// ---- login ----

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DB.PingContext(r.Context()); err != nil {
		http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", "Anmelden", "login", nil)
}

var errLogin = errors.New("Name oder Passwort falsch.")

func (s *Server) loginLocal(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	pw := r.PostFormValue("password")
	ip := clientIP(r)
	u, err := s.Store.UserByName(r.Context(), name)
	switch {
	case err != nil || u.Kind != "local" || u.PasswordHash == "":
		_ = auth.Verify(pw, dummyHash) // same timing as a real check
		s.Log.Warn("login failed", "name", name, "ip", ip)
		back(w, r, "/login", "", errLogin)
		return
	case u.LockedUntil.After(time.Now()):
		back(w, r, "/login", "", errors.New("Konto für 15 Minuten gesperrt (zu viele Fehlversuche)."))
		return
	}
	if err := auth.Verify(pw, u.PasswordHash); err != nil {
		_ = s.Store.LoginFailed(r.Context(), u, ip)
		s.Log.Warn("login failed", "name", name, "ip", ip)
		back(w, r, "/login", "", errLogin)
		return
	}
	token := auth.Token(32)
	if err := s.Store.CreateSession(r.Context(), u, token, auth.Token(24), ip); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(store.SessionTTL.Seconds())})
	s.Log.Info("login", "name", name, "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

var dummyHash, _ = auth.Hash("timing-equaliser")

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
