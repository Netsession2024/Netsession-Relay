package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/compile"
	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// settingMonitorToken holds the SHA-256 (hex) of the monitoring token; the token itself is shown once.
const settingMonitorToken = "monitor_token_sha256"

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// monitorAuth accepts "Authorization: Bearer <token>" against the stored hash. No token configured: 404,
// so a fresh installation exposes nothing.
func (s *Server) monitorAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want, _ := s.Store.Setting(r.Context(), settingMonitorToken, "")
		if want == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "monitoring token not configured (System page)"})
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(tokenHash(strings.TrimSpace(tok))), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="nsrelay-monitoring"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong token"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	})
}

func (s *Server) monitorReport(ctx context.Context) (monitor.Report, []engineapi.RuleStat) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := s.Engine.Status(ctx)
	_, evErr := s.Store.ActiveEvent(ctx)
	return monitor.Build(st, err, s.Version, evErr == nil, time.Now()), st.RuleStats
}

// apiMonitoring is the Zabbix master item (HTTP agent, deploy/zabbix/template_nsrelay.yaml).
func (s *Server) apiMonitoring(w http.ResponseWriter, r *http.Request) {
	rep, _ := s.monitorReport(r.Context())
	writeJSON(w, http.StatusOK, rep)
}

// metrics serves the same data in the Prometheus text format.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	rep, rules := s.monitorReport(r.Context())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := monitor.WritePrometheus(w, rep, rules); err != nil {
		s.Log.Debug("metrics", "err", err)
	}
}

// newMonitorToken creates a new token, stores its hash and shows it exactly once on the system page.
func (s *Server) newMonitorToken(w http.ResponseWriter, r *http.Request) {
	tok := auth.Token(32)
	if err := s.Store.SetSetting(r.Context(), settingMonitorToken, tokenHash(tok)); err != nil {
		back(w, r, "/system", "", err)
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "monitor.token", "", "", "")
	mode, _ := s.Store.Setting(r.Context(), store.SettingMode, compile.ModeActive)
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "system", "System", "system", map[string]any{"Mode": mode, "MonitorSet": true, "NewToken": tok})
}
