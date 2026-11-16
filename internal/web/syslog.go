package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
)

// The first version had exactly one syslog target on the system page. Until that section moves to the
// monitoring page, its form works on the target named "Syslog" (migration 0005 created it from the old setting).

const legacySyslogName = "Syslog"

func (s *Server) legacySyslog(ctx context.Context) (store.Target, bool) {
	ts, _ := s.Store.Targets(ctx)
	for _, t := range ts {
		if t.Kind == store.TargetSyslog && t.Name == legacySyslogName {
			return t, true
		}
	}
	return store.Target{}, false
}

// syslogTarget is the endpoint of that target ("" = none), shown on the system page.
func (s *Server) syslogTarget(ctx context.Context) string {
	if t, ok := s.legacySyslog(ctx); ok && t.Enabled {
		return t.Endpoint
	}
	return ""
}

func (s *Server) syslogSet(w http.ResponseWriter, r *http.Request) {
	ep := strings.TrimSpace(r.PostFormValue("target"))
	cur, exists := s.legacySyslog(r.Context())
	switch {
	case ep == "" && exists:
		if err := s.Store.DeleteTarget(r.Context(), s.actor(r), cur.ID); err != nil {
			back(w, r, "/system", "", err)
			return
		}
	case ep != "":
		if host, port, err := net.SplitHostPort(ep); err != nil || host == "" || port == "" {
			back(w, r, "/system", "", errors.New("Syslog-Ziel bitte als Adresse:Port, z. B. 10.0.0.5:514."))
			return
		}
		t := cur
		if !exists {
			t = store.Target{Kind: store.TargetSyslog, Name: legacySyslogName, Events: []string{"alarm", "audit"},
				Config: map[string]any{"transport": "udp", "format": "rfc5424", "facility": "local0"}}
		}
		t.Endpoint, t.Enabled = ep, true
		if _, err := s.Store.SaveTarget(r.Context(), s.actor(r), t); err != nil {
			back(w, r, "/system", "", err)
			return
		}
	}
	s.reloadOutputs(r.Context())
	msg := "Syslog aus."
	if ep != "" {
		msg = "Syslog geht an " + ep + "."
	}
	back(w, r, "/system", msg, nil)
}

func (s *Server) syslogTest(w http.ResponseWriter, r *http.Request) {
	t, ok := s.legacySyslog(r.Context())
	if !ok {
		back(w, r, "/system", "", errors.New("Erst ein Syslog-Ziel eintragen."))
		return
	}
	ev := notify.Event{Type: notify.TypeTest, Severity: notify.Info, User: s.actor(r), Text: "Testmeldung von " + s.actor(r)}
	if err := s.notify.Test(r.Context(), t.ID, ev); err != nil {
		back(w, r, "/system", "", fmt.Errorf("Senden fehlgeschlagen: %v", err))
		return
	}
	back(w, r, "/system", "Testmeldung an "+t.Endpoint+" gesendet. Kommt sie dort an?", nil)
}
