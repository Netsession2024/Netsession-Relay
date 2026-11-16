package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
	"github.com/Netsession2024/Netsession-Relay/internal/otlp"
	"github.com/Netsession2024/Netsession-Relay/internal/snmp"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
	"github.com/Netsession2024/Netsession-Relay/internal/syslog"
)

// Page System → Monitoring (admin): the token for Zabbix/Prometheus, the host name, and the push targets.

// targetRow is one target in the list.
type targetRow struct {
	store.Target
	Status   notify.Status
	KindName string
	Summary  string // "UDP · RFC 5424" / "gRPC · Metriken, Meldungen"
	What     string // "Alarme, Protokoll"
	LastOK   string
	LastErr  string
}

func targetKindName(k string) string {
	switch k {
	case store.TargetSyslog:
		return "Syslog"
	case store.TargetOTLP:
		return "OpenTelemetry"
	case store.TargetSNMPTrap:
		return "SNMP-Trap"
	}
	return k
}

func targetSummary(t store.Target) string {
	switch t.Kind {
	case store.TargetSyslog:
		f := "RFC 5424"
		if cfgString(t.Config, "format", "rfc5424") == "rfc3164" {
			f = "RFC 3164"
		}
		return strings.ToUpper(cfgString(t.Config, "transport", "udp")) + " · " + f + " · " + cfgString(t.Config, "facility", "local0")
	case store.TargetSNMPTrap:
		v := cfgString(t.Config, "version", "v3")
		if cfgBool(t.Config, "inform") {
			v += " · Inform"
		}
		return v
	case store.TargetOTLP:
		var sig []string
		if !cfgBool(t.Config, "no_metrics") {
			sig = append(sig, "Metriken")
		}
		if !cfgBool(t.Config, "no_logs") {
			sig = append(sig, "Meldungen")
		}
		p := "gRPC"
		if cfgString(t.Config, "protocol", "grpc") == "http" {
			p = "HTTP"
		}
		if cfgString(t.Config, "tls", "none") == "tls" {
			p += " + TLS"
		}
		return p + " · " + strings.Join(sig, ", ")
	}
	return ""
}

func eventsName(ev []string) string {
	var out []string
	if slices.Contains(ev, "alarm") {
		out = append(out, "Alarme")
	}
	if slices.Contains(ev, "audit") {
		out = append(out, "Verlauf")
	}
	if len(out) == 0 {
		return "nur Tests"
	}
	return strings.Join(out, ", ")
}

func agoText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < 5*time.Second:
		return "gerade"
	case d < 90*time.Second:
		return fmt.Sprintf("vor %d s", int(d.Seconds()))
	case d < 90*time.Minute:
		return fmt.Sprintf("vor %d min", int(d.Minutes()))
	case d < 36*time.Hour:
		return fmt.Sprintf("vor %d h", int(d.Hours()))
	}
	return t.Local().Format("02.01. 15:04")
}

func (s *Server) monitoringData(r *http.Request) map[string]any {
	ctx := r.Context()
	tok, _ := s.Store.Setting(ctx, settingMonitorToken, "")
	ts, _ := s.Store.Targets(ctx)
	status := map[int64]notify.Status{}
	for _, st := range s.notify.Status() {
		status[st.ID] = st
	}
	var rows []targetRow
	failing := 0
	for _, t := range ts {
		st := status[t.ID]
		row := targetRow{Target: t, Status: st, KindName: targetKindName(t.Kind), Summary: targetSummary(t), What: eventsName(t.Events),
			LastOK: agoText(st.LastOK)}
		if st.LastErr != "" {
			row.LastErr = st.LastErr
		}
		if st.Failing() {
			failing++
		}
		rows = append(rows, row)
	}
	host, _ := s.Store.Setting(ctx, settingHostName, "")
	return map[string]any{"MonitorSet": tok != "", "Targets": rows, "Failing": failing, "Host": host,
		"HostDefault": s.hostName(ctx), "Max": store.MaxTargets, "Agent": s.agentForm(ctx)}
}

func (s *Server) monitoringPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "monitoring", "Monitoring", "system", s.monitoringData(r))
}

func (s *Server) monitoringHost(w http.ResponseWriter, r *http.Request) {
	h := strings.TrimSpace(r.PostFormValue("host"))
	if len(h) > 64 || strings.ContainsAny(h, " \t\r\n") {
		back(w, r, "/system/monitoring", "", errors.New("Der Name darf keine Leerzeichen enthalten (höchstens 64 Zeichen)."))
		return
	}
	old, _ := s.Store.Setting(r.Context(), settingHostName, "")
	if err := s.Store.SetSetting(r.Context(), settingHostName, h); err != nil {
		back(w, r, "/system/monitoring", "", err)
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "monitor.host", "", old, h)
	s.restartOutputs(r)
	msg := "Name gespeichert."
	if h == "" {
		msg = "Name zurückgesetzt, es gilt der Hostname der VM."
	}
	back(w, r, "/system/monitoring", msg, nil)
}

// restartOutputs rebuilds every sender (the host name is part of each sender's configuration).
func (s *Server) restartOutputs(r *http.Request) {
	ts, _ := s.Store.Targets(r.Context())
	for i := range ts {
		ts[i].Updated += "*"
	}
	s.notify.Reload(ts)
}

// ---- target form ----

type targetForm struct {
	ID       int64
	Kind     string
	Name     string
	Enabled  bool
	Endpoint string
	Alarm    bool
	Audit    bool
	// syslog
	Transport, Format, Facility string
	// otlp
	Protocol          string
	TLS               bool
	TLSCA             string
	SkipVerify        bool
	Metrics, Logs     bool
	Interval          int
	RuleMetrics, Gzip bool
	HeaderNames       []string // stored header names (values never shown)
	// snmptrap
	Version, User, AuthProto, PrivProto string
	Inform                              bool
	SecretsSet                          []string // names of stored secrets (community, auth_pass, priv_pass)
	Headers                             string   // new "Name: Wert" lines
	ClearHeaders                        bool
	Facilities                          []string
	Err                                 string
}

func formFromTarget(t store.Target) targetForm {
	f := targetForm{ID: t.ID, Kind: t.Kind, Name: t.Name, Enabled: t.Enabled, Endpoint: t.Endpoint,
		Alarm: slices.Contains(t.Events, "alarm"), Audit: slices.Contains(t.Events, "audit"),
		Transport: cfgString(t.Config, "transport", "udp"), Format: cfgString(t.Config, "format", "rfc5424"),
		Facility: cfgString(t.Config, "facility", "local0"), Protocol: cfgString(t.Config, "protocol", "grpc"),
		TLS: cfgString(t.Config, "tls", "none") == "tls", TLSCA: cfgString(t.Config, "tls_ca", ""),
		SkipVerify: cfgBool(t.Config, "tls_skip_verify"), Metrics: !cfgBool(t.Config, "no_metrics"), Logs: !cfgBool(t.Config, "no_logs"),
		Interval: 30, RuleMetrics: cfgBool(t.Config, "rule_metrics"), Gzip: cfgBool(t.Config, "gzip"), Facilities: syslog.Facilities}
	if v, ok := t.Config["interval_s"].(float64); ok && v > 0 {
		f.Interval = int(v)
	}
	f.Version, f.User = cfgString(t.Config, "version", "v3"), cfgString(t.Config, "user", "")
	f.AuthProto, f.PrivProto = cfgString(t.Config, "auth_proto", "sha256"), cfgString(t.Config, "priv_proto", "aes128")
	f.Inform = cfgBool(t.Config, "inform")
	for _, k := range []string{"community", "auth_pass", "priv_pass"} {
		if t.Secret[k] != "" {
			f.SecretsSet = append(f.SecretsSet, k)
		}
	}
	if f.Transport == "tls" {
		f.TLS = true
	}
	for k := range t.Secret {
		if name, ok := strings.CutPrefix(k, "header:"); ok {
			f.HeaderNames = append(f.HeaderNames, name)
		}
	}
	slices.Sort(f.HeaderNames)
	return f
}

func (s *Server) targetNew(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("art")
	if kind != store.TargetOTLP && kind != store.TargetSNMPTrap {
		kind = store.TargetSyslog
	}
	t := store.Target{Kind: kind, Enabled: true, Events: []string{"alarm", "audit"}, Config: map[string]any{}}
	if kind == store.TargetSNMPTrap {
		t.Events = []string{"alarm"} // audit as trap is possible but noise
	}
	f := formFromTarget(t)
	if kind == store.TargetOTLP {
		f.Name, f.Endpoint = "", ""
	}
	s.render(w, r, "monitoring-target", "Ziel hinzufügen", "system", f)
}

func (s *Server) targetEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.Store.Target(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Dieses Ziel gibt es nicht.")
		return
	}
	s.render(w, r, "monitoring-target", t.Name+" bearbeiten", "system", formFromTarget(t))
}

func (s *Server) targetSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) == "1" }
	id, _ := strconv.ParseInt(v("id"), 10, 64)
	f := targetForm{ID: id, Kind: v("kind"), Name: v("name"), Enabled: on("enabled"), Endpoint: v("endpoint"),
		Alarm: on("alarm"), Audit: on("audit"), Transport: v("transport"), Format: v("format"), Facility: v("facility"),
		Protocol: v("protocol"), TLS: on("tls"), TLSCA: v("tls_ca"), SkipVerify: on("tls_skip_verify"),
		Metrics: on("metrics"), Logs: on("logs"), RuleMetrics: on("rule_metrics"), Gzip: on("gzip"),
		Headers: r.PostFormValue("headers"), ClearHeaders: on("clear_headers"), Facilities: syslog.Facilities,
		Version: v("version"), User: v("user"), AuthProto: v("auth_proto"), PrivProto: v("priv_proto"), Inform: on("inform")}
	f.Interval, _ = strconv.Atoi(v("interval_s"))
	if id != 0 {
		if cur, err := s.Store.Target(r.Context(), id); err == nil {
			cf := formFromTarget(cur)
			f.HeaderNames, f.SecretsSet = cf.HeaderNames, cf.SecretsSet
			f.Kind = cur.Kind
		}
	}
	reject := func(msg string) {
		f.Err = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "monitoring-target", "Ziel", "system", f)
	}
	t := store.Target{ID: id, Kind: f.Kind, Name: f.Name, Enabled: f.Enabled, Endpoint: f.Endpoint,
		Config: map[string]any{}, Secret: map[string]string{}}
	if f.Alarm {
		t.Events = append(t.Events, "alarm")
	}
	if f.Audit {
		t.Events = append(t.Events, "audit")
	}
	if f.Name == "" {
		reject("Bitte einen Namen eingeben.")
		return
	}
	switch f.Kind {
	case store.TargetSyslog:
		c := syslog.Config{Transport: f.Transport, Format: f.Format, Facility: f.Facility, TLSCA: f.TLSCA, TLSSkipVerify: f.SkipVerify}
		if err := syslog.Validate(f.Endpoint, c); err != nil {
			reject(germanTargetError(err))
			return
		}
		t.Config = map[string]any{"transport": f.Transport, "format": f.Format, "facility": f.Facility}
		if f.Transport == "tls" {
			t.Config["tls_ca"], t.Config["tls_skip_verify"] = f.TLSCA, f.SkipVerify
		}
	case store.TargetOTLP:
		if f.Interval < 10 || f.Interval > 300 {
			f.Interval = 30
		}
		headers, msg := parseHeaders(f.Headers)
		if msg != "" {
			reject(msg)
			return
		}
		c := otlp.Config{Protocol: f.Protocol, TLS: f.TLS, TLSCA: f.TLSCA, SkipVerify: f.SkipVerify, Metrics: f.Metrics, Logs: f.Logs, Headers: headers}
		if err := otlp.Validate(f.Endpoint, c); err != nil {
			reject(germanTargetError(err))
			return
		}
		tls := "none"
		if f.TLS {
			tls = "tls"
		}
		t.Config = map[string]any{"protocol": f.Protocol, "tls": tls, "no_metrics": !f.Metrics, "no_logs": !f.Logs,
			"interval_s": f.Interval, "rule_metrics": f.RuleMetrics, "gzip": f.Gzip}
		if f.TLS {
			t.Config["tls_ca"], t.Config["tls_skip_verify"] = f.TLSCA, f.SkipVerify
		}
		for k, val := range headers {
			t.Secret["header:"+k] = val
		}
	case store.TargetSNMPTrap:
		sec := map[string]string{"community": r.PostFormValue("community"), "auth_pass": r.PostFormValue("auth_pass"), "priv_pass": r.PostFormValue("priv_pass")}
		// validation needs the effective secrets: new value or the stored one
		eff := snmp.TrapConfig{Version: f.Version, Inform: f.Inform, User: f.User, AuthProto: f.AuthProto, PrivProto: f.PrivProto,
			Community: sec["community"], AuthPass: sec["auth_pass"], PrivPass: sec["priv_pass"]}
		if id != 0 {
			if cur, err := s.Store.Target(r.Context(), id); err == nil {
				if eff.Community == "" {
					eff.Community = cur.Secret["community"]
				}
				if eff.AuthPass == "" {
					eff.AuthPass = cur.Secret["auth_pass"]
				}
				if eff.PrivPass == "" {
					eff.PrivPass = cur.Secret["priv_pass"]
				}
			}
		}
		if err := snmp.ValidateTrap(f.Endpoint, eff); err != nil {
			reject(germanTargetError(err))
			return
		}
		t.Config = map[string]any{"version": f.Version, "inform": f.Inform}
		if f.Version == "v3" {
			t.Config["user"], t.Config["auth_proto"], t.Config["priv_proto"] = f.User, f.AuthProto, f.PrivProto
		}
		t.Secret = sec
	default:
		reject("Diese Art gibt es nicht.")
		return
	}
	if f.ClearHeaders && id != 0 {
		// SaveTarget merges secrets; to drop old headers the stored ones are replaced explicitly
		cur, _ := s.Store.Target(r.Context(), id)
		for k := range cur.Secret {
			if strings.HasPrefix(k, "header:") {
				if _, keep := t.Secret[k]; !keep {
					t.Secret[k] = store.SecretDelete
				}
			}
		}
	}
	newID, err := s.Store.SaveTarget(r.Context(), s.actor(r), t)
	if err != nil {
		reject(germanTargetError(err))
		return
	}
	s.reloadOutputs(r.Context())
	_ = newID
	back(w, r, "/system/monitoring", fmt.Sprintf("%s gespeichert. Schick eine Testmeldung.", t.Name), nil)
}

func parseHeaders(text string) (map[string]string, string) {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" || strings.ContainsAny(k, " \t") {
			return nil, "Header bitte als „Name: Wert“, einer pro Zeile."
		}
		out[k] = v
	}
	return out, ""
}

func germanTargetError(err error) string {
	e := err.Error()
	switch {
	case errors.Is(err, store.ErrExists):
		return "Ein Ziel mit diesem Namen gibt es schon."
	case strings.Contains(e, "at most"):
		return fmt.Sprintf("Höchstens %d Ziele.", store.MaxTargets)
	case strings.Contains(e, "want host:port"):
		return "Adresse bitte als Adresse:Port, z. B. 10.0.0.5:514."
	case strings.Contains(e, "want http(s)"):
		return "Adresse bitte als URL, z. B. http://10.0.0.5:4318."
	case strings.Contains(e, "neither metrics nor logs"):
		return "Bitte Metriken, Meldungen oder beides wählen."
	case strings.Contains(e, "community missing"):
		return "Bitte die Community eintragen."
	case strings.Contains(e, "v3 user missing"):
		return "Bitte den SNMPv3-Benutzer eintragen."
	case strings.Contains(e, "at least 8"):
		return "Die SNMPv3-Passwörter brauchen mindestens 8 Zeichen."
	case strings.Contains(e, "TLS CA"):
		return "Im CA-Feld steht kein Zertifikat (PEM)."
	}
	return "Das passt nicht: " + e
}

func (s *Server) targetTest(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.Store.Target(r.Context(), id)
	if err != nil {
		back(w, r, "/system/monitoring", "", errors.New("Dieses Ziel gibt es nicht."))
		return
	}
	if !t.Enabled {
		back(w, r, "/system/monitoring", "", errors.New(t.Name+" ist ausgeschaltet."))
		return
	}
	ev := notify.Event{Type: notify.TypeTest, Severity: notify.Info, User: s.actor(r), Text: "Testmeldung von " + s.actor(r)}
	if err := s.notify.Test(r.Context(), id, ev); err != nil {
		back(w, r, "/system/monitoring", "", fmt.Errorf("%s: Senden fehlgeschlagen: %v", t.Name, err))
		return
	}
	_ = s.Store.Audit(r.Context(), s.actor(r), "monitor.target.test", t.Name, "", "")
	msg := "Testmeldung an " + t.Name + " gesendet."
	if (t.Kind == store.TargetSyslog && cfgString(t.Config, "transport", "udp") == "udp") || (t.Kind == store.TargetSNMPTrap && !cfgBool(t.Config, "inform")) {
		msg += " Ohne Bestätigung: Kommt sie dort an?"
	}
	back(w, r, "/system/monitoring", msg, nil)
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.Store.Target(r.Context(), id)
	if err != nil {
		back(w, r, "/system/monitoring", "", errors.New("Dieses Ziel gibt es nicht."))
		return
	}
	if err := s.Store.DeleteTarget(r.Context(), s.actor(r), id); err != nil {
		back(w, r, "/system/monitoring", "", err)
		return
	}
	s.reloadOutputs(r.Context())
	back(w, r, "/system/monitoring", t.Name+" gelöscht.", nil)
}

// mibFile serves NETSESSION-RELAY-MIB for SNMP managers.
func (s *Server) mibFile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="NETSESSION-RELAY-MIB.txt"`)
	_, _ = w.Write([]byte(snmp.MIB()))
}
