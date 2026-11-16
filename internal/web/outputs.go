package web

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/auth"
	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
	"github.com/Netsession2024/Netsession-Relay/internal/notify"
	"github.com/Netsession2024/Netsession-Relay/internal/otlp"
	"github.com/Netsession2024/Netsession-Relay/internal/snmp"
	"github.com/Netsession2024/Netsession-Relay/internal/store"
	"github.com/Netsession2024/Netsession-Relay/internal/syslog"
)

// Monitoring outputs (docs/05-monitoring-konzept.md): audit entries and alarms become notify.Events, the
// dispatcher pushes them to every target. Targets live in the database; every change reloads the dispatcher.

// settingInstanceID is a random id created once (OTLP service.instance.id).
const settingInstanceID = "monitor_instance_id"

// settingHostName is the host name used in all outputs (syslog HOSTNAME, OTLP host.name, SNMP sysName).
const settingHostName = "monitor_host_name"

// engineDownAfter: the engine must not answer for this long before engine_down opens.
const engineDownAfter = 30 * time.Second

func (s *Server) hostName(ctx context.Context) string {
	if h, _ := s.Store.Setting(ctx, settingHostName, ""); h != "" {
		return h
	}
	h, _ := os.Hostname()
	return h
}

// initOutputs builds the dispatcher and loads the targets (called from New).
func (s *Server) initOutputs() {
	s.bumpSNMPBoots(context.Background())
	s.notify = notify.New(s.Log, map[string]notify.Factory{
		store.TargetSyslog: func(t store.Target) (notify.Sender, error) {
			return syslog.NewSender(t.Endpoint, syslogConfig(t, s.hostName(context.Background()), s.BindAddr))
		},
		store.TargetSNMPTrap: func(t store.Target) (notify.Sender, error) {
			return snmp.NewTrapSender(t.Endpoint, s.trapConfig(context.Background(), t))
		},
		store.TargetOTLP: func(t store.Target) (notify.Sender, error) {
			c := otlpConfig(t, s.otlpResource(context.Background()), s.BindAddr)
			return otlp.NewSender(t.Endpoint, c, func(ctx context.Context) []otlp.Metric {
				rep, rules := s.monitorReport(ctx)
				return otlp.FromReport(rep, rules, s.notify.Status(), time.Now(), s.started, c.RuleMetrics)
			})
		},
	})
	s.reloadOutputs(context.Background())
}

func cfgString(m map[string]any, k, def string) string {
	if v, ok := m[k].(string); ok && v != "" {
		return v
	}
	return def
}

func cfgBool(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

// SNMPv3 engine id (created once) and boot counter (+1 per start of the web part).
const (
	settingSNMPEngineID = "snmp_engine_id"
	settingSNMPBoots    = "snmp_engine_boots"
)

func (s *Server) snmpEngine(ctx context.Context) (string, uint32) {
	id, _ := s.Store.Setting(ctx, settingSNMPEngineID, "")
	if id == "" {
		id = snmp.NewEngineID()
		_ = s.Store.SetSetting(ctx, settingSNMPEngineID, id)
	}
	b, _ := s.Store.Setting(ctx, settingSNMPBoots, "0")
	n, _ := strconv.Atoi(b)
	return id, uint32(n)
}

// bumpSNMPBoots counts this start (USM needs a growing boot counter with the engine time).
func (s *Server) bumpSNMPBoots(ctx context.Context) {
	b, _ := s.Store.Setting(ctx, settingSNMPBoots, "0")
	n, _ := strconv.Atoi(b)
	_ = s.Store.SetSetting(ctx, settingSNMPBoots, strconv.Itoa(n+1))
}

func (s *Server) trapConfig(ctx context.Context, t store.Target) snmp.TrapConfig {
	eid, boots := s.snmpEngine(ctx)
	return snmp.TrapConfig{Version: cfgString(t.Config, "version", "v3"), Inform: cfgBool(t.Config, "inform"),
		Community: t.Secret["community"], User: cfgString(t.Config, "user", ""), AuthProto: cfgString(t.Config, "auth_proto", "sha256"),
		AuthPass: t.Secret["auth_pass"], PrivProto: cfgString(t.Config, "priv_proto", "aes128"), PrivPass: t.Secret["priv_pass"],
		EngineID: eid, Boots: boots, Bind: s.BindAddr}
}

func (s *Server) instanceID(ctx context.Context) string {
	if id, _ := s.Store.Setting(ctx, settingInstanceID, ""); id != "" {
		return id
	}
	id := auth.Token(12)
	_ = s.Store.SetSetting(ctx, settingInstanceID, id)
	return id
}

func (s *Server) otlpResource(ctx context.Context) otlp.Resource {
	return otlp.Resource{ServiceName: "nsrelay", Version: s.Version, InstanceID: s.instanceID(ctx), HostName: s.hostName(ctx)}
}

func otlpConfig(t store.Target, res otlp.Resource, bind netip.Addr) otlp.Config {
	c := otlp.Config{Protocol: cfgString(t.Config, "protocol", "grpc"), TLS: cfgString(t.Config, "tls", "none") == "tls",
		TLSCA: cfgString(t.Config, "tls_ca", ""), SkipVerify: cfgBool(t.Config, "tls_skip_verify"),
		Metrics: !cfgBool(t.Config, "no_metrics"), Logs: !cfgBool(t.Config, "no_logs"),
		RuleMetrics: cfgBool(t.Config, "rule_metrics"), Gzip: cfgBool(t.Config, "gzip"), Resource: res, Bind: bind,
		Interval: 30 * time.Second, Headers: map[string]string{}}
	if v, ok := t.Config["interval_s"].(float64); ok && v > 0 {
		c.Interval = time.Duration(v) * time.Second
	}
	for k, v := range t.Secret {
		if name, ok := strings.CutPrefix(k, "header:"); ok && v != "" {
			c.Headers[name] = v
		}
	}
	return c
}

func syslogConfig(t store.Target, host string, bind netip.Addr) syslog.Config {
	return syslog.Config{Transport: cfgString(t.Config, "transport", "udp"), Format: cfgString(t.Config, "format", "rfc5424"),
		Facility: cfgString(t.Config, "facility", "local0"), TLSCA: cfgString(t.Config, "tls_ca", ""),
		TLSSkipVerify: cfgBool(t.Config, "tls_skip_verify"), Host: host, Bind: bind}
}

// SetBindAddr sets the source address for outgoing monitoring connections (host part of the MGMT listen
// address; loopback and 0.0.0.0 mean "any") and rebuilds the senders.
func (s *Server) SetBindAddr(listen string) {
	s.BindAddr = bindFrom(listen)
	s.reloadOutputs(context.Background())
	s.restartAgent(context.Background())
}

// CloseOutputs flushes and stops all senders (shutdown).
func (s *Server) CloseOutputs() { s.notify.Close() }

// reloadOutputs re-reads the targets after a change.
func (s *Server) reloadOutputs(ctx context.Context) {
	ts, err := s.Store.Targets(ctx)
	if err != nil {
		s.Log.Error("monitoring targets", "err", err)
		return
	}
	s.notify.Reload(ts)
}

// auditToOutputs is the store's audit hook. Publish never blocks.
func (s *Server) auditToOutputs(e store.AuditEntry) {
	v := auditOf(e)
	text := v.Text
	if e.User != "" {
		text = e.User + ": " + text
	}
	if v.Object != "" {
		text += " " + v.Object
	}
	sev := notify.Notice
	if v.Tone == "danger" || v.Tone == "warn" {
		sev = notify.Warn
	}
	s.notify.Publish(notify.Event{Type: notify.TypeAudit, Severity: sev, Action: e.Action, User: e.User, Object: e.Object, Text: text})
}

// alarmTitle covers the engine alarms and the ones the web role raises itself.
func alarmTitle(kind string) string {
	switch kind {
	case "vlan_silent":
		return "Netz schweigt"
	case "engine_down":
		return "Engine antwortet nicht"
	}
	if t := alarmTitles[kind]; t != "" {
		return t
	}
	return kind
}

func vlanOf(key string) int {
	if n, err := strconv.Atoi(key); err == nil && n >= 1 && n <= 4094 {
		return n
	}
	return 0
}

// WatchAlarms turns alarm instances (kind, key) into "open" and "clear" events. The open ones are kept in the
// database, so a restart repeats nothing and loses no "clear". It runs for the lifetime of the web process.
func (s *Server) WatchAlarms(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var downSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.watchOnce(ctx, &downSince, time.Now())
	}
}

func (s *Server) watchOnce(ctx context.Context, downSince *time.Time, now time.Time) {
	open, err := s.Store.OpenAlarms(ctx)
	if err != nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	st, engErr := s.Engine.Status(rctx)
	cancel()
	_, evErr := s.Store.ActiveEvent(ctx)
	active := map[store.AlarmKey]string{} // instance → text
	engineKey := store.AlarmKey{Kind: "engine_down", Key: "engine"}
	if engErr != nil {
		if downSince.IsZero() {
			*downSince = now
		}
		if now.Sub(*downSince) >= engineDownAfter {
			active[engineKey] = "Engine antwortet nicht: " + engErr.Error()
		} else if _, ok := open[engineKey]; ok {
			active[engineKey] = ""
		}
		// without the engine nothing is known about the other alarms: keep them as they are
		for k := range open {
			if k != engineKey {
				active[k] = ""
			}
		}
	} else {
		*downSince = time.Time{}
		rep := monitor.Build(st, nil, s.Version, evErr == nil, now)
		detail := map[store.AlarmKey]string{}
		for _, a := range st.Alarms {
			detail[store.AlarmKey{Kind: a.Kind, Key: a.Key}] = a.Detail
		}
		for kind, sum := range rep.Alarms {
			for _, key := range sum.Keys {
				k := store.AlarmKey{Kind: kind, Key: key}
				text := alarmTitle(kind)
				if kind == "vlan_silent" {
					text = fmt.Sprintf("Netz schweigt: VLAN %s bekommt seit %d Minuten keine Broadcasts", key, int(monitor.SilentAfter.Minutes()))
				} else if d := detail[k]; d != "" {
					text += ": " + d
				} else if key != "" {
					text += " (" + key + ")"
				}
				active[k] = text
			}
		}
	}
	for k, text := range active {
		if _, ok := open[k]; ok {
			continue
		}
		if err := s.Store.SetAlarmOpen(ctx, k, true); err != nil {
			continue
		}
		s.notify.Publish(notify.Event{Time: now, Type: notify.TypeAlarm, State: "open", Severity: notify.Warn,
			Kind: k.Kind, Key: k.Key, VLAN: vlanOf(k.Key), Text: text})
	}
	for k := range open {
		if _, still := active[k]; still {
			continue
		}
		if err := s.Store.SetAlarmOpen(ctx, k, false); err != nil {
			continue
		}
		why := "seit 5 Minuten ruhig oder als gesehen markiert"
		if k.Kind == "engine_down" {
			why = "Engine antwortet wieder"
		}
		text := alarmTitle(k.Kind)
		if k.Key != "" && k.Kind != "engine_down" {
			text += " (" + k.Key + ")"
		}
		s.notify.Publish(notify.Event{Time: now, Type: notify.TypeAlarm, State: "clear", Severity: notify.Notice,
			Kind: k.Kind, Key: k.Key, VLAN: vlanOf(k.Key), Text: text + " beendet: " + why})
	}
}

// outputStats feeds the monitoring report (outputs_total/failing/dropped).
func (s *Server) outputStats() (total, failing int, dropped uint64) {
	return notify.Summary(s.notify.Status())
}

// bindFrom returns the host part of a listen address as source address for outgoing connections (MGMT).
func bindFrom(addr string) netip.Addr {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || a.IsUnspecified() || a.IsLoopback() {
		return netip.Addr{}
	}
	return a
}
