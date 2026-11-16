package monitor

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
)

// Alarm kinds always present in the report, so Zabbix items and triggers exist before the first incident.
var Kinds = []string{"foreign_relay", "loop", "storm", "dual_active", "vlan_silent"}

// DropReasons are always present in Report.Drops (0 until the engine reports them), see engine.Reason.
var DropReasons = []string{"parse", "own_mac", "blocked", "foreign_relay", "src_subnet", "not_broadcast", "unknown_port",
	"no_target", "size", "ttl", "mode", "loop", "rate", "auto_paused"}

// ActiveWindow: an unacknowledged alarm counts as active while it was seen within this window.
const ActiveWindow = 5 * time.Minute

// SilentAfter: during an active event in mode "active", a VLAN without any received broadcast for this long
// raises vlan_silent (docs/02-plan.md section 7).
const SilentAfter = 10 * time.Minute

// Output is one monitoring target in the Prometheus export.
type Output struct {
	Name, Kind  string
	Up          bool
	Sent        uint64
	Dropped     uint64
	LastSuccess int64 // unix seconds, 0 = never
}

// Report is the JSON answer of GET /api/v1/monitoring. Flat numbers for Zabbix dependent items (JSONPath),
// vlan_list for low-level discovery. Booleans are 0/1 so Zabbix can store them as numbers.
type Report struct {
	Time          int64                   `json:"time"`
	WebVersion    string                  `json:"web_version"`
	EngineUp      int                     `json:"engine_up"`
	EngineError   string                  `json:"engine_error,omitempty"`
	EngineVersion string                  `json:"engine_version"`
	UptimeS       int64                   `json:"uptime_s"`
	Mode          string                  `json:"mode"`
	Standby       int                     `json:"standby"`
	Sending       int                     `json:"sending"`
	EventActive   int                     `json:"event_active"`
	Snapshot      string                  `json:"snapshot"`
	VLANs         int                     `json:"vlans"`
	Rules         int                     `json:"rules"`
	RXTotal       uint64                  `json:"rx_total"`
	SentTotal     uint64                  `json:"sent_total"`
	RXPerS        uint64                  `json:"rx_per_s"`
	SentPerS      uint64                  `json:"sent_per_s"`
	Drops         map[string]uint64       `json:"drops"`
	AlarmsActive  int                     `json:"alarms_active"`
	Alarms        map[string]AlarmSummary `json:"alarms"`
	SelfTest      int                     `json:"self_test_findings"`
	VLANList      []VLAN                  `json:"vlan_list"`
	// monitoring targets of the web role (syslog, OTLP, SNMP traps): enabled ones, failing ones, events dropped
	OutputsTotal   int      `json:"outputs_total"`
	OutputsFailing int      `json:"outputs_failing"`
	OutputsDropped uint64   `json:"outputs_dropped"`
	Outputs        []Output `json:"-"` // per target, for Prometheus only
}

// AlarmSummary aggregates all alarms of one kind.
type AlarmSummary struct {
	Active int      `json:"active"` // unacknowledged and seen within ActiveWindow
	Acked  int      `json:"acked"`  // acknowledged ("Gesehen") but still known
	Count  uint64   `json:"count"`  // occurrences since engine start
	Last   int64    `json:"last"`   // unix seconds, 0 = never
	Keys   []string `json:"keys"`   // affected rules/VLANs of the active ones
}

// VLAN is one entry for Zabbix low-level discovery ({#VID}, {#NAME}, {#GROUP}).
type VLAN struct {
	VID       int    `json:"vid"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Interface string `json:"interface"`
	In        uint64 `json:"in"`
	Out       uint64 `json:"out"`
	InPerS    uint64 `json:"in_per_s"`
	LastIn    int64  `json:"last_in"`  // unix seconds, 0 = nothing since engine start
	SilentS   int64  `json:"silent_s"` // seconds without received frames (since engine start if never)
	Silent    int    `json:"silent"`   // 1 = counts for vlan_silent
}

// Build turns an engine status into a report. engineErr != nil means the engine did not answer.
func Build(st engineapi.Status, engineErr error, webVersion string, eventActive bool, now time.Time) Report {
	r := Report{Time: now.Unix(), WebVersion: webVersion, Drops: map[string]uint64{}, Alarms: map[string]AlarmSummary{},
		VLANList: []VLAN{}}
	for _, k := range Kinds {
		r.Alarms[k] = AlarmSummary{Keys: []string{}}
	}
	if eventActive {
		r.EventActive = 1
	}
	if engineErr != nil {
		r.EngineError = engineErr.Error()
		return r
	}
	for _, k := range DropReasons {
		r.Drops[k] = 0
	}
	r.EngineUp = 1
	r.EngineVersion, r.Mode, r.Snapshot = st.Version, st.Mode, st.SnapshotHash
	if !st.Started.IsZero() {
		r.UptimeS = int64(now.Sub(st.Started) / time.Second)
	}
	r.Standby, r.Sending = b2i(st.Standby), b2i(st.Sending)
	r.VLANs, r.Rules = st.VLANs, st.Rules
	r.RXTotal, r.SentTotal, r.RXPerS, r.SentPerS = st.RX, st.Sent, st.RXRate, st.SentRate
	for k, v := range st.Reasons {
		if k != "relayed" {
			r.Drops[k] = v
		}
	}
	r.SelfTest = len(st.SelfTest)

	for _, a := range st.Alarms {
		s := r.Alarms[a.Kind]
		if s.Keys == nil {
			s.Keys = []string{}
		}
		s.Count += a.Count
		if u := a.Last.Unix(); !a.Last.IsZero() && u > s.Last {
			s.Last = u
		}
		switch {
		case !a.AckedAt.IsZero():
			s.Acked++
		case now.Sub(a.Last) <= ActiveWindow:
			s.Active++
			s.Keys = append(s.Keys, a.Key)
		}
		r.Alarms[a.Kind] = s
	}

	watch := eventActive && st.Mode == "active" && !st.Standby
	silent := r.Alarms["vlan_silent"]
	for _, v := range st.VLANStats {
		x := VLAN{VID: v.VID, Name: v.Name, Group: v.Group, Interface: v.Interface, In: v.In, Out: v.Out, InPerS: v.InRate}
		since := st.Started
		if !v.LastIn.IsZero() {
			x.LastIn, since = v.LastIn.Unix(), v.LastIn
		}
		if !since.IsZero() {
			x.SilentS = int64(now.Sub(since) / time.Second)
		}
		if watch && !since.IsZero() && now.Sub(since) >= SilentAfter {
			x.Silent = 1
			silent.Active++
			silent.Keys = append(silent.Keys, fmt.Sprint(v.VID))
		}
		r.VLANList = append(r.VLANList, x)
	}
	r.Alarms["vlan_silent"] = silent
	for _, s := range r.Alarms {
		sort.Strings(s.Keys)
		r.AlarmsActive += s.Active
	}
	return r
}

func b2f(b bool) float64 { return float64(b2i(b)) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// WritePrometheus writes the report (plus per-rule counters) in the Prometheus text format 0.0.4.
func WritePrometheus(w io.Writer, r Report, rules []engineapi.RuleStat) error {
	p := &promWriter{w: w}
	p.metric("nsrelay_engine_up", "gauge", "1 if the engine answered the web part.", nil, float64(r.EngineUp))
	p.metric("nsrelay_info", "gauge", "Versions, mode and active snapshot.",
		[]string{"web_version", r.WebVersion, "engine_version", r.EngineVersion, "mode", r.Mode, "snapshot", r.Snapshot}, 1)
	p.metric("nsrelay_uptime_seconds", "gauge", "Seconds since the engine started.", nil, float64(r.UptimeS))
	p.metric("nsrelay_standby", "gauge", "1 if the dual-active guard put this engine in standby.", nil, float64(r.Standby))
	p.metric("nsrelay_sending", "gauge", "1 if the engine currently relays.", nil, float64(r.Sending))
	p.metric("nsrelay_event_active", "gauge", "1 if an event is active in the web part.", nil, float64(r.EventActive))
	p.metric("nsrelay_vlans", "gauge", "VLANs in the active snapshot.", nil, float64(r.VLANs))
	p.metric("nsrelay_rules", "gauge", "Rules in the active snapshot.", nil, float64(r.Rules))
	p.metric("nsrelay_received_frames_total", "counter", "Frames received after the kernel filter.", nil, float64(r.RXTotal))
	p.metric("nsrelay_sent_frames_total", "counter", "Frames sent (all copies).", nil, float64(r.SentTotal))
	p.metric("nsrelay_self_test_findings", "gauge", "Host self-test findings at engine start.", nil, float64(r.SelfTest))

	reasons := make([]string, 0, len(r.Drops))
	for k := range r.Drops {
		reasons = append(reasons, k)
	}
	sort.Strings(reasons)
	p.head("nsrelay_dropped_frames_total", "counter", "Frames not relayed, by reason.")
	for _, k := range reasons {
		p.sample("nsrelay_dropped_frames_total", []string{"reason", k}, float64(r.Drops[k]))
	}
	p.head("nsrelay_alarms_active", "gauge", "Unacknowledged alarms seen in the last 5 minutes, by kind.")
	for _, k := range Kinds {
		p.sample("nsrelay_alarms_active", []string{"kind", k}, float64(r.Alarms[k].Active))
	}
	p.head("nsrelay_alarm_occurrences_total", "counter", "Alarm occurrences since engine start, by kind.")
	for _, k := range Kinds {
		p.sample("nsrelay_alarm_occurrences_total", []string{"kind", k}, float64(r.Alarms[k].Count))
	}
	type vm struct {
		name, typ, help string
		val             func(VLAN) float64
	}
	for _, m := range []vm{
		{"nsrelay_vlan_received_frames_total", "counter", "Frames received per VLAN.", func(v VLAN) float64 { return float64(v.In) }},
		{"nsrelay_vlan_sent_frames_total", "counter", "Frames sent per VLAN.", func(v VLAN) float64 { return float64(v.Out) }},
		{"nsrelay_vlan_last_received_timestamp_seconds", "gauge", "Unix time of the last received frame (0 = none).", func(v VLAN) float64 { return float64(v.LastIn) }},
	} {
		p.head(m.name, m.typ, m.help)
		for _, v := range r.VLANList {
			p.sample(m.name, []string{"vid", fmt.Sprint(v.VID), "name", v.Name, "group", v.Group}, m.val(v))
		}
	}
	type om struct {
		name, typ, help string
		val             func(Output) float64
	}
	for _, m := range []om{
		{"nsrelay_output_up", "gauge", "1 unless the monitoring target is failing.", func(o Output) float64 { return b2f(o.Up) }},
		{"nsrelay_output_sent_total", "counter", "Events delivered to the monitoring target since the web part started.", func(o Output) float64 { return float64(o.Sent) }},
		{"nsrelay_output_dropped_total", "counter", "Events dropped for the monitoring target (queue full, too old, send failed).", func(o Output) float64 { return float64(o.Dropped) }},
		{"nsrelay_output_last_success_timestamp_seconds", "gauge", "Unix time of the last successful send (0 = never).", func(o Output) float64 { return float64(o.LastSuccess) }},
	} {
		p.head(m.name, m.typ, m.help)
		for _, o := range r.Outputs {
			p.sample(m.name, []string{"target", o.Name, "kind", o.Kind}, m.val(o))
		}
	}
	p.head("nsrelay_rule_received_frames_total", "counter", "Frames matched per rule.")
	for _, x := range rules {
		p.sample("nsrelay_rule_received_frames_total", []string{"rule", x.ID}, float64(x.RX))
	}
	p.head("nsrelay_rule_relayed_frames_total", "counter", "Frames relayed per rule (before fan-out).")
	for _, x := range rules {
		p.sample("nsrelay_rule_relayed_frames_total", []string{"rule", x.ID}, float64(x.Relayed))
	}
	return p.err
}

type promWriter struct {
	w   io.Writer
	err error
}

func (p *promWriter) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

func (p *promWriter) head(name, typ, help string) {
	p.printf("# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (p *promWriter) sample(name string, labels []string, v float64) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(escapeLabel(labels[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	p.printf("%s %v\n", b.String(), v)
}

func (p *promWriter) metric(name, typ, help string, labels []string, v float64) {
	p.head(name, typ, help)
	p.sample(name, labels, v)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
