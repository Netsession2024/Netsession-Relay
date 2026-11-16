package otlp

import (
	"fmt"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

// Metric is one OTLP metric with integer data points.
type Metric struct {
	Name, Unit, Desc string
	Sum              bool      // monotonic cumulative counter; otherwise a gauge
	Start            time.Time // counters: start of the counting (engine start)
	Time             time.Time
	Points           []Point
}

// Point is one data point.
type Point struct {
	Attrs []KV
	Value int64
}

// KV is one attribute; Value is a string or an int.
type KV struct {
	Key   string
	Value any
}

// MetricNames is the stable list of exported metric names (a test keeps it in sync with FromReport).
var MetricNames = []string{
	"nsrelay.engine.up", "nsrelay.uptime", "nsrelay.info", "nsrelay.mode", "nsrelay.standby", "nsrelay.sending",
	"nsrelay.event.active", "nsrelay.vlans", "nsrelay.rules", "nsrelay.selftest.findings", "nsrelay.rx", "nsrelay.sent",
	"nsrelay.drops", "nsrelay.alarms.active", "nsrelay.alarms.acked", "nsrelay.alarm.occurrences", "nsrelay.vlan.in",
	"nsrelay.vlan.out", "nsrelay.vlan.silent.duration", "nsrelay.vlan.silent", "nsrelay.rule.rx", "nsrelay.rule.relayed",
	"nsrelay.output.up", "nsrelay.output.sent", "nsrelay.output.dropped",
}

// ModeNumber maps the mode to the number used by OTLP and SNMP: 0 unknown, 1 active, 2 observe, 3 paused.
func ModeNumber(mode string) int64 {
	switch mode {
	case "active":
		return 1
	case "observe":
		return 2
	case "paused":
		return 3
	}
	return 0
}

// FromReport converts the monitoring report into OTLP metrics. Counters start at the engine start, so an
// engine restart shows as a counter reset. Without the engine only engine.up, event.active and the outputs go
// out, never frozen counters.
func FromReport(rep monitor.Report, rules []engineapi.RuleStat, outputs []notify.Status, now, webStart time.Time, withRules bool) []Metric {
	gauge := func(name, unit, desc string, v int64, attrs ...KV) Metric {
		return Metric{Name: name, Unit: unit, Desc: desc, Time: now, Points: []Point{{Attrs: attrs, Value: v}}}
	}
	ms := []Metric{
		gauge("nsrelay.engine.up", "1", "1 if the engine answers the web part.", int64(rep.EngineUp)),
		gauge("nsrelay.event.active", "1", "1 if an event is active.", int64(rep.EventActive)),
	}
	if rep.EngineUp == 1 {
		start := now.Add(-time.Duration(rep.UptimeS) * time.Second)
		sum := func(name, unit, desc string, pts []Point) Metric {
			return Metric{Name: name, Unit: unit, Desc: desc, Sum: true, Start: start, Time: now, Points: pts}
		}
		one := func(v uint64, attrs ...KV) []Point { return []Point{{Attrs: attrs, Value: int64(v)}} }
		ms = append(ms,
			gauge("nsrelay.uptime", "s", "Seconds since the engine started.", rep.UptimeS),
			gauge("nsrelay.info", "1", "Mode, snapshot and engine version as attributes.", 1,
				KV{"nsrelay.mode", rep.Mode}, KV{"nsrelay.snapshot", rep.Snapshot}, KV{"nsrelay.engine.version", rep.EngineVersion}),
			gauge("nsrelay.mode", "1", "0 unknown, 1 active, 2 observe, 3 paused.", ModeNumber(rep.Mode)),
			gauge("nsrelay.standby", "1", "1 if a second relay put this one in standby.", int64(rep.Standby)),
			gauge("nsrelay.sending", "1", "1 if the engine currently relays.", int64(rep.Sending)),
			gauge("nsrelay.vlans", "{vlan}", "VLANs in the active snapshot.", int64(rep.VLANs)),
			gauge("nsrelay.rules", "{rule}", "Rules in the active snapshot.", int64(rep.Rules)),
			gauge("nsrelay.selftest.findings", "{finding}", "Host self-test findings at engine start.", int64(rep.SelfTest)),
			sum("nsrelay.rx", "{frame}", "Frames received after the kernel filter.", one(rep.RXTotal)),
			sum("nsrelay.sent", "{frame}", "Frames sent (all copies).", one(rep.SentTotal)),
		)
		var drops []Point
		for _, r := range monitor.DropReasons {
			drops = append(drops, Point{Attrs: []KV{{"reason", r}}, Value: int64(rep.Drops[r])})
		}
		ms = append(ms, sum("nsrelay.drops", "{frame}", "Frames not relayed, by reason.", drops))
		var act, acked, occ []Point
		for _, k := range monitor.Kinds {
			a := rep.Alarms[k]
			act = append(act, Point{Attrs: []KV{{"kind", k}}, Value: int64(a.Active)})
			acked = append(acked, Point{Attrs: []KV{{"kind", k}}, Value: int64(a.Acked)})
			occ = append(occ, Point{Attrs: []KV{{"kind", k}}, Value: int64(a.Count)})
		}
		m := gauge("nsrelay.alarms.active", "{alarm}", "Unacknowledged alarms seen in the last 5 minutes, by kind.", 0)
		m.Points = act
		ms = append(ms, m)
		m = gauge("nsrelay.alarms.acked", "{alarm}", "Acknowledged alarms still known, by kind.", 0)
		m.Points = acked
		ms = append(ms, m, sum("nsrelay.alarm.occurrences", "{occurrence}", "Alarm occurrences since engine start, by kind.", occ))
		var in, out, silentS, silent []Point
		for _, v := range rep.VLANList {
			attrs := []KV{{"vlan", int64(v.VID)}, {"vlan.name", v.Name}, {"vlan.group", v.Group}}
			in = append(in, Point{Attrs: attrs, Value: int64(v.In)})
			out = append(out, Point{Attrs: attrs, Value: int64(v.Out)})
			silentS = append(silentS, Point{Attrs: attrs, Value: v.SilentS})
			silent = append(silent, Point{Attrs: attrs, Value: int64(v.Silent)})
		}
		ms = append(ms, sum("nsrelay.vlan.in", "{frame}", "Frames received per VLAN.", in),
			sum("nsrelay.vlan.out", "{frame}", "Frames sent per VLAN.", out))
		m = gauge("nsrelay.vlan.silent.duration", "s", "Seconds without received frames per VLAN.", 0)
		m.Points = silentS
		ms = append(ms, m)
		m = gauge("nsrelay.vlan.silent", "1", "1 if the VLAN counts as silent (vlan_silent).", 0)
		m.Points = silent
		ms = append(ms, m)
		if withRules {
			var rx, rel []Point
			for _, r := range rules {
				rx = append(rx, Point{Attrs: []KV{{"rule", r.ID}}, Value: int64(r.RX)})
				rel = append(rel, Point{Attrs: []KV{{"rule", r.ID}}, Value: int64(r.Relayed)})
			}
			ms = append(ms, sum("nsrelay.rule.rx", "{frame}", "Frames matched per rule.", rx),
				sum("nsrelay.rule.relayed", "{frame}", "Frames relayed per rule.", rel))
		}
	}
	var up, sent, dropped []Point
	for _, o := range outputs {
		if o.State == "off" {
			continue
		}
		attrs := []KV{{"target", o.Name}, {"kind", o.Kind}}
		v := int64(1)
		if o.Failing() {
			v = 0
		}
		up = append(up, Point{Attrs: attrs, Value: v})
		sent = append(sent, Point{Attrs: attrs, Value: int64(o.Sent)})
		dropped = append(dropped, Point{Attrs: attrs, Value: int64(o.Dropped)})
	}
	if len(up) > 0 {
		m := gauge("nsrelay.output.up", "1", "1 unless the monitoring target is failing.", 0)
		m.Points = up
		ms = append(ms, m,
			Metric{Name: "nsrelay.output.sent", Unit: "{event}", Desc: "Events delivered per monitoring target.", Sum: true, Start: webStart, Time: now, Points: sent},
			Metric{Name: "nsrelay.output.dropped", Unit: "{event}", Desc: "Events dropped per monitoring target.", Sum: true, Start: webStart, Time: now, Points: dropped})
	}
	return ms
}

func anyValue(v any) *commonpb.AnyValue {
	switch x := v.(type) {
	case string:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: x}}
	case int64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: x}}
	case int:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(x)}}
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: x}}
	}
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: fmt.Sprint(v)}}
}

func attributes(kvs []KV) []*commonpb.KeyValue {
	out := make([]*commonpb.KeyValue, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, &commonpb.KeyValue{Key: kv.Key, Value: anyValue(kv.Value)})
	}
	return out
}

func resource(r Resource) *resourcepb.Resource {
	kvs := []KV{{"service.name", r.ServiceName}}
	for _, kv := range []KV{{"service.version", r.Version}, {"service.instance.id", r.InstanceID}, {"host.name", r.HostName}} {
		if kv.Value != "" {
			kvs = append(kvs, kv)
		}
	}
	return &resourcepb.Resource{Attributes: attributes(kvs)}
}

func nanos(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano())
}

func resourceMetrics(r Resource, ms []Metric, _ bool) []*metricspb.ResourceMetrics {
	out := make([]*metricspb.Metric, 0, len(ms))
	for _, m := range ms {
		pts := make([]*metricspb.NumberDataPoint, 0, len(m.Points))
		for _, p := range m.Points {
			dp := &metricspb.NumberDataPoint{Attributes: attributes(p.Attrs), TimeUnixNano: nanos(m.Time),
				Value: &metricspb.NumberDataPoint_AsInt{AsInt: p.Value}}
			if m.Sum {
				dp.StartTimeUnixNano = nanos(m.Start)
			}
			pts = append(pts, dp)
		}
		pm := &metricspb.Metric{Name: m.Name, Unit: m.Unit, Description: m.Desc}
		if m.Sum {
			pm.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: pts, IsMonotonic: true,
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE}}
		} else {
			pm.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: pts}}
		}
		out = append(out, pm)
	}
	return []*metricspb.ResourceMetrics{{Resource: resource(r), ScopeMetrics: []*metricspb.ScopeMetrics{{
		Scope: &commonpb.InstrumentationScope{Name: "nsrelay", Version: r.Version}, Metrics: out}}}}
}

// severity maps an event to the OTLP severity: WARN only for opened alarms (filter by severity in Zabbix),
// INFO2 for audit entries of dangerous actions, INFO for everything else.
func severity(e notify.Event) (logspb.SeverityNumber, string) {
	switch {
	case e.Type == notify.TypeAlarm && e.State == "open":
		return logspb.SeverityNumber_SEVERITY_NUMBER_WARN, "WARN"
	case e.Type == notify.TypeAudit && e.Severity == notify.Warn:
		return logspb.SeverityNumber_SEVERITY_NUMBER_INFO2, "INFO2"
	}
	return logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "INFO"
}

func resourceLogs(r Resource, batch []notify.Event) []*logspb.ResourceLogs {
	now := time.Now()
	recs := make([]*logspb.LogRecord, 0, len(batch))
	for _, e := range batch {
		num, text := severity(e)
		kvs := []KV{{"nsrelay.msgid", e.MsgID()}}
		add := func(k, v string) {
			if v != "" {
				kvs = append(kvs, KV{k, v})
			}
		}
		if e.Type == notify.TypeAlarm {
			add("nsrelay.alarm.kind", e.Kind)
			add("nsrelay.alarm.key", e.Key)
			add("nsrelay.alarm.state", e.State)
		}
		if e.VLAN > 0 {
			kvs = append(kvs, KV{"vlan", int64(e.VLAN)})
		}
		if e.Type == notify.TypeAudit {
			add("nsrelay.audit.action", e.Action)
			add("nsrelay.audit.object", e.Object)
		}
		add("user.name", e.User)
		recs = append(recs, &logspb.LogRecord{TimeUnixNano: nanos(e.Time), ObservedTimeUnixNano: nanos(now),
			SeverityNumber: num, SeverityText: text, Body: anyValue(e.Text), Attributes: attributes(kvs)})
	}
	return []*logspb.ResourceLogs{{Resource: resource(r), ScopeLogs: []*logspb.ScopeLogs{{
		Scope: &commonpb.InstrumentationScope{Name: "nsrelay", Version: r.Version}, LogRecords: recs}}}}
}
