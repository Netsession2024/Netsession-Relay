// Package snmp holds the relay's SNMP tree (NETSESSION-RELAY-MIB), sends traps/informs to several receivers
// and (later) answers GET/GETNEXT/GETBULK as a read-only agent. The object list in this file is the single
// source: the MIB file deploy/snmp/NETSESSION-RELAY-MIB.txt is generated from it (`nsrelay snmp-mib`) and a
// test keeps both in sync (docs/05-monitoring-konzept.md, 5).
package snmp

import (
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

// Enterprise is 1.3.6.1.4.1.<PEN>; Base the relay MIB (netsession.products(1).nsRelayMIB(1)).
var (
	Enterprise = fmt.Sprintf("1.3.6.1.4.1.%d", notify.PEN)
	Base       = Enterprise + ".1.1"
)

// View is everything the agent needs to answer: the monitoring report plus web-role facts.
type View struct {
	Report         monitor.Report
	OutputsFailing int
}

// Syntax of an object (SMIv2 type and its BER type for gosnmp).
type Syntax struct {
	MIB string // SYNTAX clause
	BER gosnmp.Asn1BER
}

var (
	sString   = Syntax{"DisplayString", gosnmp.OctetString}
	sTruth    = Syntax{"TruthValue", gosnmp.Integer}
	sTicks    = Syntax{"TimeTicks", gosnmp.TimeTicks}
	sGauge    = Syntax{"Gauge32", gosnmp.Gauge32}
	sCounter  = Syntax{"Counter64", gosnmp.Counter64}
	sUnsigned = Syntax{"Unsigned32", gosnmp.Uinteger32}
	sIndex    = Syntax{"Integer32 (1..4094)", gosnmp.Integer}
	sMode     = Syntax{"INTEGER { unknown(0), active(1), observe(2), paused(3) }", gosnmp.Integer}
)

// Scalar is one scalar object (instance .0).
type Scalar struct {
	Sub    string // relative to Base, without .0
	Name   string
	Syntax Syntax
	Desc   string
	Get    func(v *View) any
}

// Column is one column of a table.
type Column struct {
	Sub    int
	Name   string
	Syntax Syntax
	Desc   string
	Get    func(row any) any
}

// Table is a conceptual table; Rows returns (index, row) pairs in index order.
type Table struct {
	Sub     string // the table, entry is Sub + ".1"
	Name    string // ...Table
	Entry   string // ...Entry
	Desc    string
	Index   Column // column 1, not-accessible
	Columns []Column
	Rows    func(v *View) []TableRow
}

// TableRow is one row of a table.
type TableRow struct {
	Index int
	Row   any
}

func truth(b int) any {
	if b == 1 {
		return 1 // true(1)
	}
	return 2 // false(2)
}

// Scalars of the relay tree in OID order.
var Scalars = []Scalar{
	{"1.1.1", "nsRelayWebVersion", sString, "Version of the web part.", func(v *View) any { return v.Report.WebVersion }},
	{"1.1.2", "nsRelayEngineVersion", sString, "Version of the engine.", func(v *View) any { return v.Report.EngineVersion }},
	{"1.1.3", "nsRelayEngineUp", sTruth, "true if the engine answers the web part.", func(v *View) any { return truth(v.Report.EngineUp) }},
	{"1.1.4", "nsRelayEngineUptime", sTicks, "Time since the engine started.", func(v *View) any { return uint32(v.Report.UptimeS * 100) }},
	{"1.1.5", "nsRelayMode", sMode, "Engine mode.", func(v *View) any { return int(modeNumber(v.Report.Mode)) }},
	{"1.1.6", "nsRelayStandby", sTruth, "true if a second relay put this one in standby.", func(v *View) any { return truth(v.Report.Standby) }},
	{"1.1.7", "nsRelaySending", sTruth, "true if the engine currently relays.", func(v *View) any { return truth(v.Report.Sending) }},
	{"1.1.8", "nsRelayEventActive", sTruth, "true if an event is active.", func(v *View) any { return truth(v.Report.EventActive) }},
	{"1.1.9", "nsRelaySnapshot", sString, "Hash of the active snapshot.", func(v *View) any { return v.Report.Snapshot }},
	{"1.1.10", "nsRelayVlanCount", sGauge, "VLANs in the active snapshot.", func(v *View) any { return uint(v.Report.VLANs) }},
	{"1.1.11", "nsRelayRuleCount", sGauge, "Rules in the active snapshot.", func(v *View) any { return uint(v.Report.Rules) }},
	{"1.1.12", "nsRelaySelfTestFindings", sGauge, "Host self-test findings at engine start.", func(v *View) any { return uint(v.Report.SelfTest) }},
	{"1.1.13", "nsRelayAlarmsActive", sGauge, "Unacknowledged alarms seen in the last 5 minutes.", func(v *View) any { return uint(v.Report.AlarmsActive) }},
	{"1.1.14", "nsRelayOutputsFailing", sGauge, "Monitoring targets that accept nothing for 2 minutes.", func(v *View) any { return uint(v.OutputsFailing) }},
	{"1.2.1", "nsRelayRxFrames", sCounter, "Frames received after the kernel filter since engine start.", func(v *View) any { return v.Report.RXTotal }},
	{"1.2.2", "nsRelaySentFrames", sCounter, "Frames sent (all copies) since engine start.", func(v *View) any { return v.Report.SentTotal }},
}

func modeNumber(m string) int64 {
	switch m {
	case "active":
		return 1
	case "observe":
		return 2
	case "paused":
		return 3
	}
	return 0
}

// alarmKindsSNMP is monitor.Kinds plus engine_down (raised by the web part only); index = position + 1.
var alarmKindsSNMP = append(append([]string(nil), monitor.Kinds...), "engine_down")

type dropRow struct {
	reason string
	frames uint64
}

// Tables of the relay tree in OID order.
var Tables = []Table{
	{Sub: "1.3", Name: "nsRelayDropTable", Entry: "nsRelayDropEntry", Desc: "Frames not relayed, by reason (index order of the drop reasons, new reasons are appended).",
		Index: Column{1, "nsRelayDropIndex", Syntax{"Integer32 (1..64)", gosnmp.Integer}, "Index.", nil},
		Columns: []Column{
			{2, "nsRelayDropReason", sString, "Reason.", func(r any) any { return r.(dropRow).reason }},
			{3, "nsRelayDropFrames", sCounter, "Frames since engine start.", func(r any) any { return r.(dropRow).frames }},
		},
		Rows: func(v *View) []TableRow {
			if v.Report.EngineUp != 1 {
				return nil
			}
			out := make([]TableRow, 0, len(monitor.DropReasons))
			for i, k := range monitor.DropReasons {
				out = append(out, TableRow{i + 1, dropRow{k, v.Report.Drops[k]}})
			}
			return out
		}},
	{Sub: "1.4", Name: "nsRelayAlarmTable", Entry: "nsRelayAlarmEntry", Desc: "Alarms by kind (index order: foreign_relay, loop, storm, dual_active, vlan_silent, engine_down).",
		Index: Column{1, "nsRelayAlarmIndex", Syntax{"Integer32 (1..64)", gosnmp.Integer}, "Index.", nil},
		Columns: []Column{
			{2, "nsRelayAlarmKind", sString, "Alarm kind.", func(r any) any { return r.(alarmRow).kind }},
			{3, "nsRelayAlarmActive", sGauge, "Unacknowledged instances seen in the last 5 minutes.", func(r any) any { return uint(r.(alarmRow).s.Active) }},
			{4, "nsRelayAlarmAcked", sGauge, "Acknowledged instances still known.", func(r any) any { return uint(r.(alarmRow).s.Acked) }},
			{5, "nsRelayAlarmOccurrences", sCounter, "Occurrences since engine start.", func(r any) any { return r.(alarmRow).s.Count }},
			{6, "nsRelayAlarmLastSeen", sUnsigned, "Unix time of the last occurrence, 0 = never.", func(r any) any { return uint32(r.(alarmRow).s.Last) }},
		},
		Rows: func(v *View) []TableRow {
			out := make([]TableRow, 0, len(alarmKindsSNMP))
			for i, k := range alarmKindsSNMP {
				s := v.Report.Alarms[k]
				if k == "engine_down" && v.Report.EngineUp == 0 {
					s.Active = 1
				}
				out = append(out, TableRow{i + 1, alarmRow{k, s}})
			}
			return out
		}},
	{Sub: "1.5", Name: "nsRelayVlanTable", Entry: "nsRelayVlanEntry", Desc: "Networks (VLANs) of the active snapshot, index = VLAN ID.",
		Index: Column{1, "nsRelayVlanId", sIndex, "VLAN ID.", nil},
		Columns: []Column{
			{2, "nsRelayVlanName", sString, "Name.", func(r any) any { return r.(monitor.VLAN).Name }},
			{3, "nsRelayVlanGroup", sString, "Group.", func(r any) any { return r.(monitor.VLAN).Group }},
			{4, "nsRelayVlanInterface", sString, "Interface.", func(r any) any { return r.(monitor.VLAN).Interface }},
			{5, "nsRelayVlanInFrames", sCounter, "Frames received from this network since engine start.", func(r any) any { return r.(monitor.VLAN).In }},
			{6, "nsRelayVlanOutFrames", sCounter, "Frames sent into this network since engine start.", func(r any) any { return r.(monitor.VLAN).Out }},
			{7, "nsRelayVlanLastIn", sUnsigned, "Unix time of the last received frame, 0 = none.", func(r any) any { return uint32(r.(monitor.VLAN).LastIn) }},
			{8, "nsRelayVlanSilentSeconds", sGauge, "Seconds without received frames.", func(r any) any { return uint(r.(monitor.VLAN).SilentS) }},
			{9, "nsRelayVlanSilent", sTruth, "true if the network counts as silent (vlan_silent).", func(r any) any { return truth(r.(monitor.VLAN).Silent) }},
		},
		Rows: func(v *View) []TableRow {
			out := make([]TableRow, 0, len(v.Report.VLANList))
			for _, x := range v.Report.VLANList {
				out = append(out, TableRow{x.VID, x})
			}
			return out
		}},
}

type alarmRow struct {
	kind string
	s    monitor.AlarmSummary
}

// NotifyObject is one object that only appears in notifications (accessible-for-notify).
type NotifyObject struct {
	Sub  string
	Name string
	Desc string
}

// NotifyObjects are the varbinds of the notifications.
var NotifyObjects = []NotifyObject{
	{"1.6.1", "nsRelayEventKind", "Alarm kind."},
	{"1.6.2", "nsRelayEventKey", "Rule or network the alarm is about."},
	{"1.6.3", "nsRelayEventVlan", "VLAN ID, empty if none."},
	{"1.6.4", "nsRelayEventText", "Message (German)."},
	{"1.6.5", "nsRelayEventAction", "Audit action (e.g. game.enable)."},
	{"1.6.6", "nsRelayEventUser", "User who did it."},
	{"1.6.7", "nsRelayEventObject", "Object of the action."},
}

// Notification is one trap/inform type.
type Notification struct {
	Sub     string
	Name    string
	Objects []string
	Desc    string
}

// Notifications of the relay.
var Notifications = []Notification{
	{"0.1", "nsRelayAlarmOpened", []string{"nsRelayEventKind", "nsRelayEventKey", "nsRelayEventVlan", "nsRelayEventText"}, "An alarm instance opened."},
	{"0.2", "nsRelayAlarmCleared", []string{"nsRelayEventKind", "nsRelayEventKey", "nsRelayEventVlan", "nsRelayEventText"}, "An alarm instance ended (quiet for 5 minutes, acknowledged, or the engine is back)."},
	{"0.3", "nsRelayAudit", []string{"nsRelayEventAction", "nsRelayEventUser", "nsRelayEventObject", "nsRelayEventText"}, "A change in the relay (audit log entry)."},
	{"0.4", "nsRelayTest", []string{"nsRelayEventUser", "nsRelayEventText"}, "Test message from the monitoring page."},
}

// OID returns Base + "." + sub.
func OID(sub string) string { return Base + "." + sub }

// notifyOID returns the OID of a notification object by name.
func notifyOID(name string) string {
	for _, o := range NotifyObjects {
		if o.Name == name {
			return OID(o.Sub)
		}
	}
	panic("unknown notify object " + name)
}

// ---- MIB text ----

// MIB renders NETSESSION-RELAY-MIB (SMIv2).
func MIB() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("NETSESSION-RELAY-MIB DEFINITIONS ::= BEGIN")
	w("")
	w("-- Generated by `nsrelay snmp-mib` from internal/snmp/mib.go. Do not edit by hand.")
	w("-- Enterprise number %d is the IANA documentation PEN (RFC 5612) until Netsession has its own.", notify.PEN)
	w("")
	w("IMPORTS")
	w("    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, enterprises,")
	w("    Integer32, Unsigned32, Gauge32, Counter64, TimeTicks FROM SNMPv2-SMI")
	w("    DisplayString, TruthValue FROM SNMPv2-TC")
	w("    MODULE-COMPLIANCE, OBJECT-GROUP, NOTIFICATION-GROUP FROM SNMPv2-CONF;")
	w("")
	w("nsRelayMIB MODULE-IDENTITY")
	w("    LAST-UPDATED \"202611160000Z\"")
	w("    ORGANIZATION \"Netsession e.V.\"")
	w("    CONTACT-INFO \"https://github.com/Netsession2024/Netsession-Relay\"")
	w("    DESCRIPTION  \"Netsession Relay: UDP broadcast and multicast relay for LAN game discovery.\"")
	w("    REVISION     \"202611160000Z\"")
	w("    DESCRIPTION  \"First version.\"")
	w("    ::= { netsessionProducts 1 }")
	w("")
	w("netsession         OBJECT IDENTIFIER ::= { enterprises %d }", notify.PEN)
	w("netsessionProducts OBJECT IDENTIFIER ::= { netsession 1 }")
	w("")
	w("nsRelayNotifications OBJECT IDENTIFIER ::= { nsRelayMIB 0 }")
	w("nsRelayObjects       OBJECT IDENTIFIER ::= { nsRelayMIB 1 }")
	w("nsRelayStatus        OBJECT IDENTIFIER ::= { nsRelayObjects 1 }")
	w("nsRelayCounters      OBJECT IDENTIFIER ::= { nsRelayObjects 2 }")
	w("nsRelayEvent         OBJECT IDENTIFIER ::= { nsRelayObjects 6 }")
	w("nsRelayConformance   OBJECT IDENTIFIER ::= { nsRelayMIB 2 }")
	w("")
	parent := map[string]string{"1.1": "nsRelayStatus", "1.2": "nsRelayCounters", "1.6": "nsRelayEvent"}
	split := func(sub string) (string, string) {
		i := strings.LastIndex(sub, ".")
		return parent[sub[:i]], sub[i+1:]
	}
	var objects []string
	for _, s := range Scalars {
		p, n := split(s.Sub)
		w("%s OBJECT-TYPE", s.Name)
		w("    SYNTAX      %s", s.Syntax.MIB)
		w("    MAX-ACCESS  read-only")
		w("    STATUS      current")
		w("    DESCRIPTION \"%s\"", s.Desc)
		w("    ::= { %s %s }", p, n)
		w("")
		objects = append(objects, s.Name)
	}
	for _, t := range Tables {
		n := t.Sub[strings.LastIndex(t.Sub, ".")+1:]
		entryType := strings.ToUpper(t.Entry[:1]) + t.Entry[1:]
		w("%s OBJECT-TYPE", t.Name)
		w("    SYNTAX      SEQUENCE OF %s", entryType)
		w("    MAX-ACCESS  not-accessible")
		w("    STATUS      current")
		w("    DESCRIPTION \"%s\"", t.Desc)
		w("    ::= { nsRelayObjects %s }", n)
		w("")
		w("%s OBJECT-TYPE", t.Entry)
		w("    SYNTAX      %s", entryType)
		w("    MAX-ACCESS  not-accessible")
		w("    STATUS      current")
		w("    DESCRIPTION \"One row.\"")
		w("    INDEX       { %s }", t.Index.Name)
		w("    ::= { %s 1 }", t.Name)
		w("")
		cols := append([]Column{t.Index}, t.Columns...)
		w("%s ::= SEQUENCE {", entryType)
		for i, c := range cols {
			sep := ","
			if i == len(cols)-1 {
				sep = ""
			}
			typ := c.Syntax.MIB
			if j := strings.IndexAny(typ, " ("); j > 0 && !strings.HasPrefix(typ, "INTEGER") {
				typ = typ[:j]
			}
			if strings.HasPrefix(typ, "INTEGER") {
				typ = "INTEGER"
			}
			w("    %s %s%s", c.Name, typ, sep)
		}
		w("}")
		w("")
		for _, c := range cols {
			access := "read-only"
			if c.Get == nil {
				access = "not-accessible"
			}
			w("%s OBJECT-TYPE", c.Name)
			w("    SYNTAX      %s", c.Syntax.MIB)
			w("    MAX-ACCESS  %s", access)
			w("    STATUS      current")
			w("    DESCRIPTION \"%s\"", c.Desc)
			w("    ::= { %s %d }", t.Entry, c.Sub)
			w("")
			if c.Get != nil {
				objects = append(objects, c.Name)
			}
		}
	}
	var notifyObjs []string
	for _, o := range NotifyObjects {
		p, n := split(o.Sub)
		w("%s OBJECT-TYPE", o.Name)
		w("    SYNTAX      DisplayString")
		w("    MAX-ACCESS  accessible-for-notify")
		w("    STATUS      current")
		w("    DESCRIPTION \"%s\"", o.Desc)
		w("    ::= { %s %s }", p, n)
		w("")
		notifyObjs = append(notifyObjs, o.Name)
	}
	var notes []string
	for _, n := range Notifications {
		w("%s NOTIFICATION-TYPE", n.Name)
		w("    OBJECTS     { %s }", strings.Join(n.Objects, ", "))
		w("    STATUS      current")
		w("    DESCRIPTION \"%s\"", n.Desc)
		w("    ::= { nsRelayNotifications %s }", n.Sub[strings.LastIndex(n.Sub, ".")+1:])
		w("")
		notes = append(notes, n.Name)
	}
	w("nsRelayGroups      OBJECT IDENTIFIER ::= { nsRelayConformance 1 }")
	w("nsRelayCompliances OBJECT IDENTIFIER ::= { nsRelayConformance 2 }")
	w("")
	w("nsRelayObjectGroup OBJECT-GROUP")
	w("    OBJECTS     { %s }", strings.Join(append(objects, notifyObjs...), ",\n                  "))
	w("    STATUS      current")
	w("    DESCRIPTION \"All objects.\"")
	w("    ::= { nsRelayGroups 1 }")
	w("")
	w("nsRelayNotificationGroup NOTIFICATION-GROUP")
	w("    NOTIFICATIONS { %s }", strings.Join(notes, ", "))
	w("    STATUS      current")
	w("    DESCRIPTION \"All notifications.\"")
	w("    ::= { nsRelayGroups 2 }")
	w("")
	w("nsRelayCompliance MODULE-COMPLIANCE")
	w("    STATUS      current")
	w("    DESCRIPTION \"Everything is mandatory.\"")
	w("    MODULE      -- this module")
	w("    MANDATORY-GROUPS { nsRelayObjectGroup, nsRelayNotificationGroup }")
	w("    ::= { nsRelayCompliances 1 }")
	w("")
	w("END")
	return b.String()
}
