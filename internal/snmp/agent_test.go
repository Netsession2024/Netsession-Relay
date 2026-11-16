package snmp

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/Netsession2024/Netsession-Relay/internal/engineapi"
	"github.com/Netsession2024/Netsession-Relay/internal/monitor"
)

func freeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func startTestAgent(t *testing.T, c AgentConfig) string {
	t.Helper()
	c.Listen = freeUDP(t)
	rep, _ := reportForTest()
	a, err := StartAgent(c, func() *View { return &View{Report: rep, OutputsFailing: 1} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return c.Listen
}

func client(t *testing.T, addr string, g *gosnmp.GoSNMP) *gosnmp.GoSNMP {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	g.Target, g.Port, g.Timeout, g.Retries = host, uint16(p), 700*time.Millisecond, 0
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Conn.Close() })
	return g
}

func TestAgentV2c(t *testing.T) {
	addr := startTestAgent(t, AgentConfig{V2c: true, Community: "ns-read", SysName: "relay01", SysDescr: "Netsession Relay test"})
	g := client(t, addr, &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "ns-read"})
	r, err := g.Get([]string{".1.3.6.1.2.1.1.5.0", "." + OID("1.1.5.0"), "." + OID("1.1.14.0"), ".1.3.6.1.2.1.1.99.0"})
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Variables[0].Value.([]byte)) != "relay01" || r.Variables[1].Value.(int) != 1 || gosnmp.ToBigInt(r.Variables[2].Value).Int64() != 1 ||
		r.Variables[3].Type != gosnmp.NoSuchObject {
		t.Errorf("get %+v", r.Variables)
	}
	// full walk of our tree: ordered, contains the VLAN table rows
	var oids []string
	err = g.BulkWalk("."+Base, func(p gosnmp.SnmpPDU) error {
		oids = append(oids, p.Name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(oids) < len(Scalars)+20 || !strings.HasSuffix(oids[0], ".1.1.1.0") || !contains(oids, "."+OID("1.5.1.2.1101")) {
		t.Errorf("walk returned %d oids, first %v", len(oids), oids[:min(3, len(oids))])
	}
	for i := 1; i < len(oids); i++ {
		if !less(parseOID(oids[i-1]), parseOID(oids[i])) {
			t.Fatalf("walk not ordered at %s, %s", oids[i-1], oids[i])
		}
	}
	// SET is refused
	if r, err := g.Set([]gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "x"}}); err != nil || r.Error != gosnmp.NotWritable {
		t.Errorf("set: %v %v", r, err)
	}
	// wrong community: no answer at all
	bad := client(t, addr, &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "public"})
	if _, err := bad.Get([]string{".1.3.6.1.2.1.1.5.0"}); err == nil {
		t.Error("wrong community answered")
	}
}

func TestAgentV3(t *testing.T) {
	eid := NewEngineID()
	addr := startTestAgent(t, AgentConfig{V3User: "monitor", AuthProto: "sha256", AuthPass: "authpass123", PrivProto: "aes128",
		PrivPass: "privpass123", EngineID: eid, Boots: 3, SysName: "relay01"})
	g := client(t, addr, &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "monitor", AuthenticationProtocol: gosnmp.SHA256,
			AuthenticationPassphrase: "authpass123", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"}})
	r, err := g.Get([]string{".1.3.6.1.2.1.1.5.0", "." + OID("1.2.1.0")})
	if err != nil {
		t.Fatalf("v3 get: %v", err)
	}
	if string(r.Variables[0].Value.([]byte)) != "relay01" || gosnmp.ToBigInt(r.Variables[1].Value).Int64() != 1000 {
		t.Errorf("v3 values %+v", r.Variables)
	}
	wrong := client(t, addr, &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "monitor", AuthenticationProtocol: gosnmp.SHA256,
			AuthenticationPassphrase: "falsch12345", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"}})
	if _, err := wrong.Get([]string{".1.3.6.1.2.1.1.5.0"}); err == nil {
		t.Error("wrong v3 password answered")
	}
	// v2c is off in this config
	v2 := client(t, addr, &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "public"})
	if _, err := v2.Get([]string{".1.3.6.1.2.1.1.5.0"}); err == nil {
		t.Error("v2c answered although off")
	}
}

func TestValidateAgent(t *testing.T) {
	for _, c := range []AgentConfig{
		{Listen: "0.0.0.0:161", V2c: true, Community: "x"},
		{Listen: "192.0.2.1:161"},
		{Listen: "192.0.2.1:161", V2c: true},
		{Listen: "192.0.2.1:161", V3User: "u", AuthPass: "kurz", PrivPass: "kurz"},
	} {
		if ValidateAgent(c) == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func less(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func reportForTest() (monitor.Report, []engineapi.RuleStat) {
	now := time.Now()
	st := engineapi.Status{Version: "1.2.3", Started: now.Add(-time.Hour), Mode: "active", Sending: true, VLANs: 2, Rules: 3, RX: 1000, Sent: 4000,
		Reasons: map[string]uint64{"unknown_port": 7},
		VLANStats: []engineapi.VLANStat{{VID: 1101, Name: "Tisch 1", Group: "tische", In: 500, Out: 2000, LastIn: now},
			{VID: 1102, Name: "Tisch 2", Group: "tische", In: 500, Out: 2000, LastIn: now}}}
	return monitor.Build(st, nil, "web", true, now), nil
}
