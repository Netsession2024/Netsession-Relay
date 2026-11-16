package snmp

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

// The MIB file in the repository is generated from the object list; both must agree.
func TestMIBFileUpToDate(t *testing.T) {
	want := MIB()
	got, err := os.ReadFile("../../deploy/snmp/NETSESSION-RELAY-MIB.txt")
	if err != nil {
		t.Fatalf("%v (generate with `nsrelay snmp-mib > deploy/snmp/NETSESSION-RELAY-MIB.txt`)", err)
	}
	if string(got) != want {
		t.Error("deploy/snmp/NETSESSION-RELAY-MIB.txt is outdated: regenerate with `nsrelay snmp-mib`")
	}
	// every object, column, notify object and notification is declared
	for _, s := range Scalars {
		if !strings.Contains(want, s.Name+" OBJECT-TYPE") {
			t.Errorf("%s missing", s.Name)
		}
	}
	for _, n := range Notifications {
		if !strings.Contains(want, n.Name+" NOTIFICATION-TYPE") {
			t.Errorf("%s missing", n.Name)
		}
	}
}

func listen(t *testing.T, params *gosnmp.GoSNMP) (string, chan *gosnmp.SnmpPacket) {
	t.Helper()
	got := make(chan *gosnmp.SnmpPacket, 10)
	tl := gosnmp.NewTrapListener()
	tl.Params = params
	tl.OnNewTrap = func(p *gosnmp.SnmpPacket, _ *net.UDPAddr) { got <- p }
	// pick a free port
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tl.Listen(addr)
	}()
	select {
	case <-tl.Listening():
	case <-time.After(2 * time.Second):
		t.Fatal("trap listener did not start")
	}
	t.Cleanup(func() { tl.Close(); wg.Wait() })
	return addr, got
}

func varbind(p *gosnmp.SnmpPacket, oid string) any {
	for _, v := range p.Variables {
		if v.Name == "."+oid || v.Name == oid {
			if b, ok := v.Value.([]byte); ok {
				return string(b)
			}
			return v.Value
		}
	}
	return nil
}

var alarm = notify.Event{Type: notify.TypeAlarm, State: "open", Kind: "foreign_relay", Key: "1102", VLAN: 1102, Text: "Fremdes Relay aktiv"}

func TestTrapV2c(t *testing.T) {
	addr, got := listen(t, &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "public", Timeout: time.Second})
	s, err := NewTrapSender(addr, TrapConfig{Version: "v2c", Community: "public"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), []notify.Event{alarm, {Type: notify.TypeTest, User: "admin", Text: "Test"}}); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{OID("0.1"), OID("0.4")} {
		select {
		case p := <-got:
			if trap := varbind(p, "1.3.6.1.6.3.1.1.4.1.0"); trap != "."+want {
				t.Errorf("trap %d: snmpTrapOID = %v, want .%s", i, trap, want)
			}
			if i == 0 && (varbind(p, notifyOID("nsRelayEventKind")) != "foreign_relay" || varbind(p, notifyOID("nsRelayEventVlan")) != "1102") {
				t.Errorf("varbinds %v", p.Variables)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("trap %d not received", i)
		}
	}
}

func TestTrapV3(t *testing.T) {
	eid := NewEngineID()
	cfg := TrapConfig{Version: "v3", User: "relay", AuthProto: "sha256", AuthPass: "authpass123", PrivProto: "aes128", PrivPass: "privpass123", EngineID: eid, Boots: 1}
	addr, got := listen(t, &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		Timeout: time.Second, SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "relay", AuthenticationProtocol: gosnmp.SHA256,
			AuthenticationPassphrase: "authpass123", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123",
			AuthoritativeEngineID: string(mustHex(eid))}})
	s, err := NewTrapSender(addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), []notify.Event{alarm}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if varbind(p, notifyOID("nsRelayEventText")) != "Fremdes Relay aktiv" {
			t.Errorf("v3 varbinds %v", p.Variables)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("v3 trap not received/decrypted")
	}
}

func TestValidateTrap(t *testing.T) {
	for _, c := range []struct {
		ep string
		c  TrapConfig
	}{
		{"192.0.2.1", TrapConfig{Version: "v2c", Community: "x"}},
		{"192.0.2.1:162", TrapConfig{Version: "v2c"}},
		{"192.0.2.1:162", TrapConfig{Version: "v3", User: "u", AuthPass: "kurz", PrivPass: "kurz"}},
		{"192.0.2.1:162", TrapConfig{Version: "v1", Community: "x"}},
	} {
		if ValidateTrap(c.ep, c.c) == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	if len(NewEngineID()) != 26 || !strings.HasPrefix(NewEngineID(), "80007ed905") {
		t.Errorf("engine id %s", NewEngineID())
	}
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}

func TestZabbixTemplateUpToDate(t *testing.T) {
	want := ZabbixTemplate()
	got, err := os.ReadFile("../../deploy/zabbix/template_nsrelay_snmp.yaml")
	if err != nil || string(got) != want {
		t.Fatalf("deploy/zabbix/template_nsrelay_snmp.yaml outdated: regenerate with `nsrelay snmp-mib -zabbix` (%v)", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`uuid: ([0-9a-f]{32})`).FindAllStringSubmatch(want, -1) {
		if m[1][12] != '4' || !strings.ContainsRune("89ab", rune(m[1][16])) || seen[m[1]] {
			t.Errorf("uuid %s not v4 or duplicate", m[1])
		}
		seen[m[1]] = true
	}
	// the template group uuid matches the HTTP template (shared group)
	http, _ := os.ReadFile("../../deploy/zabbix/template_nsrelay.yaml")
	if !strings.Contains(string(http), zuuid("group:Templates/Applications")) {
		t.Error("group uuid differs from the HTTP template")
	}
}
