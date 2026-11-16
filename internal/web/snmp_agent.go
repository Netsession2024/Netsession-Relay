package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Netsession2024/Netsession-Relay/internal/snmp"
)

// SNMP agent (read-only) of the web role. Configuration in the settings snmp_agent (JSON) and
// snmp_agent_secret (JSON: community, auth_pass, priv_pass; in the database and therefore in the backup,
// decision E4, never shown in the UI).

const (
	settingSNMPAgent       = "snmp_agent"
	settingSNMPAgentSecret = "snmp_agent_secret"
)

type agentSettings struct {
	Enabled   bool     `json:"enabled"`
	Port      int      `json:"port"`
	V2c       bool     `json:"v2c"`
	User      string   `json:"v3_user"`
	AuthProto string   `json:"auth_proto"`
	PrivProto string   `json:"priv_proto"`
	Allow     []string `json:"allow"`
	Contact   string   `json:"contact"`
	Location  string   `json:"location"`
}

type agentSecret struct {
	Community string `json:"community"`
	AuthPass  string `json:"auth_pass"`
	PrivPass  string `json:"priv_pass"`
}

func (s *Server) agentSettings(ctx context.Context) (agentSettings, agentSecret) {
	a := agentSettings{Port: 161, AuthProto: "sha256", PrivProto: "aes128"}
	var sec agentSecret
	if v, _ := s.Store.Setting(ctx, settingSNMPAgent, ""); v != "" {
		_ = json.Unmarshal([]byte(v), &a)
	}
	if v, _ := s.Store.Setting(ctx, settingSNMPAgentSecret, ""); v != "" {
		_ = json.Unmarshal([]byte(v), &sec)
	}
	return a, sec
}

// agentHost is the address the agent binds: NSRELAY_SNMP_ADDR or the MGMT address of the web part.
func (s *Server) agentHost() netip.Addr {
	if a, err := netip.ParseAddr(s.SNMPAddr); err == nil && !a.IsUnspecified() {
		return a
	}
	return s.BindAddr
}

// restartAgent stops a running agent and starts it again with the stored settings.
func (s *Server) restartAgent(ctx context.Context) {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if s.agent != nil {
		s.agent.Close()
		s.agent = nil
	}
	s.agentErr = ""
	a, sec := s.agentSettings(ctx)
	if !a.Enabled {
		return
	}
	host := s.agentHost()
	if !host.IsValid() {
		s.agentErr = "Keine MGMT-Adresse bekannt (NSRELAY_HTTP_ADDR ist 0.0.0.0 oder localhost), der Agent startet nicht."
		return
	}
	eid, boots := s.snmpEngine(ctx)
	c := snmp.AgentConfig{Listen: net.JoinHostPort(host.String(), strconv.Itoa(a.Port)), V2c: a.V2c, Community: sec.Community,
		V3User: a.User, AuthProto: a.AuthProto, AuthPass: sec.AuthPass, PrivProto: a.PrivProto, PrivPass: sec.PrivPass,
		EngineID: eid, Boots: boots, SysDescr: "Netsession Relay " + s.Version, SysName: s.hostName(ctx), Contact: a.Contact, Location: a.Location}
	for _, p := range a.Allow {
		if pfx, err := netip.ParsePrefix(p); err == nil {
			c.Allow = append(c.Allow, pfx)
		}
	}
	ag, err := snmp.StartAgent(c, func() *snmp.View {
		rep, _ := s.monitorReport(context.Background())
		return &snmp.View{Report: rep, OutputsFailing: rep.OutputsFailing}
	})
	if err != nil {
		s.agentErr = err.Error()
		if strings.Contains(err.Error(), "permission denied") {
			s.agentErr = fmt.Sprintf("Port %d ist auf diesem Host nicht freigegeben. Nimm 1161 oder führe setup.sh neu aus (sysctl net.ipv4.ip_unprivileged_port_start=161).", a.Port)
		}
		s.Log.Warn("snmp agent", "err", err)
		return
	}
	s.agent = ag
}

// agentStatus is shown on the monitoring page.
func (s *Server) agentStatus() (running bool, listen, errText string) {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if s.agent != nil {
		a, _ := s.agentSettings(context.Background())
		return true, net.JoinHostPort(s.agentHost().String(), strconv.Itoa(a.Port)), ""
	}
	return false, "", s.agentErr
}

// CloseAgent stops the SNMP agent (shutdown).
func (s *Server) CloseAgent() {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if s.agent != nil {
		s.agent.Close()
		s.agent = nil
	}
}

func (s *Server) agentSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	cur, curSec := s.agentSettings(ctx)
	a := agentSettings{Enabled: v("enabled") == "1", V2c: v("v2c") == "1", User: v("user"), AuthProto: v("auth_proto"),
		PrivProto: v("priv_proto"), Contact: v("contact"), Location: v("location")}
	a.Port, _ = strconv.Atoi(v("port"))
	if a.Port < 1 || a.Port > 65535 {
		back(w, r, "/system/monitoring#snmp", "", errors.New("Port bitte zwischen 1 und 65535 (Standard 161)."))
		return
	}
	for _, p := range strings.FieldsFunc(v("allow"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			if ad, err2 := netip.ParseAddr(p); err2 == nil {
				pfx = netip.PrefixFrom(ad, ad.BitLen())
			} else {
				back(w, r, "/system/monitoring", "", fmt.Errorf("Erlaubte Absender: %q ist keine Adresse oder kein Netz.", p))
				return
			}
		}
		a.Allow = append(a.Allow, pfx.String())
	}
	sec := curSec
	if x := r.PostFormValue("community"); x != "" {
		sec.Community = x
	}
	if x := r.PostFormValue("auth_pass"); x != "" {
		sec.AuthPass = x
	}
	if x := r.PostFormValue("priv_pass"); x != "" {
		sec.PrivPass = x
	}
	if a.Enabled {
		c := snmp.AgentConfig{Listen: "192.0.2.1:" + strconv.Itoa(a.Port), V2c: a.V2c, Community: sec.Community, V3User: a.User,
			AuthProto: a.AuthProto, AuthPass: sec.AuthPass, PrivProto: a.PrivProto, PrivPass: sec.PrivPass}
		if err := snmp.ValidateAgent(c); err != nil {
			back(w, r, "/system/monitoring", "", errors.New(germanAgentError(err)))
			return
		}
	}
	b, _ := json.Marshal(a)
	bs, _ := json.Marshal(sec)
	if err := s.Store.SetSetting(ctx, settingSNMPAgent, string(b)); err != nil {
		back(w, r, "/system/monitoring", "", err)
		return
	}
	_ = s.Store.SetSetting(ctx, settingSNMPAgentSecret, string(bs))
	before, _ := json.Marshal(cur)
	_ = s.Store.Audit(ctx, s.actor(r), "snmp.agent.set", "snmp", string(before), string(b))
	s.restartAgent(ctx)
	running, listen, errText := s.agentStatus()
	switch {
	case errText != "":
		back(w, r, "/system/monitoring", "", errors.New("SNMP-Agent: "+errText))
	case running:
		back(w, r, "/system/monitoring", "SNMP-Agent läuft auf "+listen+".", nil)
	default:
		back(w, r, "/system/monitoring", "SNMP-Agent ist aus.", nil)
	}
}

func germanAgentError(err error) string {
	e := err.Error()
	switch {
	case strings.Contains(e, "neither v2c nor v3"):
		return "Bitte v3 (Benutzer) oder v2c (Community) einrichten."
	case strings.Contains(e, "community missing"):
		return "Bitte die Community für v2c eintragen."
	case strings.Contains(e, "at least 8"):
		return "Die SNMPv3-Passwörter brauchen mindestens 8 Zeichen."
	}
	return "SNMP: " + e
}

// agentForm is the view of the SNMP section.
func (s *Server) agentForm(ctx context.Context) map[string]any {
	a, sec := s.agentSettings(ctx)
	running, listen, errText := s.agentStatus()
	return map[string]any{"S": a, "Allow": strings.Join(a.Allow, ", "), "CommunitySet": sec.Community != "",
		"AuthSet": sec.AuthPass != "", "PrivSet": sec.PrivPass != "", "Running": running, "Listen": listen, "Err": errText,
		"Host": s.agentHost().String(), "HostValid": s.agentHost().IsValid()}
}
