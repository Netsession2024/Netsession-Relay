package snmp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// The agent answers GET, GETNEXT and GETBULK read-only (SET: notWritable) for the system group and the relay
// tree. Receiving, v3 authentication/decryption and engine discovery reports come from gosnmp's
// TrapListener; this file only resolves the variables (docs/05-monitoring-konzept.md, 5.3-5.6).

// AgentConfig of the SNMP agent.
type AgentConfig struct {
	Listen    string // host:port, MGMT address only
	V2c       bool
	Community string
	V3User    string
	AuthProto string
	AuthPass  string
	PrivProto string
	PrivPass  string
	EngineID  string // hex
	Boots     uint32
	Allow     []netip.Prefix // empty = every source
	SysDescr  string
	SysName   string
	Contact   string
	Location  string
}

// ValidateAgent checks the configuration (at least one of v2c and v3).
func ValidateAgent(c AgentConfig) error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return fmt.Errorf("listen address %q", c.Listen)
	}
	if a, err := netip.ParseAddr(host); err != nil || a.IsUnspecified() {
		return errors.New("listen address must be the MGMT address, not 0.0.0.0")
	}
	if !c.V2c && c.V3User == "" {
		return errors.New("neither v2c nor v3 configured")
	}
	if c.V2c && c.Community == "" {
		return errors.New("community missing")
	}
	if c.V3User != "" {
		if _, err := authProto(c.AuthProto); err != nil {
			return err
		}
		if _, err := privProto(c.PrivProto); err != nil {
			return err
		}
		if len(c.AuthPass) < 8 || len(c.PrivPass) < 8 {
			return errors.New("v3 passwords: at least 8 characters")
		}
	}
	return nil
}

type entry struct {
	oid []int
	pdu gosnmp.SnmpPDU
}

// Agent is a running SNMP agent.
type Agent struct {
	c     AgentConfig
	view  func() *View
	start time.Time
	tl    *gosnmp.TrapListener
	done  chan struct{}

	mu       sync.Mutex
	cache    []entry
	cachedAt time.Time

	rateMu sync.Mutex
	rate   map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	maxRepetitions = 50
	maxResponse    = 1400 // bytes of variable values, keeps GETBULK from amplifying
	ratePerSource  = 50   // requests per second
)

func parseOID(s string) []int {
	parts := strings.Split(strings.TrimPrefix(s, "."), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func oidString(o []int) string {
	var b strings.Builder
	for _, n := range o {
		b.WriteByte('.')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// StartAgent binds the UDP socket and serves until Close.
func StartAgent(c AgentConfig, view func() *View) (*Agent, error) {
	if err := ValidateAgent(c); err != nil {
		return nil, err
	}
	a := &Agent{c: c, view: view, start: time.Now(), done: make(chan struct{}), rate: map[netip.Addr]*bucket{}}
	params := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Timeout: 2 * time.Second, Logger: gosnmp.NewLogger(log.New(io.Discard, "", 0))}
	if c.V3User != "" {
		ap, _ := authProto(c.AuthProto)
		pp, _ := privProto(c.PrivProto)
		eid, _ := hex.DecodeString(c.EngineID)
		params.Version, params.SecurityModel, params.MsgFlags = gosnmp.Version3, gosnmp.UserSecurityModel, gosnmp.AuthPriv
		params.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: c.V3User, AuthenticationProtocol: ap,
			AuthenticationPassphrase: c.AuthPass, PrivacyProtocol: pp, PrivacyPassphrase: c.PrivPass,
			AuthoritativeEngineID: string(eid), AuthoritativeEngineBoots: c.Boots}
	}
	tl := gosnmp.NewTrapListener()
	tl.Params = params
	tl.OnNewTrap = a.handle
	a.tl = tl
	errc := make(chan error, 1)
	go func() {
		defer close(a.done)
		errc <- tl.Listen(c.Listen)
	}()
	select {
	case <-tl.Listening():
		return a, nil
	case err := <-errc:
		if err == nil {
			err = errors.New("listener stopped")
		}
		return nil, err
	case <-time.After(3 * time.Second):
		tl.Close()
		return nil, errors.New("SNMP listener did not start")
	}
}

// Close stops the agent.
func (a *Agent) Close() {
	a.tl.Close()
	<-a.done
}

func (a *Agent) allowed(src netip.Addr) bool {
	if len(a.c.Allow) > 0 && !slices.ContainsFunc(a.c.Allow, func(p netip.Prefix) bool { return p.Contains(src) }) {
		return false
	}
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	now := time.Now()
	b := a.rate[src]
	if b == nil {
		if len(a.rate) > 1024 { // forget old sources
			clear(a.rate)
		}
		b = &bucket{tokens: ratePerSource, last: now}
		a.rate[src] = b
	}
	b.tokens = min(ratePerSource, b.tokens+now.Sub(b.last).Seconds()*ratePerSource)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// table returns all variables sorted by OID (cached for 5 s: one engine query for any number of requests).
func (a *Agent) table() []entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache != nil && time.Since(a.cachedAt) < 5*time.Second {
		return a.cache
	}
	v := a.view()
	var es []entry
	add := func(oid string, typ gosnmp.Asn1BER, val any) {
		es = append(es, entry{oid: parseOID(oid), pdu: gosnmp.SnmpPDU{Name: "." + strings.TrimPrefix(oid, "."), Type: typ, Value: val}})
	}
	sys := "1.3.6.1.2.1.1."
	add(sys+"1.0", gosnmp.OctetString, a.c.SysDescr)
	add(sys+"2.0", gosnmp.ObjectIdentifier, "."+Base)
	add(sys+"3.0", gosnmp.TimeTicks, uint32(time.Since(a.start)/(10*time.Millisecond)))
	add(sys+"4.0", gosnmp.OctetString, a.c.Contact)
	add(sys+"5.0", gosnmp.OctetString, a.c.SysName)
	add(sys+"6.0", gosnmp.OctetString, a.c.Location)
	add(sys+"7.0", gosnmp.Integer, 72)
	for _, s := range Scalars {
		add(OID(s.Sub)+".0", s.Syntax.BER, s.Get(v))
	}
	for _, t := range Tables {
		rows := t.Rows(v)
		for _, c := range t.Columns {
			for _, r := range rows {
				add(fmt.Sprintf("%s.1.%d.%d", OID(t.Sub), c.Sub, r.Index), c.Syntax.BER, c.Get(r.Row))
			}
		}
	}
	slices.SortFunc(es, func(x, y entry) int { return slices.Compare(x.oid, y.oid) })
	a.cache, a.cachedAt = es, time.Now()
	return es
}

func (a *Agent) get(es []entry, oid []int) gosnmp.SnmpPDU {
	i, found := slices.BinarySearchFunc(es, oid, func(e entry, o []int) int { return slices.Compare(e.oid, o) })
	if found {
		return es[i].pdu
	}
	return gosnmp.SnmpPDU{Name: oidString(oid), Type: gosnmp.NoSuchObject}
}

func (a *Agent) next(es []entry, oid []int) gosnmp.SnmpPDU {
	i, found := slices.BinarySearchFunc(es, oid, func(e entry, o []int) int { return slices.Compare(e.oid, o) })
	if found {
		i++
	}
	if i >= len(es) {
		return gosnmp.SnmpPDU{Name: oidString(oid), Type: gosnmp.EndOfMibView}
	}
	return es[i].pdu
}

func pduSize(p gosnmp.SnmpPDU) int {
	n := len(p.Name) + 8
	if s, ok := p.Value.(string); ok {
		n += len(s)
	}
	return n
}

func (a *Agent) handle(p *gosnmp.SnmpPacket, remote *net.UDPAddr) {
	src, _ := netip.AddrFromSlice(remote.IP)
	if !a.allowed(src.Unmap()) {
		return
	}
	switch p.Version {
	case gosnmp.Version2c, gosnmp.Version1:
		if !a.c.V2c || p.Community != a.c.Community {
			return // wrong community: no answer
		}
	case gosnmp.Version3:
		if a.c.V3User == "" {
			return
		}
		if sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			sp.AuthoritativeEngineBoots = a.c.Boots
			sp.AuthoritativeEngineTime = uint32(time.Since(a.start).Seconds())
		}
	default:
		return
	}
	es := a.table()
	resp := *p
	resp.PDUType = gosnmp.GetResponse
	resp.Error, resp.ErrorIndex = gosnmp.NoError, 0
	var out []gosnmp.SnmpPDU
	switch p.PDUType {
	case gosnmp.GetRequest:
		for _, v := range p.Variables {
			out = append(out, a.get(es, parseOID(v.Name)))
		}
	case gosnmp.GetNextRequest:
		for _, v := range p.Variables {
			out = append(out, a.next(es, parseOID(v.Name)))
		}
	case gosnmp.GetBulkRequest:
		nonRep := min(int(p.NonRepeaters), len(p.Variables))
		for _, v := range p.Variables[:nonRep] {
			out = append(out, a.next(es, parseOID(v.Name)))
		}
		reps := min(int(p.MaxRepetitions), maxRepetitions)
		size := 0
		cursors := make([][]int, 0, len(p.Variables)-nonRep)
		for _, v := range p.Variables[nonRep:] {
			cursors = append(cursors, parseOID(v.Name))
		}
	bulk:
		for r := 0; r < reps && len(cursors) > 0; r++ {
			for i, c := range cursors {
				pdu := a.next(es, c)
				size += pduSize(pdu)
				if size > maxResponse && len(out) > 0 {
					break bulk
				}
				out = append(out, pdu)
				cursors[i] = parseOID(pdu.Name)
			}
		}
		resp.NonRepeaters, resp.MaxRepetitions = 0, 0
	case gosnmp.SetRequest:
		resp.Error, resp.ErrorIndex = gosnmp.NotWritable, 1
		out = p.Variables
	default:
		return
	}
	resp.Variables = out
	_ = a.tl.SendUDP(&resp, remote)
}
