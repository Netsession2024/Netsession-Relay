package syslog

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netsession2024/Netsession-Relay/internal/notify"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func alarm() notify.Event {
	return notify.Event{Time: t0, Type: notify.TypeAlarm, State: "open", Severity: notify.Warn, Kind: "foreign_relay",
		Key: "1102", VLAN: 1102, Text: `Fremdes Relay aktiv: VLAN 1102 "x" ]`}
}

func TestFormat5424(t *testing.T) {
	got := Format5424(alarm(), "relay01", "local0")
	want := `<132>1 2026-11-16T12:00:00Z relay01 nsrelay `
	if !strings.HasPrefix(got, want) {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(got, ` alarm [nsrelay@32473 msgid="alarm" state="open" kind="foreign_relay" key="1102" vlan="1102"] Fremdes Relay aktiv`) {
		t.Errorf("structured data / msg: %q", got)
	}
	audit := notify.Event{Time: t0, Type: notify.TypeAudit, Severity: notify.Notice, Action: "game.enable", User: "alex",
		Object: `fl"at`, Text: "alex: Spiel eingeschaltet"}
	if got := Format5424(audit, "relay01", "daemon"); !strings.HasPrefix(got, "<29>1 ") || !strings.Contains(got, `object="fl\"at"`) {
		t.Errorf("audit: %q", got)
	}
}

func TestFormat3164(t *testing.T) {
	e := alarm()
	e.Text = strings.Repeat("x", 2000)
	got := Format3164(e, "relay01", "local7")
	if !strings.HasPrefix(got, "<188>") || len(got) != 1024 || !strings.Contains(got, " relay01 nsrelay[") {
		t.Errorf("3164: %d %q", len(got), got[:60])
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Transport: "udp", Format: "rfc5424", Facility: "local0"}
	if err := Validate("192.0.2.1:514", ok); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ep string
		c  Config
	}{
		{"192.0.2.1", ok},
		{"192.0.2.1:514", Config{Transport: "sctp", Format: "rfc5424", Facility: "local0"}},
		{"192.0.2.1:514", Config{Transport: "udp", Format: "json", Facility: "local0"}},
		{"192.0.2.1:514", Config{Transport: "udp", Format: "rfc5424", Facility: "local9"}},
		{"192.0.2.1:514", Config{Transport: "tls", Format: "rfc5424", Facility: "local0", TLSCA: "kein pem"}},
	} {
		if Validate(c.ep, c.c) == nil {
			t.Errorf("accepted %q %+v", c.ep, c.c)
		}
	}
}

func TestSendUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s, err := NewSender(pc.LocalAddr().String(), Config{Transport: "udp", Format: "rfc5424", Facility: "local0", Host: "relay01"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Reliable() {
		t.Error("udp reported reliable")
	}
	if err := s.Send(context.Background(), []notify.Event{alarm(), alarm()}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for i := 0; i < 2; i++ {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil || !strings.HasPrefix(string(buf[:n]), "<132>1 ") {
			t.Fatalf("datagram %d: %q %v", i, buf[:n], err)
		}
	}
}

func TestSendTCPReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					lines <- sc.Text()
				}
			}(c)
		}
	}()
	s, _ := NewSender(ln.Addr().String(), Config{Transport: "tcp", Format: "rfc3164", Facility: "local0", Host: "relay01"})
	defer s.Close()
	if err := s.Send(context.Background(), []notify.Event{alarm()}); err != nil {
		t.Fatal(err)
	}
	if l := <-lines; !strings.HasPrefix(l, "<132>") {
		t.Errorf("tcp line %q", l)
	}
	// the server side drops the connection; the next send fails or reconnects, the one after must work
	s.mu.Lock()
	_ = s.conn.Close()
	s.mu.Unlock()
	_ = s.Send(context.Background(), []notify.Event{alarm()})
	if err := s.Send(context.Background(), []notify.Event{alarm()}); err != nil {
		t.Fatalf("after reconnect: %v", err)
	}
	select {
	case <-lines:
	case <-time.After(2 * time.Second):
		t.Error("nothing after reconnect")
	}
}

func TestSendTLS(t *testing.T) {
	certPEM, cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		lenStr, _ := r.ReadString(' ')
		n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
		buf := make([]byte, n)
		_, _ = io_ReadFull(r, buf)
		got <- string(buf)
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s, err := NewSender("localhost:"+port, Config{Transport: "tls", Format: "rfc5424", Facility: "local0", TLSCA: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), []notify.Event{alarm()}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if !strings.HasPrefix(m, "<132>1 ") || !strings.HasSuffix(m, `"x" ]`) {
			t.Errorf("tls message %q", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing received over TLS")
	}
	// wrong CA: refused
	other, _ := selfSigned(t)
	bad, _ := NewSender("localhost:"+port, Config{Transport: "tls", Format: "rfc5424", Facility: "local0", TLSCA: other})
	defer bad.Close()
	if err := bad.Send(context.Background(), []notify.Event{alarm()}); err == nil {
		t.Error("certificate of an unknown CA accepted")
	}
}

func io_ReadFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func selfSigned(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	cert, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, cert
}
