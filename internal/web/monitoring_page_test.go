package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMonitoringPageTargets(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	sink := newSink(t)
	admin, csrf := e.client("admin")
	post := func(path string, v url.Values) (int, string, string) {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := admin.PostForm(e.srv.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, r.Request.URL.RawQuery, string(b)
	}
	if code, page := get(t, admin, e.srv.URL+"/system/monitoring"); code != 200 || !strings.Contains(page, "Noch kein Ziel") {
		t.Fatalf("monitoring page %d", code)
	}
	if code, page := get(t, admin, e.srv.URL+"/system/monitoring/ziel/neu?art=otlp"); code != 200 || !strings.Contains(page, `name="protocol"`) {
		t.Fatalf("otlp form %d", code)
	}
	// syslog over UDP
	code, _, _ := post("/system/monitoring/ziel", url.Values{"kind": {"syslog"}, "name": {"rsyslog"}, "endpoint": {sink.addr()},
		"transport": {"udp"}, "format": {"rfc5424"}, "facility": {"local3"}, "alarm": {"1"}, "audit": {"1"}, "enabled": {"1"}})
	if code != 200 {
		t.Fatalf("save syslog = %d", code)
	}
	ts, _ := e.st.Targets(ctx)
	if len(ts) != 1 || ts[0].Config["facility"] != "local3" {
		t.Fatalf("targets %+v", ts)
	}
	_, q, _ := post(fmt.Sprintf("/system/monitoring/ziel/%d/test", ts[0].ID), url.Values{})
	if strings.Contains(q, "fehler") {
		t.Fatalf("test: %s", q)
	}
	if m := sink.next(t, "Testmeldung von admin"); !strings.HasPrefix(m, "<158>1 ") { // local3 info
		t.Errorf("test message %q", m)
	}
	// OTLP with a header; the header value never appears in the page
	code, _, body := post("/system/monitoring/ziel", url.Values{"kind": {"otlp"}, "name": {"Zabbix APM"}, "endpoint": {"192.0.2.10"},
		"protocol": {"grpc"}, "metrics": {"1"}, "logs": {"1"}, "alarm": {"1"}, "enabled": {"1"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Adresse:Port") {
		t.Errorf("otlp without port = %d", code)
	}
	code, _, _ = post("/system/monitoring/ziel", url.Values{"kind": {"otlp"}, "name": {"Zabbix APM"}, "endpoint": {"192.0.2.10:4317"},
		"protocol": {"grpc"}, "metrics": {"1"}, "logs": {"1"}, "alarm": {"1"}, "enabled": {"0"}, "interval_s": {"60"},
		"headers": {"Authorization: Bearer streng-geheim"}})
	if code != 200 {
		t.Fatalf("save otlp = %d", code)
	}
	_, page := get(t, admin, e.srv.URL+"/system/monitoring")
	if strings.Contains(page, "streng-geheim") || !strings.Contains(page, "Zabbix APM") {
		t.Error("secret shown or target missing")
	}
	ts, _ = e.st.Targets(ctx)
	var otlpID int64
	for _, x := range ts {
		if x.Name == "Zabbix APM" {
			otlpID = x.ID
			if x.Secret["header:Authorization"] != "Bearer streng-geheim" || x.Enabled {
				t.Errorf("stored otlp %+v", x)
			}
		}
	}
	_, form := get(t, admin, fmt.Sprintf("%s/system/monitoring/ziel/%d", e.srv.URL, otlpID))
	if strings.Contains(form, "streng-geheim") || !strings.Contains(form, "Authorization") {
		t.Error("edit form shows the secret or not the header name")
	}
	// audit never contains the secret
	audit, _ := e.st.AuditLog(ctx, 20)
	for _, a := range audit {
		if strings.Contains(a.Before+a.After, "streng-geheim") {
			t.Errorf("secret in audit %s", a.Action)
		}
	}
	post(fmt.Sprintf("/system/monitoring/ziel/%d/loeschen", otlpID), url.Values{})
	if ts, _ := e.st.Targets(ctx); len(ts) != 1 {
		t.Errorf("%d targets after delete", len(ts))
	}
	op, _ := e.client("op")
	if code, _ := get(t, op, e.srv.URL+"/system/monitoring"); code != http.StatusForbidden {
		t.Errorf("operator monitoring page = %d", code)
	}
}

func TestSNMPTrapTarget(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin, csrf := e.client("admin")
	post := func(v url.Values) (int, string) {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := admin.PostForm(e.srv.URL+"/system/monitoring/ziel", v)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	base := url.Values{"kind": {"snmptrap"}, "name": {"NMS"}, "endpoint": {"192.0.2.20:162"}, "version": {"v3"}, "user": {"relay"},
		"auth_proto": {"sha256"}, "priv_proto": {"aes128"}, "alarm": {"1"}, "enabled": {"0"}}
	v := url.Values{}
	for k, x := range base {
		v[k] = x
	}
	v.Set("auth_pass", "kurz")
	v.Set("priv_pass", "kurz")
	if code, body := post(v); code != http.StatusUnprocessableEntity || !strings.Contains(body, "mindestens 8") {
		t.Errorf("short v3 passwords = %d", code)
	}
	v.Set("auth_pass", "authpass123")
	v.Set("priv_pass", "privpass123")
	if code, _ := post(v); code != 200 {
		t.Fatalf("save trap = %d", code)
	}
	ts, _ := e.st.Targets(ctx)
	if len(ts) != 1 || ts[0].Secret["auth_pass"] != "authpass123" || ts[0].Config["user"] != "relay" {
		t.Fatalf("stored %+v", ts)
	}
	// edit without passwords keeps them
	v.Set("id", fmt.Sprint(ts[0].ID))
	v.Set("auth_pass", "")
	v.Set("priv_pass", "")
	if code, _ := post(v); code != 200 {
		t.Fatal("edit without passwords refused")
	}
	if tt, _ := e.st.Target(ctx, ts[0].ID); tt.Secret["priv_pass"] != "privpass123" {
		t.Error("password lost on edit")
	}
	_, form := get(t, admin, fmt.Sprintf("%s/system/monitoring/ziel/%d", e.srv.URL, ts[0].ID))
	if strings.Contains(form, "authpass123") || !strings.Contains(form, "gesetzt, leer lassen") {
		t.Error("form shows the password or not that it is set")
	}
	if code, mib := get(t, admin, e.srv.URL+"/system/monitoring/mib"); code != 200 || !strings.HasPrefix(mib, "NETSESSION-RELAY-MIB DEFINITIONS") {
		t.Errorf("mib download %d", code)
	}
}
