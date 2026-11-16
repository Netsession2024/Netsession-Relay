package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestServiceHosts(t *testing.T) {
	e := setup(t)
	admin, csrf := e.client("admin")
	_, page := get(t, admin, e.srv.URL+"/spieler")
	if strings.Contains(page, "Dienst?") {
		t.Fatal("a sender in one game is offered as service")
	}
	if _, form := get(t, admin, e.srv.URL+"/system?dienst=10.10.1.10"); !strings.Contains(form, `value="10.10.1.10"`) {
		t.Error("system form not prefilled")
	}
	post := func(path string, v url.Values) string {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := admin.PostForm(e.srv.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.Request.URL.RawQuery
	}
	if q := post("/system/dienste", url.Values{"ip": {"kein.ip"}, "name": {"x"}}); !strings.Contains(q, "fehler") {
		t.Error("invalid address accepted")
	}
	post("/system/dienste", url.Values{"ip": {"10.10.1.10"}, "name": {"Discord-Notifier"}})
	hs, _ := e.st.Services(context.Background())
	if len(hs) != 1 || hs[0].Name != "Discord-Notifier" || hs[0].User != "admin" {
		t.Fatalf("services %+v", hs)
	}
	// the only sender is now a service: no player groups, one service block
	_, frag := get(t, admin, e.srv.URL+"/spieler?teil=tabelle")
	if !strings.Contains(frag, "Dienste, zählen nicht mit (1)") || !strings.Contains(frag, "Discord-Notifier") || strings.Contains(frag, "PC in") {
		t.Errorf("players fragment: %.600s", frag)
	}
	view, _ := e.client("view")
	if _, p := get(t, view, e.srv.URL+"/spieler"); strings.Contains(p, "/system?dienst=") {
		t.Error("viewer sees the admin link")
	}
	if code, _ := get(t, view, e.srv.URL+"/system"); code != http.StatusForbidden {
		t.Errorf("viewer system = %d", code)
	}
	post("/system/dienste/10.10.1.10/loeschen", url.Values{})
	if hs, _ := e.st.Services(context.Background()); len(hs) != 0 {
		t.Error("service not removed")
	}
}
