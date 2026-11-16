package monitor

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestZabbixTemplate checks that deploy/zabbix/template_nsrelay.yaml parses and that every simple JSONPath
// ($.a or $.a.b) of a dependent item exists in the real report, so a renamed field cannot silently break Zabbix.
func TestZabbixTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/zabbix/template_nsrelay.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("template is not valid YAML: %v", err)
	}
	now := time.Now()
	b, _ := json.Marshal(Build(status(now), nil, "w1", true, now))
	var rep map[string]any
	_ = json.Unmarshal(b, &rep)
	paths := regexp.MustCompile(`- '(\$\.[a-z_]+(?:\.[a-z_]+)?)'`).FindAllStringSubmatch(string(raw), -1)
	if len(paths) < 20 {
		t.Fatalf("only %d JSONPaths found", len(paths))
	}
	for _, m := range paths {
		var cur any = rep
		for _, part := range strings.Split(strings.TrimPrefix(m[1], "$."), ".") {
			obj, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur, ok = obj[part]
			if !ok {
				cur = nil
				break
			}
		}
		if cur == nil {
			t.Errorf("JSONPath %s not in the monitoring report", m[1])
		}
	}
	for _, f := range regexp.MustCompile(`\]\.([a-z_]+)\.first\(\)`).FindAllStringSubmatch(string(raw), -1) {
		if _, ok := rep["vlan_list"].([]any)[0].(map[string]any)[f[1]]; !ok {
			t.Errorf("VLAN field %s not in vlan_list", f[1])
		}
	}
	uuids := regexp.MustCompile(`uuid: ([0-9a-f]{32})\n`).FindAllStringSubmatch(string(raw), -1)
	seen := map[string]bool{}
	for _, m := range uuids {
		if seen[m[1]] || m[1][12] != '4' {
			t.Errorf("uuid %s duplicate or not v4", m[1])
		}
		seen[m[1]] = true
	}
}
