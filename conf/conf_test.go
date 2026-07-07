package conf

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadYAMLDisableSniffing confirms viper reads a YAML config (XrayR-style,
// with `-` separated nodes) and parses the new per-node DisableSniffing field.
func TestLoadYAMLDisableSniffing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yml")
	yaml := "" +
		"Log:\n" +
		"  Level: error\n" +
		"Nodes:\n" +
		"  - ApiHost: https://x.com\n" +
		"    NodeID: 1\n" +
		"    ApiKey: \"k1\"\n" +
		"    DisableSniffing: true\n" +
		"  - ApiHost: https://y.com\n" +
		"    NodeID: 2\n" +
		"    ApiKey: \"k2\"\n"
	if err := os.WriteFile(p, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFromPath(p); err != nil {
		t.Fatalf("load yaml config: %v", err)
	}
	if len(c.NodeConfigs) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(c.NodeConfigs))
	}
	if !c.NodeConfigs[0].SniffDisabled(c.Global) {
		t.Fatal("node0 DisableSniffing must resolve to true")
	}
	if c.NodeConfigs[1].SniffDisabled(c.Global) {
		t.Fatal("node1 DisableSniffing must default to false (global)")
	}
	if c.NodeConfigs[0].APIHost != "https://x.com" || c.NodeConfigs[1].NodeID != 2 {
		t.Fatal("basic node fields must parse from YAML")
	}
}

func b(v bool) *bool { return &v }

// TestResolversOverride checks the global-default / node-override merge logic.
func TestResolversOverride(t *testing.T) {
	g := GlobalConfig{
		DisableSniffing: true,
		AutoSpeedLimit:  &AutoSpeedLimitConfig{Enable: b(true), Limit: 300, WarnTimes: 5, LimitSpeed: 70, LimitDuration: 3},
		Cert:            &CertConfig{CertMode: "dns", Provider: "cloudflare", Email: "g@x", DNSEnv: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "gtok"}},
	}

	// Node inherits global sniffing.
	inherit := NodeConfig{}
	if !inherit.SniffDisabled(g) {
		t.Fatal("node without override must inherit global DisableSniffing=true")
	}
	// Node overrides sniffing to false.
	override := NodeConfig{DisableSniffing: b(false)}
	if override.SniffDisabled(g) {
		t.Fatal("node override DisableSniffing=false must win over global")
	}

	// Cert: node changes only Provider/DNSEnv; CertMode/Email inherit global.
	certNode := NodeConfig{Cert: &CertConfig{Provider: "alidns", DNSEnv: map[string]string{"ALICLOUD_ACCESS_KEY": "ak"}}}
	ec := certNode.EffectiveCert(g)
	if ec.CertMode != "dns" || ec.Email != "g@x" || ec.Provider != "alidns" || ec.DNSEnv["ALICLOUD_ACCESS_KEY"] != "ak" {
		t.Fatalf("cert override merge wrong: %+v", ec)
	}

	// AutoSpeedLimit: node disables it.
	off := NodeConfig{AutoSpeedLimit: &AutoSpeedLimitConfig{Enable: b(false)}}
	if off.EffectiveAutoSpeedLimit(g) != nil {
		t.Fatal("node Enable=false must disable auto speed limit")
	}
	// Node inherits enabled global with its params.
	on := NodeConfig{}
	if a := on.EffectiveAutoSpeedLimit(g); a == nil || a.Limit != 300 || a.LimitSpeed != 70 {
		t.Fatalf("node must inherit enabled global auto speed limit: %+v", a)
	}
}
