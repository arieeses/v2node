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
	if !c.NodeConfigs[0].DisableSniffing {
		t.Fatal("node0 DisableSniffing must be true")
	}
	if c.NodeConfigs[1].DisableSniffing {
		t.Fatal("node1 DisableSniffing must default to false")
	}
	if c.NodeConfigs[0].APIHost != "https://x.com" || c.NodeConfigs[1].NodeID != 2 {
		t.Fatal("basic node fields must parse from YAML")
	}
}
