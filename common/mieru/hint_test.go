package mieru

import (
	"encoding/json"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
)

func nodeWithNS(ns string) *panel.NodeInfo {
	info := &panel.NodeInfo{Common: &panel.CommonNode{}}
	if ns != "" {
		info.Common.NetworkSettings = json.RawMessage(ns)
	}
	return info
}

func TestForceUserHintDefaultsOn(t *testing.T) {
	if !forceUserHint(nodeWithNS("")) {
		t.Fatal("empty network_settings should default to hint mandatory (true)")
	}
	if !forceUserHint(nodeWithNS(`{"transport":"TCP"}`)) {
		t.Fatal("unrelated network_settings should still default to true")
	}
}

func TestForceUserHintExplicitOverride(t *testing.T) {
	if forceUserHint(nodeWithNS(`{"mieru_force_user_hint":false}`)) {
		t.Fatal("mieru_force_user_hint=false must disable the requirement")
	}
	if !forceUserHint(nodeWithNS(`{"mieru_force_user_hint":true}`)) {
		t.Fatal("mieru_force_user_hint=true must enable the requirement")
	}
	// heki-style key.
	if forceUserHint(nodeWithNS(`{"user_hint_mandatory":false}`)) {
		t.Fatal("user_hint_mandatory=false must disable the requirement")
	}
}

// The panel's admin JSON editor stores every value as a STRING. With a plain
// *bool/*int these fail the strict decoder and flip to zero (true -> false,
// mtu -> 0). flexBool/flexInt must parse the string forms so the configured
// value survives. Payload mirrors a real node 28 config dump.
func TestStringFormNetworkSettings(t *testing.T) {
	ns := `{"transport":"TCP","ports":"2012-2022","mtu":"1400","traffic_pattern":"IgY","mieru_force_user_hint":"true","mieru_tcp_idle_timeout":"30"}`
	parsed := parseNS(nodeWithNS(ns).Common.NetworkSettings)
	if parsed.TrafficPattern != "IgY" || parsed.Ports != "2012-2022" {
		t.Fatalf("string fields lost: %+v", parsed)
	}
	if parsed.MTU == nil || int(*parsed.MTU) != 1400 {
		t.Fatalf(`mtu "1400" must parse to 1400, got %v`, parsed.MTU)
	}
	// The critical one: string "true" must NOT become false.
	if !forceUserHint(nodeWithNS(ns)) {
		t.Fatal(`mieru_force_user_hint:"true" (string) must stay true, not flip to false`)
	}
	if tcpIdleTimeout(nodeWithNS(ns)).Seconds() != 30 {
		t.Fatalf(`mieru_tcp_idle_timeout:"30" must parse to 30s, got %v`, tcpIdleTimeout(nodeWithNS(ns)))
	}
	// And a string "false" must disable it.
	if forceUserHint(nodeWithNS(`{"mieru_force_user_hint":"false"}`)) {
		t.Fatal(`mieru_force_user_hint:"false" (string) must disable the requirement`)
	}
}
