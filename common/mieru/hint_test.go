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
