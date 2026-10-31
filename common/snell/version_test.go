package snell

import (
	"encoding/json"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// The panel's admin JSON editor stores network_settings values as strings. A
// plain int Version would fail to parse "6" and stay 0, silently downgrading a
// snell v6 node to the v4/v5 path. flexInt must parse the string form.
func TestSnellVersionStringForm(t *testing.T) {
	cases := []struct {
		ns   string
		want int
	}{
		{`{"version":6,"psk":"x"}`, 6},   // number
		{`{"version":"6","psk":"x"}`, 6}, // string (panel form)
		{`{"version":"5","psk":"x"}`, 5},
		{`{"psk":"x"}`, 0}, // unset -> 0 -> v4/v5 else-branch
	}
	for _, c := range cases {
		r := &Runner{info: &panel.NodeInfo{Common: &panel.CommonNode{NetworkSettings: json.RawMessage(c.ns)}}}
		if got := int(r.settings().Version); got != c.want {
			t.Fatalf("ns %s: version = %d, want %d", c.ns, got, c.want)
		}
	}
	// The decisive one: string "6" must select the v6 path.
	r := &Runner{info: &panel.NodeInfo{Common: &panel.CommonNode{NetworkSettings: json.RawMessage(`{"version":"6"}`)}}}
	if int(r.settings().Version) < 6 {
		t.Fatal(`version:"6" (string) must select the v6 path, not downgrade to v4/v5`)
	}
}
