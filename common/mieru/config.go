// Package mieru embeds the GPLv3 mieru proxy server (github.com/enfein/mieru)
// as a native, in-process inbound: it runs mieru's own protocol.Mux, accepts
// decrypted client streams, and bridges each to Xray's dispatcher so per-user
// traffic accounting, speed/device limits and routing all work exactly like the
// other protocols. NOTE: linking mieru makes this binary GPLv3.
package mieru

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mcommon "github.com/enfein/mieru/v3/pkg/common"
	mprotocol "github.com/enfein/mieru/v3/pkg/protocol"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// flexBool / flexInt unmarshal a JSON bool/number OR its string form. The
// panel's admin JSON editor stores every network_settings value as a string
// ("true", "1400", "0"); with a plain *bool/*int the strict decoder fails that
// one field, leaves the allocated pointer's value at zero, and so silently
// flips a configured "true" to false (and a custom mtu to 0 → default). Parsing
// them leniently keeps these knobs working no matter how the panel serialized
// them. Same fix as common/trojanss' flexBool for ss_obfs.enabled.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(string(data)), `"`))
	*b = s == "true" || s == "1"
	return nil
}

type flexInt int

func (n *flexInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if v, err := strconv.Atoi(s); err == nil {
		*n = flexInt(v)
	}
	return nil
}

// mieruNS is the mieru-specific slice of the panel node's network_settings.
// The panel (v2board/Xboard mieru patch) reuses network_settings and puts the
// transport (TCP/UDP) and an optional traffic pattern there.
type mieruNS struct {
	Transport      string `json:"transport"`
	TrafficPattern string `json:"traffic_pattern"`
	// Ports lets a node listen on MANY ports instead of only server_port — the
	// operation docs recommend a larger port range so a firewall closing idle
	// ports (and port-scan based blocking) is harder. Format mirrors mihomo's
	// client port-range: a single range "2012-2022", a single port, or a comma-
	// separated mix "2012-2022,2027". Empty = just server_port (prior behavior).
	// The same value should be put on the client (network_settings.ports flows to
	// the subscription's port-range) so client and server agree on the range.
	Ports string `json:"ports"`
	// MTU is the UDP-transport max payload size mieru wraps packets to. Unset =
	// mieru's own default (1400). The operation docs recommend lowering it (e.g.
	// 1280, the floor) on both ends when a path MTU mismatch throttles UDP-
	// transport speed. Only affects the UDP underlay; ignored for TCP transport.
	MTU *flexInt `json:"mtu"`
	// ForceUserHint / UserHintMandatory both map to mieru's
	// SetServerUserHintIsMandatory. Two keys are accepted so either a
	// soga-style panel field (mieru_force_user_hint) or a heki-style one
	// (user_hint_mandatory) works. Pointers so "unset" is distinguishable from
	// an explicit false. See forceUserHint for the default.
	ForceUserHint     *flexBool `json:"mieru_force_user_hint"`
	UserHintMandatory *flexBool `json:"user_hint_mandatory"`
	// TCPIdleTimeoutSec maps to mieru's SetServerTCPIdleTimeout (seconds). 0 /
	// unset = never actively close an idle server TCP underlay, which is mieru's
	// own default and matches a stock mita server on the wire (stealthiest). Set
	// a positive value only if a connection-pooling relay makes empty underlays
	// accumulate (CPU). See tcpIdleTimeout.
	TCPIdleTimeoutSec *flexInt `json:"mieru_tcp_idle_timeout"`
}

func parseNS(raw json.RawMessage) mieruNS {
	ns := mieruNS{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &ns)
	}
	return ns
}

// forceUserHint decides whether mieru requires every connection to carry a user
// hint. With it ON, hint-less junk (scanners, probes, relay-pool noise) is
// rejected before the expensive per-user trial-decrypt (XChaCha20 against every
// registered user's key) — the single biggest CPU sink on a busy multi-user
// node. Modern mieru clients always send the hint.
//
// Default is ON (true): v2node is performance-oriented and this is the multi-
// user optimization. Operators with old/third-party clients that do NOT send a
// hint can opt out by setting "mieru_force_user_hint": false (or
// "user_hint_mandatory": false) in the node's network_settings — those clients
// would otherwise be unable to connect.
func forceUserHint(info *panel.NodeInfo) bool {
	ns := parseNS(info.Common.NetworkSettings)
	if ns.ForceUserHint != nil {
		return bool(*ns.ForceUserHint)
	}
	if ns.UserHintMandatory != nil {
		return bool(*ns.UserHintMandatory)
	}
	return true
}

// tcpIdleTimeout returns how long a server TCP underlay may stay idle before the
// mieru Mux actively closes it. Default 0 (never) = mieru's own default, wire-
// identical to a stock mita server. v2node previously PATCHED mieru to reap idle
// underlays at 30-60s (to bound empty-underlay accumulation behind a pooling
// relay), but that gave the server a distinctive "closes idle TCP ~45s" finger-
// print unlike stock mieru. We now use mieru's official, opt-in mechanism
// instead, off by default; operators who hit the accumulation can set a value.
func tcpIdleTimeout(info *panel.NodeInfo) time.Duration {
	ns := parseNS(info.Common.NetworkSettings)
	if ns.TCPIdleTimeoutSec != nil && int(*ns.TCPIdleTimeoutSec) > 0 {
		return time.Duration(int(*ns.TCPIdleTimeoutSec)) * time.Second
	}
	return 0
}

// portBindings turns the node's port spec into mieru PortBindings. spec is the
// network_settings.ports string ("2012-2022" range, a single port, or a comma-
// separated mix); empty falls back to the single server_port. Ranges are left
// as PortRange on the binding — mieru's AddrPortToUnderlayProperties flattens
// them (FlatPortBindings) into one listener per port. If every token is
// unparseable we fall back to server_port rather than binding nothing.
func portBindings(spec string, serverPort int, proto pb.TransportProtocol) []*pb.PortBinding {
	single := func() []*pb.PortBinding {
		p := int32(serverPort)
		pr := proto
		return []*pb.PortBinding{{Port: &p, Protocol: &pr}}
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return single()
	}
	out := make([]*pb.PortBinding, 0)
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		pr := proto
		if strings.Contains(tok, "-") {
			r := tok
			out = append(out, &pb.PortBinding{PortRange: &r, Protocol: &pr})
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		p := int32(n)
		out = append(out, &pb.PortBinding{Port: &p, Protocol: &pr})
	}
	if len(out) == 0 {
		return single()
	}
	return out
}

// buildEndpoints maps the panel node (server_port/ports + transport) into mieru
// underlay endpoints.
func buildEndpoints(info *panel.NodeInfo) ([]mprotocol.UnderlayProperties, error) {
	ns := parseNS(info.Common.NetworkSettings)
	proto := pb.TransportProtocol_TCP
	if strings.EqualFold(ns.Transport, "UDP") {
		proto = pb.TransportProtocol_UDP
	}
	pbs := portBindings(ns.Ports, info.Common.ServerPort, proto)
	// MTU: operator-configurable (network_settings.mtu), default 1400, floored at
	// mieru's minimum 1280. Only meaningful for the UDP underlay.
	mtu := mcommon.DefaultMTU
	if ns.MTU != nil && int(*ns.MTU) >= 1280 {
		mtu = int(*ns.MTU)
	}
	// mieru v3.39 renamed this and added a listen-IP arg (v3.37, issue #286).
	// Empty listen IP = bind all interfaces, matching the prior behavior.
	return appctlcommon.AddrPortToUnderlayProperties(info.Common.ListenIP, pbs, mtu)
}

// buildUserMap builds mieru's registered-user map from panel users.
// Per the panel contract (buildMieru($user['uuid'])): mieru name = password =
// the user's uuid.
func buildUserMap(users map[string]panel.UserInfo) map[string]*pb.User {
	list := make([]*pb.User, 0, len(users))
	for uuid := range users {
		name := uuid
		pw := uuid
		list = append(list, &pb.User{Name: &name, Password: &pw})
	}
	return appctlcommon.UserListToMap(list)
}
