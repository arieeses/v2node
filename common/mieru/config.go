// Package mieru embeds the GPLv3 mieru proxy server (github.com/enfein/mieru)
// as a native, in-process inbound: it runs mieru's own protocol.Mux, accepts
// decrypted client streams, and bridges each to Xray's dispatcher so per-user
// traffic accounting, speed/device limits and routing all work exactly like the
// other protocols. NOTE: linking mieru makes this binary GPLv3.
package mieru

import (
	"encoding/json"
	"strings"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mcommon "github.com/enfein/mieru/v3/pkg/common"
	mprotocol "github.com/enfein/mieru/v3/pkg/protocol"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// mieruNS is the mieru-specific slice of the panel node's network_settings.
// The panel (v2board/Xboard mieru patch) reuses network_settings and puts the
// transport (TCP/UDP) and an optional traffic pattern there.
type mieruNS struct {
	Transport      string `json:"transport"`
	TrafficPattern string `json:"traffic_pattern"`
	// ForceUserHint / UserHintMandatory both map to mieru's
	// SetServerUserHintIsMandatory. Two keys are accepted so either a
	// soga-style panel field (mieru_force_user_hint) or a heki-style one
	// (user_hint_mandatory) works. Pointers so "unset" is distinguishable from
	// an explicit false. See forceUserHint for the default.
	ForceUserHint     *bool `json:"mieru_force_user_hint"`
	UserHintMandatory *bool `json:"user_hint_mandatory"`
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
		return *ns.ForceUserHint
	}
	if ns.UserHintMandatory != nil {
		return *ns.UserHintMandatory
	}
	return true
}

// buildEndpoints maps the panel node (server_port + transport) into mieru
// underlay endpoints. Single port for now; mieru port-range hopping can be
// added by passing a PortRange instead of Port.
func buildEndpoints(info *panel.NodeInfo) ([]mprotocol.UnderlayProperties, error) {
	ns := parseNS(info.Common.NetworkSettings)
	proto := pb.TransportProtocol_TCP
	if strings.EqualFold(ns.Transport, "UDP") {
		proto = pb.TransportProtocol_UDP
	}
	port := int32(info.Common.ServerPort)
	pbs := []*pb.PortBinding{{Port: &port, Protocol: &proto}}
	return appctlcommon.PortBindingsToUnderlayProperties(pbs, mcommon.DefaultMTU)
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
