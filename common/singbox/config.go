// Package singbox supervises an external sing-box process that terminates the
// shadow-tls (v3) camouflage layer in front of an Xray Shadowsocks inbound.
//
// Wire path:
//
//	client --TLS/ShadowTLS--> [sing-box shadowtls inbound]  --plain SS bytes-->  [Xray SS inbound]
//	                          0.0.0.0:<public_port>          127.0.0.1:<internal>  (real SS + accounting)
//
// sing-box only peels the shadow-tls layer; Xray still terminates real
// Shadowsocks, so all user/traffic accounting stays in Xray.
package singbox

import (
	"encoding/json"
	"fmt"
	"strconv"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// User is one shadow-tls credential.
type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Config is the resolved input for one node's sing-box front.
type Config struct {
	Tag           string // node tag; registry key, not serialized
	PublicListen  string // e.g. "0.0.0.0"
	PublicPort    int    // the node's public server_port
	InternalHost  string // "127.0.0.1"
	InternalPort  int    // allocated loopback port the Xray SS inbound binds
	Version       int    // shadow-tls version (3)
	Users         []User
	HandshakeHost string // TLS handshake/camouflage server
	HandshakePort int    // default 443
	StrictMode    bool
}

// ConfigFromNode maps a Shadowsocks node's shadow-tls plugin options (from
// network_settings) plus the allocated loopback port into a Config.
// The plugin_opts convention is "host=<handshake>;password=<pw>;version=<n>".
func ConfigFromNode(tag string, info *panel.NodeInfo, internalPort int) *Config {
	c := info.Common
	plugin := c.ShadowsocksPlugin()
	version := 3
	if v := plugin.Opt("version"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			version = n
		}
	}
	users := []User{{Name: "u0", Password: plugin.Opt("password")}}
	listen := c.ListenIP
	if listen == "" {
		listen = "0.0.0.0"
	}
	return &Config{
		Tag:           tag,
		PublicListen:  listen,
		PublicPort:    c.ServerPort,
		InternalHost:  "127.0.0.1",
		InternalPort:  internalPort,
		Version:       version,
		Users:         users,
		HandshakeHost: plugin.Opt("host"),
		HandshakePort: 443,
		StrictMode:    true,
	}
}

// MarshalSingBox renders the sing-box JSON config: a shadowtls inbound whose
// peeled stream is relayed (via a direct outbound with a fixed override target)
// to the loopback Xray Shadowsocks inbound.
func (c *Config) MarshalSingBox() ([]byte, error) {
	if c.PublicPort == 0 {
		return nil, fmt.Errorf("singbox: public port is zero for %s", c.Tag)
	}
	if c.InternalPort == 0 {
		return nil, fmt.Errorf("singbox: internal port is zero for %s", c.Tag)
	}
	handshakePort := c.HandshakePort
	if handshakePort == 0 {
		handshakePort = 443
	}
	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "warn",
			"timestamp": false,
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":        "shadowtls",
				"tag":         "st-in",
				"listen":      c.PublicListen,
				"listen_port": c.PublicPort,
				"version":     c.Version,
				"strict_mode": c.StrictMode,
				"users":       c.Users,
				"handshake": map[string]interface{}{
					"server":      c.HandshakeHost,
					"server_port": handshakePort,
				},
				"detour": "ss-relay",
			},
			// Blind relay: whatever sing-box hands to this inbound is forwarded
			// unmodified to the loopback Xray SS listener, which does the real
			// Shadowsocks decryption and all user/traffic accounting.
			map[string]interface{}{
				"type":             "direct",
				"tag":              "ss-relay",
				"listen":           c.InternalHost,
				"override_address": c.InternalHost,
				"override_port":    c.InternalPort,
			},
		},
		"outbounds": []interface{}{
			map[string]interface{}{"type": "direct", "tag": "direct"},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
