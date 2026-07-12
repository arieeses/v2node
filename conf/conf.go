package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig   LogConfig    `mapstructure:"Log"`
	Global      GlobalConfig `mapstructure:"Global"`
	NodeConfigs []NodeConfig `mapstructure:"Nodes"`
	PprofPort   int          `mapstructure:"PprofPort"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

// GlobalConfig holds defaults inherited by every node. A node may override any
// of these in its own entry; node values win over global.
type GlobalConfig struct {
	PullInterval    int                   `mapstructure:"PullInterval"`
	DisableSniffing bool                  `mapstructure:"DisableSniffing"`
	AutoSpeedLimit  *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimit"`
	Cert            *CertConfig           `mapstructure:"Cert"`
	Policy          *PolicyConfig         `mapstructure:"Policy"`

	// ApiIPStrategy controls how the panel API HTTP client dials:
	//   "auto" (default) => try IPv4 first, fall back to IPv6
	//   "ipv4"           => IPv4 only (tcp4)
	//   "ipv6"           => IPv6 only (tcp6)
	// Use ipv4 when a node's IPv6 path to the panel is broken/slow and the
	// default dual-stack dialer causes TLS-handshake/deadline timeouts. Nodes
	// inherit this unless they set their own.
	ApiIPStrategy string `mapstructure:"ApiIPStrategy"`

	// Rule sources. "remote" (default) = build DNS/routing from the panel's
	// routes; "local" = load the corresponding local xray json file below.
	RouteMode string `mapstructure:"RouteMode"`
	DnsMode   string `mapstructure:"DnsMode"`

	RouteConfigPath    string `mapstructure:"RouteConfigPath"`
	DnsConfigPath      string `mapstructure:"DnsConfigPath"`
	InboundConfigPath  string `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string `mapstructure:"OutboundConfigPath"`

	// SingBoxPath / SingBoxDir configure the sing-box subprocess used to
	// terminate shadow-tls in front of a Shadowsocks inbound. Empty values
	// fall back to the defaults below.
	SingBoxPath string `mapstructure:"SingBoxPath"`
	SingBoxDir  string `mapstructure:"SingBoxDir"`
}

// EffectiveSingBoxPath returns the configured sing-box binary path or the default.
func (g GlobalConfig) EffectiveSingBoxPath() string {
	if g.SingBoxPath != "" {
		return g.SingBoxPath
	}
	return "/usr/local/bin/sing-box"
}

// EffectiveSingBoxDir returns the configured sing-box working dir or the default.
func (g GlobalConfig) EffectiveSingBoxDir() string {
	if g.SingBoxDir != "" {
		return g.SingBoxDir
	}
	return "/etc/v2node/singbox"
}

// AutoSpeedLimitConfig mirrors XrayR's auto (dynamic) speed limit: a user whose
// per-cycle speed exceeds Limit (mbps) WarnTimes in a row is throttled to
// LimitSpeed (mbps) for LimitDuration minutes.
type AutoSpeedLimitConfig struct {
	Enable        *bool `mapstructure:"Enable"`
	Limit         int   `mapstructure:"Limit"`
	WarnTimes     int   `mapstructure:"WarnTimes"`
	LimitSpeed    int   `mapstructure:"LimitSpeed"`
	LimitDuration int   `mapstructure:"LimitDuration"`
}

// CertConfig is the LOCAL certificate-issuance config. The certificate DOMAIN
// always comes from the panel (node server_name); only the issuance method and
// secrets live here so DNS API keys never need to be stored in the panel.
type CertConfig struct {
	CertMode string            `mapstructure:"CertMode"`
	Provider string            `mapstructure:"Provider"`
	Email    string            `mapstructure:"Email"`
	DNSEnv   map[string]string `mapstructure:"DNSEnv"`
	CertFile string            `mapstructure:"CertFile"`
	KeyFile  string            `mapstructure:"KeyFile"`
}

// PolicyConfig exposes the xray connection policy knobs (pointers so "unset"
// falls back to the built-in default).
type PolicyConfig struct {
	Handshake      *int `mapstructure:"Handshake"`
	ConnIdle       *int `mapstructure:"ConnIdle"`
	BufferSize     *int `mapstructure:"BufferSize"`
	GrpcBufferSize *int `mapstructure:"GrpcBufferSize"`
}

type NodeConfig struct {
	APIHost    string `mapstructure:"ApiHost"`
	NodeID     int    `mapstructure:"NodeID"`
	Key        string `mapstructure:"ApiKey"`
	Timeout    int    `mapstructure:"Timeout"`
	RetryCount *int   `mapstructure:"RetryCount"`

	// NodeType, when set (vmess/vless/trojan/shadowsocks/tuic/hysteria/anytls),
	// makes the node talk the per-protocol UniProxy panel API (like XrayR)
	// instead of the unified v2node /api/v2/server/config. Empty = v2node node.
	NodeType string `mapstructure:"NodeType"`

	// DisableSniffing overrides Global.DisableSniffing when set.
	DisableSniffing *bool `mapstructure:"DisableSniffing"`

	// SpeedLimit is a node-wide local speed cap in Mbps (0 = no local cap).
	SpeedLimit int `mapstructure:"SpeedLimit"`
	// DeviceLimit is a local device-count fallback used when the panel does
	// not send a per-user device_limit (0 = unlimited).
	DeviceLimit int `mapstructure:"DeviceLimit"`
	// PullInterval overrides Global.PullInterval / panel interval when > 0.
	PullInterval int `mapstructure:"PullInterval"`

	AutoSpeedLimit *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimit"`
	Cert           *CertConfig           `mapstructure:"Cert"`

	// ApiIPStrategy overrides Global.ApiIPStrategy for this node's panel API
	// client (auto/ipv4/ipv6). Empty = inherit global.
	ApiIPStrategy string `mapstructure:"ApiIPStrategy"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
		// Node inherits the global ApiIPStrategy unless it set its own.
		if p.NodeConfigs[i].ApiIPStrategy == "" {
			p.NodeConfigs[i].ApiIPStrategy = p.Global.ApiIPStrategy
		}
	}
	return nil
}

// ---- effective-value resolvers (node overrides global) ----

// SniffDisabled reports whether sniffing is off for this node.
func (n *NodeConfig) SniffDisabled(g GlobalConfig) bool {
	if n.DisableSniffing != nil {
		return *n.DisableSniffing
	}
	return g.DisableSniffing
}

// EffectiveCert returns the cert config for this node (node overrides global,
// field by field), or nil if neither is set.
func (n *NodeConfig) EffectiveCert(g GlobalConfig) *CertConfig {
	if n.Cert == nil {
		return g.Cert
	}
	if g.Cert == nil {
		return n.Cert
	}
	out := *g.Cert // copy global as the base
	c := n.Cert
	if c.CertMode != "" {
		out.CertMode = c.CertMode
	}
	if c.Provider != "" {
		out.Provider = c.Provider
	}
	if c.Email != "" {
		out.Email = c.Email
	}
	if c.DNSEnv != nil {
		out.DNSEnv = c.DNSEnv
	}
	if c.CertFile != "" {
		out.CertFile = c.CertFile
	}
	if c.KeyFile != "" {
		out.KeyFile = c.KeyFile
	}
	return &out
}

// EffectiveAutoSpeedLimit resolves the auto-speed-limit for this node.
//
// Semantics (global switch is the master):
//   - Global AutoSpeedLimit absent, or its Enable != true  => OFF on every node
//     (per-node settings cannot re-enable it).
//   - Global Enable == true:
//   - node's own Enable == true  => use the NODE's values (each unset field
//     falls back to the global value);
//   - node Enable false/unset    => use the GLOBAL values.
//
// Returns nil when disabled or no trigger threshold (Limit <= 0) is set.
func (n *NodeConfig) EffectiveAutoSpeedLimit(g GlobalConfig) *AutoSpeedLimitConfig {
	base := g.AutoSpeedLimit
	// Master switch: only the global Enable turns the feature on at all.
	if base == nil || base.Enable == nil || !*base.Enable {
		return nil
	}
	out := *base // start from the global values
	// A node that opts in (its own Enable == true) overrides with its values;
	// otherwise the node just inherits the global values.
	if o := n.AutoSpeedLimit; o != nil && o.Enable != nil && *o.Enable {
		if o.Limit != 0 {
			out.Limit = o.Limit
		}
		if o.WarnTimes != 0 {
			out.WarnTimes = o.WarnTimes
		}
		if o.LimitSpeed != 0 {
			out.LimitSpeed = o.LimitSpeed
		}
		if o.LimitDuration != 0 {
			out.LimitDuration = o.LimitDuration
		}
	}
	if out.Limit <= 0 {
		return nil
	}
	return &out
}

func intPtr(v int) *int {
	return &v
}
