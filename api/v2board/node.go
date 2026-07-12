package panel

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Tag          string
	Common       *CommonNode
}

type CommonNode struct {
	Protocol   string      `json:"protocol"`
	ListenIP   string      `json:"listen_ip"`
	ServerPort int         `json:"server_port"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
	//vless vmess trojan
	Tls                int         `json:"tls"`
	TlsSettings        TlsSettings `json:"tls_settings"`
	CertInfo           *CertInfo
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"network_settings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	ServerName         string          `json:"server_name"`
	Flow               string          `json:"flow"`
	//shadowsocks
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
	//tuic
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	//anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	//hysteria hysteria2
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsPassword            string `json:"obfs_password"`
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
	//shadowflow
	Camouflage        string          `json:"camouflage"`
	ShapingSettings   json.RawMessage `json:"shaping_settings"`
	SniMode           string          `json:"sni_mode"`
	SwitchIntervalMin int             `json:"switch_interval_min"`
	SwitchIntervalMax int             `json:"switch_interval_max"`
	UploadHost        string          `json:"upload_host"`
	DownloadHost      string          `json:"download_host"`
	PathPool          string          `json:"path_pool"`
	ConnMaxLifetime   int             `json:"conn_max_lifetime"`
	TransportType     string          `json:"transport_type"`
	TransportPath     string          `json:"transport_path"`
	TransportHost     string          `json:"transport_host"`
}

type Route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
}

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	ServerNames      []string `json:"server_names"`
	Dest             string   `json:"dest"`
	ServerPort       string   `json:"server_port"`
	ShortId          string   `json:"short_id"`
	ShortIds         []string `json:"short_ids"`
	PrivateKey       string   `json:"private_key"`
	Mldsa65Seed      string   `json:"mldsa65Seed"`
	Xver             uint64   `json:"xver,string"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	RejectUnknownSni string   `json:"reject_unknown_sni"`
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

// GetNodeInfo fetches node config from the panel.
// Always fetches full config (no ETag/304) to ensure the panel
// registers a heartbeat on every call. Change detection is handled
// by nodeNeedsRebuild() in the caller.
func (c *Client) GetNodeInfo(ctx context.Context) (*NodeInfo, error) {
	if c.NodeType != "" {
		return c.getNodeInfoUniProxy(ctx)
	}
	return c.getNodeInfoV2(ctx)
}

// getNodeInfoV2 fetches the unified v2node config (/api/v2/server/config).
func (c *Client) getNodeInfoV2(ctx context.Context) (node *NodeInfo, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	const path = "/api/v2/server/config"
	r, err := c.client.R().SetContext(ctx).ForceContentType("application/json").Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.RawBody() != nil {
		defer r.RawBody().Close()
	}
	node = &NodeInfo{Id: c.NodeId}
	cm := &CommonNode{}
	if err = json.Unmarshal(r.Body(), cm); err != nil {
		return nil, fmt.Errorf("decode node params error: %s", err)
	}
	switch cm.Protocol {
	case "hysteria2", "tuic":
		// QUIC protocols mandate TLS regardless of the panel's tls flag.
		node.Type = cm.Protocol
		node.Security = Tls
	case "vmess", "trojan", "anytls", "vless", "shadowflow":
		node.Type = cm.Protocol
		node.Security = cm.Tls
	case "shadowsocks":
		node.Type = cm.Protocol
		node.Security = 0
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", cm.Protocol)
	}
	c.finalizeNode(node, cm)
	return node, nil
}

// getNodeInfoUniProxy fetches an XrayR-style per-protocol config
// (/api/v1/server/UniProxy/config) for a node whose NodeType is set. The
// protocol comes from NodeType (the response has no top-level protocol field).
func (c *Client) getNodeInfoUniProxy(ctx context.Context) (*NodeInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	const path = "/api/v1/server/UniProxy/config"
	r, err := c.client.R().SetContext(ctx).ForceContentType("application/json").Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.RawBody() != nil {
		defer r.RawBody().Close()
	}
	proto := normalizeNodeType(c.NodeType)
	cm, err := parseUniProxyConfig(r.Body(), proto)
	if err != nil {
		return nil, err
	}
	node := &NodeInfo{Id: c.NodeId, Type: proto}
	switch proto {
	case "shadowsocks":
		node.Security = 0
	case "hysteria2", "tuic":
		// hysteria2/tuic (QUIC) mandate TLS at the transport layer, regardless
		// of the panel's tls flag. Without it the inbound fails with
		// "hysteria: tls config is nil".
		node.Security = Tls
	default:
		node.Security = cm.Tls
	}
	c.finalizeNode(node, cm)
	return node, nil
}

// parseUniProxyConfig unmarshals a UniProxy per-protocol config body into a
// CommonNode, handling the per-protocol field-name quirks (proto must already
// be normalized).
func parseUniProxyConfig(body []byte, proto string) (*CommonNode, error) {
	cm := &CommonNode{}
	if err := json.Unmarshal(body, cm); err != nil {
		return nil, fmt.Errorf("decode uniproxy node params error: %s", err)
	}
	cm.Protocol = proto
	switch proto {
	case "vmess":
		// vmess uses "networkSettings" (camelCase) not "network_settings".
		if len(cm.NetworkSettings) == 0 {
			var alt struct {
				NS json.RawMessage `json:"networkSettings"`
			}
			_ = json.Unmarshal(body, &alt)
			cm.NetworkSettings = alt.NS
		}
	case "hysteria2":
		// hysteria uses "obfs-password" (hyphen).
		if cm.ObfsPassword == "" {
			var alt struct {
				OP string `json:"obfs-password"`
			}
			_ = json.Unmarshal(body, &alt)
			cm.ObfsPassword = alt.OP
		}
	case "shadowsocks":
		// SS HTTP obfs carries path/host under "obfs_settings"; map it into
		// NetworkSettings the way buildShadowsocks expects.
		if len(cm.NetworkSettings) == 0 {
			var alt struct {
				Obfs         string `json:"obfs"`
				ObfsSettings struct {
					Path string `json:"path"`
					Host string `json:"host"`
				} `json:"obfs_settings"`
			}
			_ = json.Unmarshal(body, &alt)
			if alt.Obfs == "http" && (alt.ObfsSettings.Path != "" || alt.ObfsSettings.Host != "") {
				ns, _ := json.Marshal(map[string]string{"path": alt.ObfsSettings.Path, "Host": alt.ObfsSettings.Host})
				cm.NetworkSettings = ns
			}
		}
	}
	return cm, nil
}

// normalizeNodeType maps configured NodeType values to v2node's internal
// protocol names.
func normalizeNodeType(t string) string {
	switch strings.ToLower(t) {
	case "v2ray":
		return "vmess"
	case "hysteria", "hysteria2":
		return "hysteria2"
	default:
		return strings.ToLower(t)
	}
}

// finalizeNode fills the shared post-parse fields (tag, cert, intervals) and
// attaches cm. node.Type/Security must already be set.
func (c *Client) finalizeNode(node *NodeInfo, cm *CommonNode) {
	node.Tag = fmt.Sprintf("[%s]-%s:%d", c.APIHost, node.Type, node.Id)
	cf := cm.TlsSettings.CertFile
	kf := cm.TlsSettings.KeyFile
	if cf == "" {
		cf = filepath.Join("/etc/v2node/", node.Type+strconv.Itoa(c.NodeId)+".cer")
	}
	if kf == "" {
		kf = filepath.Join("/etc/v2node/", node.Type+strconv.Itoa(c.NodeId)+".key")
	}
	cm.CertInfo = &CertInfo{
		CertMode:         cm.TlsSettings.CertMode,
		CertFile:         cf,
		KeyFile:          kf,
		Email:            "node@v2board.com",
		CertDomain:       cm.TlsSettings.PrimaryServerName(),
		DNSEnv:           make(map[string]string),
		Provider:         cm.TlsSettings.Provider,
		RejectUnknownSni: cm.TlsSettings.RejectUnknownSni == "1",
	}
	if cm.CertInfo.CertMode == "dns" && cm.TlsSettings.DNSEnv != "" {
		for _, env := range strings.Split(cm.TlsSettings.DNSEnv, ",") {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) == 2 {
				cm.CertInfo.DNSEnv[kv[0]] = kv[1]
			}
		}
	}
	if cm.BaseConfig != nil {
		node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
		node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)
	} else {
		node.PushInterval = 60 * time.Second
		node.PullInterval = 60 * time.Second
	}
	node.Common = cm
}

func intervalToTime(i interface{}) time.Duration {
	if i == nil {
		return 60 * time.Second
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}

func (t TlsSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) > 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	// Support comma-separated SNI list from panel (e.g. "www.apple.com,www.microsoft.com")
	if strings.Contains(t.ServerName, ",") {
		parts := strings.Split(t.ServerName, ",")
		var names []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				names = append(names, p)
			}
		}
		if len(names) > 0 {
			return names
		}
	}
	return []string{t.ServerName}
}

func (t TlsSettings) EffectiveShortIds() []string {
	if len(t.ShortIds) > 0 {
		return t.ShortIds
	}
	if t.ShortId == "" {
		return nil
	}
	return []string{t.ShortId}
}

// SSPlugin is an SS SIP003 plugin config parsed from a node's network_settings
// ({"plugin":"...","plugin_opts":"k=v;k=v"}).
type SSPlugin struct {
	Name string
	Opts map[string]string
}

// Opt returns a plugin option value (empty string if absent).
func (p *SSPlugin) Opt(k string) string {
	if p == nil {
		return ""
	}
	return p.Opts[k]
}

// ShadowsocksPlugin parses the SIP003 plugin carried in network_settings.
// Returns nil when no plugin is configured.
func (c *CommonNode) ShadowsocksPlugin() *SSPlugin {
	if len(c.NetworkSettings) == 0 {
		return nil
	}
	var ns struct {
		Plugin     string `json:"plugin"`
		PluginOpts string `json:"plugin_opts"`
	}
	if err := json.Unmarshal(c.NetworkSettings, &ns); err != nil || ns.Plugin == "" {
		return nil
	}
	opts := make(map[string]string)
	for _, pair := range strings.Split(ns.PluginOpts, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if i := strings.Index(pair, "="); i >= 0 {
			opts[strings.TrimSpace(pair[:i])] = strings.TrimSpace(pair[i+1:])
		} else {
			opts[pair] = ""
		}
	}
	return &SSPlugin{Name: ns.Plugin, Opts: opts}
}

// ShadowTLSEnabled reports whether this SS node should be fronted by a
// shadow-tls terminator (a sing-box subprocess).
func (c *CommonNode) ShadowTLSEnabled() bool {
	p := c.ShadowsocksPlugin()
	return p != nil && p.Name == "shadow-tls" && p.Opt("host") != "" && p.Opt("password") != ""
}

func (t TlsSettings) PrimaryServerName() string {
	serverNames := t.EffectiveServerNames()
	if len(serverNames) == 0 {
		return ""
	}
	return serverNames[0]
}
