package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// loadJSONFile reads path and unmarshals it into v.
func loadJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// loadOutbounds loads a local outbound config file (a single object or an
// array of xray OutboundDetourConfig) and builds them.
func loadOutbounds(path string) ([]*core.OutboundHandlerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []coreConf.OutboundDetourConfig
	if err := json.Unmarshal(data, &arr); err != nil {
		var single coreConf.OutboundDetourConfig
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err
		}
		arr = []coreConf.OutboundDetourConfig{single}
	}
	out := make([]*core.OutboundHandlerConfig, 0, len(arr))
	for i := range arr {
		b, err := arr[i].Build()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// loadInbounds loads a local inbound config file (single object or array).
func loadInbounds(path string) ([]*core.InboundHandlerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []coreConf.InboundDetourConfig
	if err := json.Unmarshal(data, &arr); err != nil {
		var single coreConf.InboundDetourConfig
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err
		}
		arr = []coreConf.InboundDetourConfig{single}
	}
	out := make([]*core.InboundHandlerConfig, 0, len(arr))
	for i := range arr {
		b, err := arr[i].Build()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func GetCustomConfig(infos []*panel.NodeInfo, global conf.GlobalConfig) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, []*core.InboundHandlerConfig, error) {
	//dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
	//outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dns, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dns)

	//route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	for _, info := range infos {
		if len(info.Common.Routes) == 0 {
			continue
		}
		for _, route := range info.Common.Routes {
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					continue
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_ip":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "default_out":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			default:
				continue
			}
		}
	}
	// Local rule sources: override the panel-built DNS/routing with a local
	// xray json file when RouteMode/DnsMode is "local".
	if strings.EqualFold(global.DnsMode, "local") && global.DnsConfigPath != "" {
		lc := &coreConf.DNSConfig{}
		if err := loadJSONFile(global.DnsConfigPath, lc); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load local dns config: %w", err)
		}
		coreDnsConfig = lc
	}
	if strings.EqualFold(global.RouteMode, "local") && global.RouteConfigPath != "" {
		lc := &coreConf.RouterConfig{}
		if err := loadJSONFile(global.RouteConfigPath, lc); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load local route config: %w", err)
		}
		coreRouterConfig = lc
	}
	// Custom outbounds appended (like XrayR's OutboundConfigPath).
	if global.OutboundConfigPath != "" {
		obs, err := loadOutbounds(global.OutboundConfigPath)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load local outbound config: %w", err)
		}
		coreOutboundConfig = append(coreOutboundConfig, obs...)
	}

	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Custom inbounds (like XrayR's InboundConfigPath).
	var inbounds []*core.InboundHandlerConfig
	if global.InboundConfigPath != "" {
		inbounds, err = loadInbounds(global.InboundConfigPath)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load local inbound config: %w", err)
		}
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, inbounds, nil
}
