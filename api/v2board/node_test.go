package panel

import (
	"strings"
	"testing"
)

func TestNormalizeNodeType(t *testing.T) {
	for in, want := range map[string]string{
		"v2ray": "vmess", "hysteria": "hysteria2", "hysteria2": "hysteria2",
		"trojan": "trojan", "vless": "vless", "shadowsocks": "shadowsocks",
		"Shadowsocks": "shadowsocks", "V2ray": "vmess", "TROJAN": "trojan", // case-insensitive
	} {
		if got := normalizeNodeType(in); got != want {
			t.Errorf("normalizeNodeType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseUniProxyVmess(t *testing.T) {
	// vmess uses camelCase "networkSettings".
	cm, err := parseUniProxyConfig([]byte(`{"server_port":443,"network":"ws","networkSettings":{"path":"/vm"},"tls":1}`), "vmess")
	if err != nil {
		t.Fatal(err)
	}
	if cm.Protocol != "vmess" || cm.ServerPort != 443 || cm.Network != "ws" || cm.Tls != 1 {
		t.Fatalf("vmess base parse wrong: %+v", cm)
	}
	if !strings.Contains(string(cm.NetworkSettings), "/vm") {
		t.Fatalf("vmess networkSettings not mapped: %s", cm.NetworkSettings)
	}
}

func TestParseUniProxyVless(t *testing.T) {
	cm, err := parseUniProxyConfig([]byte(`{"server_port":443,"network":"grpc","network_settings":{"serviceName":"gg"},"tls":1,"flow":"xtls-rprx-vision","server_name":"a.com"}`), "vless")
	if err != nil {
		t.Fatal(err)
	}
	if cm.Flow != "xtls-rprx-vision" || cm.ServerName != "a.com" || cm.Tls != 1 {
		t.Fatalf("vless fields wrong: %+v", cm)
	}
	if !strings.Contains(string(cm.NetworkSettings), "gg") {
		t.Fatalf("vless network_settings not mapped: %s", cm.NetworkSettings)
	}
}

func TestParseUniProxyHysteria(t *testing.T) {
	cm, err := parseUniProxyConfig([]byte(`{"server_port":443,"up_mbps":100,"down_mbps":200,"obfs":"salamander","obfs-password":"secret"}`), "hysteria2")
	if err != nil {
		t.Fatal(err)
	}
	if cm.ObfsPassword != "secret" || cm.UpMbps != 100 || cm.DownMbps != 200 {
		t.Fatalf("hysteria obfs-password/mbps not mapped: %+v", cm)
	}
}

func TestParseUniProxyShadowsocks(t *testing.T) {
	cm, err := parseUniProxyConfig([]byte(`{"server_port":8388,"cipher":"aes-128-gcm","obfs":"http","obfs_settings":{"path":"/p","host":"h.com"}}`), "shadowsocks")
	if err != nil {
		t.Fatal(err)
	}
	if cm.Cipher != "aes-128-gcm" || cm.ServerPort != 8388 {
		t.Fatalf("ss base wrong: %+v", cm)
	}
	if !strings.Contains(string(cm.NetworkSettings), "/p") || !strings.Contains(string(cm.NetworkSettings), "h.com") {
		t.Fatalf("ss obfs_settings not mapped to network settings: %s", cm.NetworkSettings)
	}
}
