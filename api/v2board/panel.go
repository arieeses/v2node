package panel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	"github.com/wyx2685/v2node/conf"
)

// Panel is the interface for different panel's api.

type Client struct {
	client   *resty.Client
	APIHost  string
	Token    string
	NodeId   int
	NodeType string // empty => unified v2node node; else XrayR-style protocol
	nodeEtag string
	userEtag string
	UserList *UserListBody
	AliveMap *AliveMap
}

func New(c *conf.NodeConfig) (*Client, error) {
	client := resty.New()
	// Use Go's default HTTP transport (HTTP/2 + keep-alive) — the same behavior
	// as upstream v2node and curl, both of which talk to the (CDN-fronted)
	// panels reliably (~1s). The previous forced-HTTP/1.1 + DisableKeepAlives
	// transport made requests to some CDN-fronted panels hang for minutes and
	// leak one connection per hang (observed: 1200+ leaked conns, FD climbing).
	// Each panel call is now bounded by a per-request timeout (see the api
	// methods) and backstopped by the task watchdog, so stalls fail fast and
	// retry instead of hanging — without disabling keep-alive.
	client.SetRetryCount(3)
	// IP strategy for the panel API dialer. Clone Go's default transport (keeps
	// HTTP/2 + keep-alive + default timeouts) and only swap the dial network, so
	// a broken/slow IPv6 path to a CDN-fronted panel can't stall the handshake.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = ipStrategyDialer(c.ApiIPStrategy)
	client.SetTransport(tr)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	// node_type: a configured NodeType (vmess/vless/trojan/shadowsocks/tuic/
	// hysteria/anytls) makes this an XrayR-style node that talks the per-protocol
	// UniProxy panel API; empty means the unified v2node node.
	// Accept any case (XrayR uses ToLower); the panel matches lowercase.
	nt := strings.ToLower(c.NodeType)
	nodeType := "v2node"
	if nt != "" {
		nodeType = nt
	}
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": nodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:   client,
		Token:    c.Key,
		APIHost:  c.APIHost,
		NodeId:   c.NodeID,
		NodeType: nt,
		UserList: &UserListBody{},
		AliveMap: &AliveMap{},
	}, nil
}

// ipStrategyDialer returns a DialContext for the panel API HTTP client per the
// configured strategy:
//   - "ipv4": dial tcp4 only
//   - "ipv6": dial tcp6 only
//   - "auto"/"" (default): try IPv4 first, fall back to IPv6
func ipStrategyDialer(strategy string) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	switch strings.ToLower(strategy) {
	case "ipv4":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" {
				network = "tcp4"
			}
			return d.DialContext(ctx, network, addr)
		}
	case "ipv6":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" {
				network = "tcp6"
			}
			return d.DialContext(ctx, network, addr)
		}
	default: // auto: prefer IPv4, fall back to IPv6
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" {
				if conn, err := d.DialContext(ctx, "tcp4", addr); err == nil {
					return conn, nil
				}
				return d.DialContext(ctx, "tcp6", addr)
			}
			return d.DialContext(ctx, network, addr)
		}
	}
}
