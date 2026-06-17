package panel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	"github.com/wyx2685/v2node/conf"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	Token            string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
}

func New(c *conf.NodeConfig) (*Client, error) {
	client := resty.New()
	// Custom transport: reuse connections (fast) but discard idle ones
	// before Cloudflare RSTs them (~60s). This prevents reads on dead
	// connections that cause "connection reset by peer" and hangs.
	client.SetTransport(&http.Transport{
		// CRITICAL: Fully disable HTTP/2. ForceAttemptHTTP2=false alone is NOT
		// enough — Go's TLS ALPN can still negotiate h2 silently. Setting
		// TLSNextProto to an empty non-nil map is the Go-official way to
		// prevent HTTP/2 entirely. Without this, long-lived HTTP/2 connections
		// rot silently, blocking ALL requests on the same multiplexed conn and
		// causing goroutine leaks that lead to OOM kills after hours of uptime.
		ForceAttemptHTTP2: false,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),

		TLSHandshakeTimeout:   10 * time.Second, // don't hang on TLS
		ResponseHeaderTimeout: 15 * time.Second, // don't hang on slow API
		// CRITICAL: Disable keep-alive to force a fresh TCP+TLS connection per
		// API call. v2node only hits the panel every ~60s, so the ~100ms TLS
		// overhead is negligible. But reusing a keep-alive connection that
		// Cloudflare/Nginx silently RST'd (after 1-3h) causes ALL subsequent
		// requests to timeout, killing the heartbeat and making the panel mark
		// the node as offline — even though Xray listeners are perfectly fine.
		// This is the HTTP/1.1 equivalent of the HTTP/2 connection rot that
		// caused OOM kills. Fresh connections every time = zero rot risk.
		DisableKeepAlives: true,
	})
	retryCount := conf.DefaultNodeRetryCount
	if c.RetryCount != nil {
		retryCount = *c.RetryCount
	}
	client.SetRetryCount(retryCount)
	client.SetHeader("User-Agent", fmt.Sprintf("v2node go-resty/%s (https://github.com/go-resty/resty)", resty.Version))
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(time.Duration(conf.DefaultNodeTimeout) * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": "v2node",
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:   client,
		Token:    c.Key,
		APIHost:  c.APIHost,
		NodeId:   c.NodeID,
		UserList: &UserListBody{},
		AliveMap: &AliveMap{},
	}, nil
}
