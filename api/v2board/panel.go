package panel

import (
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
		// CRITICAL: Disable HTTP/2. Go's HTTP/2 connection multiplexing causes
		// "http2: timeout awaiting response headers" after long uptime because
		// a single dead HTTP/2 connection silently blocks ALL requests to the
		// same host. HTTP/1.1 with connection pooling is more resilient: each
		// request gets its own TCP connection, so one dead connection doesn't
		// block others.
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       20 * time.Second, // discard before CF kills at ~60s
		TLSHandshakeTimeout:   10 * time.Second, // don't hang on TLS
		ResponseHeaderTimeout: 15 * time.Second, // don't hang on slow API
		MaxIdleConnsPerHost:   2,                // limit pool size per panel
		MaxConnsPerHost:       4,                // cap total connections per panel
		DisableKeepAlives:     false,            // reuse connections for performance
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
