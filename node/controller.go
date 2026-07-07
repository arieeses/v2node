package node

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/task"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
	"github.com/wyx2685/v2node/limiter"
)

type Controller struct {
	server                  *core.V2Core
	apiClient               *panel.Client
	tag                     string
	limiter                 *limiter.Limiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	conf                    *conf.NodeConfig
	global                  conf.GlobalConfig
	info                    *panel.NodeInfo
	nodeInfoMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	reconcileCounter        int
	// auto-speed-limit state
	reportInterval time.Duration
	speedWarn      map[int]int // UID -> consecutive over-limit cycles
}

// NewController return a Node controller with default parameters.
func NewController(api *panel.Client, conf *conf.NodeConfig, info *panel.NodeInfo, global conf.GlobalConfig) *Controller {
	controller := &Controller{
		apiClient: api,
		info:      info,
		conf:      conf,
		global:    global,
		speedWarn: make(map[int]int),
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start(x *core.V2Core) error {
	// Init Core
	c.server = x
	var err error
	// Bound the startup fetches so a hung panel can't block Start forever.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// First fetch Node Info
	node := c.info
	if node == nil {
		c.info, err = c.apiClient.GetNodeInfo(ctx)
		if err != nil {
			return fmt.Errorf("get node info error: %s", err)
		}
		node = c.info
	}
	// Update user
	var initUserEtag string
	c.userList, initUserEtag, err = c.apiClient.GetUserList(ctx)
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	c.apiClient.CommitUserEtag(initUserEtag)
	if len(c.userList) == 0 {
		log.WithField("tag", node.Tag).Warn("No users found, node will start and wait for users")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive(ctx)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Get alive list failed, using empty")
		c.aliveMap = make(map[int]int)
	}
	c.tag = node.Tag

	// add limiter (node-level SpeedLimit + local DeviceLimit fallback)
	l := limiter.AddLimiter(c.info.Type, c.tag, c.userList, c.aliveMap, c.conf.SpeedLimit, c.conf.DeviceLimit)
	c.limiter = l
	// Apply local cert override: domain stays from the panel (server_name);
	// only the issuance method + secrets come from config.
	c.applyCertOverride()
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.conf.SniffDisabled(c.global))
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	if len(c.userList) > 0 {
		added, err := c.server.AddUsers(&core.AddUsersParams{
			Tag:      c.tag,
			Users:    c.userList,
			NodeInfo: node,
		})
		if err != nil {
			return fmt.Errorf("add users error: %s", err)
		}
		log.WithField("tag", c.tag).Infof("Added %d new users", added)
	}
	c.info = node
	c.startTasks(node)
	return nil
}

// applyCertOverride overlays the local cert config onto the panel-provided
// CertInfo. The certificate DOMAIN is deliberately left as the panel's
// server_name; only CertMode/Provider/Email/DNSEnv/CertFile/KeyFile are
// overridden so DNS API secrets never need to live in the panel.
func (c *Controller) applyCertOverride() {
	cc := c.conf.EffectiveCert(c.global)
	if cc == nil || c.info == nil || c.info.Common == nil || c.info.Common.CertInfo == nil {
		return
	}
	ci := c.info.Common.CertInfo
	if cc.CertMode != "" {
		ci.CertMode = cc.CertMode
	}
	if cc.Provider != "" {
		ci.Provider = cc.Provider
	}
	if cc.Email != "" {
		ci.Email = cc.Email
	}
	if len(cc.DNSEnv) > 0 {
		ci.DNSEnv = cc.DNSEnv
	}
	if cc.CertFile != "" {
		ci.CertFile = cc.CertFile
	}
	if cc.KeyFile != "" {
		ci.KeyFile = cc.KeyFile
	}
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	limiter.DeleteLimiter(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}
