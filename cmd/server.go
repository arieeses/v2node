package cmd

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wyx2685/v2node/common/memtune"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
	"github.com/wyx2685/v2node/limiter"
	"github.com/wyx2685/v2node/node"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run v2node server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/v2node/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	// Cap steady-state RSS on busy multi-user nodes: auto-set GOMEMLIMIT from the
	// detected machine/cgroup memory so the GC returns pages before an OOM kill.
	memtune.Apply()
	// Return freed heap to the OS periodically so RSS falls back down after a
	// traffic peak instead of lingering at the high-water mark (Go's own
	// scavenger does this only lazily). Interval via V2NODE_MEM_SCAVENGE_SEC.
	memtune.StartScavenger()
	c := conf.New()
	err := c.LoadFromPath(config)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
	})
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "none":
		// Silence everything below panic (no error/warn/info logs, minimal IO).
		log.SetLevel(log.PanicLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		} else {
			log.SetOutput(f)
		}
	}
	// Enable pprof if configured
	if c.PprofPort != 0 {
		go func() {
			log.Infof("Starting pprof server on :%d", c.PprofPort)
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.PprofPort), nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}
	//init limiter
	limiter.Init()
	//get node info
	nodes, err := node.New(c.NodeConfigs, c.Global)
	if err != nil {
		log.WithField("err", err).Error("Get node info failed")
		return
	}
	log.Info("Got nodes info from server")
	//core
	var reloadCh = make(chan struct{}, 1)
	v2core := core.New(c)
	v2core.ReloadCh = reloadCh
	err = v2core.Start(nodes.NodeInfos)
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		return
	}
	defer v2core.Close()
	//node
	err = nodes.Start(v2core)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		return
	}
	log.Info("Nodes started")
	if watch {
		// On file change, just signal reload; do not run reload concurrently here
		err = c.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default: // drop if a reload is already queued
			}
		})
		if err != nil {
			log.WithField("err", err).Error("start watch failed")
			return
		}
	}
	// clear memory
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			log.Info("收到退出信号，正在关闭程序...")
			os.Exit(0)
		case <-reloadCh:
			log.Info("收到重启信号，正在重新加载配置...")
			if err := reload(config, &nodes, &v2core); err != nil {
				log.WithField("err", err).Error("重启失败，保持当前状态运行")
			} else {
				log.Info("重启成功")
			}
		}
	}
}

func reload(config string, nodes **node.Node, v2core **core.V2Core) error {
	// ────────────────────────────────────────────────────────
	// Phase 1: VALIDATE — read new config and fetch all panel
	// data BEFORE touching the running system. If anything
	// fails here, we abort and keep the old nodes running.
	// ────────────────────────────────────────────────────────
	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	newNodes, err := node.New(newConf.NodeConfigs, newConf.Global)
	if err != nil {
		return fmt.Errorf("fetch node info: %w (old nodes still running)", err)
	}

	// ────────────────────────────────────────────────────────
	// Phase 2: TEARDOWN — new config is valid, now tear down
	// the old system. From this point on we MUST succeed or
	// the process is in an inconsistent state.
	// ────────────────────────────────────────────────────────
	var oldReloadCh chan struct{}
	if *v2core != nil {
		oldReloadCh = (*v2core).ReloadCh
	}

	// Keep each surviving node's rate limiter alive across the teardown: capture
	// the old tags now, tear down with CloseForReload (which does NOT delete
	// limiters), then after the rebuild prune only the limiters of nodes that are
	// gone. The old Close deleted EVERY limiter here, leaving a ~teardown-long
	// window with no limiter, during which anytls mux connections that outlive
	// inbound removal flooded "get limiter not found". See Controller.CloseForReload.
	oldTags := (*nodes).Tags()

	if err := (*nodes).CloseForReload(); err != nil {
		log.WithField("err", err).Error("Close old nodes failed during reload")
	}
	if err := (*v2core).Close(); err != nil {
		log.WithField("err", err).Error("Close old core failed during reload")
	}

	// ────────────────────────────────────────────────────────
	// Phase 3: REBUILD — start the new system.
	// ────────────────────────────────────────────────────────
	switch newConf.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "none":
		log.SetLevel(log.PanicLevel)
	}
	if newConf.LogConfig.Output != "" {
		f, err := os.OpenFile(newConf.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		} else {
			// 关闭旧的日志文件（如果是文件）
			if oldWriter, ok := log.StandardLogger().Out.(*os.File); ok && oldWriter != os.Stdout && oldWriter != os.Stderr {
				oldWriter.Close()
			}
			log.SetOutput(f)
		}
	}

	newCore := core.New(newConf)
	newCore.ReloadCh = oldReloadCh
	if err := newCore.Start(newNodes.NodeInfos); err != nil {
		return fmt.Errorf("start new core: %w", err)
	}

	if err := newNodes.Start(newCore); err != nil {
		return fmt.Errorf("start new nodes: %w", err)
	}

	// Prune limiters of nodes that existed before but are gone in the new config.
	// Surviving nodes' limiters were overwritten in place by newNodes.Start
	// (AddLimiter), so they were never absent — no reload window, no flood.
	newTagSet := make(map[string]struct{}, len(newNodes.Tags()))
	for _, t := range newNodes.Tags() {
		newTagSet[t] = struct{}{}
	}
	for _, t := range oldTags {
		if _, ok := newTagSet[t]; !ok {
			limiter.DeleteLimiter(t)
		}
	}

	*nodes = newNodes
	*v2core = newCore

	runtime.GC()
	return nil
}
