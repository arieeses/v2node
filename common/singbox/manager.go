package singbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	stopGrace   = 5 * time.Second
	backoffMin  = 1 * time.Second
	backoffMax  = 30 * time.Second
	writeDirPRM = 0o755
)

type instance struct {
	tag      string
	cfgPath  string
	intPort  int
	cancel   context.CancelFunc
	stopping atomic.Bool
	done     chan struct{}
}

// Manager supervises one sing-box process per shadow-tls node tag.
type Manager struct {
	binPath string
	workDir string

	mu    sync.Mutex
	insts map[string]*instance
	ports map[int]string // reserved loopback port -> tag (intra-process guard)
}

// NewManager builds a manager. Call Available() before relying on it.
func NewManager(binPath, workDir string) *Manager {
	m := &Manager{
		binPath: binPath,
		workDir: workDir,
		insts:   make(map[string]*instance),
		ports:   make(map[int]string),
	}
	return m
}

// Available reports whether the sing-box binary exists and is executable.
func (m *Manager) Available() bool {
	if m == nil || m.binPath == "" {
		return false
	}
	fi, err := os.Stat(m.binPath)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&0o111 != 0
}

// AllocPort reserves a free loopback TCP port for the Xray SS inbound to bind,
// recording it under tag so Stop/Release can free it.
func (m *Manager) AllocPort(tag string) (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("alloc loopback port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	m.mu.Lock()
	m.ports[port] = tag
	m.mu.Unlock()
	return port, nil
}

// Release frees a port reserved for tag without a running process (rollback path).
func (m *Manager) Release(tag string) {
	m.mu.Lock()
	for p, t := range m.ports {
		if t == tag {
			delete(m.ports, p)
		}
	}
	m.mu.Unlock()
}

func sanitizeTag(tag string) string {
	repl := strings.NewReplacer("/", "_", ":", "_", "[", "_", "]", "_", " ", "_")
	return repl.Replace(tag)
}

// StartOrReload writes the config for cfg.Tag and (re)spawns the supervised
// process. An existing instance for the tag is stopped first.
func (m *Manager) StartOrReload(cfg *Config) error {
	if !m.Available() {
		return fmt.Errorf("sing-box binary unavailable at %q", m.binPath)
	}
	data, err := cfg.MarshalSingBox()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.workDir, writeDirPRM); err != nil {
		return fmt.Errorf("create sing-box workdir: %w", err)
	}
	cfgPath := filepath.Join(m.workDir, sanitizeTag(cfg.Tag)+".json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}

	// Replace any existing instance for this tag.
	_ = m.Stop(cfg.Tag)

	ctx, cancel := context.WithCancel(context.Background())
	inst := &instance{
		tag:     cfg.Tag,
		cfgPath: cfgPath,
		intPort: cfg.InternalPort,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	m.mu.Lock()
	m.insts[cfg.Tag] = inst
	m.ports[cfg.InternalPort] = cfg.Tag
	m.mu.Unlock()

	go m.supervise(ctx, inst)
	log.WithFields(log.Fields{"tag": cfg.Tag, "public_port": cfg.PublicPort, "internal_port": cfg.InternalPort}).
		Info("sing-box shadow-tls front started")
	return nil
}

// supervise runs sing-box and restarts it with capped backoff until stopped.
func (m *Manager) supervise(ctx context.Context, inst *instance) {
	defer close(inst.done)
	backoff := backoffMin
	for {
		if inst.stopping.Load() || ctx.Err() != nil {
			return
		}
		cmd := exec.CommandContext(ctx, m.binPath, "run", "-c", inst.cfgPath)
		cmd.Stdout = logWriter{tag: inst.tag}
		cmd.Stderr = logWriter{tag: inst.tag}
		start := time.Now()
		err := cmd.Start()
		if err == nil {
			err = cmd.Wait()
		}
		if inst.stopping.Load() || ctx.Err() != nil {
			return
		}
		// Reset backoff if the process stayed up for a healthy while.
		if time.Since(start) > 30*time.Second {
			backoff = backoffMin
		}
		log.WithFields(log.Fields{"tag": inst.tag, "err": err, "backoff": backoff}).
			Warn("sing-box exited, restarting")
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < backoffMax {
			backoff *= 2
			if backoff > backoffMax {
				backoff = backoffMax
			}
		}
	}
}

// Stop terminates the process for tag (if any), removes its config file, and
// frees the reserved loopback port.
func (m *Manager) Stop(tag string) error {
	m.mu.Lock()
	inst := m.insts[tag]
	if inst != nil {
		delete(m.insts, tag)
	}
	for p, t := range m.ports {
		if t == tag {
			delete(m.ports, p)
		}
	}
	m.mu.Unlock()
	if inst == nil {
		return nil
	}
	inst.stopping.Store(true)
	inst.cancel() // sends SIGKILL via CommandContext once grace elapses
	select {
	case <-inst.done:
	case <-time.After(stopGrace):
		log.WithField("tag", tag).Warn("sing-box stop timed out")
	}
	_ = os.Remove(inst.cfgPath)
	return nil
}

// StopAll stops every supervised instance (called on core shutdown/reload).
func (m *Manager) StopAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	tags := make([]string, 0, len(m.insts))
	for t := range m.insts {
		tags = append(tags, t)
	}
	m.mu.Unlock()
	for _, t := range tags {
		_ = m.Stop(t)
	}
}

// logWriter pipes sing-box stdout/stderr into logrus at debug level.
type logWriter struct{ tag string }

func (w logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		log.WithField("tag", w.tag).Debugf("sing-box: %s", msg)
	}
	return len(p), nil
}
