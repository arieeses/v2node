// Package sudoku terminates a v2board "protocol=sudoku" node and bridges every
// stream into the Xray dispatcher, so per-user traffic accounting, speed/device
// limits and routing run through the same pipeline as the native protocols.
//
// Multi-user is O(1): the node holds ONE shared master public key (all crypto
// uses it), and each client carries an 8-byte UserHash in the KIP hello. The
// runner keeps a {UserHash -> uuid} map (rebuilt only on user changes) and does
// a single map lookup per connection — no per-user crypto, so per-connection
// cost is constant regardless of how many users the node serves.
package sudoku

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	sudokubridge "github.com/SUDOKU-ASCII/sudoku/v2bridge"
	log "github.com/sirupsen/logrus"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

// sudokuSettings is the subset of the node's network_settings the runner needs.
// The panel provisions the node master public key here (split private keys go to
// the clients); the rest mirror the sudoku server config.
type sudokuSettings struct {
	MasterKey          string `json:"master_key"`
	AEADMethod         string `json:"aead_method"`
	AEAD               string `json:"aead"`
	TableType          string `json:"table_type"`
	ASCII              string `json:"ascii"`
	PaddingMin         int    `json:"padding_min"`
	PaddingMax         int    `json:"padding_max"`
	EnablePureDownlink *bool  `json:"enable_pure_downlink"` // 指针:区分「未配置」与「显式 false」
	FallbackAddress    string `json:"fallback_address"`
	SuspiciousAction   string `json:"suspicious_action"`
}

// Runner owns one sudoku node's listener + server codec and bridges to the
// dispatcher. Users start empty (AddNode runs before AddUsers); the listener is
// started lazily on the first user so an empty node cannot accept junk.
type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu       sync.RWMutex
	server   *sudokubridge.Server
	ln       net.Listener
	hashUser map[string]string // UserHash(hex) -> uuid
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, hashUser: map[string]string{}}
}

func (r *Runner) settings() sudokuSettings {
	var s sudokuSettings
	if r.info != nil && r.info.Common != nil && len(r.info.Common.NetworkSettings) > 0 {
		_ = json.Unmarshal(r.info.Common.NetworkSettings, &s)
	}
	return s
}

// startLocked builds the server codec and starts the listener. Caller holds r.mu.
func (r *Runner) startLocked() error {
	s := r.settings()
	aead := s.AEADMethod
	if aead == "" {
		aead = s.AEAD
	}
	if aead == "" {
		aead = "chacha20-poly1305"
	}
	table := s.TableType
	if table == "" {
		table = s.ASCII
	}
	if table == "" {
		table = "prefer_ascii"
	}
	susp := s.SuspiciousAction
	if susp == "" && s.FallbackAddress != "" {
		susp = "fallback"
	}
	// 对齐 mihomo transport/sudoku 的 DefaultConfig:pure 下行默认 true、padding 默认
	// 10/30。客户端(mihomo)未配时也走这些默认,服务端必须一致,否则下行 obfs 帧格式
	// 不符、握手后死锁。显式配置(含 false)则尊重。
	pure := true
	if s.EnablePureDownlink != nil {
		pure = *s.EnablePureDownlink
	}
	pmin, pmax := s.PaddingMin, s.PaddingMax
	if pmin == 0 && pmax == 0 {
		pmin, pmax = 10, 30
	}
	srv, err := sudokubridge.NewServer(sudokubridge.Options{
		Key:                s.MasterKey,
		AEAD:               aead,
		TableType:          table,
		PaddingMin:         pmin,
		PaddingMax:         pmax,
		EnablePureDownlink: pure,
		FallbackAddr:       s.FallbackAddress,
		SuspiciousAction:   susp,
	}, r)
	if err != nil {
		return fmt.Errorf("sudoku: build server: %w", err)
	}

	listenIP := "0.0.0.0"
	if r.info.Common.ListenIP != "" {
		listenIP = r.info.Common.ListenIP
	}
	addr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", r.info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sudoku: listen %s: %w", addr, err)
	}
	r.server = srv
	r.ln = ln
	go r.acceptLoop(ln)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort}).Info("sudoku server started")
	return nil
}

func (r *Runner) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on teardown
		}
		r.mu.RLock()
		srv := r.server
		r.mu.RUnlock()
		if srv == nil {
			_ = conn.Close()
			continue
		}
		go srv.ServeConn(conn)
	}
}

// DialTarget implements sudokubridge.Dialer: resolve the user from the UserHash,
// dispatch to the target through the Xray dispatcher (so traffic is counted and
// limits applied under this user), and return the link as a net.Conn.
func (r *Runner) DialTarget(userHash, targetAddr string, source net.Addr) (net.Conn, error) {
	r.mu.RLock()
	uuid := r.hashUser[userHash]
	r.mu.RUnlock()
	if uuid == "" {
		return nil, fmt.Errorf("sudoku: unknown user hash %s", userHash)
	}

	dest, err := xnet.ParseDestination("tcp:" + targetAddr)
	if err != nil {
		return nil, fmt.Errorf("sudoku: bad target %s: %w", targetAddr, err)
	}

	email := format.UserTag(r.tag, uuid)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: xnet.DestinationFromAddr(source),
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})

	link, err := r.disp.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer),
		cnc.ConnectionOutputMulti(link.Reader),
	), nil
}

// AddUsers merges users and (re)starts the listener on the first user.
func (r *Runner) AddUsers(users []panel.UserInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range users {
		if users[i].Key == "" {
			continue // no UserHash provisioned for this user; skip
		}
		r.hashUser[users[i].Key] = users[i].Uuid
	}
	if r.ln == nil {
		if len(r.hashUser) == 0 {
			return nil
		}
		return r.startLocked()
	}
	return nil
}

// DelUsers removes users (by uuid) from the hash map.
func (r *Runner) DelUsers(uuids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	drop := make(map[string]struct{}, len(uuids))
	for _, u := range uuids {
		drop[u] = struct{}{}
	}
	for h, u := range r.hashUser {
		if _, ok := drop[u]; ok {
			delete(r.hashUser, h)
		}
	}
}

func (r *Runner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		err := r.ln.Close()
		r.ln = nil
		return err
	}
	return nil
}
