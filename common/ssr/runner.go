// runner.go: one SSR node's listener + per-user map, bridging decoded streams
// into the Xray dispatcher (per-user accounting/limits/routing). SPMU: the node
// shares one cipher password; each user carries a userID the auth protocol maps
// to that user's key (O(1), no trial decryption).
package ssr

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	xnet "github.com/xtls/xray-core/common/net"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

// ssrSettings is the subset of network_settings the runner needs.
type ssrSettings struct {
	Cipher    string `json:"cipher"`
	Password  string `json:"password"`   // node shared cipher password (SPMU)
	Protocol  string `json:"protocol"`
	Obfs      string `json:"obfs"`
	ObfsParam string `json:"obfs_param"`
}

type userEntry struct {
	userKey []byte
	uuid    string
}

type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu     sync.RWMutex
	srv    *server
	ln     net.Listener
	byID   map[uint32]userEntry // userID -> entry
	uuids  map[string]uint32    // uuid -> userID (for DelUsers)
	hashFn func([]byte) []byte  // per-protocol user-key hash
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, byID: map[uint32]userEntry{}, uuids: map[string]uint32{}}
}

func (r *Runner) settings() ssrSettings {
	var s ssrSettings
	if r.info != nil && r.info.Common != nil && len(r.info.Common.NetworkSettings) > 0 {
		_ = json.Unmarshal(r.info.Common.NetworkSettings, &s)
	}
	return s
}

func (r *Runner) lookup(userID uint32) ([]byte, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byID[userID]
	return e.userKey, e.uuid, ok
}

func (r *Runner) startLocked() error {
	s := r.settings()
	opt := Options{Cipher: s.Cipher, Password: s.Password, Protocol: s.Protocol, Obfs: s.Obfs, ObfsHost: s.ObfsParam}
	if opt.Cipher == "" {
		opt.Cipher = "aes-256-cfb"
	}
	if opt.Protocol == "" {
		opt.Protocol = "auth_aes128_sha1"
	}
	if opt.Password == "" {
		opt.Password = "v2node" // shared cipher password; must match the panel default
	}
	switch opt.Protocol {
	case "auth_aes128_md5":
		r.hashFn = md5Sum
	case "auth_chain_a", "auth_chain_b":
		// auth_chain user key = raw protocol-param password (the uuid), unhashed.
		r.hashFn = func(b []byte) []byte { return b }
	default:
		r.hashFn = sha1Sum
	}
	srv, err := newServer(opt, r.lookup)
	if err != nil {
		return fmt.Errorf("ssr: build server: %w", err)
	}
	// (re)hash all known users now that hashFn is set.
	for uuid, id := range r.uuids {
		r.byID[id] = userEntry{userKey: r.hashFn([]byte(uuid)), uuid: uuid}
	}

	listenIP := "0.0.0.0"
	if r.info.Common.ListenIP != "" {
		listenIP = r.info.Common.ListenIP
	}
	addr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", r.info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssr: listen %s: %w", addr, err)
	}
	r.srv = srv
	r.ln = ln
	go r.acceptLoop(ln, srv)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort, "cipher": opt.Cipher, "protocol": opt.Protocol, "obfs": opt.Obfs}).Info("ssr server started")
	return nil
}

func (r *Runner) acceptLoop(ln net.Listener, srv *server) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			uuid, dest, pc, err := srv.handshake(c)
			if err != nil {
				_ = c.Close()
				log.WithFields(log.Fields{"tag": r.tag}).Debugf("ssr: handshake: %v", err)
				return
			}
			r.dispatch(uuid, xnet.DestinationFromAddr(c.RemoteAddr()), dest, pc)
		}(conn)
	}
}

func (r *Runner) dispatch(uuid string, source, dest xnet.Destination, pc net.Conn) {
	email := format.UserTag(r.tag, uuid)
	dctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: source, // required: the dispatcher's limiter reads Source.Address.IP()
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})
	link, err := r.disp.Dispatch(dctx, dest)
	if err != nil {
		_ = pc.Close()
		return
	}
	_ = singbridge.CopyConn(dctx, nil, link, pc)
}

func (r *Runner) AddUsers(users []panel.UserInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range users {
		id := uint32(users[i].Id)
		r.uuids[users[i].Uuid] = id
		key := []byte(users[i].Uuid)
		if r.hashFn != nil {
			key = r.hashFn([]byte(users[i].Uuid))
		}
		r.byID[id] = userEntry{userKey: key, uuid: users[i].Uuid}
	}
	if r.ln == nil {
		if len(r.byID) == 0 {
			return nil
		}
		return r.startLocked()
	}
	return nil
}

func (r *Runner) DelUsers(uuids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uuids {
		if id, ok := r.uuids[u]; ok {
			delete(r.byID, id)
			delete(r.uuids, u)
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
