// Package snell terminates a v2board "protocol=snell" node using the sing-snell
// server and bridges every stream into the Xray dispatcher, so per-user traffic
// accounting, speed/device limits and routing run through the same pipeline as
// the native protocols.
//
// Multi-user is O(1): the node holds ONE shared PSK (all AEAD crypto uses it),
// and each client carries a per-user ClientID (snell v5/v6's on-wire user tag).
// sing-snell's MultiService resolves the user by a single map lookup on the
// ClientID — no per-user trial decryption. v6 is the recommended mode (shared
// PSK + ClientID by design); v5 is supported for older clients.
package snell

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	log "github.com/sirupsen/logrus"
	xnet "github.com/xtls/xray-core/common/net"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

// snellService is the shared surface of snellv5/v6 MultiService the runner uses.
type snellService interface {
	NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error
	UpdateUsers(users []string, userKeys [][]byte) error
}

// snellSettings is the subset of the node's network_settings the runner needs.
type snellSettings struct {
	Version int    `json:"version"`
	PSK     string `json:"psk"`     // shared node PSK (12..255 bytes)
	Obfs    string `json:"obfs"`    // v4/v5 only: "" | "http" | "tls"
	Mode    string `json:"v6_mode"` // v6 only: "default" | "unshaped"
}

// Runner owns one snell node's MultiService + listener and bridges to the
// dispatcher. The listener starts lazily on the first user.
type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu    sync.RWMutex
	svc   snellService
	ln    net.Listener
	users map[string]string // uuid -> ClientID
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, users: map[string]string{}}
}

func (r *Runner) settings() snellSettings {
	var s snellSettings
	if r.info != nil && r.info.Common != nil && len(r.info.Common.NetworkSettings) > 0 {
		_ = json.Unmarshal(r.info.Common.NetworkSettings, &s)
	}
	return s
}

// currentUsersLocked returns the (uuids, clientIDs) arrays for UpdateUsers.
func (r *Runner) currentUsersLocked() ([]string, [][]byte) {
	uuids := make([]string, 0, len(r.users))
	keys := make([][]byte, 0, len(r.users))
	for uuid, cid := range r.users {
		uuids = append(uuids, uuid)
		keys = append(keys, []byte(cid))
	}
	return uuids, keys
}

func (r *Runner) startLocked() error {
	s := r.settings()

	var svc snellService
	if s.Version >= 6 {
		// v6: ONE shared node PSK does all the AEAD; users are told apart by a
		// per-user ClientID the client sends (O(1) map lookup, no per-user crypto).
		psk := []byte(s.PSK)
		if len(psk) < 12 {
			return fmt.Errorf("snell v6: shared PSK must be >= 12 bytes")
		}
		mode := snellv6.ModeDefault
		if m, err := snellv6.ParseMode(s.Mode); err == nil {
			mode = m
		}
		ms, err := snellv6.NewMultiService[string](snellv6.ServerOptions{
			PSK:     psk,
			Mode:    mode,
			Handler: r,
		})
		if err != nil {
			return fmt.Errorf("snell v6: %w", err)
		}
		svc = ms
	} else {
		// v4/v5 backward-compat: standard Clash/Surge clients send only a PSK and
		// no ClientID, so users are told apart by a PER-USER PSK. The trial service
		// reads the plaintext salt then tries each user's PSK against the first
		// AEAD record (wrong PSK fails on the tag, fast, before any payload read),
		// so Clash/Mihomo work at the cost of O(users) Argon2 per handshake.
		svc = newTrialService(r, parseObfsMode(s.Obfs))
	}

	uuids, keys := r.currentUsersLocked()
	if err := svc.UpdateUsers(uuids, keys); err != nil {
		return fmt.Errorf("snell: update users: %w", err)
	}

	listenIP := "0.0.0.0"
	if r.info.Common.ListenIP != "" {
		listenIP = r.info.Common.ListenIP
	}
	addr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", r.info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("snell: listen %s: %w", addr, err)
	}
	r.svc = svc
	r.ln = ln
	go r.acceptLoop(ln, svc)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort, "version": s.Version}).Info("snell server started")
	return nil
}

func (r *Runner) acceptLoop(ln net.Listener, svc snellService) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on teardown
		}
		go func(c net.Conn) {
			source := M.SocksaddrFromNet(c.RemoteAddr())
			_ = svc.NewConnection(context.Background(), c, source, nil)
		}(conn)
	}
}

// NewConnectionEx implements snell.Handler (TCP): the user is already resolved
// into ctx by the v6 MultiService; dispatch under that user.
func (r *Runner) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	uuid, _ := auth.UserFromContext[string](ctx)
	r.dispatchTCP(uuid, conn, source, destination, onClose)
}

// NewPacketConnectionEx implements snell.Handler (UDP-over-TCP): user resolved by
// the v6 MultiService.
func (r *Runner) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	uuid, _ := auth.UserFromContext[string](ctx)
	r.dispatchUDP(uuid, conn, source, destination, onClose)
}

// dispatchTCP bridges a decrypted snell TCP stream into the Xray dispatcher
// (counted/limited under uuid). Shared by the v6 handler (user from ctx) and the
// v4/v5 trial handler (user known from the matched per-user PSK).
func (r *Runner) dispatchTCP(uuid string, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	email := format.UserTag(r.tag, uuid)
	dctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: toXrayDest(source),
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})
	link, err := r.disp.Dispatch(dctx, toXrayDest(destination))
	if err != nil {
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	// Reuse the SS/singbridge conn<->link copy (idle-timeout + teardown fixed in
	// v1.0.14) so a half-dead snell stream cannot pin its buffers.
	err = singbridge.CopyConn(dctx, nil, link, conn)
	if onClose != nil {
		onClose(err)
	}
}

// dispatchUDP bridges a snell UoT PacketConn onto one dispatcher UDP link. Each
// datagram carries its own target via the buffer's .UDP endpoint (full-cone).
func (r *Runner) dispatchUDP(uuid string, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	email := format.UserTag(r.tag, uuid)
	dctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: toXrayDest(source),
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})
	err := r.disp.DispatchLink(dctx, toXrayDestUDP(destination), &transport.Link{
		Reader: &packetReader{conn: conn},
		Writer: &packetWriter{conn: conn},
	})
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (r *Runner) AddUsers(users []panel.UserInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range users {
		cid := users[i].Key
		if cid == "" {
			cid = users[i].Uuid // fall back to uuid as ClientID when unset
		}
		r.users[users[i].Uuid] = cid
	}
	if r.ln == nil {
		if len(r.users) == 0 {
			return nil
		}
		return r.startLocked()
	}
	uuids, keys := r.currentUsersLocked()
	return r.svc.UpdateUsers(uuids, keys)
}

func (r *Runner) DelUsers(uuids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uuids {
		delete(r.users, u)
	}
	if r.svc != nil && len(r.users) > 0 {
		uu, kk := r.currentUsersLocked()
		_ = r.svc.UpdateUsers(uu, kk)
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

// toXrayDest converts a sing Socksaddr to an xray TCP Destination.
func toXrayDest(a M.Socksaddr) xnet.Destination {
	if a.IsIP() {
		return xnet.TCPDestination(xnet.IPAddress(a.Addr.AsSlice()), xnet.Port(a.Port))
	}
	return xnet.TCPDestination(xnet.DomainAddress(a.Fqdn), xnet.Port(a.Port))
}
