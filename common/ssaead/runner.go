// Package ssaead terminates a v2board "protocol=shadowsocks" node whose cipher
// is one of the EXTENDED AEAD methods that Xray's native shadowsocks cannot do
// (aegis-128l, aegis-256, aes-gcm-siv, ascon, …). It drives metacubex/
// sagernet sing-shadowsocks' shadowaead MultiService (which supports those
// ciphers) and bridges every accepted stream into the Xray dispatcher, so
// per-user accounting, limits and routing run through the same pipeline as the
// native protocols. Standard SS ciphers (aes-128-gcm, aes-256-gcm,
// chacha20-ietf-poly1305) still go through Xray's own shadowsocks inbound.
//
// Multi-user: each user's SS password is their uuid (matching Xray's SS and the
// panel's client config). shadowaead MultiService trial-decrypts the first AEAD
// record against each user's derived key, so the matched user is resolved into
// ctx before the handler runs — O(users) per handshake, like Xray's SS.
package ssaead

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	log "github.com/sirupsen/logrus"
	xnet "github.com/xtls/xray-core/common/net"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/obfs"
)

const udpTimeoutSeconds = 300

// IsExtendedCipher reports whether a shadowsocks cipher must be handled by this
// package (shadowaead) rather than Xray's native shadowsocks inbound. These are
// exactly the AEAD methods shadowaead supports that Xray does not.
func IsExtendedCipher(cipher string) bool {
	switch strings.ToLower(strings.TrimSpace(cipher)) {
	case "aegis-128l", "aegis-256",
		"aes-192-gcm",
		"aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
		"aes-128-gcm-siv", "aes-256-gcm-siv",
		"chacha8-ietf-poly1305", "xchacha8-ietf-poly1305", "xchacha20-ietf-poly1305",
		"rabbit128-poly1305", "aez-384", "deoxys-ii-256-128",
		"lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
		"ascon128", "ascon128a":
		return true
	}
	return false
}

// Runner owns one shadowaead node's MultiService + listener and bridges to the
// dispatcher. The listener starts lazily on the first user.
type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu    sync.Mutex
	svc   *shadowaead.MultiService[string]
	ln    net.Listener
	users map[string]string // uuid -> password (== uuid)
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, users: map[string]string{}}
}

func (r *Runner) cipher() string {
	if r.info != nil && r.info.Common != nil {
		return strings.ToLower(strings.TrimSpace(r.info.Common.Cipher))
	}
	return ""
}

// currentUsersLocked returns the (uuids, passwords) arrays for UpdateUsers.
func (r *Runner) currentUsersLocked() ([]string, []string) {
	uuids := make([]string, 0, len(r.users))
	pwds := make([]string, 0, len(r.users))
	for uuid, pwd := range r.users {
		uuids = append(uuids, uuid)
		pwds = append(pwds, pwd)
	}
	return uuids, pwds
}

func (r *Runner) startLocked() error {
	svc, err := shadowaead.NewMultiService[string](r.cipher(), udpTimeoutSeconds, r)
	if err != nil {
		return fmt.Errorf("ssaead: build %s service: %w", r.cipher(), err)
	}
	uuids, pwds := r.currentUsersLocked()
	if err := svc.UpdateUsersWithPasswords(uuids, pwds); err != nil {
		return fmt.Errorf("ssaead: update users: %w", err)
	}

	listenIP := "0.0.0.0"
	if r.info.Common.ListenIP != "" {
		listenIP = r.info.Common.ListenIP
	}
	addr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", r.info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssaead: listen %s: %w", addr, err)
	}
	r.svc = svc
	r.ln = ln
	go r.acceptLoop(ln, svc)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort, "cipher": r.cipher()}).Info("ssaead server started")
	return nil
}

func (r *Runner) acceptLoop(ln net.Listener, svc *shadowaead.MultiService[string]) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on teardown
		}
		go func(c net.Conn) {
			// simple-obfs (tls/http): strip the obfs layer inline before the SS
			// AEAD, since the extended-cipher path owns the listener directly and
			// does not go through the port-owning obfs front.
			if r.info.Common.SimpleObfsEnabled() {
				c = obfs.NewServerConn(c, r.info.Common.SimpleObfsMode())
			}
			md := M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())}
			_ = svc.NewConnection(context.Background(), c, md)
		}(conn)
	}
}

// NewConnection implements shadowsocks.Handler (TCP): the user is already in ctx
// (MultiService resolved it by trial-decrypt); dispatch under that user.
func (r *Runner) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	uuid, _ := auth.UserFromContext[string](ctx)
	r.dispatchTCP(uuid, conn, metadata.Source, metadata.Destination)
	return nil
}

// NewPacketConnection implements shadowsocks.Handler (UDP).
func (r *Runner) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	uuid, _ := auth.UserFromContext[string](ctx)
	r.dispatchUDP(uuid, conn, metadata.Source, metadata.Destination)
	return nil
}

// NewError implements sing's E.Handler: swallow handshake/probe noise at debug.
func (r *Runner) NewError(_ context.Context, err error) {
	log.WithFields(log.Fields{"tag": r.tag}).Debugf("ssaead: %v", err)
}

// dispatchTCP bridges a decrypted SS stream into the Xray dispatcher (counted/
// limited under uuid), reusing the SS/singbridge conn<->link copy (idle-timeout
// + teardown fixed in v1.0.14).
func (r *Runner) dispatchTCP(uuid string, conn net.Conn, source, destination M.Socksaddr) {
	email := format.UserTag(r.tag, uuid)
	dctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: toXrayDest(source),
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})
	link, err := r.disp.Dispatch(dctx, toXrayDest(destination))
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = singbridge.CopyConn(dctx, nil, link, conn)
}

// dispatchUDP bridges an SS UDP PacketConn onto one dispatcher UDP link.
func (r *Runner) dispatchUDP(uuid string, conn N.PacketConn, source, destination M.Socksaddr) {
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
	_ = err
}

func (r *Runner) AddUsers(users []panel.UserInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range users {
		r.users[users[i].Uuid] = users[i].Uuid // SS password == uuid
	}
	if r.ln == nil {
		if len(r.users) == 0 {
			return nil
		}
		return r.startLocked()
	}
	uuids, pwds := r.currentUsersLocked()
	return r.svc.UpdateUsersWithPasswords(uuids, pwds)
}

func (r *Runner) DelUsers(uuids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uuids {
		delete(r.users, u)
	}
	if r.svc != nil && len(r.users) > 0 {
		uu, pp := r.currentUsersLocked()
		_ = r.svc.UpdateUsersWithPasswords(uu, pp)
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
