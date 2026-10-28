// runner.go: one trojan+ss-obfs node's listener, bridging decoded streams into
// the Xray dispatcher. The shadowsocks AEAD layer is node-shared (method +
// password); per-user auth is the inner trojan SHA224(uuid). When the node has
// TLS enabled, the accepted connection is TLS-terminated before the ss layer.
package trojanss

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
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

// flexBool unmarshals a JSON boolean, OR the string/number forms panels store it
// as ("true"/"false"/"1"/"0"/1/0). Panels (and their admin JSON editors) often
// persist booleans as strings; with a plain bool field a value of "true" makes
// the whole json.Unmarshal fail with an UnmarshalTypeError, which silently
// disabled the entire ss-obfs layer (node fell back to plain trojan). Parsing it
// leniently keeps ss-obfs working regardless of how the panel serialized it.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(string(data)), `"`))
	*b = s == "true" || s == "1"
	return nil
}

// SSObfs is the ss-obfs block inside a trojan node's network_settings.
type SSObfs struct {
	Enabled  flexBool `json:"enabled"`
	Method   string   `json:"method"`
	Password string   `json:"password"`
}

type networkSettings struct {
	SSObfs SSObfs `json:"ss_obfs"`
}

// Enabled reports whether a trojan node's network_settings turns on ss-obfs.
func Enabled(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s networkSettings
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	return bool(s.SSObfs.Enabled)
}

type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu     sync.RWMutex
	ln     net.Listener
	method string
	key    []byte
	tlsCfg *tls.Config
	byKey  map[string]string // hex(SHA224(uuid)) -> uuid
	uuids  map[string]string // uuid -> hexKey (for DelUsers)
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, byKey: map[string]string{}, uuids: map[string]string{}}
}

func (r *Runner) settings() SSObfs {
	var s networkSettings
	if r.info != nil && r.info.Common != nil && len(r.info.Common.NetworkSettings) > 0 {
		_ = json.Unmarshal(r.info.Common.NetworkSettings, &s)
	}
	return s.SSObfs
}

func userHexKey(uuid string) string {
	h := sha256.Sum224([]byte(uuid))
	return hex.EncodeToString(h[:])
}

func (r *Runner) lookup(hexKey string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uuid, ok := r.byKey[hexKey]
	return uuid, ok
}

func (r *Runner) startLocked() error {
	ss := r.settings()
	r.method = ss.Method
	if r.method == "" {
		r.method = "AES-128-GCM"
	}
	kl, err := ssKeyLen(r.method)
	if err != nil {
		return err
	}
	r.key = evpBytesToKey(ss.Password, kl)

	// Optional TLS: terminate it before the ss layer (TLS -> ss -> trojan).
	if r.info.Common != nil && r.info.Common.Tls == 1 && r.info.Common.CertInfo != nil {
		cert, cerr := tls.LoadX509KeyPair(r.info.Common.CertInfo.CertFile, r.info.Common.CertInfo.KeyFile)
		if cerr != nil {
			return fmt.Errorf("trojanss: load cert: %w", cerr)
		}
		r.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	listenIP := "0.0.0.0"
	if r.info.Common != nil && r.info.Common.ListenIP != "" {
		listenIP = r.info.Common.ListenIP
	}
	addr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", r.info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("trojanss: listen %s: %w", addr, err)
	}
	r.ln = ln
	go r.acceptLoop(ln)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort, "method": r.method, "tls": r.tlsCfg != nil}).Info("trojan ss-obfs server started")
	return nil
}

func (r *Runner) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			if r.tlsCfg != nil {
				tconn := tls.Server(c, r.tlsCfg)
				if err := tconn.Handshake(); err != nil {
					_ = c.Close()
					return
				}
				c = tconn
			}
			hexKey, dest, pc, err := handshake(c, r.method, r.key)
			if err != nil {
				_ = c.Close()
				log.WithFields(log.Fields{"tag": r.tag}).Debugf("trojanss: handshake: %v", err)
				return
			}
			uuid, ok := r.lookup(hexKey)
			if !ok {
				_ = c.Close()
				log.WithFields(log.Fields{"tag": r.tag}).Debug("trojanss: unknown user")
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
		Source: source,
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
		hk := userHexKey(users[i].Uuid)
		r.byKey[hk] = users[i].Uuid
		r.uuids[users[i].Uuid] = hk
	}
	if r.ln == nil {
		if len(r.byKey) == 0 {
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
		if hk, ok := r.uuids[u]; ok {
			delete(r.byKey, hk)
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
