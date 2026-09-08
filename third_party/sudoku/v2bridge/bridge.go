// Package v2bridge exposes sudoku's server-side tunnel as an embeddable library
// for v2node. It performs the KIP handshake, identifies the connecting user by
// the UserHash carried in the client hello, reads the first request, and hands
// each requested target to a caller-provided Dialer instead of dialing the
// target itself — so v2node routes every stream through the Xray dispatcher for
// per-user traffic accounting, speed/device limits and routing, exactly like
// its other protocols.
//
// It lives inside the sudoku module (not v2node) because it must import the
// module's internal/ packages, which Go forbids from another module.
package v2bridge

import (
	"bytes"
	"net"

	"github.com/SUDOKU-ASCII/sudoku/internal/app"
	"github.com/SUDOKU-ASCII/sudoku/internal/config"
	"github.com/SUDOKU-ASCII/sudoku/internal/handler"
	"github.com/SUDOKU-ASCII/sudoku/internal/protocol"
	"github.com/SUDOKU-ASCII/sudoku/internal/tunnel"
	"github.com/SUDOKU-ASCII/sudoku/pkg/connutil"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	sudokuobfs "github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"
)

// Dialer is implemented by the host (v2node). DialTarget must open a connection
// to targetAddr ("host:port") on behalf of the user identified by userHash (an
// 8-byte hex string), and return it as a net.Conn. source is the client's remote
// address (used by the host for per-user online-IP / device limits). Returning an
// error aborts the stream. It is called once per TCP request and once per
// multiplexed sub-stream.
type Dialer interface {
	DialTarget(userHash, targetAddr string, source net.Addr) (net.Conn, error)
	// HandleUDP bridges a UoT (UDP-over-TCP) association for the user. Each call to
	// uc.ReadPacket yields one (targetAddr, payload) datagram to dispatch; responses
	// are written back via uc.WritePacket. The host owns the loop and closes uc.
	HandleUDP(userHash string, uc UoTConn, source net.Addr)
}

// UoTConn exposes a sudoku UoT stream as discrete datagrams to the host, hiding
// the internal wire framing (the host cannot import sudoku's internal packages).
type UoTConn interface {
	// ReadPacket returns the next client datagram: target "host:port" and payload.
	ReadPacket() (addr string, payload []byte, err error)
	// WritePacket sends a response datagram back to the client.
	WritePacket(addr string, payload []byte) error
	Close() error
}

// uotConn wraps a decrypted tunnel conn as a UoTConn using the internal datagram
// codec.
type uotConn struct{ conn net.Conn }

func (u *uotConn) ReadPacket() (string, []byte, error) { return tunnel.ReadUoTDatagram(u.conn) }
func (u *uotConn) WritePacket(addr string, payload []byte) error {
	return tunnel.WriteUoTDatagram(u.conn, addr, payload)
}
func (u *uotConn) Close() error { return u.conn.Close() }

// Options are plain-typed server parameters (sourced from the panel), so the
// host never has to construct sudoku's internal config types.
type Options struct {
	Key                string // master public key (hex)
	AEAD               string // "chacha20-poly1305" | "aes-128-gcm" | "none"
	TableType          string // sudoku ASCII table preference: "prefer_ascii" | "prefer_entropy" | directional
	PaddingMin         int
	PaddingMax         int
	EnablePureDownlink bool
	FallbackAddr       string // decoy target for rejected/suspicious connections
	SuspiciousAction   string // "fallback" | "silent"
}

// Server terminates the sudoku protocol for one node and bridges to the host's
// Dialer. It is safe to hand accepted connections to ServeConn concurrently.
type Server struct {
	cfg       *config.Config
	tables    []*sudokuobfs.Table
	dialer    Dialer
	tunnelSrv *httpmask.TunnelServer // httpmask(HTTP 伪装隧道)服务端;mihomo 默认用它
}

// NewServer builds the server-side codec (tables) from opts. The host runs its
// own listener and feeds accepted connections to ServeConn.
func NewServer(opts Options, dialer Dialer) (*Server, error) {
	cfg := &config.Config{
		Mode:               "server",
		Transport:          "tcp",
		Key:                opts.Key,
		AEAD:               opts.AEAD,
		ASCII:              opts.TableType,
		PaddingMin:         opts.PaddingMin,
		PaddingMax:         opts.PaddingMax,
		EnablePureDownlink: opts.EnablePureDownlink,
		FallbackAddr:       opts.FallbackAddr,
		SuspiciousAction:   opts.SuspiciousAction,
	}
	// 注:EnablePureDownlink 与 padding 的默认值(pure=true、10/30,对齐 mihomo
	// DefaultConfig)由调用方 common/sudoku/runner.go 负责填充,这里只按 opts 使用。
	// 启用 httpmask 隧道:mihomo 的 sudoku 客户端默认把握手包成 HTTP(POST /...),
	// 服务端必须先解这个 HTTP 壳。mode=auto 同时接受 stream/poll/ws。
	cfg.HTTPMask.Mode = "auto"
	// 与上游一致:归一化 cfg(HTTPMask.Mode/Multiplex/ASCII/AEAD 等默认值),否则
	// httpmask/握手行为会和上游不同。
	if err := cfg.Finalize(); err != nil {
		return nil, err
	}
	tables, err := app.BuildTables(cfg)
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, tables: tables, dialer: dialer}
	if cfg.HTTPMaskTunnelEnabled() {
		// 完全对齐上游 internal/app.RunServer 的 TunnelServer 构造(含 AuthKey: cfg.Key)。
		srv.tunnelSrv = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
			Mode:     cfg.HTTPMask.Mode,
			PathRoot: cfg.HTTPMask.PathRoot,
			AuthKey:  cfg.Key,
			EarlyHandshake: tunnel.NewHTTPMaskServerEarlyHandshake(tunnel.EarlyCodecConfig{
				PSK:                cfg.Key,
				AEAD:               cfg.AEAD,
				EnablePureDownlink: cfg.EnablePureDownlink,
				PaddingMin:         cfg.PaddingMin,
				PaddingMax:         cfg.PaddingMax,
			}, tables, tunnel.AllowHandshakeReplay),
			PassThroughOnReject: cfg.SuspiciousAction == "silent" ||
				(cfg.SuspiciousAction == "fallback" && cfg.FallbackAddr != ""),
		})
	}
	return srv, nil
}

// ServeConn handles one accepted raw connection: handshake, identify the user,
// read the first KIP request, and bridge it to the target via the host Dialer.
// It takes ownership of rawConn and always closes the connections it opens.
func (s *Server) ServeConn(rawConn net.Conn) {
	// httpmask 前奏:mihomo 默认把 sudoku 握手包成 HTTP(POST /feed/update ...)。
	// 先让 TunnelServer 解这个 HTTP 壳,拿到承载原始 sudoku 流的内层 conn,再做握手。
	if s.tunnelSrv != nil {
		res, c, err := s.tunnelSrv.HandleConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return
		}
		switch res {
		case httpmask.HandleDone:
			return // 纯控制请求(poll push/pull),本 TCP 连接上不跑握手
		case httpmask.HandleStartTunnel:
			inner := *s.cfg
			inner.HTTPMask.Disable = true // 外层 httpmask 已由 c 处理,内层不再重复
			s.serveHandshake(c, &inner)
			return
		case httpmask.HandlePassThrough:
			s.serveHandshake(c, s.cfg) // 非 httpmask 的原始连接:c 会回放已预读的字节
			return
		default:
			_ = rawConn.Close()
			return
		}
	}
	s.serveHandshake(rawConn, s.cfg)
}

// serveHandshake 完成 sudoku 握手、识别用户、读首个 KIP 请求并桥接到目标。
func (s *Server) serveHandshake(rawConn net.Conn, cfg *config.Config) {
	tunnelConn, meta, err := tunnel.HandshakeAndUpgradeWithTablesMeta(rawConn, cfg, s.tables)
	if err != nil {
		// A suspicious/failed handshake: mimic a decoy when configured, else drop.
		if suspErr, ok := err.(*tunnel.SuspiciousError); ok &&
			s.cfg.SuspiciousAction == "fallback" && s.cfg.FallbackAddr != "" {
			handler.HandleSuspicious(suspErr.Conn, rawConn, s.cfg)
			return
		}
		_ = rawConn.Close()
		return
	}

	userHash := ""
	if meta != nil {
		userHash = meta.UserHash
	}
	source := rawConn.RemoteAddr()

	// First non-keepalive KIP control message selects the session type.
	var msg *tunnel.KIPMessage
	for {
		m, err := tunnel.ReadKIPMessage(tunnelConn)
		if err != nil {
			_ = tunnelConn.Close()
			return
		}
		if m.Type == tunnel.KIPTypeKeepAlive {
			continue
		}
		msg = m
		break
	}

	switch msg.Type {
	case tunnel.KIPTypeOpenTCP:
		destAddr, _, _, err := protocol.ReadAddress(bytes.NewReader(msg.Payload))
		if err != nil {
			_ = tunnelConn.Close()
			return
		}
		target, err := s.dialer.DialTarget(userHash, destAddr, source)
		if err != nil {
			_ = tunnelConn.Close()
			return
		}
		connutil.PipeConn(tunnelConn, target)

	case tunnel.KIPTypeStartMux:
		// Every multiplexed sub-stream is dialed through the host, so each is
		// dispatched (and accounted) individually for this user.
		_ = tunnel.HandleMuxWithDialer(tunnelConn, nil, func(addr string) (net.Conn, error) {
			return s.dialer.DialTarget(userHash, addr, source)
		})

	case tunnel.KIPTypeStartUoT:
		s.dialer.HandleUDP(userHash, &uotConn{conn: tunnelConn}, source)

	default:
		// Reverse-proxy sessions are not bridged.
		_ = tunnelConn.Close()
	}
}
