package snell

import (
	"context"
	"net"
	"strings"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// parseObfsMode maps the panel's obfs string to a sing-snell obfs mode.
func parseObfsMode(s string) snell.ObfsMode {
	switch strings.ToLower(s) {
	case "http":
		return snell.ObfsModeHTTP
	case "tls":
		return snell.ObfsModeTLS
	default:
		return snell.ObfsModeNone
	}
}

// trialCred is one user's v4/v5 per-user PSK and the uuid it belongs to.
type trialCred struct {
	psk  []byte
	uuid string
}

// trialService terminates a v4/v5 snell node where every user has their OWN PSK
// (standard Clash/Surge clients send no ClientID). On each connection it reads
// the plaintext salt once and trial-decrypts the first AEAD record against each
// user's PSK; the wrong PSK fails on the record-header tag after reading only the
// salt + a fixed header (no payload, no hang), so identifying a user costs
// O(users) Argon2 — but only at handshake time. It satisfies the snellService
// interface, so the runner drives it exactly like the v6 MultiService.
type trialService struct {
	runner *Runner
	obfs   snell.ObfsMode

	mu    sync.RWMutex
	creds []trialCred
}

func newTrialService(runner *Runner, obfs snell.ObfsMode) *trialService {
	return &trialService{runner: runner, obfs: obfs}
}

// UpdateUsers rebuilds the (psk -> uuid) credential set. keys[i] is user i's PSK.
func (t *trialService) UpdateUsers(users []string, keys [][]byte) error {
	creds := make([]trialCred, 0, len(users))
	for i := range users {
		if i >= len(keys) || len(keys[i]) == 0 {
			continue
		}
		creds = append(creds, trialCred{psk: keys[i], uuid: users[i]})
	}
	t.mu.Lock()
	t.creds = creds
	t.mu.Unlock()
	return nil
}

// NewConnection identifies the user by trial-decrypting with each PSK, then lets
// the matching single-user snell service drive the real dispatch.
func (t *trialService) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	t.mu.RLock()
	creds := t.creds
	t.mu.RUnlock()

	rw := newRewindConn(conn)
	for i := range creds {
		rw.Rewind()
		h := &trialHandler{runner: t.runner, uuid: creds[i].uuid, rw: rw}
		svc, err := snellv5.NewService(snellv5.ServiceOptions{
			PSK:      creds[i].psk,
			ObfsMode: t.obfs,
			Handler:  h,
		})
		if err != nil {
			continue
		}
		// Wrong PSK: fails at the record header (tag mismatch) having read only the
		// small handshake prefix, which rewindConn replays for the next attempt.
		// Right PSK: the handler is invoked, commits the rewind buffer, and does the
		// real (blocking) dispatch — so this returns only once the stream is done.
		_ = svc.NewConnection(ctx, rw, source, onClose)
		if h.invoked {
			return nil
		}
	}
	_ = conn.Close()
	return nil
}

// trialHandler is a per-connection snell.Handler bound to the uuid of the PSK
// being tried. When snell reaches it, that PSK matched, so it commits the rewind
// buffer and hands off to the runner's shared dispatch under this uuid.
type trialHandler struct {
	runner  *Runner
	uuid    string
	rw      *rewindConn
	invoked bool
}

func (h *trialHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.invoked = true
	h.rw.Commit()
	h.runner.dispatchTCP(h.uuid, conn, source, destination, onClose)
}

func (h *trialHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.invoked = true
	h.rw.Commit()
	h.runner.dispatchUDP(h.uuid, conn, source, destination, onClose)
}

// rewindConn records bytes read from the underlying conn so an unsuccessful
// decrypt attempt can be replayed for the next PSK. Once a PSK matches, Commit
// stops recording and the connection streams straight through. The recorded
// prefix is tiny (salt + one AEAD record header) because a wrong PSK fails on the
// header tag before any payload is read.
type rewindConn struct {
	net.Conn
	buf       []byte
	off       int
	recording bool
}

func newRewindConn(c net.Conn) *rewindConn {
	return &rewindConn{Conn: c, recording: true}
}

func (c *rewindConn) Read(p []byte) (int, error) {
	// Serve buffered (replayed) bytes first.
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	n, err := c.Conn.Read(p)
	if n > 0 && c.recording {
		c.buf = append(c.buf, p[:n]...)
		c.off = len(c.buf)
	}
	return n, err
}

// Rewind resets the read cursor so the recorded prefix is replayed from the start.
func (c *rewindConn) Rewind() {
	c.off = 0
}

// Commit stops recording and drops the already-consumed prefix, keeping any
// buffered-but-unread tail to be served before falling through to the live conn.
func (c *rewindConn) Commit() {
	if c.off < len(c.buf) {
		c.buf = c.buf[c.off:]
	} else {
		c.buf = nil
	}
	c.off = 0
	c.recording = false
}
