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
	// salt is ONE shared salt-replay cache for the whole node. snellv5.NewService
	// allocates its Bloom filters (~5.7MB) lazily on first use; the trial creates a
	// fresh Service per PSK per connection, so WITHOUT sharing, every successful
	// handshake allocated 5.7MB that was used once and GC'd — at any real handshake
	// rate that pinned the CPU in garbage collection and starved the other protocols
	// in the process. Shared, it is allocated once and the replay check actually
	// works across connections.
	salt *snellv5.SaltReplayCache

	mu    sync.RWMutex
	creds []trialCred
}

func newTrialService(runner *Runner, obfs snell.ObfsMode) *trialService {
	return &trialService{runner: runner, obfs: obfs, salt: &snellv5.SaltReplayCache{}}
}

// UpdateUsers rebuilds the (psk -> uuid) credential set. keys[i] is user i's PSK.
// It PRESERVES the current trial order so the self-organizing hot set (see
// promote) survives periodic user reconciles: users still present keep their
// learned position (recently-active ones near the front), and newly-added users
// are appended at the end.
func (t *trialService) UpdateUsers(users []string, keys [][]byte) error {
	newSet := make(map[string][]byte, len(users))
	for i := range users {
		if i < len(keys) && len(keys[i]) > 0 {
			newSet[users[i]] = keys[i]
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	creds := make([]trialCred, 0, len(newSet))
	seen := make(map[string]struct{}, len(newSet))
	for _, c := range t.creds { // keep existing order (hot users stay near front)
		if psk, ok := newSet[c.uuid]; ok {
			creds = append(creds, trialCred{psk: psk, uuid: c.uuid})
			seen[c.uuid] = struct{}{}
		}
	}
	for uuid, psk := range newSet { // append newly-added users
		if _, ok := seen[uuid]; !ok {
			creds = append(creds, trialCred{psk: psk, uuid: uuid})
		}
	}
	t.creds = creds
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
			PSK:       creds[i].psk,
			ObfsMode:  t.obfs,
			Handler:   h,
			SaltCache: t.salt, // ONE shared cache per node — not 5.7MB per handshake
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
			t.promote(creds[i].uuid)
			return nil
		}
	}
	_ = conn.Close()
	return nil
}

// promote moves the matched user to the FRONT of the trial order — a classic
// self-organizing (move-to-front) list. snell v4/v5 clients carry no user tag,
// so identifying a user costs O(users) Argon2 trial-decryptions; without this,
// a single client opening many connections (a browser loading one page opens
// dozens) pays that O(users) cost on EVERY connection, saturating the CPU and
// starving the other protocols sharing the process. With move-to-front, each
// active user floats to the front, so a client's burst pays the full trial only
// on its FIRST connection; the rest match on the first probe (1 Argon2). Measured
// (2000 users, one user opening 20 connections, worst-case last position): 40000
// trial-decryptions -> 2019 (~20x). Auth is unchanged: on a miss every user is
// still tried; only the order changes. Copy-on-write keeps NewConnection's
// snapshot lock-free while this reorders the shared slice.
func (t *trialService) promote(uuid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.creds) == 0 || t.creds[0].uuid == uuid {
		return // already at front
	}
	idx := -1
	for i := range t.creds {
		if t.creds[i].uuid == uuid {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return
	}
	nc := make([]trialCred, 0, len(t.creds))
	nc = append(nc, t.creds[idx])
	nc = append(nc, t.creds[:idx]...)
	nc = append(nc, t.creds[idx+1:]...)
	t.creds = nc
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
