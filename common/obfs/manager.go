package obfs

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const dialTimeout = 10 * time.Second

// obfsRelayIdle closes a relayed obfs connection idle in BOTH directions for
// this long, so an idle client cannot pin the copy goroutines and fds forever.
const obfsRelayIdle = 90 * time.Second

// relayBufPool reuses copy buffers across relays so a burst of connections does
// not allocate (and hold) a fresh 32KB buffer per copy goroutine. 16KB is ample
// for TCP copy throughput and halves the per-connection footprint.
var relayBufPool = sync.Pool{New: func() any { b := make([]byte, 16*1024); return &b }}

// clientMaxSeg caps the segment size sent to obfs clients. Mobile paths with a
// small MTU and black-holed PMTUD drop full-size segments; 1200 stays under the
// common mobile MTU floor while costing negligible overhead on good paths.
const clientMaxSeg = 1200

// clampMaxSeg limits the outgoing TCP segment size on an accepted client conn.
func clampMaxSeg(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if rc, err := tc.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { setTCPMaxSeg(int(fd), clientMaxSeg) })
	}
}

// front is one obfs listener on a node's public port, relaying peeled streams
// to the node's loopback Shadowsocks inbound. It runs strictly the configured
// mode (tls or http); a client using the other mode is rejected.
type front struct {
	ln       net.Listener
	loopback string
	mode     int
	host     string
	closing  atomic.Bool
}

// Manager owns one obfs-tls front per Shadowsocks node tag.
type Manager struct {
	mu     sync.Mutex
	fronts map[string]*front
	ports  map[int]string // reserved loopback port -> tag
}

func NewManager() *Manager {
	return &Manager{fronts: make(map[string]*front), ports: make(map[int]string)}
}

// AllocPort reserves a free loopback TCP port for the Xray SS inbound to bind,
// recording it under tag so Stop/Release can free it.
func (m *Manager) AllocPort(tag string) (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("obfs: alloc loopback port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	m.mu.Lock()
	m.ports[port] = tag
	m.mu.Unlock()
	return port, nil
}

// Release frees a port reserved for tag without a running front (rollback path).
func (m *Manager) Release(tag string) {
	m.mu.Lock()
	for p, t := range m.ports {
		if t == tag {
			delete(m.ports, p)
		}
	}
	m.mu.Unlock()
}

// Start opens the public obfs listener for tag and relays to loopbackPort,
// running strictly the given mode ("tls" or "http"). An existing front for the
// tag is replaced.
func (m *Manager) Start(tag, listenIP string, publicPort, loopbackPort int, mode, host string) error {
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	m2 := modeTLS
	if strings.EqualFold(mode, "http") {
		m2 = modeHTTP
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(publicPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("obfs: listen %s: %w", addr, err)
	}
	f := &front{ln: ln, loopback: net.JoinHostPort("127.0.0.1", strconv.Itoa(loopbackPort)), mode: m2, host: host}

	m.mu.Lock()
	if old := m.fronts[tag]; old != nil {
		old.closing.Store(true)
		_ = old.ln.Close()
	}
	m.fronts[tag] = f
	m.ports[loopbackPort] = tag
	m.mu.Unlock()

	go m.acceptLoop(tag, f)
	log.WithFields(log.Fields{"tag": tag, "mode": mode, "public_port": publicPort, "loopback_port": loopbackPort, "host": host}).
		Info("obfs front started")
	return nil
}

func (m *Manager) acceptLoop(tag string, f *front) {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			if f.closing.Load() {
				return
			}
			// Non-temporary listener error (e.g. closed): stop the loop.
			log.WithFields(log.Fields{"tag": tag, "err": err}).Debug("obfs-tls accept ended")
			return
		}
		go relay(conn, f.loopback, f.mode)
	}
}

// relay peels the obfs framing (per the front's fixed mode) off client and
// pipes plaintext to/from the loopback Shadowsocks inbound.
func relay(client net.Conn, loopback string, mode int) {
	defer client.Close()
	clampMaxSeg(client)
	up, err := net.DialTimeout("tcp", loopback, dialTimeout)
	if err != nil {
		return
	}
	defer up.Close()

	// Proxy both ways with a both-sides-idle timeout. When either direction ends
	// OR both sides are silent for obfsRelayIdle, close both ends (closing the
	// underlying client unblocks the obfs-framed copy). Without this, a client
	// that goes idle while the loopback xray keeps its side open would pin the
	// relay + 2 copy goroutines + fds forever.
	oc := newObfsConn(client, mode)
	relayIdle(oc, up, client)
}

// relayIdle copies both ways between framed client conn a and upstream b,
// returning once either side ends or both are idle for obfsRelayIdle, closing
// both (a's underlying socket via closeClient).
func relayIdle(a, b, closeClient net.Conn) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { closeClient.Close(); b.Close() }) }
	var tmu sync.Mutex
	timer := time.AfterFunc(obfsRelayIdle, closeBoth)
	touch := func() { tmu.Lock(); timer.Reset(obfsRelayIdle); tmu.Unlock() }
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		bufp := relayBufPool.Get().(*[]byte)
		buf := *bufp
		defer relayBufPool.Put(bufp)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				touch()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(b, a) // client -> xray
	go cp(a, b) // xray -> client
	<-done
	timer.Stop()
	closeBoth()
	<-done
}

// Stop closes the front for tag (if any) and frees its loopback reservation.
func (m *Manager) Stop(tag string) {
	m.mu.Lock()
	f := m.fronts[tag]
	if f != nil {
		delete(m.fronts, tag)
	}
	for p, t := range m.ports {
		if t == tag {
			delete(m.ports, p)
		}
	}
	m.mu.Unlock()
	if f != nil {
		f.closing.Store(true)
		_ = f.ln.Close()
	}
}

// Has reports whether an obfs-tls front is running for tag.
func (m *Manager) Has(tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.fronts[tag]
	return ok
}

// StopAll closes every front (called on core shutdown/reload).
func (m *Manager) StopAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	tags := make([]string, 0, len(m.fronts))
	for t := range m.fronts {
		tags = append(tags, t)
	}
	m.mu.Unlock()
	for _, t := range tags {
		m.Stop(t)
	}
}
