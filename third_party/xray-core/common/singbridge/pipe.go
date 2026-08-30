package singbridge

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

// ssInboundIdleTimeout bounds a sing-based inbound copy (Shadowsocks / SS2022 /
// TUIC) when it goes idle in BOTH directions. sing's bufio.CopyConn waits for
// BOTH copy directions to finish and provides NO inactivity timeout, so when a
// client half-closes and then goes silent (a dropped mobile client, or a
// connection-pooling relay that holds the socket open), the surviving direction
// blocks on Read forever — the connection and its SS AEAD reader/writer buffers
// are never freed, so RSS climbs even with no traffic. (v2node patch.)
const ssInboundIdleTimeout = 5 * time.Minute

func CopyConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, serverConn net.Conn) error {
	conn := &PipeConnWrapper{
		W:    link.Writer,
		Conn: inboundConn,
	}
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	// v2node patch: cancel the copy when both directions have been idle for
	// ssInboundIdleTimeout so sing's group tears down and the buffers are freed.
	// Wrapping both conns updates the timer on any read; hiding the WriteCloser
	// interface also makes sing full-close (not CloseWrite) each side when a
	// direction ends, promptly unblocking the other (half-close teardown).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, ssInboundIdleTimeout)
	return ReturnError(bufio.CopyConn(ctx,
		&activityConn{Conn: conn, timer: timer},
		&activityConn{Conn: serverConn, timer: timer}))
}

// activityConn refreshes an inactivity timer on every non-empty read so an
// active connection is never reaped, while an idle one lets the timer fire.
type activityConn struct {
	net.Conn
	timer *signal.ActivityTimer
}

func (c *activityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.timer.Update()
	}
	return n, err
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn
}

func (w *PipeConnWrapper) Close() error {
	return nil
}

func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	// Delegate to underlying reader; timeout/sniffing are handled upstream
	return w.R.Read(b)
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}
