package singbridge

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/xtls/xray-core/common"
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
	// v2node patch — the actual fix for "SS/SS2022/TUIC RSS climbs with no
	// traffic". sing's bufio.CopyConn runs a task.Group that waits for BOTH copy
	// directions to finish (group.Run's `<-taskContext.Done()`), and its cleanup
	// closes the conns via common.Close — but PipeConnWrapper.Close() is a no-op,
	// so closing "source" never closes the inbound pipe. When a client half-closes
	// then goes silent, the upload-direction Read (on link.Reader) blocks forever,
	// group.Run never returns, and the copy goroutines + their SS AEAD reader/
	// writer buffers are pinned for the process lifetime. A plain context cancel
	// does NOT help, because the cancel path still relies on that no-op Close.
	//
	// So on genuine both-directions-idle we forcibly tear the connection down:
	// interrupt the inbound pipe reader (unblocks the upload Read) and close both
	// real sockets (unblocks the download Read). That makes CopyConn actually
	// return so the buffers are freed. activityConn refreshes the timer on every
	// read, so an active connection is never reaped — only a half-dead/idle one.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	teardown := func() {
		once.Do(func() {
			common.Interrupt(link.Reader)
			common.Close(link.Writer)
			if inboundConn != nil {
				_ = inboundConn.Close()
			}
			if serverConn != nil {
				_ = serverConn.Close()
			}
		})
	}

	timer := signal.CancelAfterInactivity(ctx, func() { teardown(); cancel() }, ssInboundIdleTimeout)
	err := ReturnError(bufio.CopyConn(ctx,
		&activityConn{Conn: conn, timer: timer},
		&activityConn{Conn: serverConn, timer: timer}))
	// On normal completion, STOP the inactivity timer — do not merely tear the
	// sockets down. CancelAfterInactivity runs a recurring task.Periodic that
	// keeps the onTimeout closure (which captures inboundConn/serverConn — the
	// ~72KB SS AEAD reader+writer) reachable until it next fires, i.e. for up to
	// one full 5-minute interval AFTER the connection has already closed. Closing
	// the sockets does not free that memory because the timer still references the
	// conns, so on a high-churn box every finished SS conn lingers ~5min and they
	// pile up into hundreds of MB of dead reader/writer buffers. SetTimeout(0)
	// fires the once-guarded teardown and closes the timer's check task, releasing
	// the closure now so the conns become collectable immediately.
	timer.SetTimeout(0)
	return err
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
