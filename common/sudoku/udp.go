package sudoku

import (
	"context"
	"net"

	sudokubridge "github.com/SUDOKU-ASCII/sudoku/v2bridge"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"

	"github.com/wyx2685/v2node/common/format"
)

// uotReader adapts a UoT stream (uplink, client -> target) to an xray buf.Reader:
// each datagram becomes one buffer whose .UDP endpoint is the datagram's target,
// so the dispatcher/outbound routes every packet independently (full-cone).
type uotReader struct {
	uc    sudokubridge.UoTConn
	first *buf.Buffer // primed first packet (already read to choose the route dest)
}

func (r *uotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.first != nil {
		b := r.first
		r.first = nil
		return buf.MultiBuffer{b}, nil
	}
	addr, payload, err := r.uc.ReadPacket()
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{packetBuffer(addr, payload)}, nil
}

func (r *uotReader) Close() error { return nil }

// uotWriter adapts xray downlink buffers (target -> client) back onto the UoT
// stream, using each buffer's .UDP endpoint as the datagram source.
type uotWriter struct {
	uc sudokubridge.UoTConn
}

func (w *uotWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		addr := ""
		if b.UDP != nil {
			addr = b.UDP.NetAddr()
		}
		if err := w.uc.WritePacket(addr, b.Bytes()); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	buf.ReleaseMulti(mb)
	return nil
}

func (w *uotWriter) Close() error { return nil }

func packetBuffer(addr string, payload []byte) *buf.Buffer {
	b := buf.New()
	_, _ = b.Write(payload)
	if d, err := xnet.ParseDestination("udp:" + addr); err == nil {
		b.UDP = &d
	}
	return b
}

// HandleUDP implements sudokubridge.Dialer: bridge a UoT association onto one
// dispatcher UDP link, so UDP traffic is counted/limited under this user just
// like TCP. It reads the first datagram to pick the routing destination, then
// streams the rest; DispatchLink blocks until the association ends.
func (r *Runner) HandleUDP(userHash string, uc sudokubridge.UoTConn, source net.Addr) {
	r.mu.RLock()
	uuid := r.hashUser[userHash]
	r.mu.RUnlock()
	if uuid == "" {
		_ = uc.Close()
		return
	}

	addr, payload, err := uc.ReadPacket()
	if err != nil {
		_ = uc.Close()
		return
	}
	first := packetBuffer(addr, payload)
	routeDest := xnet.UDPDestination(xnet.IPAddress([]byte{0, 0, 0, 0}), 0)
	if first.UDP != nil {
		routeDest = *first.UDP
	}

	email := format.UserTag(r.tag, uuid)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: xnet.DestinationFromAddr(source),
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})
	_ = r.disp.DispatchLink(ctx, routeDest, &transport.Link{
		Reader: &uotReader{uc: uc, first: first},
		Writer: &uotWriter{uc: uc},
	})
	_ = uc.Close()
}
