package ssaead

import (
	"net/netip"

	singbuf "github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	xbuf "github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// packetReader adapts a sing PacketConn (uplink, client -> target) to an xray
// buf.Reader: each sing datagram becomes one xray buffer whose .UDP endpoint is
// the datagram's destination, so the dispatcher routes every packet to its own
// target (full-cone UDP over one link).
type packetReader struct {
	conn N.PacketConn
}

func (r *packetReader) ReadMultiBuffer() (xbuf.MultiBuffer, error) {
	sb := singbuf.NewPacket()
	dest, err := r.conn.ReadPacket(sb)
	if err != nil {
		sb.Release()
		return nil, err
	}
	xb := xbuf.New()
	_, _ = xb.Write(sb.Bytes())
	sb.Release()
	d := toXrayDestUDP(dest)
	xb.UDP = &d
	return xbuf.MultiBuffer{xb}, nil
}

func (r *packetReader) Close() error { return nil }

// packetWriter adapts xray downlink buffers (target -> client) back onto the
// sing PacketConn, using each buffer's .UDP endpoint as the datagram source.
type packetWriter struct {
	conn N.PacketConn
}

func (w *packetWriter) WriteMultiBuffer(mb xbuf.MultiBuffer) error {
	for _, xb := range mb {
		var dest M.Socksaddr
		if xb.UDP != nil {
			dest = toSingSocksaddr(*xb.UDP)
		}
		sb := singbuf.NewPacket()
		_, _ = sb.Write(xb.Bytes())
		if err := w.conn.WritePacket(sb, dest); err != nil {
			xbuf.ReleaseMulti(mb)
			return err
		}
	}
	xbuf.ReleaseMulti(mb)
	return nil
}

func (w *packetWriter) Close() error { return nil }

func toXrayDestUDP(a M.Socksaddr) xnet.Destination {
	if a.IsIP() {
		return xnet.UDPDestination(xnet.IPAddress(a.Addr.AsSlice()), xnet.Port(a.Port))
	}
	return xnet.UDPDestination(xnet.DomainAddress(a.Fqdn), xnet.Port(a.Port))
}

func toSingSocksaddr(d xnet.Destination) M.Socksaddr {
	if d.Address.Family().IsIP() {
		if addr, ok := netip.AddrFromSlice(d.Address.IP()); ok {
			return M.SocksaddrFrom(addr.Unmap(), uint16(d.Port))
		}
	}
	return M.Socksaddr{Fqdn: d.Address.Domain(), Port: uint16(d.Port)}
}
