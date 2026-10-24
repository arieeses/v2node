package ssr

import (
	"fmt"
	"io"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
)

// Options is one SSR node's immutable config (from network_settings).
type Options struct {
	Cipher   string // e.g. aes-256-cfb
	Password string // node shared cipher password (SPMU)
	Protocol string // origin | auth_aes128_md5 | auth_aes128_sha1 | ...
	Obfs     string // plain | http_simple | ...
	ObfsHost string // obfs-param host
}

// server holds the per-node precomputed cipher spec + key.
type server struct {
	opt    Options
	spec   cipherSpec
	key    []byte
	lookup userLookup
}

func newServer(opt Options, lookup userLookup) (*server, error) {
	spec, err := newCipherSpec(opt.Cipher)
	if err != nil {
		return nil, err
	}
	return &server{opt: opt, spec: spec, key: kdf(opt.Password, spec.keySize), lookup: lookup}, nil
}

// handshake decodes one accepted connection down to the SSR protocol layer and
// reads the target address. It returns the matched user's uuid, the destination,
// and the protocol conn carrying the remaining (decoded) stream.
func (s *server) handshake(raw net.Conn) (uuid string, dest xnet.Destination, pc protoConn, err error) {
	obfsed, err := obfsServerConn(s.opt.Obfs, raw, s.opt.ObfsHost, s.key)
	if err != nil {
		return "", dest, nil, err
	}
	sc := newStreamConn(obfsed, s.spec, s.key)

	switch s.opt.Protocol {
	case "auth_aes128_sha1":
		pc = newAuthAES128(sc, s.key, s.lookup, true)
	case "auth_aes128_md5":
		pc = newAuthAES128(sc, s.key, s.lookup, false)
	case "auth_chain_a", "auth_chain_b":
		pc = newAuthChain(sc, s.key, s.lookup, s.opt.Protocol)
	case "", "origin":
		// origin is single-user: no per-user tag on the wire. Not valid for SPMU
		// multi-user nodes; rejected until a single-user path is wired.
		return "", dest, nil, fmt.Errorf("ssr: protocol %q not supported for multi-user", s.opt.Protocol)
	default:
		return "", dest, nil, fmt.Errorf("ssr: unsupported protocol %q", s.opt.Protocol)
	}

	addr, err := readTargetAddr(pc)
	if err != nil {
		return "", dest, nil, err
	}
	return pc.UUID(), addr, pc, nil
}

// readTargetAddr parses the leading shadowsocks SOCKS5-style address the client
// sends right after the protocol handshake.
func readTargetAddr(r io.Reader) (xnet.Destination, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return xnet.Destination{}, err
	}
	switch head[0] {
	case 0x01: // IPv4
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		ip := xnet.IPAddress(buf[:4])
		port := xnet.PortFromBytes(buf[4:6])
		return xnet.TCPDestination(ip, port), nil
	case 0x04: // IPv6
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		ip := xnet.IPAddress(buf[:16])
		port := xnet.PortFromBytes(buf[16:18])
		return xnet.TCPDestination(ip, port), nil
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return xnet.Destination{}, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		domain := string(buf[:l[0]])
		port := xnet.PortFromBytes(buf[l[0]:])
		return xnet.TCPDestination(xnet.DomainAddress(domain), port), nil
	default:
		return xnet.Destination{}, fmt.Errorf("ssr: bad address type 0x%02x", head[0])
	}
}
