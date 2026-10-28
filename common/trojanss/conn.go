package trojanss

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
)

const (
	keyLength = 56 // hex(SHA224(password))
	cmdTCP    = 0x01
	cmdUDP    = 0x03
)

// handshake wraps the (already TLS-terminated, if applicable) conn with the
// shadowsocks AEAD layer and reads the trojan request header:
//
//	56 bytes hex(SHA224(password)) | CRLF | cmd(1) | SOCKS5 addr | CRLF | payload...
//
// It returns the hex key (to map to a user), the target, and the ss conn whose
// subsequent Read/Write carry the raw tunnelled payload.
func handshake(c net.Conn, method string, key []byte) (hexKey string, dest xnet.Destination, conn net.Conn, err error) {
	ss := newSSConn(c, method, key)

	hdr := make([]byte, keyLength)
	if _, err = io.ReadFull(ss, hdr); err != nil {
		return "", dest, nil, err
	}
	hexKey = string(hdr)
	if _, err = hex.DecodeString(hexKey); err != nil {
		return "", dest, nil, fmt.Errorf("trojanss: non-hex key")
	}

	crlf := make([]byte, 2)
	if _, err = io.ReadFull(ss, crlf); err != nil {
		return "", dest, nil, err
	}
	var cmd [1]byte
	if _, err = io.ReadFull(ss, cmd[:]); err != nil {
		return "", dest, nil, err
	}
	if cmd[0] != cmdTCP {
		// UDP (0x03) not yet bridged; only TCP CONNECT is supported.
		return "", dest, nil, fmt.Errorf("trojanss: unsupported command 0x%02x", cmd[0])
	}
	dest, err = readSocksAddr(ss)
	if err != nil {
		return "", dest, nil, err
	}
	if _, err = io.ReadFull(ss, crlf); err != nil {
		return "", dest, nil, err
	}
	return hexKey, dest, ss, nil
}

// readSocksAddr parses a SOCKS5-style address (ATYP + addr + port).
func readSocksAddr(r io.Reader) (xnet.Destination, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return xnet.Destination{}, err
	}
	switch atyp[0] {
	case 0x01: // IPv4
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		return xnet.TCPDestination(xnet.IPAddress(buf[:4]), xnet.PortFromBytes(buf[4:6])), nil
	case 0x04: // IPv6
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		return xnet.TCPDestination(xnet.IPAddress(buf[:16]), xnet.PortFromBytes(buf[16:18])), nil
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return xnet.Destination{}, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return xnet.Destination{}, err
		}
		return xnet.TCPDestination(xnet.DomainAddress(string(buf[:l[0]])), xnet.PortFromBytes(buf[l[0]:])), nil
	default:
		return xnet.Destination{}, fmt.Errorf("trojanss: bad address type 0x%02x", atyp[0])
	}
}
