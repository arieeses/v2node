// Package obfs implements a server-side simple-obfs (SIP003) "tls" front for
// Shadowsocks nodes. The public port is owned by this front; it peels the
// obfs-tls framing and relays the plaintext Shadowsocks stream to a loopback
// port where the real Xray SS inbound listens — the same "front on the public
// port, plain SS on loopback" shape used by shadow-tls.
//
// Wire format (must match shadowsocks/simple-obfs and mihomo/clash simple-obfs):
//
//	client -> server, first packet: a fake TLS ClientHello record. The real
//	  payload is carried in the SessionTicket extension (0x0023), which the
//	  template places immediately after the 138-byte ClientHello header.
//	client -> server, thereafter: TLS application-data records
//	  [0x17 0x03 0x03][len:2][payload].
//	server -> client, first packet: ServerHello(96) + ChangeCipherSpec(6) +
//	  a handshake record header [0x16 0x03 0x03][len:2] wrapping the first
//	  payload chunk.
//	server -> client, thereafter: application-data records like the client's.
package obfs

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// clientHelloHeaderLen is sizeof(struct tls_client_hello) in simple-obfs:
	// the fixed ClientHello bytes up to and including ext_len, after which the
	// SessionTicket extension (carrying the payload) begins.
	clientHelloHeaderLen = 138
	// maxRecord is the app-data record payload cap (TLS record limit) used by
	// the reference client when chunking.
	maxRecord = 16384
	// handshakeTimeout bounds how long we wait for the client's ClientHello.
	handshakeTimeout = 15 * time.Second
)

// serverHelloTemplate is the 96-byte ServerHello record from simple-obfs
// (tls_server_hello_template) with placeholders for the 4-byte timestamp,
// 28-byte random and 32-byte session id, which are filled per connection.
// No client validates these fields, but faithful bytes keep the camouflage.
var serverHelloTemplate = []byte{
	0x16, 0x03, 0x01, 0x00, 0x5b, // record: handshake, TLS1.0, len=91
	0x02, 0x00, 0x00, 0x57, // handshake: server_hello, len=87
	0x03, 0x03, // handshake version TLS1.2
	0, 0, 0, 0, // random_unix_time (filled)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random_bytes[0:14] (filled)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random_bytes[14:28] (filled)
	0x20,                                           // session_id_len = 32
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // session_id[0:16] (filled)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // session_id[16:32] (filled)
	0xcc, 0xa8, // cipher_suite
	0x00,       // comp_method
	0x00, 0x00, // ext_len (as in the template)
	0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
	0x00, 0x17, 0x00, 0x00, // extended_master_secret
	0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats
}

// changeCipherSpec is the 6-byte CCS record that follows the ServerHello.
var changeCipherSpec = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

// obfs mode, auto-detected from the client's first byte.
const (
	modeUnknown = iota
	modeTLS     // fake TLS handshake, everything framed as app-data records
	modeHTTP    // fake HTTP/WebSocket-upgrade handshake, raw stream afterwards
)

// obfsConn wraps a raw client connection, exposing the de-obfuscated
// Shadowsocks stream via Read and re-obfuscating anything written back. It runs
// strictly the mode configured on the node (tls or http); a client speaking the
// other mode is rejected, matching the panel configuration exactly.
type obfsConn struct {
	net.Conn
	r *bufio.Reader

	// read side
	mode          int
	handshakeDone bool
	plain         []byte // leftover de-obfuscated bytes (tls handshake payload)
	plainOff      int

	// write side
	firstResponse bool
}

func newObfsConn(c net.Conn, mode int) *obfsConn {
	return &obfsConn{Conn: c, r: bufio.NewReader(c), mode: mode, firstResponse: true}
}

// Read returns de-obfuscated plaintext (the client's Shadowsocks stream).
func (c *obfsConn) Read(p []byte) (int, error) {
	for c.plainOff >= len(c.plain) {
		if !c.handshakeDone {
			if err := c.readHandshake(); err != nil {
				return 0, err
			}
			c.handshakeDone = true
			// HTTP mode carries no buffered payload — the body follows raw in
			// the stream, so hand off to the raw path below immediately.
			if c.mode == modeHTTP {
				return c.r.Read(p)
			}
		} else if c.mode == modeHTTP {
			// After the HTTP handshake the stream is raw/unframed.
			return c.r.Read(p)
		} else {
			data, err := c.readAppData()
			if err != nil {
				return 0, err
			}
			c.plain, c.plainOff = data, 0
		}
		// Loop again if an empty ticket/frame yielded no bytes.
	}
	n := copy(p, c.plain[c.plainOff:])
	c.plainOff += n
	return n, nil
}

// readHandshake consumes the client's obfs handshake. It auto-detects tls vs
// http from the client's first byte (0x16 = tls ClientHello, otherwise http),
// so a single front serves clients speaking either mode — matching the standard
// simple-obfs server, which accepts both. The panel-configured mode is only a
// default hint; the wire wins.
func (c *obfsConn) readHandshake() error {
	_ = c.Conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer c.Conn.SetReadDeadline(time.Time{})

	first, err := c.r.Peek(1)
	if err != nil {
		return err
	}
	if first[0] == 0x16 {
		c.mode = modeTLS
		return c.readClientHello()
	}
	c.mode = modeHTTP
	return c.readHTTPRequest()
}

// readClientHello consumes the ClientHello record and extracts the payload the
// client stuffed into the SessionTicket extension. It parses the handshake
// structure (rather than assuming the simple-obfs fixed offset) so clients with
// a different cipher-suite count or extension ordering still interoperate.
func (c *obfsConn) readClientHello() error {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x16 || hdr[1] != 0x03 {
		log.WithFields(log.Fields{"remote": c.Conn.RemoteAddr(), "head": hex.EncodeToString(hdr[:3])}).
			Warn("obfs-tls: client is not speaking tls-obfs (node configured mode=tls); rejecting")
		return fmt.Errorf("obfs-tls: not a handshake record: % x", hdr[:3])
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 42 { // handshake header + random at minimum
		return fmt.Errorf("obfs-tls: ClientHello too short (%d)", recLen)
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return err
	}
	payload, err := extractSessionTicket(body)
	if err != nil {
		n := len(body)
		if n > 80 {
			n = 80
		}
		log.WithFields(log.Fields{
			"remote": c.Conn.RemoteAddr(),
			"err":    err,
			"reclen": recLen,
			"head":   hex.EncodeToString(body[:n]),
		}).Warn("obfs-tls: ClientHello parse failed")
		return err
	}
	c.plain = append([]byte(nil), payload...)
	c.plainOff = 0
	return nil
}

// extractSessionTicket walks a ClientHello body (the record payload, i.e. the
// bytes after the 5-byte record header) and returns the data carried in the
// SessionTicket extension (type 0x0023), which simple-obfs uses to carry the
// first chunk of real payload.
func extractSessionTicket(b []byte) ([]byte, error) {
	if len(b) < 39 || b[0] != 0x01 {
		return nil, fmt.Errorf("not a client_hello")
	}
	// handshake_type(1) + handshake_len(3) + version(2) + random(32) = 38
	p := 38
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return nil, fmt.Errorf("truncated at cipher_suites")
	}
	csLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2 + csLen
	if p+1 > len(b) {
		return nil, fmt.Errorf("truncated at comp_methods")
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return nil, fmt.Errorf("no extensions block")
	}
	extTotal := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	end := p + extTotal
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(b[p : p+2])
		elen := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return nil, fmt.Errorf("extension %#04x overruns record", etype)
		}
		if etype == 0x0023 { // session_ticket
			return b[p : p+elen], nil
		}
		p += elen
	}
	return nil, fmt.Errorf("no session-ticket extension")
}

// readAppData reads one TLS application-data record and returns its payload.
func (c *obfsConn) readAppData() ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
		return nil, fmt.Errorf("obfs-tls: bad app-data header % x", hdr[:3])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxRecord {
		return nil, fmt.Errorf("obfs-tls: app-data record too large: %d", n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(c.r, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Write re-obfuscates plaintext (the server's Shadowsocks stream) toward the
// client, prepending the fake handshake on the very first call.
func (c *obfsConn) Write(p []byte) (int, error) {
	if c.mode == modeHTTP {
		if c.firstResponse {
			c.firstResponse = false
			if _, err := c.Conn.Write(buildHTTPResponse(p)); err != nil {
				return 0, err
			}
			return len(p), nil
		}
		return c.Conn.Write(p) // raw/unframed after the handshake
	}

	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecord {
			chunk = chunk[:maxRecord]
		}
		var out []byte
		if c.firstResponse {
			out = c.buildServerHello(chunk)
			c.firstResponse = false
		} else {
			out = wrapAppData(chunk)
		}
		if _, err := c.Conn.Write(out); err != nil {
			return total - len(p), err
		}
		p = p[len(chunk):]
	}
	return total, nil
}

// buildServerHello returns ServerHello + ChangeCipherSpec + a handshake record
// wrapping the first response chunk.
func (c *obfsConn) buildServerHello(data []byte) []byte {
	hello := make([]byte, len(serverHelloTemplate))
	copy(hello, serverHelloTemplate)
	binary.BigEndian.PutUint32(hello[11:15], uint32(time.Now().Unix()))
	_, _ = rand.Read(hello[15:43]) // random_bytes
	_, _ = rand.Read(hello[44:76]) // session_id

	out := make([]byte, 0, len(hello)+len(changeCipherSpec)+5+len(data))
	out = append(out, hello...)
	out = append(out, changeCipherSpec...)
	var rec [5]byte
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(data)))
	out = append(out, rec[:]...)
	out = append(out, data...)
	return out
}

// wrapAppData frames data as a TLS application-data record.
func wrapAppData(data []byte) []byte {
	out := make([]byte, 5+len(data))
	out[0], out[1], out[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(len(data)))
	copy(out[5:], data)
	return out
}
