package ssr

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// obfsServerConn wraps an accepted connection with the server side of an SSR
// obfs plugin. plain is a passthrough; tls1.2_ticket_auth (and its fastauth
// alias) perform a fake TLS 1.2 handshake and then frame data as TLS
// application_data records. http_simple/http_post/random_head are added
// incrementally. key is the node cipher key (the obfs HMAC key is key||clientID).
func obfsServerConn(name string, c net.Conn, host string, key []byte) (net.Conn, error) {
	switch name {
	case "", "plain":
		return c, nil
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return &tlsTicketObfs{Conn: c, key: key}, nil
	default:
		return nil, errUnsupportedObfs(name)
	}
}

type errUnsupportedObfs string

func (e errUnsupportedObfs) Error() string { return "ssr: unsupported obfs " + string(e) }

// tlsTicketObfs is the server side of tls1.2_ticket_auth. The client opens with
// a fake TLS ClientHello carrying its 32-byte client id as the session id; we
// reply with a fake ServerHello + ChangeCipherSpec + Finished whose two HMACs
// (over the server random and over the whole record set, keyed by key||clientID)
// the client verifies. After that both sides tunnel the real stream inside TLS
// application_data records (0x17 0x03 0x03 | len | payload). Verified against the
// mihomo tls1.2_ticket_auth client.
type tlsTicketObfs struct {
	net.Conn
	key       []byte
	clientID  []byte
	sentHello bool
	raw       bytes.Buffer // undecoded bytes from the wire
	dec       bytes.Buffer // decoded application_data payloads
}

func (o *tlsTicketObfs) hmac10(data []byte) []byte {
	k := append(append([]byte{}, o.key...), o.clientID...)
	return hmacSHA1(k, data)[:10]
}

func (o *tlsTicketObfs) doHandshake() error {
	b := o.raw.Bytes()
	if len(b) < 5 {
		return errNeedMore
	}
	if b[0] != 0x16 {
		return fmt.Errorf("ssr: tls obfs bad clienthello type 0x%02x", b[0])
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return errNeedMore
	}
	// session id (client id) sits at record bytes [44:76]; [43] is its length.
	if recLen < 71 || b[43] != 0x20 {
		return fmt.Errorf("ssr: tls obfs malformed clienthello")
	}
	o.clientID = append([]byte{}, b[44:76]...)
	o.raw.Next(5 + recLen)
	if err := o.sendServerHello(); err != nil {
		return err
	}
	o.sentHello = true
	return nil
}

func (o *tlsTicketObfs) sendServerHello() error {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // server version TLS 1.2
	rnd := make([]byte, 22)        // server random = time(4) + rand(18) ...
	binary.BigEndian.PutUint32(rnd[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(rnd[4:]); err != nil {
		return err
	}
	body.Write(rnd)
	body.Write(o.hmac10(rnd)) // ... + hmac(10) completes the 32-byte random
	body.WriteByte(0x20)      // session id length
	body.Write(o.clientID)    // echo client id as session id
	// cipher suite c02f, null compression, 5-byte renegotiation_info extension.
	body.Write([]byte{0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00})

	var hs bytes.Buffer
	hs.Write([]byte{0x02, 0x00}) // ServerHello + high length byte
	binary.Write(&hs, binary.BigEndian, uint16(body.Len()))
	hs.Write(body.Bytes())

	var out bytes.Buffer
	out.Write([]byte{0x16, 0x03, 0x03})
	binary.Write(&out, binary.BigEndian, uint16(hs.Len()))
	out.Write(hs.Bytes())
	out.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}) // ChangeCipherSpec
	// Finished record: header + 22 random, then a 10-byte HMAC over everything
	// emitted so far (the client checks buf[n-10:] == hmac(buf[:n-10])).
	fin := make([]byte, 22)
	if _, err := rand.Read(fin); err != nil {
		return err
	}
	out.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x20})
	out.Write(fin)
	out.Write(o.hmac10(out.Bytes()))

	_, err := o.Conn.Write(out.Bytes())
	return err
}

func (o *tlsTicketObfs) drain() error {
	for o.raw.Len() >= 5 {
		b := o.raw.Bytes()
		typ := b[0]
		size := int(binary.BigEndian.Uint16(b[3:5]))
		if o.raw.Len() < 5+size {
			break
		}
		o.raw.Next(5)
		payload := o.raw.Next(size)
		switch typ {
		case 0x17: // application_data: the real tunnelled stream
			o.dec.Write(payload)
		case 0x14, 0x16: // ChangeCipherSpec / handshake: framing only, skip
		default:
			return fmt.Errorf("ssr: tls obfs bad record type 0x%02x", typ)
		}
	}
	return nil
}

func (o *tlsTicketObfs) Read(p []byte) (int, error) {
	for {
		if o.dec.Len() > 0 {
			return o.dec.Read(p)
		}
		if o.sentHello {
			if err := o.drain(); err != nil {
				return 0, err
			}
			if o.dec.Len() > 0 {
				return o.dec.Read(p)
			}
		}
		buf := make([]byte, 16384)
		n, err := o.Conn.Read(buf)
		if n > 0 {
			o.raw.Write(buf[:n])
		}
		if !o.sentHello {
			if herr := o.doHandshake(); herr != nil && herr != errNeedMore {
				return 0, herr
			}
		}
		if err != nil {
			if o.sentHello {
				_ = o.drain()
				if o.dec.Len() > 0 {
					return o.dec.Read(p)
				}
			}
			return 0, err
		}
	}
}

func (o *tlsTicketObfs) Write(p []byte) (int, error) {
	var out bytes.Buffer
	b := p
	for len(b) > 0 {
		n := len(b)
		if n > 16384 {
			n = 16384
		}
		out.Write([]byte{0x17, 0x03, 0x03})
		binary.Write(&out, binary.BigEndian, uint16(n))
		out.Write(b[:n])
		b = b[n:]
	}
	if _, err := o.Conn.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}
