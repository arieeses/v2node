package ssr

import (
	"crypto/cipher"
	crand "crypto/rand"
	"io"
	"net"
)

// streamConn is the shadowsocks stream-cipher layer: the sender prepends a fresh
// random IV then encrypts; the receiver reads the IV then decrypts. It is used
// symmetrically for both directions (uplink decrypt on Read, downlink encrypt on
// Write). The read IV is exposed via ReadIV once the first record arrives, since
// the SSR auth protocols mix it into their first HMAC.
type streamConn struct {
	net.Conn
	spec cipherSpec
	key  []byte

	readIV  []byte
	dec     cipher.Stream
	writeIV []byte
	enc     cipher.Stream
}

func newStreamConn(c net.Conn, spec cipherSpec, key []byte) *streamConn {
	return &streamConn{Conn: c, spec: spec, key: key}
}

// initRead reads the IV (if not yet) and builds the decrypt stream.
func (c *streamConn) initRead() error {
	if c.dec != nil {
		return nil
	}
	iv := make([]byte, c.spec.ivSize)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return err
	}
	dec, err := c.spec.newDec(c.key, iv)
	if err != nil {
		return err
	}
	c.readIV = iv
	c.dec = dec
	return nil
}

// ReadIV returns the client's IV, reading it from the wire if necessary.
func (c *streamConn) ReadIV() ([]byte, error) {
	if err := c.initRead(); err != nil {
		return nil, err
	}
	return c.readIV, nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	if err := c.initRead(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	if c.enc == nil {
		iv := make([]byte, c.spec.ivSize)
		if _, err := crand.Read(iv); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(iv); err != nil {
			return 0, err
		}
		enc, err := c.spec.newEnc(c.key, iv)
		if err != nil {
			return 0, err
		}
		c.writeIV = iv
		c.enc = enc
	}
	ct := make([]byte, len(p))
	c.enc.XORKeyStream(ct, p)
	if _, err := c.Conn.Write(ct); err != nil {
		return 0, err
	}
	return len(p), nil
}
