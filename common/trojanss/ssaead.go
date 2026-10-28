// Package trojanss implements trojan-go's shadowsocks-AEAD obfuscation layer as
// a native v2node listener. A trojan node with ss-obfs enabled is served here
// instead of the Xray trojan inbound: the wire is TCP -> [TLS] -> shadowsocks
// AEAD (node-shared method+password) -> trojan protocol (per-user SHA224 auth).
// The shadowsocks AEAD transport is the standard SIP004 framing, verified
// byte-for-byte against the mihomo trojan `ss-opts` client.
package trojanss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// evpBytesToKey is shadowsocks' password->key derivation (OpenSSL EVP_BytesToKey
// with MD5, no salt), identical to the SSR/SS key schedule.
func evpBytesToKey(password string, keyLen int) []byte {
	var prev, out []byte
	h := md5.New()
	for len(out) < keyLen {
		h.Reset()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// ssKeyLen / ssAEAD map the trojan-go method names to key length + AEAD.
func ssKeyLen(method string) (int, error) {
	switch method {
	case "AES-128-GCM":
		return 16, nil
	case "AES-256-GCM", "CHACHA20-IETF-POLY1305":
		return 32, nil
	default:
		return 0, fmt.Errorf("trojanss: unsupported ss method %q", method)
	}
}

func ssAEAD(method string, subkey []byte) (cipher.AEAD, error) {
	switch method {
	case "AES-128-GCM", "AES-256-GCM":
		blk, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case "CHACHA20-IETF-POLY1305":
		return chacha20poly1305.New(subkey)
	}
	return nil, fmt.Errorf("trojanss: unsupported ss method %q", method)
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func subkeyAEAD(method string, key, salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, len(key))
	if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey); err != nil {
		return nil, err
	}
	return ssAEAD(method, subkey)
}

// ssConn is a shadowsocks AEAD stream over an underlying conn. Each direction
// carries its own salt + HKDF subkey; the read salt is consumed lazily on first
// Read, the write salt emitted lazily on first Write.
type ssConn struct {
	net.Conn
	method string
	key    []byte

	rAEAD  cipher.AEAD
	rNonce []byte
	rbuf   []byte // decrypted-but-unread plaintext

	wAEAD  cipher.AEAD
	wNonce []byte
}

func newSSConn(c net.Conn, method string, key []byte) *ssConn {
	return &ssConn{Conn: c, method: method, key: key}
}

func (s *ssConn) initRead() error {
	salt := make([]byte, len(s.key))
	if _, err := io.ReadFull(s.Conn, salt); err != nil {
		return err
	}
	aead, err := subkeyAEAD(s.method, s.key, salt)
	if err != nil {
		return err
	}
	s.rAEAD = aead
	s.rNonce = make([]byte, aead.NonceSize())
	return nil
}

func (s *ssConn) readChunk() error {
	lenBuf := make([]byte, 2+s.rAEAD.Overhead())
	if _, err := io.ReadFull(s.Conn, lenBuf); err != nil {
		return err
	}
	lenPlain, err := s.rAEAD.Open(lenBuf[:0], s.rNonce, lenBuf, nil)
	if err != nil {
		return err
	}
	incNonce(s.rNonce)
	n := int(binary.BigEndian.Uint16(lenPlain))
	if n == 0 || n > 0x3fff {
		return fmt.Errorf("trojanss: bad chunk length %d", n)
	}
	data := make([]byte, n+s.rAEAD.Overhead())
	if _, err := io.ReadFull(s.Conn, data); err != nil {
		return err
	}
	plain, err := s.rAEAD.Open(data[:0], s.rNonce, data, nil)
	if err != nil {
		return err
	}
	incNonce(s.rNonce)
	s.rbuf = append(s.rbuf, plain...)
	return nil
}

func (s *ssConn) Read(p []byte) (int, error) {
	if s.rAEAD == nil {
		if err := s.initRead(); err != nil {
			return 0, err
		}
	}
	for len(s.rbuf) == 0 {
		if err := s.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *ssConn) initWrite() error {
	salt := make([]byte, len(s.key))
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := s.Conn.Write(salt); err != nil {
		return err
	}
	aead, err := subkeyAEAD(s.method, s.key, salt)
	if err != nil {
		return err
	}
	s.wAEAD = aead
	s.wNonce = make([]byte, aead.NonceSize())
	return nil
}

func (s *ssConn) Write(p []byte) (int, error) {
	if s.wAEAD == nil {
		if err := s.initWrite(); err != nil {
			return 0, err
		}
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0x3fff {
			n = 0x3fff
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(n))
		out := s.wAEAD.Seal(nil, s.wNonce, lb[:], nil)
		incNonce(s.wNonce)
		out = s.wAEAD.Seal(out, s.wNonce, p[:n], nil)
		incNonce(s.wNonce)
		if _, err := s.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
