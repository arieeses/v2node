package ssr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
)

func hmacSHA1(key, data []byte) []byte { m := hmac.New(sha1.New, key); m.Write(data); return m.Sum(nil) }
func hmacMD5(key, data []byte) []byte  { m := hmac.New(md5.New, key); m.Write(data); return m.Sum(nil) }
func sha1Sum(b []byte) []byte          { h := sha1.Sum(b); return h[:] }
func md5Sum(b []byte) []byte           { h := md5.Sum(b); return h[:] }

// userLookup resolves an SSR userID to that user's key + uuid. userKey is
// hashDigest(user password); the Runner builds the map from the panel user list.
type userLookup func(userID uint32) (userKey []byte, uuid string, ok bool)

// protoConn is the SSR protocol layer over the (decrypted) cipher stream: Read
// decodes the client's uplink, Write frames the server's downlink.
type protoConn interface {
	net.Conn
	UUID() string // matched user's uuid (empty until the auth header is decoded)
}

// --- origin: passthrough, single-user (no per-user tag) ---

type originConn struct {
	net.Conn
	uuid string
}

func (c *originConn) UUID() string { return c.uuid }

// --- auth_aes128_sha1 / auth_aes128_md5 ---

type authAES128 struct {
	*streamConn
	cipherKey []byte // node cipher key (for checkHead macKey = iv||key)
	lookup    userLookup
	hmacFn    func(key, data []byte) []byte
	hashFn    func([]byte) []byte
	salt      string

	uuid    string
	userKey []byte
	recvID  uint32
	packID  uint32
	gotHdr  bool
	acc     bytes.Buffer // decrypted-but-unparsed
	rbuf    bytes.Buffer // decoded plaintext
}

func newAuthAES128(sc *streamConn, cipherKey []byte, lookup userLookup, useSHA1 bool) *authAES128 {
	a := &authAES128{streamConn: sc, cipherKey: cipherKey, lookup: lookup, packID: 1}
	if useSHA1 {
		a.hmacFn, a.hashFn, a.salt = hmacSHA1, sha1Sum, "auth_aes128_sha1"
	} else {
		a.hmacFn, a.hashFn, a.salt = hmacMD5, md5Sum, "auth_aes128_md5"
	}
	return a
}

func (a *authAES128) UUID() string { return a.uuid }

func (a *authAES128) pump() error {
	tmp := make([]byte, 8192)
	n, err := a.streamConn.Read(tmp)
	if n > 0 {
		a.acc.Write(tmp[:n])
	}
	if !a.gotHdr {
		if derr := a.decodeHeader(); derr != nil {
			if derr == errNeedMore {
				return err
			}
			return derr
		}
	}
	if a.gotHdr {
		if derr := a.decodeData(); derr != nil {
			return derr
		}
	}
	return err
}

var errNeedMore = fmt.Errorf("ssr: need more")

func (a *authAES128) decodeHeader() error {
	b := a.acc.Bytes()
	if len(b) < 31 {
		return errNeedMore
	}
	iv, err := a.streamConn.ReadIV()
	if err != nil {
		return err
	}
	macKey := append(append([]byte{}, iv...), a.cipherKey...)
	if !bytes.Equal(a.hmacFn(macKey, b[:1])[:6], b[1:7]) {
		return fmt.Errorf("ssr: checkHead hmac mismatch")
	}
	userID := binary.LittleEndian.Uint32(b[7:11])
	uk, uuid, ok := a.lookup(userID)
	if !ok {
		return fmt.Errorf("ssr: unknown userID %d", userID)
	}
	if !bytes.Equal(a.hmacFn(macKey, b[7:27])[:4], b[27:31]) {
		return fmt.Errorf("ssr: authdata hmac mismatch")
	}
	ck := kdf(base64.StdEncoding.EncodeToString(uk)+a.salt, 16)
	blk, err := aes.NewCipher(ck)
	if err != nil {
		return err
	}
	dec := make([]byte, 16)
	cipher.NewCBCDecrypter(blk, make([]byte, 16)).CryptBlocks(dec, b[11:27])
	packedLen := int(binary.LittleEndian.Uint16(dec[12:14]))
	randLen := int(binary.LittleEndian.Uint16(dec[14:16]))
	if packedLen < 31+randLen+4 {
		return fmt.Errorf("ssr: bad packed length")
	}
	if len(b) < packedLen {
		return errNeedMore
	}
	if !bytes.Equal(a.hmacFn(uk, b[:packedLen-4])[:4], b[packedLen-4:packedLen]) {
		return fmt.Errorf("ssr: auth final hmac mismatch")
	}
	dataLen := packedLen - 31 - randLen - 4
	a.rbuf.Write(b[31+randLen : 31+randLen+dataLen])
	a.userKey = uk
	a.uuid = uuid
	a.recvID = 1
	a.acc.Next(packedLen)
	a.gotHdr = true
	return nil
}

func (a *authAES128) decodeData() error {
	for a.acc.Len() > 4 {
		b := a.acc.Bytes()
		macKey := make([]byte, len(a.userKey)+4)
		copy(macKey, a.userKey)
		binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.recvID)
		length := int(binary.LittleEndian.Uint16(b[:2]))
		if length < 7 || length >= 8192 {
			return fmt.Errorf("ssr: bad data length")
		}
		if length > a.acc.Len() {
			break
		}
		if !bytes.Equal(a.hmacFn(macKey, b[:2])[:2], b[2:4]) {
			return fmt.Errorf("ssr: data length hmac mismatch")
		}
		if !bytes.Equal(a.hmacFn(macKey, b[:length-4])[:4], b[length-4:length]) {
			return fmt.Errorf("ssr: data hmac mismatch")
		}
		a.recvID++
		pos := int(b[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(b[5:7])) + 4
		}
		a.rbuf.Write(b[pos : length-4])
		a.acc.Next(length)
	}
	return nil
}

func (a *authAES128) Read(p []byte) (int, error) {
	for a.rbuf.Len() == 0 {
		if err := a.pump(); err != nil && a.rbuf.Len() == 0 {
			return 0, err
		}
	}
	return a.rbuf.Read(p)
}

func (a *authAES128) Write(p []byte) (int, error) {
	// chunk to keep each packData small
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 8000 {
			n = 8000
		}
		if err := a.writeChunk(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (a *authAES128) writeChunk(p []byte) error {
	macKey := make([]byte, len(a.userKey)+4)
	copy(macKey, a.userKey)
	binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.packID)
	a.packID++
	var hdr bytes.Buffer
	packedLen := 2 + 2 + 1 + len(p) + 4
	binary.Write(&hdr, binary.LittleEndian, uint16(packedLen))
	hdr.Write(a.hmacFn(macKey, hdr.Bytes()[:2])[:2])
	hdr.WriteByte(1) // rand prefix: 0 random bytes
	hdr.Write(p)
	hdr.Write(a.hmacFn(macKey, hdr.Bytes())[:4])
	_, err := a.streamConn.Write(hdr.Bytes())
	return err
}
