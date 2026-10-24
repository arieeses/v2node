// authchain.go: auth_chain_a / auth_chain_b SSR protocols (server side).
//
// These are the hardest SSR protocols: each packet's length field and random
// padding are driven by a per-connection hash chain plus an XorShift128+ PRNG,
// seeded from the previous packet's HMAC. The server must mirror the client's
// two independent chains — (lastClientHash, randomClient) for the uplink it
// decodes, (lastServerHash, randomServer) for the downlink it encodes — exactly.
//
// Unlike auth_aes128_*, the auth_chain user key is the RAW protocol-param
// password bytes (not hashed); for SPMU the Runner uses the uuid verbatim.
// Verified byte-for-byte against the mihomo auth_chain_a/_b client.
package ssr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
)

// xorShift128Plus replicates mihomo's tools.XorShift128Plus bit-for-bit,
// including InitFromBinAndLength overwriting the seed's first 2 bytes.
type xorShift128Plus struct{ s0, s1 uint64 }

func (r *xorShift128Plus) next() uint64 {
	x, y := r.s0, r.s1
	r.s0 = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	r.s1 = x
	return x + y
}

func (r *xorShift128Plus) initFromBin(bin []byte) {
	full := make([]byte, 16)
	copy(full, bin)
	r.s0 = binary.LittleEndian.Uint64(full[:8])
	r.s1 = binary.LittleEndian.Uint64(full[8:16])
}

func (r *xorShift128Plus) initFromBinAndLength(bin []byte, length int) {
	full := make([]byte, 16)
	copy(full, bin)
	binary.LittleEndian.PutUint16(full, uint16(length))
	r.s0 = binary.LittleEndian.Uint64(full[:8])
	r.s1 = binary.LittleEndian.Uint64(full[8:16])
	for i := 0; i < 4; i++ {
		r.next()
	}
}

func getRandStartPos(randLen int, r *xorShift128Plus) int {
	if randLen == 0 {
		return 0
	}
	return int(int64(r.next()%8589934609) % int64(randLen))
}

type authChain struct {
	*streamConn
	cipherKey []byte
	lookup    userLookup
	salt      string // auth_chain_a | auth_chain_b
	overhead  int    // registered protocol overhead (4)
	dsl, dsl2 []int  // chain_b data-size lists (nil for chain_a)

	uuid           string
	userKey        []byte
	lastClientHash []byte
	lastServerHash []byte
	rc4dec, rc4enc cipher.Stream
	randClient     xorShift128Plus
	randServer     xorShift128Plus
	recvID, packID uint32
	sentFirst      bool
	gotHdr         bool
	acc, rbuf      bytes.Buffer
}

// newAuthChain builds an auth_chain_a or auth_chain_b server conn. For _b it
// derives the two data-size lists from the node cipher key, as the client does.
func newAuthChain(sc *streamConn, cipherKey []byte, lookup userLookup, salt string) *authChain {
	a := &authChain{streamConn: sc, cipherKey: cipherKey, lookup: lookup, salt: salt, overhead: 4}
	if salt == "auth_chain_b" {
		var r xorShift128Plus
		r.initFromBin(cipherKey)
		n := r.next()%8 + 4
		for ; n > 0; n-- {
			a.dsl = append(a.dsl, int(r.next()%2340%2040%1440))
		}
		sort.Ints(a.dsl)
		n = r.next()%16 + 8
		for ; n > 0; n-- {
			a.dsl2 = append(a.dsl2, int(r.next()%2340%2040%1440))
		}
		sort.Ints(a.dsl2)
	}
	return a
}

func (a *authChain) UUID() string { return a.uuid }

func (a *authChain) getRandLen(length int, lastHash []byte, r *xorShift128Plus) int {
	if a.salt == "auth_chain_b" {
		return a.getRandLenB(length, lastHash, r)
	}
	// auth_chain_a
	if length > 1440 {
		return 0
	}
	r.initFromBinAndLength(lastHash, length)
	switch {
	case length > 1300:
		return int(r.next() % 31)
	case length > 900:
		return int(r.next() % 127)
	case length > 400:
		return int(r.next() % 521)
	}
	return int(r.next() % 1021)
}

func (a *authChain) getRandLenB(length int, lastHash []byte, r *xorShift128Plus) int {
	if length >= 1440 {
		return 0
	}
	r.initFromBinAndLength(lastHash, length)
	pos := sort.Search(len(a.dsl), func(i int) bool { return a.dsl[i] >= length+a.overhead })
	finalPos := pos + int(r.next()%uint64(len(a.dsl)))
	if finalPos < len(a.dsl) {
		return a.dsl[finalPos] - length - a.overhead
	}
	pos = sort.Search(len(a.dsl2), func(i int) bool { return a.dsl2[i] >= length+a.overhead })
	finalPos = pos + int(r.next()%uint64(len(a.dsl2)))
	if finalPos < len(a.dsl2) {
		return a.dsl2[finalPos] - length - a.overhead
	}
	if finalPos < pos+len(a.dsl2)-1 {
		return 0
	}
	switch {
	case length > 1300:
		return int(r.next() % 31)
	case length > 900:
		return int(r.next() % 127)
	case length > 400:
		return int(r.next() % 521)
	}
	return int(r.next() % 1021)
}

func (a *authChain) pump() error {
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

func (a *authChain) decodeHeader() error {
	b := a.acc.Bytes()
	if len(b) < 36 {
		return errNeedMore
	}
	iv, err := a.streamConn.ReadIV()
	if err != nil {
		return err
	}
	macKey := append(append([]byte{}, iv...), a.cipherKey...)
	a.lastClientHash = hmacMD5(macKey, b[:4])
	if !bytes.Equal(a.lastClientHash[:8], b[4:12]) {
		return fmt.Errorf("ssr: auth_chain checkHead hmac mismatch")
	}
	userID := binary.LittleEndian.Uint32(b[12:16]) ^ binary.LittleEndian.Uint32(a.lastClientHash[8:12])
	uk, uuid, ok := a.lookup(userID)
	if !ok {
		return fmt.Errorf("ssr: unknown userID %d", userID)
	}
	a.userKey, a.uuid = uk, uuid
	rkey := kdf(base64.StdEncoding.EncodeToString(uk)+base64.StdEncoding.EncodeToString(a.lastClientHash), 16)
	a.rc4dec, _ = rc4.NewCipher(rkey)
	a.rc4enc, _ = rc4.NewCipher(rkey)
	// Decrypt the authdata block and take the client's actual protocol overhead
	// from it (dec[12:14]). auth_chain_b's getRandLength feeds this overhead into
	// the dataSize-list lookup, and mihomo sets it to obfsOverhead + 4 (e.g. 9
	// for tls1.2_ticket_auth, 4 for plain) — NOT a fixed 4. Reading it here keeps
	// us in lockstep with the client regardless of which obfs the node uses.
	blk, err := aes.NewCipher(kdf(base64.StdEncoding.EncodeToString(uk)+a.salt, 16))
	if err != nil {
		return err
	}
	dec := make([]byte, 16)
	cipher.NewCBCDecrypter(blk, make([]byte, 16)).CryptBlocks(dec, b[16:32])
	if ov := int(binary.LittleEndian.Uint16(dec[12:14])); ov >= 0 && ov < 256 {
		a.overhead = ov
	}
	a.lastServerHash = hmacMD5(uk, b[12:32])
	if !bytes.Equal(a.lastServerHash[:4], b[32:36]) {
		return fmt.Errorf("ssr: auth_chain server hash mismatch")
	}
	a.recvID, a.packID = 1, 1
	a.acc.Next(36)
	a.gotHdr = true
	return nil
}

func (a *authChain) decodeData() error {
	for a.acc.Len() > 4 {
		b := a.acc.Bytes()
		dataLength := int(binary.LittleEndian.Uint16(b[:2]) ^ binary.LittleEndian.Uint16(a.lastClientHash[14:16]))
		randLen := a.getRandLen(dataLength, a.lastClientHash, &a.randClient)
		length := dataLength + randLen
		if dataLength < 0 || randLen < 0 || length < 0 {
			return fmt.Errorf("ssr: auth_chain bad length")
		}
		if length >= 4096 {
			return fmt.Errorf("ssr: auth_chain length error")
		}
		if 4+length > a.acc.Len() {
			break
		}
		macKey := make([]byte, len(a.userKey)+4)
		copy(macKey, a.userKey)
		binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.recvID)
		h := hmacMD5(macKey, b[:length+2])
		if !bytes.Equal(h[:2], b[length+2:length+4]) {
			log.WithFields(log.Fields{
				"salt": a.salt, "recvID": a.recvID, "dataLen": dataLength,
				"randLen": randLen, "overhead": a.overhead,
			}).Debug("ssr: auth_chain data hmac mismatch")
			return fmt.Errorf("ssr: auth_chain data hmac mismatch")
		}
		a.lastClientHash = h
		pos := 2
		if dataLength > 0 && randLen > 0 {
			pos += getRandStartPos(randLen, &a.randClient)
		}
		wanted := make([]byte, dataLength)
		copy(wanted, b[pos:pos+dataLength])
		a.rc4dec.XORKeyStream(wanted, wanted)
		a.rbuf.Write(wanted) // uplink: client does not prepend on its first packet
		a.recvID++
		a.acc.Next(length + 4)
	}
	return nil
}

func (a *authChain) Read(p []byte) (int, error) {
	for a.rbuf.Len() == 0 {
		if err := a.pump(); err != nil && a.rbuf.Len() == 0 {
			return 0, err
		}
	}
	return a.rbuf.Read(p)
}

func (a *authChain) Write(p []byte) (int, error) {
	data := p
	if !a.sentFirst {
		// the client's Decode strips the first 2 bytes of the first downlink packet
		data = append([]byte{0, 0}, p...)
		a.sentFirst = true
	}
	var out bytes.Buffer
	for len(data) > 2800 {
		a.packOne(&out, data[:2800])
		data = data[2800:]
	}
	if len(data) > 0 {
		a.packOne(&out, data)
	}
	if _, err := a.streamConn.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

// packOne frames one downlink packet, mirroring the client's packData using the
// server's chain state (lastServerHash / randServer / rc4enc / packID).
func (a *authChain) packOne(out *bytes.Buffer, data []byte) {
	buf := make([]byte, len(data))
	copy(buf, data)
	a.rc4enc.XORKeyStream(buf, buf)
	macKey := make([]byte, len(a.userKey)+4)
	copy(macKey, a.userKey)
	binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.packID)
	a.packID++
	length := uint16(len(buf)) ^ binary.LittleEndian.Uint16(a.lastServerHash[14:16])
	start := out.Len()
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], length)
	out.Write(lb[:])
	randLen := a.getRandLen(len(buf), a.lastServerHash, &a.randServer)
	switch {
	case len(buf) == 0:
		out.Write(make([]byte, randLen))
	case randLen > 0:
		sp := getRandStartPos(randLen, &a.randServer)
		out.Write(make([]byte, sp))
		out.Write(buf)
		out.Write(make([]byte, randLen-sp))
	default:
		out.Write(buf)
	}
	a.lastServerHash = hmacMD5(macKey, out.Bytes()[start:])
	out.Write(a.lastServerHash[:2])
}
